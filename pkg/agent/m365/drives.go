package m365

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/osshield/gopbs/scan"
)

// driveItem is what root/delta returns
type driveItem struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Size     int64     `json:"size"`
	CTag     string    `json:"cTag"`
	WebURL   string    `json:"webUrl"`
	Modified time.Time `json:"lastModifiedDateTime"`
	File     *struct{} `json:"file"`
	Folder   *struct{} `json:"folder"`
	Package  *struct {
		Type string `json:"type"`
	} `json:"package"`
	Deleted *struct{} `json:"deleted"`
	Root    *struct{} `json:"root"`
	Parent  struct {
		Path string `json:"path"`
	} `json:"parentReference"`
	CreatedBy  identitySet `json:"createdBy"`
	ModifiedBy identitySet `json:"lastModifiedBy"`
}

type identitySet struct {
	User *struct {
		DisplayName string `json:"displayName"`
		Email       string `json:"email"`
	} `json:"user"`
}

func (s identitySet) String() string {
	if s.User == nil {
		return ""
	}
	if s.User.Email != "" {
		return s.User.DisplayName + " <" + s.User.Email + ">"
	}
	return s.User.DisplayName
}

// driveStats counts one drive
type driveStats struct {
	Files, Folders int
	Bytes          uint64
	Resyncs        int
}

// driveRef names a drive to archive and where its items go in the unit's tree
type driveRef struct {
	ID, Name, WebURL, Prefix string
}

// userDrive returns the user's OneDrive, or nil when none is provisioned
func userDrive(ctx context.Context, c *Client, userID string) (*driveRef, error) {
	var d struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		WebURL string `json:"webUrl"`
	}
	if err := c.Get(ctx, "users/"+userID+"/drive?$select=id,name,webUrl", &d, nil); err != nil {
		if IsStatus(err, http.StatusNotFound, http.StatusBadRequest) {
			return nil, nil
		}
		return nil, fmt.Errorf("OneDrive: %w", err)
	}
	return &driveRef{ID: d.ID, Name: d.Name, WebURL: d.WebURL, Prefix: "onedrive"}, nil
}

// siteDrives lists a site's document libraries, each under files/<library>
func siteDrives(ctx context.Context, c *Client, siteID string) ([]driveRef, error) {
	type drive struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		WebURL string `json:"webUrl"`
	}
	drives, err := List[drive](ctx, c, "sites/"+siteID+"/drives?$select=id,name,webUrl")
	if err != nil {
		return nil, fmt.Errorf("document libraries: %w", err)
	}
	sort.Slice(drives, func(i, j int) bool { return drives[i].Name < drives[j].Name })
	out := make([]driveRef, 0, len(drives))
	seen := map[string]int{}
	for _, d := range drives {
		name := safeComponent(d.Name)
		if seen[name] > 0 {
			name = fmt.Sprintf("%s-%d", name, seen[name])
		}
		seen[safeComponent(d.Name)]++
		out = append(out, driveRef{ID: d.ID, Name: d.Name, WebURL: d.WebURL, Prefix: "files/" + name})
	}
	return out, nil
}

// collectDrive applies the drive's delta to its index and produces the entries.
// Files are streamed from Graph when gopbs reads them (size and mtime come from the
// delta, so unchanged files are reused without a request); folders are explicit
// directories so empty ones survive. Exclude patterns match the archive path below
// the drive prefix, as proxmox-backup-client patterns would.
func collectDrive(ctx context.Context, c *Client, idx *DriveIndex, excludes scan.PatternList, now time.Time, warn func(string)) ([]Entry, []Dir, driveStats, error) {
	var st driveStats
	if idx.Items == nil {
		idx.Items = map[string]*DriveEntry{}
	}
	const sel = "?$select=id,name,size,cTag,webUrl,lastModifiedDateTime,file,folder,package,deleted,root,parentReference,createdBy,lastModifiedBy&$top=999"
	first := "drives/" + idx.ID + "/root/delta" + sel
	link := idx.Delta
	fresh := link == ""
	if fresh {
		link = first
	}
	seen := map[string]bool{}
	apply := func(raw json.RawMessage) error {
		var it driveItem
		if err := json.Unmarshal(raw, &it); err != nil {
			return err
		}
		if it.Deleted != nil {
			delete(idx.Items, it.ID)
			return nil
		}
		if it.Root != nil {
			return nil
		}
		path := itemPathOf(it)
		if path == "" {
			return nil
		}
		seen[it.ID] = true
		if it.Package != nil {
			// OneNote notebooks and the like have no downloadable content
			if _, known := idx.Items[it.ID]; !known {
				warn(fmt.Sprintf("%s: %s package skipped (no file content through Graph)", path, it.Package.Type))
			}
			delete(idx.Items, it.ID)
			return nil
		}
		cur := idx.Items[it.ID]
		if cur != nil && cur.CTag == it.CTag && cur.Path == path && it.CTag != "" && cur.Dir == (it.Folder != nil) {
			return nil
		}
		idx.Items[it.ID] = &DriveEntry{Path: path, Dir: it.Folder != nil, Size: it.Size, Mtime: it.Modified.Unix(), CTag: it.CTag,
			WebURL: it.WebURL, CreatedBy: it.CreatedBy.String(), ModifiedBy: it.ModifiedBy.String()}
		return nil
	}
	delta, err := c.Each(ctx, link, nil, apply)
	if err != nil && IsResync(err) && !fresh {
		st.Resyncs++
		fresh = true
		delta, err = c.Each(ctx, first, nil, apply)
	}
	if err != nil {
		return nil, nil, st, fmt.Errorf("drive delta: %w", err)
	}
	if fresh {
		for id := range idx.Items {
			if !seen[id] {
				delete(idx.Items, id)
			}
		}
	}
	idx.Delta = delta

	var entries []Entry
	var dirs []Dir
	type meta struct {
		ID         string `json:"id"`
		Path       string `json:"path"`
		Size       int64  `json:"size,omitempty"`
		Modified   string `json:"modified"`
		WebURL     string `json:"web_url,omitempty"`
		CreatedBy  string `json:"created_by,omitempty"`
		ModifiedBy string `json:"modified_by,omitempty"`
	}
	var sidecar []meta
	for id, e := range idx.Items {
		if mt, ok := excludes.Match(e.Path, e.Dir); ok && mt == scan.MatchExclude {
			continue
		}
		mtime := time.Unix(e.Mtime, 0).UTC()
		sidecar = append(sidecar, meta{ID: id, Path: e.Path, Size: e.Size, Modified: mtime.Format(time.RFC3339), WebURL: e.WebURL, CreatedBy: e.CreatedBy, ModifiedBy: e.ModifiedBy})
		if e.Dir {
			st.Folders++
			dirs = append(dirs, Dir{Path: idx.Prefix + "/" + e.Path, Mtime: mtime})
			continue
		}
		st.Files++
		st.Bytes += uint64(e.Size)
		url := "drives/" + idx.ID + "/items/" + id + "/content"
		entries = append(entries, Entry{Path: idx.Prefix + "/" + e.Path, Size: e.Size, Mtime: mtime, Open: func() (io.ReadCloser, error) {
			body, _, err := c.Download(context.Background(), url)
			return body, err
		}})
	}
	sort.Slice(sidecar, func(i, j int) bool { return sidecar[i].Path < sidecar[j].Path })
	data, _ := json.MarshalIndent(map[string]any{"drive": map[string]string{"id": idx.ID, "name": idx.Name, "web_url": idx.WebURL}, "items": sidecar}, "", "  ")
	entries = append(entries, memEntry(idx.Prefix+"/.fallbck/items.json", data, now))
	return entries, dirs, st, nil
}

// itemPathOf derives the archive path of a drive item from its parent reference
// ("/drive/root:/Documents/Sub" or "/drives/<id>/root:/Documents/Sub") and name
func itemPathOf(it driveItem) string {
	p := it.Parent.Path
	if i := strings.Index(p, "root:"); i >= 0 {
		p = p[i+len("root:"):]
	} else {
		p = ""
	}
	p = strings.Trim(p, "/")
	name := safeComponent(it.Name)
	if p == "" {
		return name
	}
	parts := strings.Split(p, "/")
	for i, s := range parts {
		parts[i] = safeComponent(unescapePathComponent(s))
	}
	return strings.Join(parts, "/") + "/" + name
}

// unescapePathComponent undoes the percent-encoding Graph applies to parent paths
func unescapePathComponent(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			var v byte
			if _, err := fmt.Sscanf(s[i+1:i+3], "%02x", &v); err == nil {
				b.WriteByte(v)
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
