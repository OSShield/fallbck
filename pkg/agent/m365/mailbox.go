package m365

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	spec "github.com/osshield/fallbck/pkg/m365"
)

// Export batching: Graph takes 20 ids per exportItems call; the base64 answer of a
// batch is held in memory, so batches are also bounded by the items' reported sizes
const (
	exportBatchItems = 20
	exportBatchBytes = 32 << 20
	// mailboxPrefix is the archive directory of the mailbox inside a user snapshot
	mailboxPrefix = "mailbox"
)

// Mail folder display names of the mailbox root that are not part of the archive path
var rootFolderNames = map[string]bool{"Top of Information Store": true, "Root": true, "IPM_SUBTREE": true, "MsgFolderRoot": true}

// mailboxFolder is what folders/delta returns
type mailboxFolder struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	ParentID    string `json:"parentFolderId"`
	Type        string `json:"type"`
	Removed     *struct {
		Reason string `json:"reason"`
	} `json:"@removed"`
}

// mailboxItem is what items/delta returns
type mailboxItem struct {
	ID        string    `json:"id"`
	ChangeKey string    `json:"changeKey"`
	Size      int64     `json:"size"`
	Type      string    `json:"type"`
	Created   time.Time `json:"createdDateTime"`
	Modified  time.Time `json:"lastModifiedDateTime"`
	Removed   *struct {
		Reason string `json:"reason"`
	} `json:"@removed"`
}

// mailboxStats counts what the collector did
type mailboxStats struct {
	Folders, Items int
	Exported       int
	ExportedBytes  uint64
	Resyncs        int
}

// mailboxCollector updates the mailbox index of one user and produces the entries of
// the mailbox/ directory. Changed items are exported into the unit's spool directory
// first (the export stream size is only known after the export); unchanged items are
// exported on demand only if gopbs cannot reuse them.
type mailboxCollector struct {
	c      *Client
	spec   *spec.Spec
	spool  string
	userID string
	idx    *MailboxIndex
	now    time.Time
	stats  mailboxStats
	warn   func(string)
}

var maxPage = map[string]string{"Prefer": "odata.maxpagesize=1000"}

// collect runs the delta round and the exports; it returns the entries and dirs
func (m *mailboxCollector) collect(ctx context.Context) ([]Entry, []Dir, error) {
	if m.idx.Folders == nil {
		m.idx.Folders = map[string]*FolderIndex{}
	}
	if m.idx.MailboxID == "" {
		var settings struct {
			PrimaryMailboxID string `json:"primaryMailboxId"`
		}
		if err := m.c.Get(ctx, "users/"+m.userID+"/settings/exchange", &settings, nil); err != nil {
			if IsStatus(err, http.StatusNotFound, http.StatusBadRequest) {
				m.warn("no Exchange mailbox")
				return nil, nil, nil
			}
			return nil, nil, fmt.Errorf("mailbox id: %w", err)
		}
		if settings.PrimaryMailboxID == "" {
			m.warn("no Exchange mailbox")
			return nil, nil, nil
		}
		m.idx.MailboxID = settings.PrimaryMailboxID
	}
	base := "admin/exchange/mailboxes/" + m.idx.MailboxID
	if err := m.syncFolders(ctx, base); err != nil {
		return nil, nil, err
	}
	m.assignPaths()

	var entries []Entry
	var dirs []Dir
	excludes := m.spec.EffMailFolderExcludes()
	for _, f := range sortedFolders(m.idx.Folders) {
		if f.Path == "" || excludedFolder(f, excludes) {
			continue
		}
		m.stats.Folders++
		if err := m.syncItems(ctx, base, f); err != nil {
			return nil, nil, fmt.Errorf("folder %s: %w", f.Path, err)
		}
		dirs = append(dirs, Dir{Path: mailboxPrefix + "/" + f.Path, Mtime: m.now})
	}
	if err := m.exportDirty(ctx, base); err != nil {
		return nil, nil, err
	}
	for _, f := range sortedFolders(m.idx.Folders) {
		if f.Path == "" || excludedFolder(f, excludes) {
			continue
		}
		for id, it := range f.Items {
			if it.Size < 0 {
				continue // export failed this run; retried next run
			}
			m.stats.Items++
			entries = append(entries, Entry{Path: itemPath(f.Path, id, it), Size: it.Size, Mtime: time.Unix(it.Mtime, 0).UTC(), Open: m.opener(base, id)})
		}
		if len(f.Browse) > 0 {
			entries = append(entries, memEntry(mailboxPrefix+"/"+f.Path+"/index.json", m.browseJSON(f), m.now))
		}
	}
	folders, _ := json.MarshalIndent(m.idx.Folders, "", "  ")
	entries = append(entries, memEntry(mailboxPrefix+"/folders.json", folders, m.now))
	return entries, dirs, nil
}

// syncFolders applies the folders delta (fresh enumeration on a lost link)
func (m *mailboxCollector) syncFolders(ctx context.Context, base string) error {
	link := m.idx.FoldersDelta
	if link == "" {
		link = base + "/folders/delta?$select=id,displayName,parentFolderId,type"
	}
	seen := map[string]bool{}
	fresh := m.idx.FoldersDelta == ""
	apply := func(raw json.RawMessage) error {
		var f mailboxFolder
		if err := json.Unmarshal(raw, &f); err != nil {
			return err
		}
		if f.Removed != nil {
			delete(m.idx.Folders, f.ID)
			return nil
		}
		seen[f.ID] = true
		cur := m.idx.Folders[f.ID]
		if cur == nil {
			cur = &FolderIndex{ID: f.ID, Items: map[string]*ItemEntry{}}
			m.idx.Folders[f.ID] = cur
		}
		cur.Name, cur.ParentID, cur.Class = f.DisplayName, f.ParentID, f.Type
		return nil
	}
	delta, err := m.c.Each(ctx, link, maxPage, apply)
	if err != nil && IsResync(err) && !fresh {
		m.stats.Resyncs++
		fresh = true
		delta, err = m.c.Each(ctx, base+"/folders/delta?$select=id,displayName,parentFolderId,type", maxPage, apply)
	}
	if err != nil {
		return fmt.Errorf("folders delta: %w", err)
	}
	if fresh {
		// A full enumeration is authoritative: folders it did not list are gone
		for id := range m.idx.Folders {
			if !seen[id] {
				delete(m.idx.Folders, id)
			}
		}
	}
	m.idx.FoldersDelta = delta
	return nil
}

// assignPaths computes every folder's archive path from its parents, dropping the
// mailbox root
func (m *mailboxCollector) assignPaths() {
	var pathOf func(id string, depth int) string
	pathOf = func(id string, depth int) string {
		f := m.idx.Folders[id]
		if f == nil || depth > 64 {
			return ""
		}
		name := safeComponent(f.Name)
		if f.ParentID == "" || m.idx.Folders[f.ParentID] == nil {
			if rootFolderNames[f.Name] {
				return ""
			}
			return name
		}
		parent := pathOf(f.ParentID, depth+1)
		if parent == "" {
			return name
		}
		return parent + "/" + name
	}
	for id, f := range m.idx.Folders {
		f.Path = pathOf(id, 0)
		if rootFolderNames[f.Name] && (f.ParentID == "" || m.idx.Folders[f.ParentID] == nil) {
			f.Path = ""
		}
	}
}

func excludedFolder(f *FolderIndex, excludes []string) bool {
	for _, e := range excludes {
		if strings.EqualFold(f.Name, e) || strings.EqualFold(f.Path, e) || strings.HasPrefix(strings.ToLower(f.Path), strings.ToLower(e)+"/") {
			return true
		}
	}
	return false
}

func sortedFolders(folders map[string]*FolderIndex) []*FolderIndex {
	out := make([]*FolderIndex, 0, len(folders))
	for _, f := range folders {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// syncItems applies the items delta of one folder and the browsing index delta
func (m *mailboxCollector) syncItems(ctx context.Context, base string, f *FolderIndex) error {
	if f.Items == nil {
		f.Items = map[string]*ItemEntry{}
	}
	const sel = "?$select=id,size,changeKey,lastModifiedDateTime,createdDateTime,type"
	first := base + "/folders/" + f.ID + "/items/delta" + sel
	link := f.ItemsDelta
	fresh := link == ""
	if fresh {
		link = first
	}
	seen := map[string]bool{}
	apply := func(raw json.RawMessage) error {
		var it mailboxItem
		if err := json.Unmarshal(raw, &it); err != nil {
			return err
		}
		if it.Removed != nil {
			delete(f.Items, it.ID)
			return nil
		}
		seen[it.ID] = true
		if spec.MatchesAny(it.Type, m.spec.ExcludeTypes) {
			delete(f.Items, it.ID)
			return nil
		}
		cur := f.Items[it.ID]
		if cur != nil && cur.ChangeKey == it.ChangeKey && cur.Size >= 0 && !cur.Dirty {
			return nil
		}
		if cur == nil {
			cur = &ItemEntry{Size: -1}
			f.Items[it.ID] = cur
		}
		cur.ChangeKey, cur.Class, cur.EstSize, cur.Dirty = it.ChangeKey, it.Type, it.Size, true
		cur.Mtime, cur.Created = it.Modified.Unix(), it.Created.Unix()
		return nil
	}
	delta, err := m.c.Each(ctx, link, maxPage, apply)
	if err != nil && IsResync(err) && !fresh {
		m.stats.Resyncs++
		fresh = true
		delta, err = m.c.Each(ctx, first, maxPage, apply)
	}
	if err != nil {
		return fmt.Errorf("items delta: %w", err)
	}
	if fresh {
		for id := range f.Items {
			if !seen[id] {
				delete(f.Items, id)
			}
		}
	}
	f.ItemsDelta = delta
	m.syncBrowse(ctx, f)
	return nil
}

// syncBrowse keeps the folder's human-readable index through the standard messages
// delta. Best effort: the standard API may not know this folder (calendar and
// contact folders, or ids that differ between the two APIs), then the folder has no
// index.json.
func (m *mailboxCollector) syncBrowse(ctx context.Context, f *FolderIndex) {
	if !strings.HasPrefix(f.Class, "IPF.Note") && f.Class != "" {
		return
	}
	const sel = "?$select=id,subject,from,receivedDateTime,hasAttachments"
	first := "users/" + m.userID + "/mailFolders/" + f.ID + "/messages/delta" + sel
	link := f.BrowseDelta
	if link == "" {
		link = first
	}
	if f.Browse == nil {
		f.Browse = map[string]*BrowseEntry{}
	}
	apply := func(raw json.RawMessage) error {
		var msg struct {
			ID       string `json:"id"`
			Subject  string `json:"subject"`
			Received string `json:"receivedDateTime"`
			HasAtt   bool   `json:"hasAttachments"`
			From     *struct {
				EmailAddress struct {
					Name    string `json:"name"`
					Address string `json:"address"`
				} `json:"emailAddress"`
			} `json:"from"`
			Removed *struct{} `json:"@removed"`
		}
		if err := json.Unmarshal(raw, &msg); err != nil {
			return err
		}
		if msg.Removed != nil {
			delete(f.Browse, msg.ID)
			return nil
		}
		e := &BrowseEntry{Subject: msg.Subject, Received: msg.Received, HasAttachments: msg.HasAtt}
		if msg.From != nil {
			e.From = strings.TrimSpace(msg.From.EmailAddress.Name + " <" + msg.From.EmailAddress.Address + ">")
		}
		f.Browse[msg.ID] = e
		return nil
	}
	delta, err := m.c.Each(ctx, link, maxPage, apply)
	if err != nil && IsResync(err) && f.BrowseDelta != "" {
		f.Browse = map[string]*BrowseEntry{}
		delta, err = m.c.Each(ctx, first, maxPage, apply)
	}
	if err != nil {
		if ctx.Err() == nil {
			slog.Debug("Mailbox browsing index unavailable for folder", "folder", f.Path, "error", err)
			f.BrowseDelta, f.Browse = "", nil
		}
		return
	}
	f.BrowseDelta = delta
}

// browseJSON renders a folder's index.json: one line per item the archive holds
func (m *mailboxCollector) browseJSON(f *FolderIndex) []byte {
	type line struct {
		File string `json:"file"`
		*BrowseEntry
		Size int64 `json:"size"`
	}
	var lines []line
	for id, it := range f.Items {
		if b := f.Browse[id]; b != nil && it.Size >= 0 {
			lines = append(lines, line{File: filepath.Base(itemPath(f.Path, id, it)), BrowseEntry: b, Size: it.Size})
		}
	}
	sort.Slice(lines, func(i, j int) bool { return lines[i].Received < lines[j].Received })
	data, _ := json.MarshalIndent(lines, "", "  ")
	return data
}

// itemPath names an item: mailbox/<folder>/<created time>-<id8>.exoitem
func itemPath(folderPath, id string, it *ItemEntry) string {
	return mailboxPrefix + "/" + folderPath + "/" + time.Unix(it.Created, 0).UTC().Format("20060102T150405Z") + "-" + shortID(id) + ".exoitem"
}

// exportDirty exports every dirty item into the spool, in batches packed by the
// reported size, and records the stream sizes
func (m *mailboxCollector) exportDirty(ctx context.Context, base string) error {
	type pending struct {
		id string
		it *ItemEntry
	}
	var todo []pending
	for _, f := range m.idx.Folders {
		if f.Path == "" || excludedFolder(f, m.spec.EffMailFolderExcludes()) {
			continue
		}
		for id, it := range f.Items {
			if it.Dirty {
				todo = append(todo, pending{id, it})
			}
		}
	}
	sort.Slice(todo, func(i, j int) bool { return todo[i].id < todo[j].id })
	if len(todo) == 0 {
		return nil
	}
	if err := os.MkdirAll(m.spool, 0o700); err != nil {
		return err
	}
	for start := 0; start < len(todo); {
		end, bytesSum := start, int64(0)
		for end < len(todo) && end-start < exportBatchItems && (end == start || bytesSum+todo[end].it.EstSize <= exportBatchBytes) {
			bytesSum += todo[end].it.EstSize
			end++
		}
		batch := todo[start:end]
		ids := make([]string, len(batch))
		for i, p := range batch {
			ids[i] = p.id
		}
		got, err := m.export(ctx, base, ids)
		if err != nil {
			return err
		}
		for _, p := range batch {
			data, ok := got[p.id]
			if !ok {
				p.it.Size, p.it.Dirty = -1, true
				m.warn("item " + shortID(p.id) + " could not be exported; retried next run")
				continue
			}
			if err := os.WriteFile(m.spoolPath(p.id), data, 0o600); err != nil {
				return fmt.Errorf("spooling item: %w", err)
			}
			p.it.Size, p.it.Dirty = int64(len(data)), false
			m.stats.Exported++
			m.stats.ExportedBytes += uint64(len(data))
		}
		start = end
	}
	return nil
}

// export calls exportItems for up to 20 ids and returns the decoded streams by id
func (m *mailboxCollector) export(ctx context.Context, base string, ids []string) (map[string][]byte, error) {
	var resp struct {
		Value []struct {
			ItemID    string          `json:"itemId"`
			ChangeKey string          `json:"changeKey"`
			Data      string          `json:"data"`
			Error     json.RawMessage `json:"error"`
		} `json:"value"`
	}
	if err := m.c.Post(ctx, base+"/exportItems", map[string]any{"itemIds": ids}, &resp); err != nil {
		return nil, fmt.Errorf("exportItems: %w", err)
	}
	out := make(map[string][]byte, len(resp.Value))
	for _, v := range resp.Value {
		if v.Data == "" {
			if len(v.Error) > 0 {
				m.warn("export of item " + shortID(v.ItemID) + " failed: " + truncate(string(v.Error), 200))
			}
			continue
		}
		data, err := base64.StdEncoding.DecodeString(v.Data)
		if err != nil {
			m.warn("export of item " + shortID(v.ItemID) + " is not base64")
			continue
		}
		out[v.ItemID] = data
	}
	return out, nil
}

func (m *mailboxCollector) spoolPath(id string) string {
	return filepath.Join(m.spool, shortID(id)+"-"+shortID(id+"/")+".exoitem")
}

// opener reads an item: from the spool when it was exported this run, otherwise
// through a single-item export (gopbs reads an unchanged item only when it cannot
// reuse the previous snapshot's chunks)
func (m *mailboxCollector) opener(base, id string) func() (io.ReadCloser, error) {
	return func() (io.ReadCloser, error) {
		if f, err := os.Open(m.spoolPath(id)); err == nil {
			return f, nil
		}
		got, err := m.export(context.Background(), base, []string{id})
		if err != nil {
			return nil, err
		}
		data, ok := got[id]
		if !ok {
			return nil, fmt.Errorf("item %s could not be exported", shortID(id))
		}
		return io.NopCloser(bytes.NewReader(data)), nil
	}
}
