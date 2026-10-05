package m365

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// IndexVersion is bumped when the index layout changes incompatibly (old files are
// then ignored and the unit is enumerated afresh)
const IndexVersion = 1

// UnitIndex is what the agent remembers about one unit (user, site, team or the
// directory) between runs: the Graph delta links and, per item, the metadata the
// previous snapshot recorded. Saved only after the unit's snapshot finished, so a
// failed run repeats the same delta round instead of skipping anything.
type UnitIndex struct {
	Version  int    `json:"version"`
	Kind     string `json:"kind"`
	Name     string `json:"name"`
	ObjectID string `json:"object_id"`
	Group    string `json:"group"`
	// LastRunID / LastStatus / LastSnapshot describe the newest finished snapshot; an
	// activity retry skips units whose LastRunID is the current run
	LastRunID    string `json:"last_run_id,omitempty"`
	LastStatus   string `json:"last_status,omitempty"`
	LastSnapshot int64  `json:"last_snapshot,omitempty"`

	Mailbox *MailboxIndex          `json:"mailbox,omitempty"`
	Drives  map[string]*DriveIndex `json:"drives,omitempty"`
	Teams   *TeamsIndex            `json:"teams,omitempty"`
}

// MailboxIndex is the mailbox of a user unit
type MailboxIndex struct {
	MailboxID    string                  `json:"mailbox_id"`
	FoldersDelta string                  `json:"folders_delta,omitempty"`
	Folders      map[string]*FolderIndex `json:"folders"`
}

// FolderIndex is one mail folder with its items
type FolderIndex struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	ParentID string `json:"parent_id,omitempty"`
	Class    string `json:"class,omitempty"`
	// Path is the folder's archive path below mailbox/ (computed from the parents)
	Path       string                `json:"path"`
	ItemsDelta string                `json:"items_delta,omitempty"`
	Items      map[string]*ItemEntry `json:"items"`
	// Browse is the human-readable index of the folder (subject, from, dates) kept
	// through the standard messages delta; BrowseDelta its link
	BrowseDelta string                  `json:"browse_delta,omitempty"`
	Browse      map[string]*BrowseEntry `json:"browse,omitempty"`
}

// ItemEntry is one exported item as the previous snapshot holds it
type ItemEntry struct {
	// Size is the export stream size (what the archive declares); -1 until exported
	Size      int64  `json:"size"`
	ChangeKey string `json:"change_key"`
	// Mtime is lastModifiedDateTime (unix seconds); Created is createdDateTime, used
	// in the file name
	Mtime   int64  `json:"mtime"`
	Created int64  `json:"created"`
	Class   string `json:"class"`
	// EstSize is the mailboxItem.size Graph reported (packing estimate for exports)
	EstSize int64 `json:"est_size,omitempty"`
	// Dirty: the item must be exported again (new, changed or a failed export)
	Dirty bool `json:"dirty,omitempty"`
}

// BrowseEntry is the browsing index line of a message
type BrowseEntry struct {
	Subject        string `json:"subject"`
	From           string `json:"from,omitempty"`
	Received       string `json:"received,omitempty"`
	HasAttachments bool   `json:"has_attachments,omitempty"`
}

// DriveIndex is one OneDrive or document library
type DriveIndex struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	WebURL string `json:"web_url,omitempty"`
	// Prefix is the archive directory the drive's items live under (onedrive, or
	// files/<library>)
	Prefix string                 `json:"prefix"`
	Delta  string                 `json:"delta,omitempty"`
	Items  map[string]*DriveEntry `json:"items"`
}

// DriveEntry is one drive item (file or folder)
type DriveEntry struct {
	Path  string `json:"path"`
	Dir   bool   `json:"dir,omitempty"`
	Size  int64  `json:"size"`
	Mtime int64  `json:"mtime"`
	CTag  string `json:"ctag,omitempty"`
	// Metadata for the .fallbck/items.json sidecar
	WebURL     string `json:"web_url,omitempty"`
	CreatedBy  string `json:"created_by,omitempty"`
	ModifiedBy string `json:"modified_by,omitempty"`
}

// TeamsIndex holds a team's channel messages (the backup data itself: messages are
// small and must be re-emitted unchanged for chunk reuse)
type TeamsIndex struct {
	// Since is the newest lastModifiedDateTime seen (the next run filters from here)
	Since    string                   `json:"since,omitempty"`
	Channels map[string]*ChannelIndex `json:"channels"`
	// Hosted are inline images and files by archive path (hosted/<message>-<id>)
	Hosted map[string]*HostedEntry `json:"hosted,omitempty"`
}

// ChannelIndex groups a channel's messages by month of creation
type ChannelIndex struct {
	Name string `json:"name"`
	// Months: "2026-10" → message id → message JSON as Graph returned it
	Months map[string]map[string]json.RawMessage `json:"months"`
}

// HostedEntry is one hosted content blob of a message
type HostedEntry struct {
	URL   string `json:"url"`
	Size  int64  `json:"size"`
	Mtime int64  `json:"mtime"`
}

// State is the per-job index directory (<data>/m365-state/<job id>)
type State struct{ Dir string }

func (s State) path(group string) string {
	return filepath.Join(s.Dir, strings.ReplaceAll(group, string(filepath.Separator), "_")+".json")
}

// Load returns the unit's index, or an empty one when none (or an older version) exists
func (s State) Load(group string) (*UnitIndex, error) {
	idx := &UnitIndex{Version: IndexVersion, Group: group}
	if s.Dir == "" {
		return idx, nil
	}
	data, err := os.ReadFile(s.path(group))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return idx, nil
		}
		return nil, err
	}
	var stored UnitIndex
	if err := json.Unmarshal(data, &stored); err != nil || stored.Version != IndexVersion {
		return idx, nil
	}
	return &stored, nil
}

// Save writes the index atomically
func (s State) Save(idx *UnitIndex) error {
	if s.Dir == "" {
		return nil
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(idx)
	if err != nil {
		return err
	}
	tmp := s.path(idx.Group) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path(idx.Group)); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("saving index: %w", err)
	}
	return nil
}
