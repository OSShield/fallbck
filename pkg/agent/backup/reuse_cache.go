package backup

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/osshield/gopbs/archive"
	"github.com/osshield/gopbs/pbs"
)

// Metadata change detection needs the previous snapshot's metadata stream. PBS
// only hands it out through a reader session, which the agent has no way to open
// through the server tunnel, so the agent keeps a local copy of every v2 metadata
// stream it uploads. Before it is used, the copy is validated against the index PBS
// reports for the previous snapshot: identical chunk digests prove the copy is what
// the server holds. A mismatch (pruned snapshot, other agent, changed group) means a
// full read, never a wrong archive.

// reuseCache is the cache directory of one backup group
type reuseCache struct {
	dir  string
	base string // archive base name (root, pvc, db, …)
}

// cacheMeta describes the stored copy
type cacheMeta struct {
	Archive     string    `json:"archive"` // <base>.mpxar.didx
	MetaDigests []string  `json:"meta_digests"`
	SavedAt     time.Time `json:"saved_at"`
	Snapshot    string    `json:"snapshot,omitempty"`
}

var cacheNameClean = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// CacheGroupDir returns the cache directory for a backup group under root
func CacheGroupDir(root, backupType, backupID string) string {
	return filepath.Join(root, cacheNameClean.ReplaceAllString(backupType+"-"+backupID, "_"))
}

func newReuseCache(dir, metaName string) *reuseCache {
	return &reuseCache{dir: dir, base: strings.TrimSuffix(metaName, ".mpxar.didx")}
}

func (c *reuseCache) streamPath() string { return filepath.Join(c.dir, c.base+".mpxar") }
func (c *reuseCache) metaPath() string   { return filepath.Join(c.dir, c.base+".mpxar.json") }
func (c *reuseCache) tmpPath() string    { return filepath.Join(c.dir, c.base+".mpxar.tmp") }

// previous returns the previous snapshot's archive for change detection, or nil
// (with the reason logged) when the cache cannot be trusted or does not exist.
func (c *reuseCache) previous(ctx context.Context, sess *pbs.BackupSession, metaName, payloadName string) *archive.Previous {
	raw, err := os.ReadFile(c.metaPath())
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			slog.Warn("Change detection: unreadable cache metadata; reading every file", "path", c.metaPath(), "error", err)
		}
		return nil
	}
	var meta cacheMeta
	if err := json.Unmarshal(raw, &meta); err != nil || meta.Archive != metaName {
		slog.Warn("Change detection: cache metadata does not match this archive; reading every file", "path", c.metaPath())
		return nil
	}
	serverMeta, err := sess.PreviousIndex(ctx, metaName)
	if err != nil {
		if errors.Is(err, pbs.ErrNoPrevious) {
			slog.Info("Change detection: no previous snapshot on the server; reading every file")
		} else {
			slog.Warn("Change detection: could not fetch the previous metadata index; reading every file", "error", err)
		}
		return nil
	}
	if !sameDigests(meta.MetaDigests, serverMeta) {
		slog.Warn("Change detection: the cached metadata stream is not the server's previous snapshot; reading every file", "cached_snapshot", meta.Snapshot)
		return nil
	}
	payloadIndex, err := sess.PreviousIndex(ctx, payloadName)
	if err != nil {
		slog.Warn("Change detection: could not fetch the previous payload index; reading every file", "error", err)
		return nil
	}
	chunks := make([]archive.PayloadChunk, len(payloadIndex))
	for i, e := range payloadIndex {
		chunks[i] = archive.PayloadChunk{EndOffset: e.EndOffset, Digest: e.Digest}
	}
	f, err := os.Open(c.streamPath())
	if err != nil {
		slog.Warn("Change detection: cached metadata stream missing; reading every file", "path", c.streamPath(), "error", err)
		return nil
	}
	defer f.Close()
	prev, err := archive.LoadPrevious(f, chunks)
	if err != nil {
		slog.Warn("Change detection: cached metadata stream unusable; reading every file", "error", err)
		return nil
	}
	slog.Info("Change detection: comparing against the previous snapshot", "snapshot", meta.Snapshot, "files", prev.Files(), "payload_chunks", len(chunks))
	return prev
}

func sameDigests(cached []string, server []pbs.IndexEntry) bool {
	if len(cached) != len(server) {
		return false
	}
	for i, e := range server {
		if cached[i] != hex.EncodeToString(e.Digest[:]) {
			return false
		}
	}
	return true
}

// begin opens the temporary file the metadata stream is teed into
func (c *reuseCache) begin() (*os.File, error) {
	if err := os.MkdirAll(c.dir, 0o700); err != nil {
		return nil, err
	}
	return os.OpenFile(c.tmpPath(), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
}

// commit makes the teed copy the cache for the next run, recording the digests of
// the uploaded metadata index for validation
func (c *reuseCache) commit(tmp *os.File, metaName, snapshot string, entries []pbs.IndexEntry) error {
	if err := tmp.Close(); err != nil {
		return err
	}
	digests := make([]string, len(entries))
	for i, e := range entries {
		digests[i] = hex.EncodeToString(e.Digest[:])
	}
	raw, err := json.MarshalIndent(cacheMeta{Archive: metaName, MetaDigests: digests, SavedAt: time.Now().UTC(), Snapshot: snapshot}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.Rename(c.tmpPath(), c.streamPath()); err != nil {
		return err
	}
	if err := os.WriteFile(c.metaPath()+".tmp", raw, 0o600); err != nil {
		return err
	}
	return os.Rename(c.metaPath()+".tmp", c.metaPath())
}

// discard removes a temporary copy after a failed upload
func (c *reuseCache) discard(tmp *os.File) {
	if c != nil && tmp != nil {
		_ = tmp.Close()
		_ = os.Remove(c.tmpPath())
	}
}

func snapshotString(ref pbs.SnapshotRef) string {
	return fmt.Sprintf("%s/%s/%s", ref.Type, ref.ID, ref.Time.UTC().Format("2006-01-02T15:04:05Z"))
}
