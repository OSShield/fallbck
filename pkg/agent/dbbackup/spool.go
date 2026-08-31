package dbbackup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	dbspec "github.com/osshield/fallbck/pkg/dbbackup"
	"golang.org/x/sys/unix"
)

// freeBytes reports the free space for unprivileged users on the filesystem holding path
var freeBytes = func(path string) (uint64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, err
	}
	return st.Bavail * uint64(st.Bsize), nil
}

// prepareRunDir creates an empty <root>/<runID> (a retried activity starts from scratch)
func prepareRunDir(root, runID string) (string, error) {
	if root == "" {
		return "", fmt.Errorf("db_backup.spool_dir is not configured")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", fmt.Errorf("creating spool directory: %w", err)
	}
	dir := filepath.Join(root, runID)
	if err := os.RemoveAll(dir); err != nil {
		return "", fmt.Errorf("clearing spool directory: %w", err)
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return "", fmt.Errorf("creating run spool directory: %w", err)
	}
	return dir, nil
}

// CleanSpool removes leftovers of earlier runs (no run is in flight at agent start)
func CleanSpool(cfg dbspec.Config) error {
	if cfg.SpoolDir == "" {
		return nil
	}
	entries, err := os.ReadDir(cfg.SpoolDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		if err := os.RemoveAll(filepath.Join(cfg.SpoolDir, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

// dirSize sums the sizes of regular files under root
func dirSize(root string) int64 {
	var total int64
	_ = filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if info, err := d.Info(); err == nil {
			total += info.Size()
		}
		return nil
	})
	return total
}

// collectFiles lists the regular files under root (relative, slash paths, sorted)
func collectFiles(root string, checksums bool) ([]dbspec.FileEntry, error) {
	var files []dbspec.FileEntry
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		entry := dbspec.FileEntry{Path: filepath.ToSlash(rel), SizeBytes: info.Size()}
		if checksums {
			sum, err := hashFile(path)
			if err != nil {
				return err
			}
			entry.SHA256 = sum
		}
		files = append(files, entry)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func fileSize(path string) int64 {
	if info, err := os.Stat(path); err == nil {
		return info.Size()
	}
	return 0
}

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// sanitizeName turns a database name into a safe file name; used names get a suffix
func sanitizeName(name string, used map[string]bool) string {
	s := unsafeName.ReplaceAllString(name, "_")
	s = strings.Trim(s, ".")
	if s == "" {
		s = "db"
	}
	base := s
	for i := 2; used[s]; i++ {
		s = fmt.Sprintf("%s~%d", base, i)
	}
	used[s] = true
	return s
}

// poller reports the spool size periodically and aborts the run when the spool
// filesystem is about to fill up
type poller struct {
	dir      string
	interval time.Duration
	minFree  uint64
	onTick   func(bytes int64)
	abort    func(error)
}

func (p *poller) run(ctx context.Context) {
	t := time.NewTicker(p.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.onTick(dirSize(p.dir))
			if p.minFree > 0 {
				if free, err := freeBytes(p.dir); err == nil && free < p.minFree {
					p.abort(fmt.Errorf("spool filesystem nearly full (%d MiB free); aborting the dump", free/(1<<20)))
					return
				}
			}
		}
	}
}

// writeSecret writes a credential file readable only by the agent
func writeSecret(dir, name, content string) (string, error) {
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return "", fmt.Errorf("writing credential file: %w", err)
	}
	return path, nil
}
