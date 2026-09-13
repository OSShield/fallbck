//go:build windows

package vss

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	govss "github.com/mxk/go-vss"
)

const supported = true

// take creates one shadow copy per volume (drive letter or mount point root)
func take(ctx context.Context, linkDir string, paths []string) ([]string, *Snapshots, error) {
	if err := os.MkdirAll(linkDir, 0o700); err != nil {
		return nil, nil, fmt.Errorf("vss: creating link directory: %w", err)
	}
	s := &Snapshots{}
	links := map[string]string{} // volume -> link path
	mapped := make([]string, len(paths))
	for i, p := range paths {
		if err := ctx.Err(); err != nil {
			s.Release()
			return nil, nil, err
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			s.Release()
			return nil, nil, err
		}
		vol := filepath.VolumeName(abs) // C: or \\server\share
		if vol == "" || strings.HasPrefix(vol, `\\`) {
			// Network shares cannot be snapshotted here; read them live
			mapped[i] = abs
			continue
		}
		vol = strings.ToUpper(vol)
		link, ok := links[vol]
		if !ok {
			id, err := govss.Create(vol + `\`)
			if err != nil {
				s.Release()
				return nil, nil, fmt.Errorf("vss: creating shadow copy of %s: %w", vol, err)
			}
			sc, err := govss.Get(id)
			if err != nil {
				_ = govss.Remove(id)
				s.Release()
				return nil, nil, fmt.Errorf("vss: looking up shadow copy %s: %w", id, err)
			}
			link = filepath.Join(linkDir, strings.Trim(id, "{}"))
			if err := sc.Link(link); err != nil {
				_ = sc.Remove()
				s.Release()
				return nil, nil, fmt.Errorf("vss: linking shadow copy %s: %w", id, err)
			}
			s.shadows = append(s.shadows, shadow{id: id, volume: vol, remove: sc.Remove})
			s.links = append(s.links, link)
			links[vol] = link
			slog.Info("VSS shadow copy created", "volume", vol, "id", id, "device", sc.DeviceObject)
		}
		rel := strings.TrimLeft(strings.TrimPrefix(abs, abs[:len(vol)]), `\`)
		mapped[i] = filepath.Join(link, rel)
	}
	return mapped, s, nil
}

func release(s *Snapshots) {
	for _, l := range s.links {
		if err := os.Remove(l); err != nil && !os.IsNotExist(err) {
			slog.Warn("VSS link not removed", "link", l, "error", err)
		}
	}
	for _, sh := range s.shadows {
		if err := sh.remove(); err != nil {
			slog.Warn("VSS shadow copy not removed; the next agent start sweeps it", "id", sh.id, "volume", sh.volume, "error", err)
		} else {
			slog.Info("VSS shadow copy removed", "id", sh.id, "volume", sh.volume)
		}
	}
	s.links, s.shadows = nil, nil
}

// sweep removes every link in linkDir and the shadow copy it points to
func sweep(linkDir string) {
	entries, err := os.ReadDir(linkDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		link := filepath.Join(linkDir, e.Name())
		if err := govss.Remove(link); err != nil {
			slog.Warn("VSS sweep: shadow copy not removed", "link", link, "error", err)
		} else {
			slog.Info("VSS sweep: removed leftover shadow copy", "link", link)
		}
		_ = os.Remove(link)
	}
}
