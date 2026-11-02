package dockerbackup

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	dockerspec "github.com/osshield/fallbck/pkg/dockerbackup"
)

// Access modes recorded per volume
const (
	accessDirect = "direct"        // read in place during the upload
	accessStaged = "direct-staged" // copied into the spool while its containers were paused
	accessHelper = "helper"        // streamed through a helper container into the spool
)

// selectVolumes marks the volumes the job does not archive
func selectVolumes(spec *dockerspec.Spec, inv *collected) {
	for i := range inv.Volumes {
		v := &inv.Volumes[i]
		switch {
		case inv.selfVolumes[v.Name]:
			v.Skipped = "state of the fallbck agent itself"
		case dockerspec.MatchesAny(v.Name, spec.ExcludeVolumes):
			v.Skipped = "excluded by the job"
		case strings.EqualFold(v.Labels[dockerspec.LabelSkip], "true"):
			v.Skipped = "label " + dockerspec.LabelSkip + "=true"
		case len(inv.volumeUsers[v.Name]) == 0 && !spec.EffIncludeUnusedVolumes():
			v.Skipped = "not mounted by any container (include_unused_volumes is off)"
		}
	}
}

// volumeAccess decides how one volume is read under the agent's setting
func volumeAccess(mode string, v *dockerspec.Volume) (string, error) {
	visible := false
	if v.Mountpoint != "" {
		if st, err := os.Stat(v.Mountpoint); err == nil && st.IsDir() {
			visible = true
		}
	}
	local := v.Driver == "" || v.Driver == "local"
	switch mode {
	case dockerspec.VolumeAccessDirect:
		if !visible {
			return "", fmt.Errorf("mountpoint %s is not readable by the agent (mount /var/lib/docker/volumes into the agent container or set docker_backup.volume_access to auto)", v.Mountpoint)
		}
		return accessDirect, nil
	case dockerspec.VolumeAccessHelper:
		return accessHelper, nil
	default:
		if visible && local {
			return accessDirect, nil
		}
		return accessHelper, nil
	}
}

// extractViaHelper mounts source (a volume name or an absolute host directory) at
// /vol in a helper container and extracts its archive stream into dst
func extractViaHelper(ctx context.Context, files *hostFiles, source, dst string) error {
	id, err := files.createHelper(ctx, []string{source + ":/vol:ro"})
	if err != nil {
		return err
	}
	defer files.removeHelper(id)
	rc, err := files.client.Archive(ctx, id, "/vol")
	if err != nil {
		return err
	}
	defer rc.Close()
	return untar(rc, dst, "vol")
}

// untar extracts a tar stream below dst, stripping the leading component strip.
// Modes, ownership (best effort), times, symlinks and hardlinks are preserved;
// everything goes through an os.Root, so no entry (nor a symlink planted by an earlier
// entry) can write outside dst.
func untar(r io.Reader, dst, strip string) error {
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return err
	}
	root, err := os.OpenRoot(dst)
	if err != nil {
		return err
	}
	defer root.Close()
	tr := tar.NewReader(r)
	type deferred struct {
		path string
		mode os.FileMode
		mod  time.Time
	}
	var dirs []deferred
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading volume archive: %w", err)
		}
		name := path.Clean(hdr.Name)
		if strip != "" {
			if name == strip {
				continue
			}
			name = strings.TrimPrefix(name, strip+"/")
		}
		if name == "." || name == "" {
			continue
		}
		if strings.HasPrefix(name, "../") || strings.Contains(name, "/../") || path.IsAbs(name) {
			return fmt.Errorf("volume archive entry %q escapes the destination", hdr.Name)
		}
		target := filepath.FromSlash(name)
		mode := hdr.FileInfo().Mode()
		if hdr.Typeflag != tar.TypeDir {
			if err := root.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return fmt.Errorf("volume archive entry %q: %w", hdr.Name, err)
			}
			// Replace whatever is there rather than writing through it
			_ = root.Remove(target)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := root.MkdirAll(target, 0o700); err != nil {
				return fmt.Errorf("volume archive entry %q: %w", hdr.Name, err)
			}
			dirs = append(dirs, deferred{target, mode.Perm(), hdr.ModTime})
		case tar.TypeReg, tar.TypeRegA:
			f, err := root.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode.Perm())
			if err != nil {
				return fmt.Errorf("volume archive entry %q: %w", hdr.Name, err)
			}
			if _, err := io.Copy(f, tr); err != nil {
				_ = f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
			_ = root.Chmod(target, mode.Perm())
			_ = root.Lchown(target, hdr.Uid, hdr.Gid)
			_ = root.Chtimes(target, hdr.ModTime, hdr.ModTime)
		case tar.TypeSymlink:
			if err := root.Symlink(hdr.Linkname, target); err != nil {
				return fmt.Errorf("volume archive entry %q: %w", hdr.Name, err)
			}
			_ = root.Lchown(target, hdr.Uid, hdr.Gid)
		case tar.TypeLink:
			link := path.Clean(hdr.Linkname)
			if strip != "" {
				link = strings.TrimPrefix(link, strip+"/")
			}
			if err := root.Link(filepath.FromSlash(link), target); err != nil {
				return fmt.Errorf("volume archive hardlink %q: %w", hdr.Linkname, err)
			}
		default:
			// devices, fifos and sockets are not part of a volume backup
		}
	}
	// Directory modes and times last, so the writes above were not blocked by them
	for i := len(dirs) - 1; i >= 0; i-- {
		d := dirs[i]
		_ = root.Chmod(d.path, d.mode)
		_ = root.Chtimes(d.path, d.mod, d.mod)
	}
	return nil
}
