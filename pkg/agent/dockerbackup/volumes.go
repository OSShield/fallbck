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
// entries escaping dst are refused.
func untar(r io.Reader, dst, strip string) error {
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return err
	}
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
		target := filepath.Join(dst, filepath.FromSlash(name))
		mode := hdr.FileInfo().Mode()
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o700); err != nil {
				return err
			}
			dirs = append(dirs, deferred{target, mode.Perm(), hdr.ModTime})
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode.Perm())
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				_ = f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
			_ = os.Chmod(target, mode.Perm())
			_ = os.Lchown(target, hdr.Uid, hdr.Gid)
			_ = os.Chtimes(target, hdr.ModTime, hdr.ModTime)
		case tar.TypeSymlink:
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return err
			}
			_ = os.Remove(target)
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				return err
			}
			_ = os.Lchown(target, hdr.Uid, hdr.Gid)
		case tar.TypeLink:
			link := path.Clean(hdr.Linkname)
			if strip != "" {
				link = strings.TrimPrefix(link, strip+"/")
			}
			if strings.HasPrefix(link, "../") || path.IsAbs(link) {
				return fmt.Errorf("volume archive hardlink %q escapes the destination", hdr.Linkname)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return err
			}
			_ = os.Remove(target)
			if err := os.Link(filepath.Join(dst, filepath.FromSlash(link)), target); err != nil {
				return err
			}
		default:
			// devices, fifos and sockets are not part of a volume backup
		}
	}
	// Directory modes and times last, so the writes above were not blocked by them
	for i := len(dirs) - 1; i >= 0; i-- {
		d := dirs[i]
		_ = os.Chmod(d.path, d.mode)
		_ = os.Chtimes(d.path, d.mod, d.mod)
	}
	return nil
}

// copyTree copies src into dst preserving modes, times, ownership (best effort) and
// symlinks; used to stage a directly readable volume while its containers are paused
func copyTree(src, dst string) error {
	return filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		switch {
		case info.IsDir():
			if err := os.MkdirAll(target, info.Mode().Perm()|0o700); err != nil {
				return err
			}
			chownLike(target, info)
			return nil
		case info.Mode()&os.ModeSymlink != 0:
			link, err := os.Readlink(p)
			if err != nil {
				return err
			}
			_ = os.Remove(target)
			if err := os.Symlink(link, target); err != nil {
				return err
			}
			chownLike(target, info)
			return nil
		case info.Mode().IsRegular():
			if err := copyFile(p, target, info); err != nil {
				return err
			}
			chownLike(target, info)
			_ = os.Chtimes(target, info.ModTime(), info.ModTime())
			return nil
		}
		return nil
	})
}

func copyFile(src, dst string, info os.FileInfo) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
