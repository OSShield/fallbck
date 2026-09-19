// Package fsutil holds the small filesystem helpers shared by the agents (tree
// copies for spooling and migration) and by the job specs (archive entry names). It
// only uses the standard library and executes nothing, so server-side packages may
// import it too.
package fsutil

import (
	"io"
	"os"
	"path/filepath"
)

// CopyTree copies src into dst recursively, keeping modes, modification times,
// ownership (best effort, needs root) and symlinks; existing files are overwritten.
// Devices, sockets and fifos are skipped.
func CopyTree(src, dst string) error {
	_, err := copyTree(src, dst, false)
	return err
}

// CopyMissing is CopyTree for the files that do not exist below dst yet; it returns
// how many files it copied.
func CopyMissing(src, dst string) (int, error) {
	return copyTree(src, dst, true)
}

func copyTree(src, dst string, skipExisting bool) (int, error) {
	copied := 0
	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
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
			if skipExisting {
				if _, err := os.Lstat(target); err == nil {
					return nil
				}
			}
			link, err := os.Readlink(p)
			if err != nil {
				return err
			}
			_ = os.Remove(target)
			if err := os.Symlink(link, target); err != nil {
				return err
			}
			chownLike(target, info)
			copied++
			return nil
		case info.Mode().IsRegular():
			if skipExisting {
				if _, err := os.Lstat(target); err == nil {
					return nil
				}
			}
			if err := copyFile(p, target, info); err != nil {
				return err
			}
			copied++
			return nil
		}
		return nil
	})
	return copied, err
}

// CopyFile copies one regular file (creating the parent directory), keeping its mode,
// modification time and ownership (best effort)
func CopyFile(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	return copyFile(src, dst, info)
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
	if err := out.Close(); err != nil {
		return err
	}
	_ = os.Chmod(dst, info.Mode().Perm())
	chownLike(dst, info)
	_ = os.Chtimes(dst, info.ModTime(), info.ModTime())
	return nil
}
