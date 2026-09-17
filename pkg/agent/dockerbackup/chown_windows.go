//go:build windows

package dockerbackup

import "os"

// chownLike is a no-op on Windows (Docker host backups are a Linux feature)
func chownLike(string, os.FileInfo) {}
