//go:build windows

package fsutil

import "os"

// chownLike is a no-op on Windows
func chownLike(string, os.FileInfo) {}
