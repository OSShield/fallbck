//go:build windows

package config

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// systemDataRoot is %ProgramData%\fallbck (the service runs as LocalSystem)
func systemDataRoot() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "fallbck")
}

// isPrivileged reports whether the process runs elevated (administrator or a
// service account), which is what the system data directory needs
func isPrivileged() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}
