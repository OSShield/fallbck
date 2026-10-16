//go:build windows

package config

import (
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

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

// protectDataDir gives the system data directory a DACL of SYSTEM and Administrators
// only. Go's 0600 is a no-op on Windows, so without this agent.yaml under
// %ProgramData% inherits BUILTIN\Users read access. Only the system directory is
// touched; a per-user directory keeps its owner's inherited rights.
func protectDataDir(dir string) {
	root := systemDataRoot()
	if !strings.HasPrefix(strings.ToLower(filepath.Clean(dir)), strings.ToLower(root)) {
		return
	}
	// SIDs rather than names so this works on localised Windows
	out, err := exec.Command("icacls", root, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "/T", "/Q").CombinedOutput()
	if err != nil {
		slog.Warn("Could not restrict the data directory ACL", "path", root, "error", err, "output", strings.TrimSpace(string(out)))
	}
}

// isPrivileged reports whether the process runs elevated (administrator or a
// service account), which is what the system data directory needs
func isPrivileged() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}
