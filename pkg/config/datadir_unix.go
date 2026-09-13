//go:build !windows

package config

import "os"

// systemDataRoot is where packaged installations keep state
func systemDataRoot() string { return "/var/lib/fallbck" }

// isPrivileged reports whether the process may use the system data directory
func isPrivileged() bool { return os.Geteuid() == 0 }
