//go:build !windows

package runtime

import (
	"os"
	"syscall"
)

// execSelf replaces the process with exe, keeping the PID (so systemd / OpenRC keep
// tracking the service) and the arguments
func execSelf(exe string) error {
	return syscall.Exec(exe, os.Args, os.Environ())
}
