//go:build !windows

package dbbackup

import (
	"os/exec"
	"syscall"
)

// configureKill puts the tool in its own process group and terminates the whole
// group on cancellation (WaitDelay escalates to SIGKILL)
func configureKill(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	}
}
