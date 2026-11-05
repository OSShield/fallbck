//go:build !windows

package vcs

import (
	"os/exec"
	"syscall"
)

// configureKill puts git in its own process group and terminates the whole group on
// cancellation (git-remote-https and git-lfs run as children); WaitDelay escalates
// to SIGKILL
func configureKill(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	}
}
