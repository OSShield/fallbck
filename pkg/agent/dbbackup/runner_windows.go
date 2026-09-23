//go:build windows

package dbbackup

import (
	"errors"
	"os/exec"
)

// configureKill: Windows has no process groups to signal; the default Cancel
// (TerminateProcess on the tool) applies
func configureKill(cmd *exec.Cmd) {}

// configureUser: peer / socket authentication is a unix concept; Windows agents use
// integrated authentication for SQL Server instead
func configureUser(cmd *exec.Cmd, name string) error {
	return errors.New("running client tools as another user is not supported on Windows")
}
