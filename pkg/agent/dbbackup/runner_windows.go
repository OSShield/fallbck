//go:build windows

package dbbackup

import "os/exec"

// configureKill: Windows has no process groups to signal; the default Cancel
// (TerminateProcess on the tool) applies
func configureKill(cmd *exec.Cmd) {}
