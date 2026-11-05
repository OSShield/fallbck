//go:build windows

package vcs

import "os/exec"

// configureKill: Windows has no process groups to signal; the default Cancel
// (TerminateProcess on git) applies
func configureKill(cmd *exec.Cmd) {}
