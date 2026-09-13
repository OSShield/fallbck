//go:build !windows

package runtime

import "errors"

// IsWindowsService is always false outside Windows
func IsWindowsService() bool { return false }

// RunAsService is Windows-only
func RunAsService(string, func(stop <-chan struct{}) error) error {
	return errors.New("service mode is only available on Windows")
}

// ServiceCommand is Windows-only; Linux installs use the packaged systemd/OpenRC units
func ServiceCommand(name, _, _, action, _ string) error {
	return errors.New("'" + name + " service " + action + "' is only available on Windows; use the systemd or OpenRC unit here")
}
