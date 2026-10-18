//go:build !linux

package backup

import "github.com/osshield/gopbs/scan"

// mountFilter is Linux-only (mountinfo, device numbers); elsewhere nothing is left out
func mountFilter([]string, bool) func(path, archivePath string, st scan.Stat) bool { return nil }
