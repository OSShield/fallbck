package db

import (
	"errors"
	"fmt"
	"github.com/osshield/gopbs/scan"
	"path/filepath"
	"sort"
	"strings"
)

// ValidateExcludePatterns checks exclude patterns against the pxar pattern syntax
// (proxmox-backup-client --exclude); invalid patterns would otherwise fail the backup
// only at run time on the agent.
func ValidateExcludePatterns(patterns []string) error {
	cleaned := make([]string, 0, len(patterns))
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p != "" {
			cleaned = append(cleaned, p)
		}
	}
	if _, err := scan.ParsePatterns(cleaned); err != nil {
		return fmt.Errorf("invalid exclude pattern: %w", err)
	}
	return nil
}

// ValidateBackupPaths normalises a job's backup paths and rejects combinations that
// cannot form one archive: every path must be absolute, exact duplicates are dropped and
// no path may lie inside another (its data would be archived twice). Paths sharing a
// basename are fine; the agent names them after their full path in the archive.
func ValidateBackupPaths(paths []string) ([]string, error) {
	seen := map[string]bool{}
	var cleaned []string
	for _, raw := range paths {
		p := strings.TrimSpace(raw)
		if p == "" {
			continue
		}
		if !filepath.IsAbs(p) {
			return nil, fmt.Errorf("backup path %q must be absolute", raw)
		}
		p = filepath.Clean(p)
		if seen[p] {
			continue
		}
		seen[p] = true
		cleaned = append(cleaned, p)
	}
	if len(cleaned) == 0 {
		return nil, errors.New("at least one backup path is required")
	}
	if len(cleaned) == 1 {
		return cleaned, nil
	}

	sorted := append([]string(nil), cleaned...)
	sort.Strings(sorted)
	for i := 1; i < len(sorted); i++ {
		parent := sorted[i-1]
		if parent == "/" || strings.HasPrefix(sorted[i], parent+string(filepath.Separator)) {
			return nil, fmt.Errorf("backup path %s is inside %s; a parent path already includes it", sorted[i], parent)
		}
	}

	return cleaned, nil
}
