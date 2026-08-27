package db

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// ValidateBackupPaths normalises a job's backup paths and rejects combinations that
// cannot form one archive: every path must be absolute, exact duplicates are dropped,
// no path may lie inside another (its data would be archived twice), and — because
// several paths are placed under a virtual root named by their basename — no two paths
// may share a basename.
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

	byName := map[string]string{}
	for _, p := range cleaned {
		name := filepath.Base(p)
		if other, dup := byName[name]; dup {
			return nil, fmt.Errorf("backup paths %s and %s would both be stored as %q at the top of the archive; choose paths with distinct names", other, p, name)
		}
		byName[name] = p
	}
	return cleaned, nil
}
