package backup

import (
	"fmt"
	"path/filepath"
	"strings"
)

// ArchiveEntryNames decides how each backup path is named at the top of the archive
// when a job has several roots. Paths keep their basename (`/etc` → `etc`); when two
// paths share a basename, both are named after their full path with `/` replaced by
// `-` (`/etc/mydir` → `etc-mydir`, `/var/lib/mydir` → `var-lib-mydir`).
func ArchiveEntryNames(paths []string) (map[string]string, error) {
	byBase := map[string][]string{}
	for _, p := range paths {
		base := filepath.Base(p)
		byBase[base] = append(byBase[base], p)
	}

	names := make(map[string]string, len(paths))
	for base, group := range byBase {
		if len(group) == 1 {
			names[group[0]] = base
			continue
		}
		for _, p := range group {
			names[p] = pathEntryName(p)
		}
	}

	// The prefixed spelling can still coincide with another root's name
	// (/etc-mydir alongside /etc/mydir and /var/lib/mydir); refuse rather than guess.
	used := map[string]string{}
	for _, p := range paths {
		name := names[p]
		if other, dup := used[name]; dup {
			return nil, fmt.Errorf("backup paths %s and %s would both be stored as %q; choose paths with distinct names", other, p, name)
		}
		used[name] = p
	}
	return names, nil
}

// pathEntryName flattens an absolute path into a single archive entry name
func pathEntryName(p string) string {
	trimmed := strings.Trim(filepath.ToSlash(filepath.Clean(p)), "/")
	if trimmed == "" {
		return "root"
	}
	return strings.ReplaceAll(trimmed, "/", "-")
}
