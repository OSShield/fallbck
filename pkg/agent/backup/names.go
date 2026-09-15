package backup

import (
	"fmt"
	"path"
	"strings"
)

// ArchiveEntryNames decides how each backup path is named at the top of the archive
// when a job has several roots. Paths keep their basename (`/etc` → `etc`); when two
// paths share a basename, both are named after their full path with `/` replaced by
// `-` (`/etc/mydir` → `etc-mydir`, `/var/lib/mydir` → `var-lib-mydir`).
func ArchiveEntryNames(paths []string) (map[string]string, error) {
	byBase := map[string][]string{}
	for _, p := range paths {
		base := entryBase(p)
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
// (`/var/lib/mydir` → `var-lib-mydir`, `D:\data\x` → `D-data-x`). Both path
// styles are handled on every platform, so the slash-only path package is used.
func pathEntryName(p string) string {
	trimmed := strings.Trim(path.Clean(strings.ReplaceAll(p, `\`, "/")), "/")
	trimmed = strings.ReplaceAll(trimmed, ":", "")
	if trimmed == "" {
		return "root"
	}
	return strings.ReplaceAll(trimmed, "/", "-")
}

// entryBase is the basename used for an archive entry: the last path element, or
// the drive letter for a Windows volume root (`C:\` → `C`; `/` → `root`)
func entryBase(p string) string {
	if drive, ok := driveRoot(p); ok {
		return drive
	}
	base := path.Base(strings.ReplaceAll(p, `\`, "/"))
	if base == "/" || base == "." || base == "" {
		return "root"
	}
	return strings.ReplaceAll(base, ":", "")
}

// driveRoot recognises Windows volume roots ("C:", "C:\", "C:/") on any platform
func driveRoot(p string) (string, bool) {
	if len(p) < 2 || len(p) > 3 || p[1] != ':' {
		return "", false
	}
	c := p[0]
	if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
		return "", false
	}
	if len(p) == 3 && p[2] != '\\' && p[2] != '/' {
		return "", false
	}
	return strings.ToUpper(string(c)), true
}
