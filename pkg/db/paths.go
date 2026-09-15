package db

import (
	"errors"
	"fmt"
	"github.com/osshield/gopbs/scan"
	"path"
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

// ValidateBackupPathsFor validates paths with the rules of the agent's operating
// system ("windows" or anything else): the server runs on Linux but stores jobs for
// Windows agents, whose paths use drive letters and backslashes.
func ValidateBackupPathsFor(agentOS string, paths []string) ([]string, error) {
	if agentOS == "windows" {
		return validateWindowsPaths(paths)
	}
	return ValidateBackupPaths(paths)
}

// validateWindowsPaths applies ValidateBackupPaths' rules to Windows paths: a drive
// letter root (C:\, also accepted with forward slashes), duplicates dropped, no path
// inside another (case-insensitive; C:\ contains everything on C:)
func validateWindowsPaths(paths []string) ([]string, error) {
	seen := map[string]bool{}
	var cleaned []string
	for _, raw := range paths {
		p := strings.TrimSpace(raw)
		if p == "" {
			continue
		}
		p = strings.ReplaceAll(p, "/", `\`)
		if len(p) < 2 || p[1] != ':' || !isDriveLetter(p[0]) || (len(p) > 2 && p[2] != '\\') {
			return nil, fmt.Errorf("backup path %q must be absolute (C:\\dir)", raw)
		}
		// Collapse repeated separators and . / .. elements
		drive := strings.ToUpper(p[:2])
		var parts []string
		for _, e := range strings.Split(p[2:], `\`) {
			switch e {
			case "", ".":
			case "..":
				if len(parts) > 0 {
					parts = parts[:len(parts)-1]
				}
			default:
				parts = append(parts, e)
			}
		}
		p = drive + `\` + strings.Join(parts, `\`)
		key := strings.ToLower(p)
		if seen[key] {
			continue
		}
		seen[key] = true
		cleaned = append(cleaned, p)
	}
	if len(cleaned) == 0 {
		return nil, errors.New("at least one backup path is required")
	}
	if len(cleaned) == 1 {
		return cleaned, nil
	}
	sorted := append([]string(nil), cleaned...)
	sort.Slice(sorted, func(i, j int) bool { return strings.ToLower(sorted[i]) < strings.ToLower(sorted[j]) })
	for i := 1; i < len(sorted); i++ {
		parent, child := strings.ToLower(sorted[i-1]), strings.ToLower(sorted[i])
		isRoot := len(parent) == 3
		if (isRoot && strings.HasPrefix(child, parent)) || (!isRoot && strings.HasPrefix(child, parent+`\`)) {
			return nil, fmt.Errorf("backup path %s is inside %s; a parent path already includes it", sorted[i], sorted[i-1])
		}
	}
	return cleaned, nil
}

func isDriveLetter(c byte) bool { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') }

// ValidateBackupPaths normalises a job's backup paths and rejects combinations that
// cannot form one archive: every path must be absolute, exact duplicates are dropped and
// no path may lie inside another (its data would be archived twice). Paths sharing a
// basename are fine; the agent names them after their full path in the archive.
// The rules are those of a Unix agent regardless of the host the server runs on, so
// the slash-only path package is used rather than path/filepath.
func ValidateBackupPaths(paths []string) ([]string, error) {
	seen := map[string]bool{}
	var cleaned []string
	for _, raw := range paths {
		p := strings.TrimSpace(raw)
		if p == "" {
			continue
		}
		if !path.IsAbs(p) {
			return nil, fmt.Errorf("backup path %q must be absolute", raw)
		}
		p = path.Clean(p)
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
		if parent == "/" || strings.HasPrefix(sorted[i], parent+"/") {
			return nil, fmt.Errorf("backup path %s is inside %s; a parent path already includes it", sorted[i], parent)
		}
	}

	return cleaned, nil
}
