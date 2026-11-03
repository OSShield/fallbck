// Package naming holds the PBS group-name and glob selection helpers shared by the
// job types that derive groups and selections from names in an external system
// (Microsoft 365 users and sites, VCS groups and projects).
package naming

import (
	"fmt"
	"path"
	"regexp"
	"strings"
)

// groupIDRe is the PBS backup-id character set
var groupIDRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]*$`)

// ValidGroupID reports whether s is a usable PBS backup id
func ValidGroupID(s string) bool { return groupIDRe.MatchString(s) }

var unsafeRe = regexp.MustCompile(`[^a-z0-9._-]+`)

// SafeName maps an external name (UPN, site, connection name) into the PBS backup-id
// character set: lower-cased, '@' becomes '_', every other run of foreign characters
// becomes '-'. alice@contoso.com → alice_contoso.com. Collisions are the caller's
// problem.
func SafeName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "@", "_")
	s = unsafeRe.ReplaceAllString(s, "-")
	s = strings.Trim(s, ".-")
	if s == "" {
		return "unnamed"
	}
	if !groupIDRe.MatchString(s) {
		// Only a leading '.' or '-' can fail after the trim above
		s = "x" + s
	}
	return s
}

// CleanGlobs trims, drops empty entries and checks the glob syntax; field names the
// setting in the error
func CleanGlobs(field string, globs []string) ([]string, error) {
	var out []string
	for _, g := range globs {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		if _, err := path.Match(g, ""); err != nil {
			return nil, fmt.Errorf("%s: invalid pattern %q", field, g)
		}
		out = append(out, g)
	}
	return out, nil
}

// CleanStrings trims and drops empty entries
func CleanStrings(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// MatchesAny reports whether name matches one of the globs (case-insensitive)
func MatchesAny(name string, globs []string) bool {
	name = strings.ToLower(name)
	for _, g := range globs {
		if ok, _ := path.Match(strings.ToLower(g), name); ok {
			return true
		}
	}
	return false
}

// Selected applies include/exclude globs: included when include is empty or matches,
// and not excluded
func Selected(name string, include, exclude []string) bool {
	if len(include) > 0 && !MatchesAny(name, include) {
		return false
	}
	return !MatchesAny(name, exclude)
}
