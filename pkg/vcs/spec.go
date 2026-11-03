// Package vcs holds the VCS (git) backup job specification, the connection model
// (provider endpoint and token), the GitLab connection test and the run manifest. It
// is shared by the server (validation, connection API, session preparation) and the
// agent (execution), so it must stay free of process-execution dependencies.
package vcs

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/naming"
)

// Providers: where the job finds its repositories
const (
	// ProviderGitLab enumerates projects through the GitLab REST API (gitlab.com or
	// self-managed)
	ProviderGitLab = "gitlab"
	// ProviderGit mirrors an explicit list of HTTPS repository URLs
	ProviderGit = "git"
)

// Names inside the snapshot
const (
	// ArchiveName is the single pxar archive of a run (vcs.pxar)
	ArchiveName = "vcs"
	// ManifestBlobName is the run manifest, a blob of the snapshot
	ManifestBlobName = "fallbck-vcs.json"
)

// DefaultConcurrency is the number of repositories fetched at once when the job does
// not say; MaxConcurrency bounds the job setting
const (
	DefaultConcurrency = 4
	MaxConcurrency     = 32
)

// MinGitMajor / MinGitMinor are the oldest git the agent runs: 2.31 brought the
// GIT_CONFIG_COUNT environment, which keeps the token off the command line
const (
	MinGitMajor = 2
	MinGitMinor = 31
)

// Workloads selects what is fetched besides the repository itself. nil means enabled.
type Workloads struct {
	// LFS fetches every Git LFS object (git lfs fetch --all); without it LFS files
	// are only pointers in the backup
	LFS *bool `json:"lfs,omitempty"`
	// Wiki mirrors the project wiki (<project>.wiki.git) where the project has one
	Wiki *bool `json:"wiki,omitempty"`
}

func on(b *bool) bool { return b == nil || *b }

// EffLFS / EffWiki apply the defaults
func (w Workloads) EffLFS() bool  { return on(w.LFS) }
func (w Workloads) EffWiki() bool { return on(w.Wiki) }

// Spec is the VCS job configuration (backup_jobs.vcs_config)
type Spec struct {
	// ConnectionID is the vcs_connections row the job uses; its provider decides
	// which of Groups or Repositories applies
	ConnectionID uuid.UUID `json:"connection_id"`
	// Groups are GitLab group full paths (platform, data/pipelines); empty means
	// every project the token can see (not allowed on gitlab.com)
	Groups []string `json:"groups,omitempty"`
	// IncludeSubgroups also takes the projects of subgroups (default true)
	IncludeSubgroups *bool `json:"include_subgroups,omitempty"`
	// Exclude are globs on project full paths; a match on a group path leaves out
	// everything below it
	Exclude []string `json:"exclude,omitempty"`
	// Archived / Forks include archived projects and forks (default true)
	Archived *bool `json:"archived,omitempty"`
	Forks    *bool `json:"forks,omitempty"`
	// Repositories are the HTTPS clone URLs of a git-provider job
	Repositories []string  `json:"repositories,omitempty"`
	Workloads    Workloads `json:"workloads"`
	// MaxRepoSize skips repositories larger than this many bytes (0 = no limit)
	MaxRepoSize int64 `json:"max_repo_size,omitempty"`
	// Concurrency is the number of repositories fetched at once (default
	// DefaultConcurrency)
	Concurrency int `json:"concurrency,omitempty"`
	// BackupID overrides the job's PBS group (default vcs-<connection name>)
	BackupID string `json:"backup_id,omitempty"`
	// Profile names agent credential profile holding the token (created with
	// fallbck-agent vcs profile create). The agent only uses a profile whose URL maqtches
	// the connection URL, the server never hands out their own token for a
	// job that names a pårofile. Empty: the connection token.
	Profile string `json:"profile,omitempty"`
}

// ErrInvalidSpec wraps every validation failure
var ErrInvalidSpec = errors.New("invalid VCS job configuration")

func specErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidSpec, fmt.Sprintf(format, args...))
}

// An agent credential profile
var profileNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// fullPathRe is a GitLab namespace or project full path: segments of letters,
// digits, '_', '-' and '.', not starting with '-'
var fullPathRe = regexp.MustCompile(`^[A-Za-z0-9_.][A-Za-z0-9_.-]*(/[A-Za-z0-9_.][A-Za-z0-9_.-]*)*$`)

// Validate normalises paths, globs and URLs and checks the ranges. Checks that need
// the connection (provider, URL prefix) are in ValidateFor.
func (s *Spec) Validate() error {
	if s == nil {
		return specErr("configuration is missing")
	}
	if s.ConnectionID == uuid.Nil {
		return specErr("connection_id is required")
	}
	groups, seen := []string{}, map[string]bool{}
	for _, g := range s.Groups {
		g = strings.Trim(strings.TrimSpace(g), "/")
		if g == "" {
			continue
		}
		if !fullPathRe.MatchString(g) || hasDotSegment(g) {
			return specErr("groups: %q is not a group full path (like platform or data/pipelines)", g)
		}
		if key := strings.ToLower(g); !seen[key] {
			seen[key] = true
			groups = append(groups, g)
		}
	}
	s.Groups = nilIfEmpty(groups)
	var err error
	if s.Exclude, err = naming.CleanGlobs("exclude", s.Exclude); err != nil {
		return specErr("%v", err)
	}
	repos, paths := []string{}, map[string]string{}
	for _, r := range naming.CleanStrings(s.Repositories) {
		u, p, err := ParseRepoURL(r)
		if err != nil {
			return specErr("repositories: %v", err)
		}
		if prev, dup := paths[p]; dup {
			if prev == u {
				continue
			}
			return specErr("repositories: %s and %s would land in the same directory (%s)", prev, u, p)
		}
		paths[p] = u
		repos = append(repos, u)
	}
	s.Repositories = nilIfEmpty(repos)
	if len(s.Groups) > 0 && len(s.Repositories) > 0 {
		return specErr("groups apply to GitLab connections and repositories to git connections; set one of them")
	}
	if s.MaxRepoSize < 0 {
		return specErr("max_repo_size must be 0 (no limit) or a size in bytes")
	}
	if s.Concurrency < 0 || s.Concurrency > MaxConcurrency {
		return specErr("concurrency must be between 1 and %d", MaxConcurrency)
	}
	s.BackupID = strings.TrimSpace(s.BackupID)
	if s.BackupID != "" && !naming.ValidGroupID(s.BackupID) {
		return specErr("backup_id may contain letters, digits, '.', '_' and '-' only")
	}
	s.Profile = strings.TrimSpace(s.Profile)
	if s.Profile != "" && !profileNameRe.MatchString(s.Profile) {
		return specErr("profile may contain letters, digits, '.', '_' and '-' (at most 64)")
	}
	return nil
}

// ValidateFor checks the spec against its connection: the provider decides between
// groups and repositories, gitlab.com cannot be enumerated as a whole, a git
// connection's token is only ever sent to its own URL, so every repository must be
// below it, a GitLab job needs a token from the connection or an agent profile.
// Call after Validate with the connection token loaded.
func (s *Spec) ValidateFor(c *Connection) error {
	if c == nil {
		return specErr("the connection does not exist")
	}
	switch c.Provider {
	case ProviderGitLab:
		if len(s.Repositories) > 0 {
			return specErr("GitLab connections select projects by group, not by repository URL")
		}
		if len(s.Groups) == 0 && IsGitLabCom(c.BaseURL) {
			return specErr("gitlab.com cannot be backed up as a whole; list the groups to back up")
		}
		if s.Profile == "" && c.Token == "" {
			return specErr("the connection stores no token; name the agent credential profile that holds it")
		}
	case ProviderGit:
		if len(s.Groups) > 0 {
			return specErr("git connections take a list of repositories, not groups")
		}
		if len(s.Repositories) == 0 {
			return specErr("list at least one repository URL")
		}
		for _, r := range s.Repositories {
			if !UnderBaseURL(r, c.BaseURL) {
				return specErr("repository %s is not below the connection's URL %s (its token is only sent there)", r, c.BaseURL)
			}
		}
	default:
		return specErr("the connection has an unknown provider %q", c.Provider)
	}
	return nil
}

// ParseRepoURL normalises a git-provider repository URL and returns it with its
// directory in the archive (<host>/<path>, without .git). Only https:// URLs without
// credentials are accepted: the token comes from the connection.
func ParseRepoURL(raw string) (normalized, dir string, err error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "", "", fmt.Errorf("%q is not a URL", raw)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return "", "", fmt.Errorf("%q: only https:// URLs are supported", raw)
	}
	if u.User != nil {
		return "", "", fmt.Errorf("%q: put the token in the connection, not in the URL", raw)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", "", fmt.Errorf("%q: a repository URL takes no query or fragment", raw)
	}
	p := strings.Trim(path.Clean("/"+u.Path), "/")
	if p == "" || p == "." || hasDotSegment(u.Path) {
		return "", "", fmt.Errorf("%q has no repository path", raw)
	}
	u.Scheme, u.Host, u.Path = "https", strings.ToLower(u.Host), "/"+p
	host := strings.ReplaceAll(u.Host, ":", "_")
	return u.String(), host + "/" + strings.TrimSuffix(p, ".git"), nil
}

// hasDotSegment reports a "." or ".." path segment
func hasDotSegment(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return true
		}
	}
	return false
}

func nilIfEmpty(v []string) []string {
	if len(v) == 0 {
		return nil
	}
	return v
}

// EffIncludeSubgroups / EffArchived / EffForks / EffConcurrency apply the defaults
func (s *Spec) EffIncludeSubgroups() bool { return on(s.IncludeSubgroups) }
func (s *Spec) EffArchived() bool         { return on(s.Archived) }
func (s *Spec) EffForks() bool            { return on(s.Forks) }

func (s *Spec) EffConcurrency() int {
	if s == nil || s.Concurrency <= 0 {
		return DefaultConcurrency
	}
	return s.Concurrency
}

// Excluded reports whether an exclude glob matches the project path or one of its
// parent groups (case-insensitive)
func (s *Spec) Excluded(fullPath string) bool {
	p := strings.Trim(fullPath, "/")
	for p != "" && p != "." {
		if naming.MatchesAny(p, s.Exclude) {
			return true
		}
		p = path.Dir(p)
	}
	return false
}

// InScope reports whether a GitLab project path is selected by the groups (directly,
// or in a subgroup when IncludeSubgroups) and not excluded. Without groups every
// project is in scope.
func (s *Spec) InScope(fullPath string) bool {
	fullPath = strings.Trim(fullPath, "/")
	if s.Excluded(fullPath) {
		return false
	}
	if len(s.Groups) == 0 {
		return true
	}
	parent := strings.ToLower(path.Dir(fullPath))
	for _, g := range s.Groups {
		g = strings.ToLower(g)
		if parent == g || (s.EffIncludeSubgroups() && strings.HasPrefix(parent, g+"/")) {
			return true
		}
	}
	return false
}

// Clone returns a deep copy
func (s *Spec) Clone() *Spec {
	if s == nil {
		return nil
	}
	c := *s
	cp := func(v []string) []string {
		if v == nil {
			return nil
		}
		return append([]string{}, v...)
	}
	cpb := func(b *bool) *bool {
		if b == nil {
			return nil
		}
		v := *b
		return &v
	}
	c.Groups, c.Exclude, c.Repositories = cp(s.Groups), cp(s.Exclude), cp(s.Repositories)
	c.IncludeSubgroups, c.Archived, c.Forks = cpb(s.IncludeSubgroups), cpb(s.Archived), cpb(s.Forks)
	c.Workloads = Workloads{LFS: cpb(s.Workloads.LFS), Wiki: cpb(s.Workloads.Wiki)}
	return &c
}

// Summary is a short human-readable description (UI tables, logs)
func (s *Spec) Summary() string {
	if s == nil {
		return "VCS"
	}
	var out string
	switch {
	case len(s.Repositories) == 1:
		out = "1 repository"
	case len(s.Repositories) > 1:
		out = strconv.Itoa(len(s.Repositories)) + " repositories"
	case len(s.Groups) > 0:
		out = "groups " + strings.Join(s.Groups, ", ")
		if !s.EffIncludeSubgroups() {
			out += " (without subgroups)"
		}
	default:
		out = "all projects"
	}
	if len(s.Exclude) > 0 {
		out += "; excluding " + strings.Join(s.Exclude, ", ")
	}
	return out
}

// DefaultBackupID is the job group when the spec does not override it
func DefaultBackupID(connectionName string) string {
	return "vcs-" + naming.SafeName(connectionName)
}

// GitVersionOK reports whether a git version string ("2.43.0", "2.39.3 (Apple
// Git-146)", "2.45.1.windows.1") is at least MinGitMajor.MinGitMinor
func GitVersionOK(v string) bool {
	major, minor, ok := parseGitVersion(v)
	return ok && (major > MinGitMajor || major == MinGitMajor && minor >= MinGitMinor)
}

func parseGitVersion(v string) (major, minor int, ok bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "git version ")
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return 0, 0, false
	}
	major, err1 := strconv.Atoi(parts[0])
	minorDigits := parts[1]
	if i := strings.IndexFunc(minorDigits, func(r rune) bool { return r < '0' || r > '9' }); i >= 0 {
		minorDigits = minorDigits[:i]
	}
	minor, err2 := strconv.Atoi(minorDigits)
	return major, minor, err1 == nil && err2 == nil
}
