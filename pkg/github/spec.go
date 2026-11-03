package github

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

// Names inside the snapshots
const (
	// ArchiveRepo is the archive of a repository snapshot (repo.git, wiki.git, metadata/)
	ArchiveRepo = "repo"
	// ArchiveIndex is the archive of the job's own group (account, selection, manifest)
	ArchiveIndex = "index"
	// ManifestBlobName is the run manifest, a blob of the job group's snapshot
	ManifestBlobName = "fallbck-github.json"
	// RepoManifestName is the per-repository manifest, a blob of every repo snapshot
	RepoManifestName = "fallbck-github-repo.json"
)

// Org repository types (GET /orgs/{org}/repos?type=)
const (
	OrgTypeAll     = "all"
	OrgTypePublic  = "public"
	OrgTypePrivate = "private"
	OrgTypeForks   = "forks"
	OrgTypeSources = "sources"
	OrgTypeMember  = "member"
)

var orgTypes = []string{OrgTypeAll, OrgTypePublic, OrgTypePrivate, OrgTypeForks, OrgTypeSources, OrgTypeMember}

// DefaultConcurrency is the number of repositories in flight when the job does not say
const DefaultConcurrency = 4

// MaxConcurrency bounds the job setting
const MaxConcurrency = 32

// OrgSource selects the repositories of an organization
type OrgSource struct {
	Name string `json:"name"`
	// Type is the GitHub repository type filter (default all)
	Type string `json:"type,omitempty"`
}

// Sources says where repositories come from; the union is backed up
type Sources struct {
	Orgs []OrgSource `json:"orgs,omitempty"`
	// Users are accounts whose own repositories are backed up. The token's own login
	// also gets its private repositories.
	Users []string `json:"users,omitempty"`
	// Repos are explicit owner/name entries
	Repos []string `json:"repos,omitempty"`
	// Starred backs up every repository the token's user has starred
	Starred bool `json:"starred,omitempty"`
}

// Content selects what is archived next to the git mirror. nil means the default.
type Content struct {
	// Wiki mirrors <repo>.wiki.git when the repository has one (default true)
	Wiki *bool `json:"wiki,omitempty"`
	// Issues stores issues and pull requests with their comments as JSON (default true)
	Issues *bool `json:"issues,omitempty"`
	// Releases stores the release list (metadata, not assets) as JSON (default true)
	Releases *bool `json:"releases,omitempty"`
	// LFS fetches Git LFS objects into the mirror when git-lfs is installed (default false)
	LFS bool `json:"lfs,omitempty"`
}

func on(b *bool) bool { return b == nil || *b }

// EffWiki / EffIssues / EffReleases apply the defaults
func (c Content) EffWiki() bool     { return on(c.Wiki) }
func (c Content) EffIssues() bool   { return on(c.Issues) }
func (c Content) EffReleases() bool { return on(c.Releases) }

// Spec is the GitHub job configuration (backup_jobs.github_config)
type Spec struct {
	// AccountID is the github_accounts row the job uses
	AccountID uuid.UUID `json:"account_id"`
	Sources   Sources   `json:"sources"`
	// Include / Exclude are owner/name globs applied to the union of the sources
	Include []string `json:"include,omitempty"`
	Exclude []string `json:"exclude,omitempty"`
	// SkipForks / SkipArchived leave forks and archived repositories out (explicit
	// Repos entries are kept regardless)
	SkipForks    bool    `json:"skip_forks,omitempty"`
	SkipArchived bool    `json:"skip_archived,omitempty"`
	Content      Content `json:"content"`
	// KeepMirrors keeps the bare mirrors on the agent between runs, so the next run
	// only fetches what changed (default true; false clones from scratch every run)
	KeepMirrors *bool `json:"keep_mirrors,omitempty"`
	// Concurrency is the number of repositories in flight (default DefaultConcurrency)
	Concurrency int `json:"concurrency,omitempty"`
	// BackupID overrides the job's PBS group, the prefix of every repository group
	// (default github-<account name>)
	BackupID string `json:"backup_id,omitempty"`
}

// ErrInvalidSpec wraps every validation failure
var ErrInvalidSpec = errors.New("invalid GitHub job configuration")

func specErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidSpec, fmt.Sprintf(format, args...))
}

var (
	// groupIDRe is the PBS backup-id character set
	groupIDRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]*$`)
	// ownerRe is a GitHub user or organization login
	ownerRe = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$`)
	// repoNameRe is a GitHub repository name
	repoNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
)

// Validate normalises the lists and checks the ranges
func (s *Spec) Validate() error {
	if s == nil {
		return specErr("configuration is missing")
	}
	if s.AccountID == uuid.Nil {
		return specErr("account_id is required")
	}
	var orgs []OrgSource
	seenOrg := map[string]bool{}
	for _, o := range s.Sources.Orgs {
		o.Name = strings.TrimSpace(o.Name)
		o.Type = strings.ToLower(strings.TrimSpace(o.Type))
		if o.Name == "" {
			continue
		}
		if !ownerRe.MatchString(o.Name) {
			return specErr("organization %q is not a valid GitHub login", o.Name)
		}
		if o.Type == "" {
			o.Type = OrgTypeAll
		}
		if !contains(orgTypes, o.Type) {
			return specErr("organization %s: type must be one of %s", o.Name, strings.Join(orgTypes, ", "))
		}
		if k := strings.ToLower(o.Name); !seenOrg[k] {
			seenOrg[k] = true
			orgs = append(orgs, o)
		}
	}
	s.Sources.Orgs = orgs
	var users []string
	for _, u := range cleanStrings(s.Sources.Users) {
		if !ownerRe.MatchString(u) {
			return specErr("user %q is not a valid GitHub login", u)
		}
		if !containsFold(users, u) {
			users = append(users, u)
		}
	}
	s.Sources.Users = users
	var repos []string
	for _, r := range cleanStrings(s.Sources.Repos) {
		r = strings.TrimSuffix(strings.TrimPrefix(r, "https://github.com/"), ".git")
		owner, name, ok := SplitFullName(r)
		if !ok {
			return specErr("repository %q must be owner/name", r)
		}
		if full := owner + "/" + name; !containsFold(repos, full) {
			repos = append(repos, full)
		}
	}
	s.Sources.Repos = repos
	if len(s.Sources.Orgs) == 0 && len(s.Sources.Users) == 0 && len(s.Sources.Repos) == 0 && !s.Sources.Starred {
		return specErr("choose at least one source: organizations, users, repositories or starred")
	}
	var err error
	if s.Include, err = cleanGlobs("include", s.Include); err != nil {
		return err
	}
	if s.Exclude, err = cleanGlobs("exclude", s.Exclude); err != nil {
		return err
	}
	if s.Concurrency < 0 || s.Concurrency > MaxConcurrency {
		return specErr("concurrency must be between 1 and %d", MaxConcurrency)
	}
	s.BackupID = strings.TrimSpace(s.BackupID)
	if s.BackupID != "" && !groupIDRe.MatchString(s.BackupID) {
		return specErr("backup_id may contain letters, digits, '.', '_' and '-' only")
	}
	return nil
}

// SplitFullName splits and checks owner/name
func SplitFullName(full string) (owner, name string, ok bool) {
	owner, name, found := strings.Cut(strings.TrimSpace(full), "/")
	if !found || !ownerRe.MatchString(owner) || !repoNameRe.MatchString(name) || name == "." || name == ".." {
		return "", "", false
	}
	return owner, name, true
}

func cleanGlobs(field string, globs []string) ([]string, error) {
	var out []string
	for _, g := range cleanStrings(globs) {
		if _, err := path.Match(g, ""); err != nil {
			return nil, specErr("%s: invalid pattern %q", field, g)
		}
		out = append(out, g)
	}
	return out, nil
}

func cleanStrings(in []string) []string {
	var out []string
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func containsFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

// Selected applies the include/exclude globs to owner/name (case-insensitive):
// included when Include is empty or matches, and not excluded
func Selected(fullName string, include, exclude []string) bool {
	match := func(globs []string) bool {
		n := strings.ToLower(fullName)
		for _, g := range globs {
			if ok, _ := path.Match(strings.ToLower(g), n); ok {
				return true
			}
		}
		return false
	}
	if len(include) > 0 && !match(include) {
		return false
	}
	return !match(exclude)
}

// EffConcurrency / EffKeepMirrors apply the defaults
func (s *Spec) EffConcurrency() int {
	if s == nil || s.Concurrency <= 0 {
		return DefaultConcurrency
	}
	return s.Concurrency
}

func (s *Spec) EffKeepMirrors() bool { return s == nil || on(s.KeepMirrors) }

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
	if s.Sources.Orgs != nil {
		c.Sources.Orgs = append([]OrgSource{}, s.Sources.Orgs...)
	}
	c.Sources.Users, c.Sources.Repos = cp(s.Sources.Users), cp(s.Sources.Repos)
	c.Include, c.Exclude = cp(s.Include), cp(s.Exclude)
	c.Content.Wiki, c.Content.Issues, c.Content.Releases = cpb(s.Content.Wiki), cpb(s.Content.Issues), cpb(s.Content.Releases)
	c.KeepMirrors = cpb(s.KeepMirrors)
	return &c
}

// Summary is a short human-readable description (UI tables, logs)
func (s *Spec) Summary() string {
	if s == nil {
		return "GitHub"
	}
	var parts []string
	for _, o := range s.Sources.Orgs {
		p := "org " + o.Name
		if o.Type != "" && o.Type != OrgTypeAll {
			p += " (" + o.Type + ")"
		}
		parts = append(parts, p)
	}
	for _, u := range s.Sources.Users {
		parts = append(parts, "user "+u)
	}
	switch n := len(s.Sources.Repos); {
	case n == 1:
		parts = append(parts, s.Sources.Repos[0])
	case n > 1:
		parts = append(parts, fmt.Sprintf("%d repositories", n))
	}
	if s.Sources.Starred {
		parts = append(parts, "starred")
	}
	return strings.Join(parts, ", ")
}

// Group naming. Every repository group extends the job's group:
// <job group>-<owner>-<name>, which is what the server's sub-ticket endpoint enforces.

// DefaultBackupID is the job group when the spec does not override it
func DefaultBackupID(accountName string) string {
	return "github-" + SafeName(accountName)
}

// GroupPrefix is what every repository group of the job must start with
func GroupPrefix(jobBackupID string) string { return jobBackupID + "-" }

// RepoGroup names the PBS group of one repository
func RepoGroup(jobBackupID, owner, name string) string {
	return GroupPrefix(jobBackupID) + SafeName(owner) + "-" + SafeName(name)
}

var unsafeRe = regexp.MustCompile(`[^a-z0-9._-]+`)

// SafeName maps a login or repository name into the PBS backup-id character set:
// lower-cased, every run of foreign characters becomes '-'
func SafeName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = unsafeRe.ReplaceAllString(s, "-")
	s = strings.Trim(s, ".-")
	if s == "" {
		return "unnamed"
	}
	if !groupIDRe.MatchString(s) {
		s = "x" + s
	}
	return s
}
