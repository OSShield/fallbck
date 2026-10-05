// Package m365 holds the Microsoft 365 backup job specification, the tenant
// (Entra app registration) model, the Graph credential flow and the run manifest.
// It is shared by the server (validation, tenant API, session preparation) and the
// agent (execution), so it must stay free of process-execution dependencies.
package m365

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/osshield/gopbs/scan"
)

// Names inside the snapshots
const (
	// ArchiveMailbox / ArchiveOneDrive are the two archives of a user group
	ArchiveMailbox  = "mailbox"
	ArchiveOneDrive = "onedrive"
	// ArchiveFiles is the document libraries of a site group (and of a team group)
	ArchiveFiles = "files"
	// ArchiveTeams is the channel messages of a team group
	ArchiveTeams = "teams"
	// ArchiveEntra is the directory archive of the job's own group
	ArchiveEntra = "entra"
	// ManifestBlobName is the run manifest, a blob of the directory group's snapshot
	ManifestBlobName = "fallbck-m365.json"
	// UnitManifestName is the per-unit manifest stored as a blob of every unit snapshot
	UnitManifestName = "fallbck-m365-unit.json"
)

// Unit kinds: one PBS group per unit, named <job group>-<kind>-<name>
const (
	UnitUser = "user"
	UnitSite = "site"
	UnitTeam = "team"
)

// DefaultConcurrency is the number of units in flight (Graph requests and PBS
// sessions) when the job does not say
const DefaultConcurrency = 4

// MaxConcurrency bounds the job setting
const MaxConcurrency = 32

// DefaultMailFolderExcludes are the mail folders left out unless the job lists its own
var DefaultMailFolderExcludes = []string{"Deleted Items", "Junk Email", "Conversation History"}

// Workloads selects what a job backs up. nil means enabled (the default is everything)
type Workloads struct {
	Mailboxes *bool `json:"mailboxes,omitempty"`
	OneDrive  *bool `json:"onedrive,omitempty"`
	Sites     *bool `json:"sites,omitempty"`
	Teams     *bool `json:"teams,omitempty"`
	Entra     *bool `json:"entra,omitempty"`
}

func on(b *bool) bool { return b == nil || *b }

// Enabled workloads, defaults applied
func (w Workloads) EffMailboxes() bool { return on(w.Mailboxes) }
func (w Workloads) EffOneDrive() bool  { return on(w.OneDrive) }
func (w Workloads) EffSites() bool     { return on(w.Sites) }
func (w Workloads) EffTeams() bool     { return on(w.Teams) }
func (w Workloads) EffEntra() bool     { return on(w.Entra) }

// Any reports whether at least one workload is enabled
func (w Workloads) Any() bool {
	return w.EffMailboxes() || w.EffOneDrive() || w.EffSites() || w.EffTeams() || w.EffEntra()
}

// UserSelection picks the users (mailbox + OneDrive) of the tenant
type UserSelection struct {
	// Groups restricts the selection to the transitive members of these groups
	// (display names or object ids); empty = every user
	Groups []string `json:"groups,omitempty"`
	// Include / Exclude are UPN globs applied after Groups
	Include []string `json:"include,omitempty"`
	Exclude []string `json:"exclude,omitempty"`
	// Unlicensed also backs up accounts without a licence (default false)
	Unlicensed bool `json:"unlicensed,omitempty"`
	// Shared includes shared mailboxes (default true)
	Shared *bool `json:"shared,omitempty"`
}

// Shared_ applies the default
func (u UserSelection) EffShared() bool { return on(u.Shared) }

// Selection picks sites (by URL glob) or teams (by display name glob); empty = all
type Selection struct {
	Include []string `json:"include,omitempty"`
	Exclude []string `json:"exclude,omitempty"`
}

// Spec is the Microsoft 365 job configuration (backup_jobs.m365_config)
type Spec struct {
	// TenantID is the m365_tenants row the job uses
	TenantID  uuid.UUID     `json:"tenant_id"`
	Workloads Workloads     `json:"workloads"`
	Users     UserSelection `json:"users"`
	Sites     Selection     `json:"sites"`
	Teams     Selection     `json:"teams"`
	// MailFolderExcludes are mail folder display names left out; absent (null) means
	// DefaultMailFolderExcludes, an empty list means none
	MailFolderExcludes []string `json:"mail_folder_excludes"`
	// ExcludeTypes are message classes left out (IPM.Appointment, IPM.Contact, ...)
	ExcludeTypes []string `json:"exclude_types,omitempty"`
	// ExcludePaths are proxmox-backup-client style patterns against the archive paths
	// of the drive archives (/Documents/Recordings/**)
	ExcludePaths []string `json:"exclude_paths,omitempty"`
	// Concurrency is the number of units in flight (default DefaultConcurrency)
	Concurrency int `json:"concurrency,omitempty"`
	// BackupID overrides the job's PBS group, the prefix of every unit group
	// (default m365-<tenant short name>)
	BackupID string `json:"backup_id,omitempty"`
}

// ErrInvalidSpec wraps every validation failure
var ErrInvalidSpec = errors.New("invalid Microsoft 365 job configuration")

func specErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidSpec, fmt.Sprintf(format, args...))
}

// groupIDRe is the PBS backup-id character set
var groupIDRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]*$`)

// Validate normalises globs and patterns and checks the ranges
func (s *Spec) Validate() error {
	if s == nil {
		return specErr("configuration is missing")
	}
	if s.TenantID == uuid.Nil {
		return specErr("tenant_id is required")
	}
	if !s.Workloads.Any() {
		return specErr("at least one workload must be enabled")
	}
	var err error
	for name, list := range map[string]*[]string{
		"users.groups": &s.Users.Groups, "users.include": &s.Users.Include, "users.exclude": &s.Users.Exclude,
		"sites.include": &s.Sites.Include, "sites.exclude": &s.Sites.Exclude,
		"teams.include": &s.Teams.Include, "teams.exclude": &s.Teams.Exclude,
	} {
		if *list, err = cleanGlobs(name, *list); err != nil {
			return err
		}
	}
	if s.MailFolderExcludes != nil {
		s.MailFolderExcludes = cleanStrings(s.MailFolderExcludes)
	}
	s.ExcludeTypes = cleanStrings(s.ExcludeTypes)
	s.ExcludePaths = cleanStrings(s.ExcludePaths)
	if _, err := scan.ParsePatterns(s.ExcludePaths); err != nil {
		return specErr("invalid exclude pattern: %v", err)
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

// cleanGlobs trims, drops empty entries and checks the glob syntax
func cleanGlobs(field string, globs []string) ([]string, error) {
	var out []string
	for _, g := range globs {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		if _, err := path.Match(g, ""); err != nil {
			return nil, specErr("%s: invalid pattern %q", field, g)
		}
		out = append(out, g)
	}
	return out, nil
}

func cleanStrings(in []string) []string {
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

// Selected applies include/exclude globs: included when Include is empty or matches,
// and not excluded
func Selected(name string, include, exclude []string) bool {
	if len(include) > 0 && !MatchesAny(name, include) {
		return false
	}
	return !MatchesAny(name, exclude)
}

// EffConcurrency / EffMailFolderExcludes apply the defaults
func (s *Spec) EffConcurrency() int {
	if s == nil || s.Concurrency <= 0 {
		return DefaultConcurrency
	}
	return s.Concurrency
}

func (s *Spec) EffMailFolderExcludes() []string {
	if s == nil || s.MailFolderExcludes == nil {
		return DefaultMailFolderExcludes
	}
	return s.MailFolderExcludes
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
	c.Users.Groups, c.Users.Include, c.Users.Exclude = cp(s.Users.Groups), cp(s.Users.Include), cp(s.Users.Exclude)
	c.Sites.Include, c.Sites.Exclude = cp(s.Sites.Include), cp(s.Sites.Exclude)
	c.Teams.Include, c.Teams.Exclude = cp(s.Teams.Include), cp(s.Teams.Exclude)
	c.MailFolderExcludes, c.ExcludeTypes, c.ExcludePaths = cp(s.MailFolderExcludes), cp(s.ExcludeTypes), cp(s.ExcludePaths)
	cpb := func(b *bool) *bool {
		if b == nil {
			return nil
		}
		v := *b
		return &v
	}
	c.Workloads = Workloads{Mailboxes: cpb(s.Workloads.Mailboxes), OneDrive: cpb(s.Workloads.OneDrive), Sites: cpb(s.Workloads.Sites), Teams: cpb(s.Workloads.Teams), Entra: cpb(s.Workloads.Entra)}
	c.Users.Shared = cpb(s.Users.Shared)
	return &c
}

// Summary is a short human-readable description (UI tables, logs)
func (s *Spec) Summary() string {
	if s == nil {
		return "Microsoft 365"
	}
	var parts []string
	w := s.Workloads
	for _, p := range []struct {
		on   bool
		name string
	}{{w.EffMailboxes(), "mailboxes"}, {w.EffOneDrive(), "OneDrive"}, {w.EffSites(), "sites"}, {w.EffTeams(), "Teams"}, {w.EffEntra(), "directory"}} {
		if p.on {
			parts = append(parts, p.name)
		}
	}
	out := strings.Join(parts, ", ")
	switch {
	case len(s.Users.Groups) > 0:
		out += "; members of " + strings.Join(s.Users.Groups, ", ")
	case len(s.Users.Include) > 0:
		out += "; users " + strings.Join(s.Users.Include, ", ")
	}
	return out
}

// Group naming. Every unit group extends the job's group: <job group>-<kind>-<name>,
// which is what the server's sub-ticket endpoint enforces.

// DefaultBackupID is the job group when the spec does not override it
func DefaultBackupID(tenantName string) string {
	return "m365-" + SafeName(tenantName)
}

// GroupPrefix is what every unit group of the job must start with
func GroupPrefix(jobBackupID string) string { return jobBackupID + "-" }

// UnitGroup names the PBS group of one unit
func UnitGroup(jobBackupID, kind, name string) string {
	return GroupPrefix(jobBackupID) + kind + "-" + SafeName(name)
}

var unsafeRe = regexp.MustCompile(`[^a-z0-9._-]+`)

// SafeName maps a UPN, site or team name into the PBS backup-id character set:
// lower-cased, '@' becomes '_', every other run of foreign characters becomes '-'.
// alice@contoso.com → alice_contoso.com. Collisions are the caller's problem
// (see the plan: append part of the object id).
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
