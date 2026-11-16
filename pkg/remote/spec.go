package remote

import (
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/naming"
)

// Names inside the snapshot
const (
	// ArchiveName is the pxar archive of a snapshot (remote.pxar)
	ArchiveName = "remote"
	// ManifestBlobName is the run manifest, a blob of the snapshot
	ManifestBlobName = "fallbck-remote.json"
)

// How a job's roots map to snapshots
const (
	// SplitSingle writes one snapshot per run, each root a directory in it
	SplitSingle = "single"
	// SplitPerRoot writes one snapshot (and PBS group) per root
	SplitPerRoot = "per_root"
)

// DefaultConcurrency is the number of directories listed and objects read at once
// when the job doesn't say; MaxConcurrency bounds the setting
const (
	DefaultConcurrency = 8
	MaxConcurrency     = 64
)

// Spec is the remote job configuration (backup_jobs.remote_config)
type Spec struct {
	// RemoteID is the remotes row the job reads from
	RemoteID uuid.UUID `json:"remote_id"`
	// Roots are what the job backs up: bucket[/prefix] (S3), container[/prefix]
	// (Azure Blob), share[/path] (SMB), or a path on the server (SFTP, WebDAV; ""
	// is the whole remote). Stored without leading or trailing slashes.
	Roots []string `json:"roots,omitempty"`
	// Include / Exclude are globs on paths below a root (path.Match syntax, '*'
	// doesn't cross '/'); a match on a directory takes everything below it
	Include []string `json:"include,omitempty"`
	Exclude []string `json:"exclude,omitempty"`
	// Split is SplitSingle (default) or SplitPerRoot
	Split string `json:"split,omitempty"`
	// Concurrency is the number of listings and reads at once (default
	// DefaultConcurrency)
	Concurrency int `json:"concurrency,omitempty"`
	// BackupID overrides the job's PBS group (default remote-<remote name>)
	BackupID string `json:"backup_id,omitempty"`
	// Profile names the agent credential profile holding the credential (created
	// with fallbck-agent remote profile create). The agent only uses a profile whose
	// endpoint is the remote's (Remote.Identity), and the server never hands out the
	// remote's credential for a job that names a profile.
	Profile string `json:"profile,omitempty"`
}

// ErrInvalidSpec wraps every validation failure
var ErrInvalidSpec = errors.New("invalid remote job configuration")

func specErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidSpec, fmt.Sprintf(format, args...))
}

// Validate normalises the roots, globs and names and checks the ranges. Checks that
// need the remote (its backend) are in ValidateFor.
func (s *Spec) Validate() error {
	if s.RemoteID == uuid.Nil {
		return specErr("remote_id is required")
	}
	roots := []string{}
	for _, raw := range s.Roots {
		root, err := cleanRoot(raw)
		if err != nil {
			return specErr("root %q: %v", raw, err)
		}
		for _, other := range roots {
			if within(root, other) || within(other, root) {
				return specErr("roots %q and %q overlap", other, root)
			}
		}
		roots = append(roots, root)
	}
	s.Roots = roots
	var err error
	if s.Include, err = naming.CleanGlobs("include", s.Include); err != nil {
		return specErr("%v", err)
	}
	if s.Exclude, err = naming.CleanGlobs("exclude", s.Exclude); err != nil {
		return specErr("%v", err)
	}
	switch s.Split = strings.ToLower(strings.TrimSpace(s.Split)); s.Split {
	case "":
		s.Split = SplitSingle
	case SplitSingle, SplitPerRoot:
	default:
		return specErr("split must be %s or %s", SplitSingle, SplitPerRoot)
	}
	if s.Split == SplitPerRoot {
		seen := map[string]string{}
		for _, r := range s.Roots {
			n := UnitName(r)
			if prev, ok := seen[n]; ok {
				return specErr("roots %q and %q would share the PBS group %q; back them up in separate jobs or use split %s", prev, r, n, SplitSingle)
			}
			seen[n] = r
		}
	}
	if s.Concurrency < 0 || s.Concurrency > MaxConcurrency {
		return specErr("concurrency must be between 1 and %d", MaxConcurrency)
	}
	s.BackupID = strings.TrimSpace(s.BackupID)
	if s.BackupID != "" && !naming.ValidGroupID(s.BackupID) {
		return specErr("backup_id may contain letters, digits, '.', '_' and '-' only")
	}
	s.Profile = naming.NormalizeProfileName(s.Profile)
	if s.Profile != "" && !naming.ValidProfileName(s.Profile) {
		return specErr("profile may contain letters, digits, '.', '_' and '-' (at most 64)")
	}
	return nil
}

// ValidateFor checks the spec against its remote: bucket backends need at least one
// root whose first segment is a usable bucket, container or share name, and a
// remote that keeps its credential on the agents needs a profile. Call after
// Validate.
func (s *Spec) ValidateFor(r *Remote) error {
	if r == nil {
		return specErr("the remote does not exist")
	}
	if r.AuthMethod == AuthAgent && s.Profile == "" {
		return specErr("the remote keeps its credential on the agents; name the agent credential profile that holds it")
	}
	what, check := rootKind(r.Backend)
	if check == nil {
		// SFTP and WebDAV: no roots means the whole remote
		if len(s.Roots) == 0 {
			s.Roots = []string{""}
		}
		return nil
	}
	if len(s.Roots) == 0 {
		return specErr("list at least one %s", what)
	}
	for _, root := range s.Roots {
		first, _, _ := strings.Cut(root, "/")
		if err := check(first); err != nil {
			return specErr("root %q: %v", root, err)
		}
	}
	return nil
}

// EffConcurrency applies the default
func (s *Spec) EffConcurrency() int {
	if s.Concurrency <= 0 {
		return DefaultConcurrency
	}
	return s.Concurrency
}

// rootKind names what the first segment of a root is on the backend, and checks it
// (nil: roots are plain paths)
func rootKind(backend string) (string, func(string) error) {
	switch backend {
	case BackendS3:
		return "bucket", func(b string) error {
			if len(b) < 3 || len(b) > 63 || strings.Trim(b, "abcdefghijklmnopqrstuvwxyz0123456789.-") != "" {
				return fmt.Errorf("%q is not an S3 bucket name (3-63 lower-case letters, digits, '.' and '-')", b)
			}
			return nil
		}
	case BackendAzure:
		return "container", func(c string) error {
			if len(c) < 3 || len(c) > 63 || strings.Trim(c, "abcdefghijklmnopqrstuvwxyz0123456789-") != "" {
				return fmt.Errorf("%q is not an Azure container name (3-63 lower-case letters, digits and '-')", c)
			}
			return nil
		}
	case BackendSMB:
		return "share", func(string) error { return nil }
	}
	return "", nil
}

// cleanRoot trims slashes and refuses empty, "." and ".." segments
func cleanRoot(raw string) (string, error) {
	root := strings.Trim(strings.TrimSpace(raw), "/")
	if root == "" {
		return "", nil
	}
	for _, seg := range strings.Split(root, "/") {
		switch seg {
		case "":
			return "", errors.New("empty path segment")
		case ".", "..":
			return "", errors.New(`"." and ".." aren't allowed`)
		}
	}
	return root, nil
}

// within reports whether path is root itself or below it ("" is the whole remote)
func within(path, root string) bool {
	return root == "" || path == root || strings.HasPrefix(path, root+"/")
}

// Group naming. Every unit group extends the job's group: <job group>-<root>, which
// is what the server's sub-ticket endpoint enforces.

// DefaultBackupID is the job group when the spec doesn't override it
func DefaultBackupID(remoteName string) string { return "remote-" + naming.SafeName(remoteName) }

// GroupPrefix is what every unit group of the job must start with
func GroupPrefix(jobBackupID string) string { return jobBackupID + "-" }

// UnitName is a root's part of its unit group ("" is the whole remote: "root")
func UnitName(root string) string {
	if root == "" {
		return "root"
	}
	return naming.SafeName(root)
}

// UnitGroup names the PBS group of one root (SplitPerRoot)
func UnitGroup(jobBackupID, root string) string { return GroupPrefix(jobBackupID) + UnitName(root) }
