package vcs

import "time"

// ManifestSchemaVersion is bumped on incompatible manifest changes
const ManifestSchemaVersion = 1

// Repository outcomes in the manifest
const (
	// RepoCompleted: fetched (or unchanged) this run
	RepoCompleted = "completed"
	// RepoStale: the fetch failed; the snapshot holds the last good mirror
	RepoStale = "stale"
	// RepoFailed: the fetch failed and there was no earlier mirror to fall back on
	RepoFailed = "failed"
	// RepoSkipped: left out by the job's settings (max_repo_size)
	RepoSkipped = "skipped"
)

// Manifest describes one VCS run: the connection, every repository and its outcome,
// and how to restore. Stored as fallbck-vcs.json, a blob of the run's snapshot.
type Manifest struct {
	SchemaVersion int               `json:"schema_version"`
	Generator     Generator         `json:"generator"`
	Job           JobInfo           `json:"job"`
	Source        SourceInfo        `json:"source"`
	StartedAt     time.Time         `json:"started_at"`
	FinishedAt    time.Time         `json:"finished_at"`
	Repositories  []RepoResult      `json:"repositories"`
	Totals        ManifestTotals    `json:"totals"`
	Spec          *Spec             `json:"spec,omitempty"`
	Warnings      []string          `json:"warnings,omitempty"`
	Restore       map[string]string `json:"restore"`
}

// Generator identifies the agent that produced the backup
type Generator struct {
	Agent      string `json:"agent"`
	Version    string `json:"version"`
	Hostname   string `json:"hostname"`
	GitVersion string `json:"git_version,omitempty"`
	LFSVersion string `json:"lfs_version,omitempty"`
}

// JobInfo identifies the job and run
type JobInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name,omitempty"`
	RunID       string `json:"run_id"`
	BackupRunID string `json:"backup_run_id"`
	Group       string `json:"group"`
}

// SourceInfo names the connection as the provider reports it
type SourceInfo struct {
	Provider string `json:"provider"`
	BaseURL  string `json:"base_url"`
	// Version of the GitLab instance (empty for the git provider)
	Version string `json:"version,omitempty"`
	// Username the token belongs to and whether it is an administrator: a job with
	// no groups is only complete with an admin token
	Username string `json:"username,omitempty"`
	IsAdmin  bool   `json:"is_admin,omitempty"`
}

// RepoResult is one repository of the run
type RepoResult struct {
	// ProjectID is the GitLab project id (0 for the git provider)
	ProjectID int64 `json:"project_id,omitempty"`
	// Path is the directory in the archive: the project full path, or
	// <host>/<path> for the git provider
	Path string `json:"path"`
	URL  string `json:"url"`
	// Status: completed | stale | failed | skipped
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
	// Changed: the refs differed from the previous run, so the mirror was fetched
	Changed bool `json:"changed"`
	// LastFetched is when the mirror in the snapshot was last fetched successfully
	LastFetched *time.Time `json:"last_fetched,omitempty"`
	Refs        int        `json:"refs"`
	// Bytes is the size of the mirror; LFSBytes of its LFS objects
	Bytes    int64 `json:"bytes"`
	LFSBytes int64 `json:"lfs_bytes,omitempty"`
	Wiki     bool  `json:"wiki,omitempty"`
	Archived bool  `json:"archived,omitempty"`
	Fork     bool  `json:"fork,omitempty"`
}

// ManifestTotals counts the repositories by outcome
type ManifestTotals struct {
	Repositories int   `json:"repositories"`
	Completed    int   `json:"completed"`
	Stale        int   `json:"stale"`
	Failed       int   `json:"failed"`
	Skipped      int   `json:"skipped"`
	Bytes        int64 `json:"bytes"`
}

// Tally recomputes Totals from Repositories
func (m *Manifest) Tally() {
	t := ManifestTotals{Repositories: len(m.Repositories)}
	for _, r := range m.Repositories {
		switch r.Status {
		case RepoCompleted:
			t.Completed++
		case RepoStale:
			t.Stale++
		case RepoFailed:
			t.Failed++
		case RepoSkipped:
			t.Skipped++
		}
		t.Bytes += r.Bytes + r.LFSBytes
	}
	m.Totals = t
}
