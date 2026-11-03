package github

import "time"

// ManifestSchemaVersion is bumped on incompatible manifest changes
const ManifestSchemaVersion = 1

// Manifest describes one run (fallbck-github.json in the job group's snapshot); each
// repository snapshot carries its RepoResult as fallbck-github-repo.json
type Manifest struct {
	SchemaVersion int               `json:"schema_version"`
	Generator     Generator         `json:"generator"`
	Job           JobInfo           `json:"job"`
	Account       AccountInfo       `json:"account"`
	StartedAt     time.Time         `json:"started_at"`
	FinishedAt    time.Time         `json:"finished_at"`
	Repos         []RepoResult      `json:"repos"`
	Spec          *Spec             `json:"spec,omitempty"`
	Warnings      []string          `json:"warnings,omitempty"`
	Restore       map[string]string `json:"restore"`
}

// Generator identifies the agent that produced the backup
type Generator struct {
	Agent    string `json:"agent"`
	Version  string `json:"version"`
	Hostname string `json:"hostname"`
	Git      string `json:"git,omitempty"`
}

// JobInfo identifies the job and run
type JobInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name,omitempty"`
	RunID       string `json:"run_id"`
	BackupRunID string `json:"backup_run_id"`
	// Group is the job's PBS group (index archive, prefix of every repository group)
	Group string `json:"group"`
}

// AccountInfo names the token's user as GitHub reports it
type AccountInfo struct {
	Login  string `json:"login"`
	APIURL string `json:"api_url"`
}

// RepoResult is one repository of the run
type RepoResult struct {
	// FullName is owner/name; Sources says why it was selected (org:x, user:x, repo, starred)
	FullName string   `json:"full_name"`
	Sources  []string `json:"sources,omitempty"`
	Group    string   `json:"group"`
	Private  bool     `json:"private,omitempty"`
	Fork     bool     `json:"fork,omitempty"`
	Archived bool     `json:"archived,omitempty"`
	// Status: completed | failed | skipped | cancelled
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
	// SnapshotTime is the snapshot written for the repository (unix seconds), 0 when none
	SnapshotTime int64 `json:"snapshot_time,omitempty"`
	// HeadCommit / Refs describe the mirror; Wiki says whether a wiki was mirrored
	DefaultBranch string `json:"default_branch,omitempty"`
	HeadCommit    string `json:"head_commit,omitempty"`
	Refs          int    `json:"refs"`
	Wiki          bool   `json:"wiki,omitempty"`
	Issues        int    `json:"issues,omitempty"`
	Pulls         int    `json:"pulls,omitempty"`
	Comments      int    `json:"comments,omitempty"`
	Releases      int    `json:"releases,omitempty"`
	// Bytes is the size of the snapshot, Uploaded the share that was new to PBS
	Bytes    int64    `json:"bytes,omitempty"`
	Uploaded int64    `json:"uploaded,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}
