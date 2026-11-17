package remote

import "time"

// ManifestSchemaVersion is bumped on incompatible manifest changes
const ManifestSchemaVersion = 1

// RunCredentials is what the server hands a run (GET /api/v1/agents/remote-credentials):
// the remote's settings always, its stored credential only when the job names no
// agent profile
type RunCredentials struct {
	Remote  *Remote `json:"remote"`
	Secrets Secrets `json:"secrets"`
}

// Manifest describes one remote run. The snapshot carries it as ManifestBlobName,
// written before the upload; the run detail gets the final one, which adds what
// happened while objects were read (objects that changed size).
type Manifest struct {
	SchemaVersion int          `json:"schema_version"`
	Generator     Generator    `json:"generator"`
	Job           JobInfo      `json:"job"`
	Remote        RemoteInfo   `json:"remote"`
	Spec          *Spec        `json:"spec"`
	Roots         []RootResult `json:"roots"`
	Totals        Totals       `json:"totals"`
	Warnings      []string     `json:"warnings,omitempty"`
	StartedAt     time.Time    `json:"started_at"`
	FinishedAt    time.Time    `json:"finished_at"`
}

// Generator is the agent that wrote the snapshot
type Generator struct {
	Agent    string `json:"agent"`
	Version  string `json:"version,omitempty"`
	Hostname string `json:"hostname,omitempty"`
}

// JobInfo names the job and run
type JobInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name,omitempty"`
	RunID       string `json:"run_id,omitempty"`
	BackupRunID string `json:"backup_run_id,omitempty"`
	Group       string `json:"group"`
}

// RemoteInfo is the remote the run read (never its credential)
type RemoteInfo struct {
	Name     string `json:"name"`
	Backend  string `json:"backend"`
	Identity string `json:"identity"`
	Profile  string `json:"profile,omitempty"`
}

// Root outcomes
const (
	RootCompleted = "completed"
	RootFailed    = "failed"
)

// RootResult is one root of the run
type RootResult struct {
	Root    string `json:"root"`
	Status  string `json:"status"`
	Objects int    `json:"objects"`
	Bytes   int64  `json:"bytes"`
	Error   string `json:"error,omitempty"`
	// Group / SnapshotID: the root's own snapshot (split per_root)
	Group      string `json:"group,omitempty"`
	SnapshotID string `json:"snapshot_id,omitempty"`
	Note       string `json:"note,omitempty"`
}

// Totals sums the roots
type Totals struct {
	Roots   int   `json:"roots"`
	Failed  int   `json:"failed"`
	Objects int   `json:"objects"`
	Bytes   int64 `json:"bytes"`
}

// Tally fills Totals from Roots
func (m *Manifest) Tally() {
	m.Totals = Totals{Roots: len(m.Roots)}
	for _, r := range m.Roots {
		if r.Status == RootFailed {
			m.Totals.Failed++
		}
		m.Totals.Objects += r.Objects
		m.Totals.Bytes += r.Bytes
	}
}
