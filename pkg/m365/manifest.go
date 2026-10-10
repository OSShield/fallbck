package m365

import "time"

// ManifestSchemaVersion is bumped on incompatible manifest changes
const ManifestSchemaVersion = 1

// Manifest describes one Microsoft 365 run: the tenant, every unit group written and
// how to restore. Stored as fallbck-m365.json, a blob of the directory group's
// snapshot; each unit snapshot carries its own UnitResult as fallbck-m365-unit.json.
type Manifest struct {
	SchemaVersion int               `json:"schema_version"`
	Generator     Generator         `json:"generator"`
	Job           JobInfo           `json:"job"`
	Tenant        TenantInfo        `json:"tenant"`
	StartedAt     time.Time         `json:"started_at"`
	FinishedAt    time.Time         `json:"finished_at"`
	Units         []UnitResult      `json:"units"`
	Spec          *Spec             `json:"spec,omitempty"`
	Warnings      []string          `json:"warnings,omitempty"`
	Restore       map[string]string `json:"restore"`
}

// Generator identifies the agent that produced the backup
type Generator struct {
	Agent    string `json:"agent"`
	Version  string `json:"version"`
	Hostname string `json:"hostname"`
}

// JobInfo identifies the job and run
type JobInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name,omitempty"`
	RunID       string `json:"run_id"`
	BackupRunID string `json:"backup_run_id"`
	// Group is the job's PBS group (directory archive, prefix of every unit group)
	Group string `json:"group"`
}

// TenantInfo names the tenant as Graph reports it
type TenantInfo struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
}

// UnitResult is one user, site or team of the run
type UnitResult struct {
	Kind string `json:"kind"`
	// Name is the UPN, site URL or team display name; ObjectID the Graph id
	Name     string `json:"name"`
	ObjectID string `json:"object_id,omitempty"`
	Group    string `json:"group"`
	// Status: completed | failed | skipped
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
	// SnapshotTime is the snapshot written for the unit (unix seconds), 0 when none
	SnapshotTime int64 `json:"snapshot_time,omitempty"`
	// Per archive: items in the tree, bytes fetched from Graph this run, bytes reused
	// from the previous snapshot
	Archives []ArchiveStats `json:"archives,omitempty"`
	Resyncs  int            `json:"resyncs,omitempty"`
	Warnings []string       `json:"warnings,omitempty"`
}

// ArchiveStats counts one archive of a unit
type ArchiveStats struct {
	Name       string `json:"name"`
	Items      int    `json:"items"`
	Bytes      uint64 `json:"bytes"`
	Downloaded uint64 `json:"downloaded"`
	Reused     uint64 `json:"reused"`
}
