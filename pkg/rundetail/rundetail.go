// Package rundetail holds the type-specific detail blob stored per backup run
// (backup_runs.details) and rendered on the run detail page. Every blob carries a
// top-level Type discriminator; the rest is type-specific.
package rundetail

import "encoding/json"

// Types
const (
	TypeFilesystem = "filesystem"
	TypeDatabase   = "database"
	TypeKubernetes = "kubernetes"
	TypePVE        = "pve"
)

// ArchiveStat is one pxar/catalog/payload archive uploaded in a snapshot
type ArchiveStat struct {
	Name         string  `json:"name"`
	Kind         string  `json:"kind,omitempty"` // pxar | payload | catalog
	SizeBytes    uint64  `json:"size_bytes"`
	Chunks       uint64  `json:"chunks"`
	NewChunks    uint64  `json:"new_chunks"`
	ReusedChunks uint64  `json:"reused_chunks"`
	Dedup        float64 `json:"dedup,omitempty"`
}

// Warning mirrors an archiver warning (path + message)
type Warning struct {
	Path    string `json:"path,omitempty"`
	Message string `json:"message"`
}

// Filesystem is the detail blob for a filesystem backup
type Filesystem struct {
	Type         string        `json:"type"` // filesystem
	Format       string        `json:"format,omitempty"`
	SnapshotID   string        `json:"snapshot_id,omitempty"`
	Paths        []string      `json:"paths,omitempty"`
	ExcludePaths []string      `json:"exclude_paths,omitempty"`
	Archives     []ArchiveStat `json:"archives,omitempty"`
	Warnings     []Warning     `json:"warnings,omitempty"`
	// Reuse reports metadata change detection (v2 archives with a metadata cache)
	Reuse *ReuseStats `json:"reuse,omitempty"`
}

// ReuseStats is what metadata change detection achieved in one run
type ReuseStats struct {
	Files         int    `json:"files"`
	ReusedFiles   int    `json:"reused_files"`
	ReusedBytes   uint64 `json:"reused_bytes"`
	InjectedBytes uint64 `json:"injected_bytes"`
	RejectedRuns  int    `json:"rejected_runs,omitempty"`
}

// Marshal renders a detail value as compact JSON (json.RawMessage for the run)
func Marshal(v any) json.RawMessage {
	data, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return data
}

// Wrapper carries a manifest-style blob (database / kubernetes) with a Type tag,
// so the detail page can switch on Type and render the manifest.
type Wrapper struct {
	Type     string          `json:"type"`
	Manifest json.RawMessage `json:"manifest,omitempty"`
}

// WrapManifest tags a marshalled manifest with its detail type
func WrapManifest(detailType string, manifest []byte) json.RawMessage {
	return Marshal(Wrapper{Type: detailType, Manifest: json.RawMessage(manifest)})
}

// ---- Live progress (backup_runs.progress) -----------------------------------

// Progress is the live state of a running backup, updated mid-run and polled by the
// detail page. It is cleared conceptually once the run finalizes (the page then shows
// the full Details blob instead).
type Progress struct {
	// Phase is the current human-readable step (e.g. "uploading db/data (40s)")
	Phase string `json:"phase,omitempty"`
	// Items are per-unit statuses keyed by a stable id (PVC group, database name)
	Items map[string]ProgressItem `json:"items,omitempty"`
	// Counts summarise the items for a quick "3/8" headline
	UpdatedAt string `json:"updated_at,omitempty"`
}

// ProgressItem is one live per-unit status (a PVC, a database)
type ProgressItem struct {
	Name string `json:"name"`
	// Status: pending | running | completed | failed | skipped
	Status        string `json:"status"`
	Kind          string `json:"kind,omitempty"` // pvc | database
	Mode          string `json:"mode,omitempty"`
	Consistency   string `json:"consistency,omitempty"`
	BytesUploaded int64  `json:"bytes_uploaded,omitempty"`
	SnapshotID    string `json:"snapshot_id,omitempty"`
	Note          string `json:"note,omitempty"`
	Error         string `json:"error,omitempty"`
}
