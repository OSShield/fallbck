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
