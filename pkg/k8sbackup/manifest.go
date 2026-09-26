package k8sbackup

import (
	"encoding/json"
	"time"
)

// ManifestSchemaVersion is bumped on incompatible manifest changes
const ManifestSchemaVersion = 1

// VolumePlan is one PVC the run intends to back up (produced by discovery)
type VolumePlan struct {
	Namespace     string `json:"namespace"`
	PVCName       string `json:"pvc"`
	PVName        string `json:"pv,omitempty"`
	StorageClass  string `json:"storage_class,omitempty"`
	Provisioner   string `json:"provisioner,omitempty"`
	VolumeMode    string `json:"volume_mode,omitempty"`
	CapacityBytes int64  `json:"capacity_bytes,omitempty"`
	// Mode: snapshot | live | skipped
	Mode          string `json:"mode"`
	SnapshotClass string `json:"snapshot_class,omitempty"`
	// GroupID is the PBS backup group this volume uploads into
	GroupID    string `json:"group_id"`
	SkipReason string `json:"skip_reason,omitempty"`
}

// Plan is the discovery result the workflow fans out over
type Plan struct {
	ClusterName    string       `json:"cluster_name"`
	ServerVersion  string       `json:"server_version,omitempty"`
	SnapshotCRD    bool         `json:"snapshot_crd"`
	AgentNamespace string       `json:"agent_namespace,omitempty"`
	Volumes        []VolumePlan `json:"volumes"`
	Warnings       []string     `json:"warnings,omitempty"`
}

// VolumeResult is the outcome of one volume backup
type VolumeResult struct {
	Namespace string `json:"namespace"`
	PVCName   string `json:"pvc"`
	GroupID   string `json:"group_id"`
	// Mode actually used (snapshot may fall back to live)
	Mode string `json:"mode"`
	// Consistency: csi-snapshot | crash-consistent-live
	Consistency string `json:"consistency,omitempty"`
	// Status: completed | failed | skipped | cancelled
	Status        string  `json:"status"`
	SnapshotID    string  `json:"snapshot_id,omitempty"`
	BytesScanned  int64   `json:"bytes_scanned"`
	BytesUploaded int64   `json:"bytes_uploaded"`
	ChunkCount    int     `json:"chunk_count"`
	DedupRatio    float64 `json:"dedup_ratio,omitempty"`
	DurationMS    int64   `json:"duration_ms,omitempty"`
	Error         string  `json:"error,omitempty"`
}

// Manifest is stored as blob k8s-manifest.blob on the resources snapshot and as a file
// inside the resources archive; it is the restore runbook's index.
type Manifest struct {
	SchemaVersion int               `json:"schema_version"`
	Generator     ManifestGenerator `json:"generator"`
	Job           ManifestJob       `json:"job"`
	Snapshot      ManifestSnapshot  `json:"snapshot"`
	Kubernetes    ManifestCluster   `json:"kubernetes"`
	Spec          *Spec             `json:"spec"`
	Resources     ManifestResources `json:"resources"`
	Volumes       []VolumeResult    `json:"volumes"`
	Warnings      []string          `json:"warnings,omitempty"`
	Restore       ManifestRestore   `json:"restore"`
	// Partial marks a manifest the server assembled from the volume outcomes because
	// the run ended (resources step failed, cancelled) before the agent produced one:
	// only Job, Snapshot and Volumes are meaningful, and nothing was uploaded for it
	Partial bool `json:"partial,omitempty"`
}

type ManifestGenerator struct {
	Agent   string `json:"agent"`
	Version string `json:"version"`
	Cluster string `json:"cluster"`
}

type ManifestJob struct {
	ID          string `json:"id"`
	Name        string `json:"name,omitempty"`
	RunID       string `json:"run_id,omitempty"`
	BackupRunID string `json:"backup_run_id"`
}

type ManifestSnapshot struct {
	Type    string    `json:"type"`
	ID      string    `json:"id"`
	Time    time.Time `json:"time"`
	Archive string    `json:"archive"`
}

type ManifestCluster struct {
	ServerVersion string `json:"server_version,omitempty"`
	SnapshotCRD   bool   `json:"snapshot_crd"`
}

type ManifestResources struct {
	DumpedAt        time.Time      `json:"dumped_at"`
	Counts          map[string]int `json:"counts,omitempty"` // "apps/deployments" -> n
	Excluded        []string       `json:"excluded,omitempty"`
	FailedGroups    []string       `json:"failed_groups,omitempty"`
	SecretsIncluded bool           `json:"secrets_included"`
	Namespaces      []string       `json:"namespaces,omitempty"`
}

type ManifestRestore struct {
	Summary  string   `json:"summary"`
	Commands []string `json:"commands"`
}

// Marshal renders the manifest as indented JSON
func (m *Manifest) Marshal() ([]byte, error) { return json.MarshalIndent(m, "", "  ") }

// ParseManifest decodes a manifest
func ParseManifest(data []byte) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}
