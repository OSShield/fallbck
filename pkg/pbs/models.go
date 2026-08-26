package pbs

import "time"

// BackupType represents the type of backup in PBS (host, ct, vm)
type BackupType string

const (
	BackupTypeHost BackupType = "host"
	BackupTypeCT   BackupType = "ct"
	BackupTypeVM   BackupType = "vm"
)

// SnapshotIdentifier uniquely identifies a PBS snapshot
type SnapshotIdentifier struct {
	Datastore  string     `json:"datastore"`
	Namespace  string     `json:"namespace,omitempty"`
	BackupType BackupType `json:"backup_type"`
	BackupID   string     `json:"backup_id"`
	BackupTime int64      `json:"backup_time"` // Unix timestamp
}

func (s SnapshotIdentifier) String() string {
	t := time.Unix(s.BackupTime, 0).UTC().Format("2006-01-02T15:04:05Z")
	return string(s.BackupType) + "/" + s.BackupID + "/" + t
}

// BackupManifest represents the PBS V2 manifest (index.json)
type BackupManifest struct {
	BackupType BackupType `json:"backup-type"`
	BackupID   string     `json:"backup-id"`
	BackupTime int64      `json:"backup-time"`
	Files      []FileInfo `json:"files"`
	Signature  string     `json:"signature,omitempty"`
}

// FileInfo describes an archive or index file inside a snapshot
type FileInfo struct {
	Filename string `json:"filename"` // e.g. "root.pxar.didx" or "catalog.pcat1.didx"
	Size     int64  `json:"size"`
	Csum     string `json:"csum"`
}

// ChunkDigest represents a SHA256 hex digest of a chunk
type ChunkDigest [32]byte

// BackupStats summarizes an executed backup run
type BackupStats struct {
	BytesScanned  int64         `json:"bytes_scanned"`
	BytesUploaded int64         `json:"bytes_uploaded"`
	ChunkCount    int           `json:"chunk_count"`
	DedupRatio    float64       `json:"dedup_ratio"`
	Duration      time.Duration `json:"duration"`
	SnapshotID    string        `json:"snapshot_id"`
}
