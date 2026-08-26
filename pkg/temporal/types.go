package temporal

import (
	"time"

	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/db"
)

const (
	ServerTaskQueue = "fallbck-server-queue"
)

// BackupSessionInfo carries all configuration needed for a worker to execute a backup
type BackupSessionInfo struct {
	JobID           uuid.UUID          `json:"job_id"`
	AgentID         uuid.UUID          `json:"agent_id"`
	TargetID        uuid.UUID          `json:"target_id"`
	AgentTaskQueue  string             `json:"agent_task_queue"`
	ProxyURL        string             `json:"proxy_url"`
	Ticket          string             `json:"ticket"`
	Datastore       string             `json:"datastore"`
	Namespace       string             `json:"namespace"`
	BackupPaths     []string           `json:"backup_paths"`
	ExcludePaths    []string           `json:"exclude_paths"`
	RetentionPolicy db.RetentionPolicy `json:"retention_policy"`
	WorkflowID      string             `json:"workflow_id"`
	RunID           string             `json:"run_id"`
	BackupRunID     uuid.UUID          `json:"backup_run_id"`
}

// BackupExecutionResult contains the outcome and metrics of a backup run
type BackupExecutionResult struct {
	Status        db.RunStatus  `json:"status"`
	BytesScanned  int64         `json:"bytes_scanned"`
	BytesUploaded int64         `json:"bytes_uploaded"`
	DedupRatio    float64       `json:"dedup_ratio"`
	ChunkCount    int           `json:"chunk_count"`
	SnapshotID    string        `json:"snapshot_id"`
	ErrorMessage  string        `json:"error_message,omitempty"`
	Duration      time.Duration `json:"duration"`
}

// BackupHeartbeatProgress is sent periodically during execution
type BackupHeartbeatProgress struct {
	CurrentFile   string  `json:"current_file"`
	BytesScanned  int64   `json:"bytes_scanned"`
	BytesUploaded int64   `json:"bytes_uploaded"`
	Percent       float64 `json:"percent"`
}
