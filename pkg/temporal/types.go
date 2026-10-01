package temporal

import (
	"encoding/json"
	"github.com/osshield/fallbck/pkg/dbbackup"
	"github.com/osshield/fallbck/pkg/dockerbackup"
	"github.com/osshield/fallbck/pkg/inventory"
	"github.com/osshield/fallbck/pkg/k8sbackup"
	"github.com/osshield/fallbck/pkg/pvebackup"
	"time"

	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/db"
)

const (
	ServerTaskQueue = "fallbck-server-queue"
)

// BackupSessionInfo carries all configuration needed for a worker to execute a backup
type BackupSessionInfo struct {
	JobID          uuid.UUID `json:"job_id"`
	AgentID        uuid.UUID `json:"agent_id"`
	TargetID       uuid.UUID `json:"target_id"`
	AgentTaskQueue string    `json:"agent_task_queue"`
	ProxyURL       string    `json:"proxy_url"`
	Ticket         string    `json:"ticket"`
	Datastore      string    `json:"datastore"`
	// Namespace is the target's PBS namespace at prepare time (informational). The
	// server tunnel and direct-mode credentials source the namespace from the target
	// directly, so an agent cannot influence which namespace a backup lands in.
	Namespace string `json:"namespace"`
	// Snapshot identity the server opens on PBS (also bound into the ticket)
	BackupType string `json:"backup_type"`
	BackupID   string `json:"backup_id"`
	BackupTime int64  `json:"backup_time"`
	// PxarFormat is "v1" or "v2" (target setting)
	PxarFormat string `json:"pxar_format"`
	// DirectPBS: the agent fetches PBS credentials with its ticket and connects to PBS
	// itself instead of through the server tunnel (job setting)
	DirectPBS bool `json:"direct_pbs"`
	// Encrypted: the target encrypts client-side; the agent fetches the key with its
	// ticket (GET /api/v1/agents/encryption-key) and must not upload without it.
	// KeyFingerprint names the key for logs and the run record; the key itself never
	// travels through Temporal.
	Encrypted      bool   `json:"encrypted,omitempty"`
	KeyFingerprint string `json:"key_fingerprint,omitempty"`
	// JobType is filesystem or database; database jobs carry DBConfig (password
	// redacted — the agent fetches it with its ticket when DBPasswordOnServer is set)
	JobType string `json:"job_type,omitempty"`
	// AgentType is the type of the agent running the job (a database job may run on a
	// kubernetes agent, which dumps from a pod); empty means the job's own type
	AgentType          string         `json:"agent_type,omitempty"`
	DBConfig           *dbbackup.Spec `json:"db_config,omitempty"`
	DBPasswordOnServer bool           `json:"db_password_on_server,omitempty"`
	// K8sConfig is the kubernetes job specification (job_type kubernetes)
	K8sConfig *k8sbackup.Spec `json:"k8s_config,omitempty"`
	// PVEConfig is the Proxmox VE host job specification (job_type pve)
	PVEConfig *pvebackup.Spec `json:"pve_config,omitempty"`
	// DockerConfig is the Docker host job specification (job_type docker)
	DockerConfig *dockerbackup.Spec `json:"docker_config,omitempty"`
	// JobName is informational (manifest)
	JobName      string    `json:"job_name,omitempty"`
	BackupPaths  []string  `json:"backup_paths"`
	ExcludePaths []string  `json:"exclude_paths"`
	WorkflowID   string    `json:"workflow_id"`
	RunID        string    `json:"run_id"`
	BackupRunID  uuid.UUID `json:"backup_run_id"`
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
	// LogTail carries the agent's recent log lines when a run fails (shown in the Runs UI)
	LogTail string `json:"log_tail,omitempty"`
	// Details is a type-specific JSON blob (archives / databases / PVCs) persisted on
	// the run for the detail page; carries a top-level "type" discriminator.
	Details json.RawMessage `json:"details,omitempty"`
	// KeyFingerprint is the encryption key the snapshot was written with ("" = plaintext)
	KeyFingerprint string `json:"key_fingerprint,omitempty"`
}

// BackupFailureDetails travel as application-error details from a failed agent
// activity to the workflow, which copies them onto the run record.
type BackupFailureDetails struct {
	// Phase the activity was in when it failed, with its elapsed time
	Phase string `json:"phase"`
	// LogTail is the agent's recent log output (all levels, capped)
	LogTail string `json:"log_tail"`
}

// BackupHeartbeatProgress is sent periodically during execution
type BackupHeartbeatProgress struct {
	// Phase names what the agent is doing right now (and for how long); recorded with
	// every heartbeat so a heartbeat-timeout failure can report where the agent stopped
	Phase         string  `json:"phase,omitempty"`
	CurrentFile   string  `json:"current_file"`
	BytesScanned  int64   `json:"bytes_scanned"`
	BytesUploaded int64   `json:"bytes_uploaded"`
	Percent       float64 `json:"percent"`
}

// AgentOpsRequest names the agent (its task queue) and the operator action the
// AgentOpsWorkflow runs there: "logs" or "inventory"
type AgentOpsRequest struct {
	AgentTaskQueue string `json:"agent_task_queue"`
	Action         string `json:"action"`
}

// AgentOpsResult carries whichever the action produced
type AgentOpsResult struct {
	Logs      *inventory.LogsResult `json:"logs,omitempty"`
	Inventory *inventory.Detail     `json:"inventory,omitempty"`
}

// AgentOpsWorkflowName is the workflow type the API starts by name
const AgentOpsWorkflowName = "AgentOpsWorkflow"
