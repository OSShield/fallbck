package db

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/config"
	"github.com/osshield/fallbck/pkg/dbbackup"
	"github.com/osshield/fallbck/pkg/k8sbackup"
)

// Agent / job types: each agent binary handles one kind of job
const (
	AgentTypeFilesystem = config.AgentTypeFilesystem
	AgentTypeDatabase   = config.AgentTypeDatabase
	AgentTypeKubernetes = config.AgentTypeKubernetes
	JobTypeFilesystem   = config.AgentTypeFilesystem
	JobTypeDatabase     = config.AgentTypeDatabase
	JobTypeKubernetes   = config.AgentTypeKubernetes
)

// NormalizeAgentType maps "" to filesystem and reports unknown values
func NormalizeAgentType(t string) (string, bool) {
	switch t {
	case "", AgentTypeFilesystem:
		return AgentTypeFilesystem, true
	case AgentTypeDatabase:
		return AgentTypeDatabase, true
	case AgentTypeKubernetes:
		return AgentTypeKubernetes, true
	}
	return t, false
}

// AgentStatus represents the lifecycle state of an agent
type AgentStatus string

const (
	AgentStatusOnline  AgentStatus = "online"
	AgentStatusOffline AgentStatus = "offline"
	AgentStatusBusy    AgentStatus = "busy"
	AgentStatusError   AgentStatus = "error"
)

// Agent represents a registered backup agent host
type Agent struct {
	ID        uuid.UUID `json:"id" db:"id"`
	Hostname  string    `json:"hostname" db:"hostname"`
	IPAddress string    `json:"ip_address" db:"ip_address"`
	OS        string    `json:"os" db:"os"`
	Arch      string    `json:"arch" db:"arch"`
	Version   string    `json:"version" db:"version"`
	AgentType string    `json:"agent_type" db:"agent_type"`
	TaskQueue string    `json:"task_queue" db:"task_queue"`
	// DebugLogging raises the agent's log level to debug (applied via heartbeats)
	DebugLogging bool        `json:"debug_logging" db:"debug_logging"`
	Status       AgentStatus `json:"status" db:"status"`
	LastSeenAt   *time.Time  `json:"last_seen_at" db:"last_seen_at"`
	CreatedAt    time.Time   `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time   `json:"updated_at" db:"updated_at"`
}

// EnrollmentToken represents a one-time or multi-use token for agent onboarding
type EnrollmentToken struct {
	ID        uuid.UUID `json:"id" db:"id"`
	TokenHash string    `json:"-" db:"token_hash"`
	Name      string    `json:"name" db:"name"`
	MaxUses   int       `json:"max_uses" db:"max_uses"`
	UsesCount int       `json:"uses_count" db:"uses_count"`
	ExpiresAt time.Time `json:"expires_at" db:"expires_at"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// Status describes whether the token can still be used
func (t *EnrollmentToken) Status() string {
	if !t.ExpiresAt.IsZero() && time.Now().After(t.ExpiresAt) {
		return "expired"
	}
	if t.MaxUses > 0 && t.UsesCount >= t.MaxUses {
		return "exhausted"
	}
	return "active"
}

// pxar archive formats a target accepts
const (
	PxarFormatV1 = "v1" // single stream + catalog; browsable everywhere
	PxarFormatV2 = "v2" // split metadata/payload streams; PBS 3.2+
)

// BackupTarget represents a remote backup repository such as Proxmox Backup Server
type BackupTarget struct {
	ID                 uuid.UUID `json:"id" db:"id"`
	Name               string    `json:"name" db:"name"`
	TargetType         string    `json:"target_type" db:"target_type"` // "pbs"
	Endpoint           string    `json:"endpoint" db:"endpoint"`
	Datastore          string    `json:"datastore" db:"datastore"`
	Namespace          string    `json:"namespace" db:"namespace"`
	AuthTokenEncrypted string    `json:"-" db:"auth_token_encrypted"`
	Fingerprint        string    `json:"fingerprint" db:"fingerprint"`
	TLSVerify          bool      `json:"tls_verify" db:"tls_verify"`
	PxarFormat         string    `json:"pxar_format" db:"pxar_format"`
	CreatedAt          time.Time `json:"created_at" db:"created_at"`
	UpdatedAt          time.Time `json:"updated_at" db:"updated_at"`

	// HasToken reports whether an API token is stored (the token itself is never returned)
	HasToken bool `json:"has_token" db:"-"`
}

// Sanitize fills derived, API-safe fields
func (t *BackupTarget) Sanitize() *BackupTarget {
	t.HasToken = t.AuthTokenEncrypted != ""
	return t
}

// RetentionPolicy defines backup retention counts
type RetentionPolicy struct {
	KeepLast    int `json:"keep_last"`
	KeepDaily   int `json:"keep_daily"`
	KeepWeekly  int `json:"keep_weekly"`
	KeepMonthly int `json:"keep_monthly"`
	KeepYearly  int `json:"keep_yearly"`
}

// BackupJob defines what, when, and where an agent backs up
type BackupJob struct {
	ID              uuid.UUID       `json:"id" db:"id"`
	Name            string          `json:"name" db:"name"`
	AgentID         uuid.UUID       `json:"agent_id" db:"agent_id"`
	TargetID        uuid.UUID       `json:"target_id" db:"target_id"`
	ScheduleCron    string          `json:"schedule_cron" db:"schedule_cron"`
	BackupPaths     []string        `json:"backup_paths" db:"backup_paths"`
	ExcludePaths    []string        `json:"exclude_paths" db:"exclude_paths"`
	RetentionPolicy RetentionPolicy `json:"retention_policy" db:"retention_policy"`
	Enabled         bool            `json:"enabled" db:"enabled"`
	// DirectPBS makes the agent talk to PBS itself (credentials handed out per run)
	// instead of through the server-side tunnel. Server-side setting only.
	DirectPBS bool `json:"direct_pbs" db:"direct_pbs"`
	// JobType is filesystem (BackupPaths) or database (DBConfig)
	JobType string `json:"job_type" db:"job_type"`
	// DBConfig is the database job specification; the password is stored but never
	// returned by the API (see Sanitize)
	DBConfig *dbbackup.Spec `json:"db_config,omitempty" db:"db_config"`
	// K8sConfig is the kubernetes job specification
	K8sConfig *k8sbackup.Spec `json:"k8s_config,omitempty" db:"k8s_config"`
	CreatedAt time.Time       `json:"created_at" db:"created_at"`
	UpdatedAt time.Time       `json:"updated_at" db:"updated_at"`

	// Joined fields for display
	AgentName  string `json:"agent_name,omitempty"`
	TargetName string `json:"target_name,omitempty"`
}

// RunStatus represents the state of a backup run
type RunStatus string

const (
	RunStatusPending   RunStatus = "pending"
	RunStatusRunning   RunStatus = "running"
	RunStatusCompleted RunStatus = "completed"
	RunStatusFailed    RunStatus = "failed"
	// RunStatusCancelling: cancellation requested, waiting for the agent to stop
	RunStatusCancelling RunStatus = "cancelling"
	RunStatusCancelled  RunStatus = "cancelled"
)

// IsActive reports whether a run can still be cancelled
func (s RunStatus) IsActive() bool {
	return s == RunStatusPending || s == RunStatusRunning
}

// BackupRun records a single execution of a backup job
type BackupRun struct {
	ID            uuid.UUID  `json:"id" db:"id"`
	JobID         uuid.UUID  `json:"job_id" db:"job_id"`
	AgentID       uuid.UUID  `json:"agent_id" db:"agent_id"`
	TargetID      uuid.UUID  `json:"target_id" db:"target_id"`
	WorkflowID    string     `json:"workflow_id" db:"workflow_id"`
	RunID         string     `json:"run_id" db:"run_id"`
	Status        RunStatus  `json:"status" db:"status"`
	StartTime     *time.Time `json:"start_time" db:"start_time"`
	EndTime       *time.Time `json:"end_time" db:"end_time"`
	BytesScanned  int64      `json:"bytes_scanned" db:"bytes_scanned"`
	BytesUploaded int64      `json:"bytes_uploaded" db:"bytes_uploaded"`
	DedupRatio    float64    `json:"dedup_ratio" db:"dedup_ratio"`
	ChunkCount    int        `json:"chunk_count" db:"chunk_count"`
	ErrorMessage  string     `json:"error_message" db:"error_message"`
	PBSSnapshotID string     `json:"pbs_snapshot_id" db:"pbs_snapshot_id"`
	// LogTail is the agent's recent log output captured when the run failed
	LogTail   string    `json:"log_tail,omitempty" db:"log_tail"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`

	// Joined fields
	JobName   string `json:"job_name,omitempty"`
	AgentName string `json:"agent_name,omitempty"`
}

// Helper to serialize RetentionPolicy to JSON bytes
func (r RetentionPolicy) ToJSON() []byte {
	bytes, _ := json.Marshal(r)
	return bytes
}

// DurationString renders how long the run took (or has been running); "-" before start
func (r *BackupRun) DurationString() string {
	if r.StartTime == nil {
		return "-"
	}
	end := time.Now()
	switch {
	case r.EndTime != nil:
		end = *r.EndTime
	case !r.Status.IsActive():
		return "-"
	}
	d := end.Sub(*r.StartTime).Round(time.Second)
	if d < 0 {
		return "-"
	}
	return d.String()
}

// IsDatabase reports whether the job is a database backup
func (j *BackupJob) IsDatabase() bool { return j.JobType == JobTypeDatabase }

// IsKubernetes reports whether the job is a kubernetes backup
func (j *BackupJob) IsKubernetes() bool { return j.JobType == JobTypeKubernetes }

// Sanitize redacts the stored database password (HasPassword tells whether one exists)
func (j *BackupJob) Sanitize() *BackupJob {
	if j.JobType == "" {
		j.JobType = JobTypeFilesystem
	}
	if j.DBConfig != nil {
		j.DBConfig = j.DBConfig.Redacted()
	}
	return j
}

// Summary describes what the job backs up (paths, database target or cluster scope)
func (j *BackupJob) Summary() string {
	if j.IsDatabase() {
		return j.DBConfig.Summary()
	}
	if j.IsKubernetes() {
		return j.K8sConfig.Summary()
	}
	return strings.Join(j.BackupPaths, ", ")
}
