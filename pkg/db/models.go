package db

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

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
	ID         uuid.UUID   `json:"id" db:"id"`
	Hostname   string      `json:"hostname" db:"hostname"`
	IPAddress  string      `json:"ip_address" db:"ip_address"`
	OS         string      `json:"os" db:"os"`
	Arch       string      `json:"arch" db:"arch"`
	Version    string      `json:"version" db:"version"`
	TaskQueue  string      `json:"task_queue" db:"task_queue"`
	Status     AgentStatus `json:"status" db:"status"`
	LastSeenAt *time.Time  `json:"last_seen_at" db:"last_seen_at"`
	CreatedAt  time.Time   `json:"created_at" db:"created_at"`
	UpdatedAt  time.Time   `json:"updated_at" db:"updated_at"`
}

// EnrollmentToken represents a one-time or multi-use token for agent onboarding
type EnrollmentToken struct {
	ID         uuid.UUID `json:"id" db:"id"`
	TokenHash  string    `json:"-" db:"token_hash"`
	Name       string    `json:"name" db:"name"`
	MaxUses    int       `json:"max_uses" db:"max_uses"`
	UsesCount  int       `json:"uses_count" db:"uses_count"`
	ExpiresAt  time.Time `json:"expires_at" db:"expires_at"`
	CreatedAt  time.Time `json:"created_at" db:"created_at"`
}

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
	CreatedAt          time.Time `json:"created_at" db:"created_at"`
	UpdatedAt          time.Time `json:"updated_at" db:"updated_at"`
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
	CreatedAt       time.Time       `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at" db:"updated_at"`

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
	CreatedAt     time.Time  `json:"created_at" db:"created_at"`

	// Joined fields
	JobName   string `json:"job_name,omitempty"`
	AgentName string `json:"agent_name,omitempty"`
}

// Helper to serialize RetentionPolicy to JSON bytes
func (r RetentionPolicy) ToJSON() []byte {
	bytes, _ := json.Marshal(r)
	return bytes
}
