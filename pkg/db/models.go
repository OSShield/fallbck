package db

import (
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/config"
	"github.com/osshield/fallbck/pkg/dbbackup"
	"github.com/osshield/fallbck/pkg/dockerbackup"
	"github.com/osshield/fallbck/pkg/k8sbackup"
	"github.com/osshield/fallbck/pkg/m365"
	"github.com/osshield/fallbck/pkg/pvebackup"
)

// Agent / job types: each agent binary handles one kind of job
const (
	AgentTypeFilesystem = config.AgentTypeFilesystem
	AgentTypeDatabase   = config.AgentTypeDatabase
	AgentTypeKubernetes = config.AgentTypeKubernetes
	JobTypeFilesystem   = config.AgentTypeFilesystem
	JobTypeDatabase     = config.AgentTypeDatabase
	JobTypeKubernetes   = config.AgentTypeKubernetes
	// JobTypePVE backs up a Proxmox VE host's configuration; it runs on the
	// filesystem agent installed on the node
	JobTypePVE = "pve"
	// JobTypeDocker backs up a Docker host (definitions, compose files, volumes); it
	// runs on the filesystem agent installed on the host
	JobTypeDocker = "docker"
	// JobTypeM365 backs up a Microsoft 365 tenant through Graph; it runs on any
	// filesystem agent with outbound HTTPS (no host capability involved)
	JobTypeM365 = "m365"
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

// NormalizeJobType maps "" to filesystem and accepts the job-only types pve, docker
// and m365
func NormalizeJobType(t string) (string, bool) {
	switch t {
	case JobTypePVE:
		return JobTypePVE, true
	case JobTypeDocker:
		return JobTypeDocker, true
	case JobTypeM365:
		return JobTypeM365, true
	}
	return NormalizeAgentType(t)
}

// JobAllowedOnAgent reports whether an agent of agentType may run a job of jobType.
// Job types normally match the agent type; the exceptions are database jobs on a
// kubernetes agent (dumped from a pod inside the cluster) or on a filesystem agent
// (the combined agent, when it reports database client tools), Proxmox VE / Docker
// host jobs, which run on the filesystem agent installed on the host, and Microsoft
// 365 jobs, which any filesystem agent runs.
func JobAllowedOnAgent(jobType, agentType string) bool {
	jobType, _ = NormalizeJobType(jobType)
	agentType, _ = NormalizeAgentType(agentType)
	if jobType == agentType {
		return true
	}
	switch jobType {
	case JobTypeDatabase:
		return agentType == AgentTypeKubernetes || agentType == AgentTypeFilesystem
	case JobTypePVE, JobTypeDocker, JobTypeM365:
		return agentType == AgentTypeFilesystem
	}
	return false
}

// AgentCapabilities are the host facts a filesystem agent reports with every heartbeat
type AgentCapabilities struct {
	PVEHost    bool
	DockerHost bool
	DBTools    bool
	DBEngines  []string
	// Version is the running binary's version (empty keeps the stored one)
	Version string
	// SelfUpdate / UpdateError: see Agent
	SelfUpdate  bool
	UpdateError string
	// Inventory is the summary attached to this heartbeat (nil: none this time)
	Inventory json.RawMessage
}

// HeartbeatState is what the heartbeat response needs from the agent row
type HeartbeatState struct {
	DebugLogging    bool
	AutoUpdate      bool
	UpdateRequested bool
	OS, Arch        string
}

// CleanDBEngines keeps the known engine names, canonical and without duplicates
func CleanDBEngines(in []string) []string {
	out := []string{}
	for _, e := range in {
		if name, ok := dbbackup.NormalizeEngine(e); ok && !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	return out
}

// CanRunDBEngine reports whether this agent can back up the engine. Filesystem agents
// go by the engines they report; one that only sent the older db_tools flag predates
// the mssql engine and is assumed to have the client tools of the other three.
// Kubernetes agents dump from a pod and the retired database agent predates mssql, so
// both handle everything except SQL Server.
func (a *Agent) CanRunDBEngine(engine string) bool {
	agentType, _ := NormalizeAgentType(a.AgentType)
	if agentType != AgentTypeFilesystem {
		return engine != dbbackup.EngineMSSQL
	}
	if len(a.DBEngines) > 0 {
		return slices.Contains(a.DBEngines, engine)
	}
	return a.DBTools && engine != dbbackup.EngineMSSQL
}

// CanRunJob reports whether this agent may run a job of jobType, including the
// capability flags a filesystem agent reports (Proxmox VE node, Docker daemon,
// database client tools)
func (a *Agent) CanRunJob(jobType string) bool {
	jobType, _ = NormalizeJobType(jobType)
	agentType, _ := NormalizeAgentType(a.AgentType)
	if !JobAllowedOnAgent(jobType, agentType) {
		return false
	}
	if agentType != AgentTypeFilesystem {
		return true
	}
	switch jobType {
	case JobTypePVE:
		return a.PVEHost
	case JobTypeDocker:
		return a.DockerHost
	case JobTypeDatabase:
		return a.DBTools
	}
	return true
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
	DebugLogging bool `json:"debug_logging" db:"debug_logging"`
	// AutoUpdate lets the agent update itself to the server's version (per-agent opt-in)
	AutoUpdate bool `json:"auto_update" db:"auto_update"`
	// SelfUpdate is reported by the agent when it can replace its own binary (Linux
	// package or manual install; not containers, not Windows)
	SelfUpdate bool `json:"self_update" db:"self_update"`
	// UpdateRequestedAt is set by "Update now" in the web UI; cleared when the agent
	// reports the server's version or an update error
	UpdateRequestedAt *time.Time `json:"update_requested_at,omitempty" db:"update_requested_at"`
	// UpdateError is the agent's last self-update failure (empty: none)
	UpdateError string `json:"update_error,omitempty" db:"update_error"`
	// PVEHost is reported by the agent when it runs on a Proxmox VE node
	PVEHost bool `json:"pve_host" db:"pve_host"`
	// DockerHost is reported by the agent when a Docker daemon answers on its host
	DockerHost bool `json:"docker_host" db:"docker_host"`
	// DBTools is reported by a filesystem agent that found database client tools
	// (pg_dump, mysqldump/mariadb-dump, mongodump) and can therefore run database jobs
	DBTools bool `json:"db_tools" db:"db_tools"`
	// DBEngines are the database engines the agent reported (see CanRunDBEngine)
	DBEngines []string `json:"db_engines" db:"db_engines"`
	// Inventory is the compact summary the agent attaches to a heartbeat every few
	// minutes (inventory.Summary); InventoryDetail the on-demand full inventory
	Inventory         json.RawMessage `json:"inventory,omitempty" db:"inventory"`
	InventoryAt       *time.Time      `json:"inventory_at,omitempty" db:"inventory_at"`
	InventoryDetail   json.RawMessage `json:"inventory_detail,omitempty" db:"inventory_detail"`
	InventoryDetailAt *time.Time      `json:"inventory_detail_at,omitempty" db:"inventory_detail_at"`
	Status            AgentStatus     `json:"status" db:"status"`
	// Labels place the agent in access scopes; copied from the enrollment token
	Labels     Labels     `json:"labels"`
	LastSeenAt *time.Time `json:"last_seen_at" db:"last_seen_at"`
	CreatedAt  time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at" db:"updated_at"`
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
	// AgentID is the agent that last enrolled with this token (onboarding waits for it)
	AgentID *uuid.UUID `json:"agent_id,omitempty" db:"agent_id"`
	// AgentHostname is joined for display; empty when no agent used the token
	AgentHostname string `json:"agent_hostname,omitempty" db:"-"`
	// Labels are copied onto every agent that enrolls with the token
	Labels Labels `json:"labels"`
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
	ID         uuid.UUID `json:"id" db:"id"`
	Name       string    `json:"name" db:"name"`
	TargetType string    `json:"target_type" db:"target_type"` // "pbs"
	Endpoint   string    `json:"endpoint" db:"endpoint"`
	Datastore  string    `json:"datastore" db:"datastore"`
	Namespace  string    `json:"namespace" db:"namespace"`
	// AuthToken is the PBS API token in clear in memory; the repository seals it with
	// the server master key on write and opens it on read (column auth_token_encrypted)
	AuthToken   string    `json:"-" db:"auth_token_encrypted"`
	Fingerprint string    `json:"fingerprint" db:"fingerprint"`
	TLSVerify   bool      `json:"tls_verify" db:"tls_verify"`
	PxarFormat  string    `json:"pxar_format" db:"pxar_format"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`

	// Client-side encryption: EncryptionNone or EncryptionEncrypt. The key comes from
	// the target's key ring (KeyRingID); targets on one ring share the active key and
	// so deduplicate against each other on PBS. EncryptionKeyID, KeyFingerprint,
	// KeyCreatedAt and MasterPublicKey are the ring's active key and RSA public key,
	// joined on read.
	EncryptionMode  string     `json:"encryption_mode" db:"encryption_mode"`
	KeyRingID       *uuid.UUID `json:"key_ring_id,omitempty" db:"key_ring_id"`
	KeyRingName     string     `json:"key_ring_name,omitempty" db:"-"`
	EncryptionKeyID *uuid.UUID `json:"encryption_key_id,omitempty" db:"-"`
	MasterPublicKey string     `json:"master_public_key,omitempty" db:"-"`
	KeyFingerprint  string     `json:"key_fingerprint,omitempty" db:"-"`
	KeyCreatedAt    *time.Time `json:"key_created_at,omitempty" db:"-"`

	// HasToken reports whether an API token is stored (the token itself is never returned)
	HasToken bool   `json:"has_token" db:"-"`
	Labels   Labels `json:"labels"`
}

// Encryption modes of a target
const (
	EncryptionNone    = "none"
	EncryptionEncrypt = "encrypt"
)

// Encrypted reports whether runs to this target encrypt client-side
func (t *BackupTarget) Encrypted() bool {
	return t != nil && t.EncryptionMode == EncryptionEncrypt && t.EncryptionKeyID != nil
}

// KeyRing is a set of encryption keys shared by the targets attached to it. Targets on
// one ring encrypt with the same active key and therefore deduplicate against each
// other on PBS (one datastore, many namespaces); targets on different rings never do.
// Rotation retires the active key for every target on the ring at once. The optional
// RSA master public key wraps the active key into every snapshot for recovery.
type KeyRing struct {
	ID              uuid.UUID  `json:"id"`
	Name            string     `json:"name"`
	ActiveKeyID     *uuid.UUID `json:"active_key_id,omitempty"`
	MasterPublicKey string     `json:"master_public_key,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	CreatedBy       string     `json:"created_by,omitempty"`
	// KeyFingerprint / KeyCreatedAt describe the active key, Targets names the targets
	// attached to the ring (joined on read)
	KeyFingerprint string     `json:"key_fingerprint,omitempty"`
	KeyCreatedAt   *time.Time `json:"key_created_at,omitempty"`
	Targets        []string   `json:"targets"`
	Labels         Labels     `json:"labels"`
}

// TargetKey is one encryption key of a key ring. Key is in clear in memory only; the
// repository seals it with the server master key (column key_sealed). A retired key
// is kept because the snapshots written with it still need it.
type TargetKey struct {
	ID          uuid.UUID  `json:"id"`
	RingID      uuid.UUID  `json:"ring_id"`
	Key         [32]byte   `json:"-"`
	Fingerprint string     `json:"fingerprint"`
	CreatedAt   time.Time  `json:"created_at"`
	RetiredAt   *time.Time `json:"retired_at,omitempty"`
	CreatedBy   string     `json:"created_by,omitempty"`
}

// Sanitize fills derived, API-safe fields
func (t *BackupTarget) Sanitize() *BackupTarget {
	t.HasToken = t.AuthToken != ""
	if t.EncryptionMode == "" {
		t.EncryptionMode = EncryptionNone
	}
	return t
}

// BackupJob defines what, when, and where an agent backs up
// EffectiveBackupID is the PBS backup group a filesystem, Docker, Proxmox VE or
// kubernetes job writes to: the stored backup_id, else the agent ID (with -docker /
// -pve for those types). Server-derived on purpose: an agent must not be able to
// pick another host's group by reporting its hostname.
func (j *BackupJob) EffectiveBackupID() string {
	if j.BackupID != "" {
		return j.BackupID
	}
	switch j.JobType {
	case JobTypeDocker:
		return j.AgentID.String() + "-docker"
	case JobTypePVE:
		return j.AgentID.String() + "-pve"
	}
	return j.AgentID.String()
}

type BackupJob struct {
	ID           uuid.UUID `json:"id" db:"id"`
	Name         string    `json:"name" db:"name"`
	AgentID      uuid.UUID `json:"agent_id" db:"agent_id"`
	TargetID     uuid.UUID `json:"target_id" db:"target_id"`
	ScheduleCron string    `json:"schedule_cron" db:"schedule_cron"`
	BackupPaths  []string  `json:"backup_paths" db:"backup_paths"`
	ExcludePaths []string  `json:"exclude_paths" db:"exclude_paths"`
	Enabled      bool      `json:"enabled" db:"enabled"`
	// DirectPBS makes the agent talk to PBS itself (credentials handed out per run)
	// instead of through the server-side tunnel. Server-side setting only.
	DirectPBS bool `json:"direct_pbs" db:"direct_pbs"`
	// BackupID is the PBS backup group of filesystem, Docker, Proxmox VE and
	// kubernetes jobs (database and Microsoft 365 jobs carry theirs in their config).
	// Empty means the agent ID, see EffectiveBackupID.
	BackupID string `json:"backup_id" db:"backup_id"`
	// JobType is filesystem (BackupPaths) or database (DBConfig)
	JobType string `json:"job_type" db:"job_type"`
	// DBConfig is the database job specification; the password is stored but never
	// returned by the API (see Sanitize)
	DBConfig *dbbackup.Spec `json:"db_config,omitempty" db:"db_config"`
	// K8sConfig is the kubernetes job specification
	K8sConfig *k8sbackup.Spec `json:"k8s_config,omitempty" db:"k8s_config"`
	// PVEConfig is the Proxmox VE host job specification
	PVEConfig *pvebackup.Spec `json:"pve_config,omitempty" db:"pve_config"`
	// DockerConfig is the Docker host job specification
	DockerConfig *dockerbackup.Spec `json:"docker_config,omitempty" db:"docker_config"`
	// M365Config is the Microsoft 365 job specification (its TenantID is also the
	// m365_tenant_id column, so a tenant cannot be deleted while jobs use it)
	M365Config *m365.Spec `json:"m365_config,omitempty" db:"m365_config"`
	CreatedAt  time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at" db:"updated_at"`
	// Labels place the job and all of its runs in access scopes. On update, an
	// absent field (nil) keeps the stored labels; {} clears them.
	Labels Labels `json:"labels"`

	// Joined fields for display
	AgentName  string `json:"agent_name,omitempty"`
	TargetName string `json:"target_name,omitempty"`
	// LastRun is the job's newest run (filled by the Jobs page; nil = never ran)
	LastRun *JobLastRun `json:"last_run,omitempty" db:"-"`
}

// JobLastRun is the newest run of a job, for list views
type JobLastRun struct {
	RunID  uuid.UUID `json:"run_id"`
	Status RunStatus `json:"status"`
	At     time.Time `json:"at"`
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
	LogTail string `json:"log_tail,omitempty" db:"log_tail"`
	// KeyFingerprint names the encryption key the snapshot was written with ("" = plaintext)
	KeyFingerprint string `json:"key_fingerprint,omitempty" db:"key_fingerprint"`
	// Details is a type-specific JSON blob (archives / databases / PVCs) for the run
	// detail page; carries a top-level "type" discriminator. Empty for older runs.
	Details json.RawMessage `json:"details,omitempty" db:"details"`
	// Progress is the live state of a running backup (phase + per-item statuses),
	// updated mid-run and polled by the detail page.
	Progress  json.RawMessage `json:"progress,omitempty" db:"progress"`
	CreatedAt time.Time       `json:"created_at" db:"created_at"`

	// Joined fields
	JobName   string `json:"job_name,omitempty"`
	AgentName string `json:"agent_name,omitempty"`
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

// IsPVE reports whether the job is a Proxmox VE host backup
func (j *BackupJob) IsPVE() bool { return j.JobType == JobTypePVE }

// IsDocker reports whether the job is a Docker host backup
func (j *BackupJob) IsDocker() bool { return j.JobType == JobTypeDocker }

// IsM365 reports whether the job is a Microsoft 365 backup
func (j *BackupJob) IsM365() bool { return j.JobType == JobTypeM365 }

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
	if j.IsPVE() {
		return j.PVEConfig.Summary()
	}
	if j.IsDocker() {
		return j.DockerConfig.Summary()
	}
	if j.IsM365() {
		return j.M365Config.Summary()
	}
	return strings.Join(j.BackupPaths, ", ")
}
