package api

import (
	"time"

	"github.com/google/uuid"
)

// EnrollRequest is sent by an agent to enroll with the central server
type EnrollRequest struct {
	Token     string `json:"token"`
	Hostname  string `json:"hostname"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	Version   string `json:"version"`
	IPAddress string `json:"ip_address,omitempty"`
	// AgentType is "filesystem" (default) or "database"
	AgentType string `json:"agent_type,omitempty"`
	// PVEHost is set by a filesystem agent running on a Proxmox VE node
	PVEHost bool `json:"pve_host,omitempty"`
	// DockerHost is set by a filesystem agent that can reach a Docker daemon
	DockerHost bool `json:"docker_host,omitempty"`
	// DBTools is set by a filesystem agent that found database client tools
	DBTools bool `json:"db_tools,omitempty"`
}

// EnrollResponse contains the credentials and configuration needed for the agent to start.
// Everything the agent talks to (HTTP API, PBS proxy, Temporal gRPC) lives behind ServerURL.
type EnrollResponse struct {
	AgentID        uuid.UUID `json:"agent_id"`
	TaskQueue      string    `json:"task_queue"`
	Namespace      string    `json:"namespace"`
	AuthToken      string    `json:"auth_token"`
	TokenExpiresAt time.Time `json:"token_expires_at"`
	ServerURL      string    `json:"server_url"`
	// ServerCAPEM optionally carries a private CA bundle the agent must trust for ServerURL
	ServerCAPEM string `json:"server_ca_pem,omitempty"`
	ProxyURL    string `json:"proxy_url"`
}

// RotateTokenResponse carries a freshly issued agent token
type RotateTokenResponse struct {
	AuthToken      string    `json:"auth_token"`
	TokenExpiresAt time.Time `json:"token_expires_at"`
}

// CreateTokenRequest is used by the admin UI/CLI to create an agent enrollment token
type CreateTokenRequest struct {
	Name      string    `json:"name"`
	MaxUses   int       `json:"max_uses"` // 0 for unlimited, default 1
	ExpiresAt time.Time `json:"expires_at"`
}

// CreateTokenResponse returns the raw one-time enrollment token to the admin
type CreateTokenResponse struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	RawToken  string    `json:"raw_token"`
	ExpiresAt time.Time `json:"expires_at"`
	MaxUses   int       `json:"max_uses"`
}

// HeartbeatRequest is sent by an agent periodically
type HeartbeatRequest struct {
	AgentID uuid.UUID `json:"agent_id"`
	Status  string    `json:"status"`
	Version string    `json:"version"`
	// PVEHost reports whether the agent runs on a Proxmox VE node
	PVEHost bool `json:"pve_host,omitempty"`
	// DockerHost reports whether a Docker daemon answers on the agent's host
	DockerHost bool `json:"docker_host,omitempty"`
	// DBTools reports whether database client tools are installed on the agent's host
	DBTools bool `json:"db_tools,omitempty"`
}

// MergeAgentRequest moves the jobs and runs of one agent onto another and deletes
// the first (POST /agents/{id}/merge): used to retire a fallbck-db-agent in favour of
// the combined fallbck-agent on the same host
type MergeAgentRequest struct {
	Into uuid.UUID `json:"into"`
}

// MergeAgentResponse reports what was moved
type MergeAgentResponse struct {
	Status    string    `json:"status"`
	From      uuid.UUID `json:"from"`
	Into      uuid.UUID `json:"into"`
	JobsMoved int64     `json:"jobs_moved"`
	RunsMoved int64     `json:"runs_moved"`
}

// HeartbeatResponse acknowledges a heartbeat and carries server-side agent settings
type HeartbeatResponse struct {
	Status string `json:"status"`
	// DebugLogging tells the agent to raise its log level to debug (web UI toggle)
	DebugLogging bool `json:"debug_logging"`
}

// SetAgentDebugRequest toggles an agent's remote debug logging
type SetAgentDebugRequest struct {
	Enabled bool `json:"enabled"`
}

// CreateAPIKeyRequest creates an admin API key for fallbck-ctl / automation
type CreateAPIKeyRequest struct {
	Name      string     `json:"name"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// CreateAPIKeyResponse returns the raw key exactly once
type CreateAPIKeyResponse struct {
	ID        uuid.UUID  `json:"id"`
	Name      string     `json:"name"`
	RawKey    string     `json:"raw_key"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// MeResponse describes the authenticated admin principal
type MeResponse struct {
	Kind    string `json:"kind"`
	Subject string `json:"subject"`
	Email   string `json:"email,omitempty"`
	Name    string `json:"name,omitempty"`
}

// CreateTargetRequest registers a backup target. AuthToken is the PBS API token
// ("user@realm!tokenid=secret" or with the PBSAPIToken= prefix); it is stored and
// used only server-side.
type CreateTargetRequest struct {
	Name        string `json:"name"`
	TargetType  string `json:"target_type"`
	Endpoint    string `json:"endpoint"`
	Datastore   string `json:"datastore"`
	Namespace   string `json:"namespace"`
	AuthToken   string `json:"auth_token"`
	Fingerprint string `json:"fingerprint"`
	TLSVerify   bool   `json:"tls_verify"`
	PxarFormat  string `json:"pxar_format"`
}

// CloneTargetRequest creates a target from an existing one with another namespace
// (POST /targets/{id}/clone); the API token is copied server-side
type CloneTargetRequest struct {
	Name       string `json:"name"`
	Namespace  string `json:"namespace"`
	PxarFormat string `json:"pxar_format,omitempty"`
}

// PBSCredentials are handed to an agent for a job configured with direct_pbs
type PBSCredentials struct {
	Endpoint    string `json:"endpoint"`
	Datastore   string `json:"datastore"`
	Namespace   string `json:"namespace"`
	Fingerprint string `json:"fingerprint"`
	TLSVerify   bool   `json:"tls_verify"`
	// APIToken is the canonical user@realm!tokenid:secret
	APIToken string `json:"api_token"`
}

// BackupTicketHeader carries the backup ticket on agent HTTP requests
const BackupTicketHeader = "X-Fallbck-Backup-Ticket"
