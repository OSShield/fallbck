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
}

// EnrollResponse contains the credentials and configuration needed for the agent to start
type EnrollResponse struct {
	AgentID           uuid.UUID `json:"agent_id"`
	TaskQueue         string    `json:"task_queue"`
	CACertPEM         string    `json:"ca_cert_pem"`
	ClientCertPEM     string    `json:"client_cert_pem"`
	ClientKeyPEM      string    `json:"client_key_pem"`
	TemporalHost      string    `json:"temporal_host"`
	TemporalNamespace string    `json:"temporal_namespace"`
	TemporalTLS       bool      `json:"temporal_tls"`
	ProxyURL          string    `json:"proxy_url"`
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
}

// BackupTicketResponse contains a signed short-lived ticket for proxy chunk uploads
type BackupTicketResponse struct {
	Ticket    string `json:"ticket"`
	ProxyURL  string `json:"proxy_url"`
	ExpiresAt int64  `json:"expires_at"`
}
