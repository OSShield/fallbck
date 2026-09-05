package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/osshield/fallbck/pkg/auth"
	"github.com/osshield/fallbck/pkg/db"
	"github.com/osshield/fallbck/pkg/k8sbackup"
)

// Ticket/token lifetimes for kubernetes runs
const (
	volumeTicketTTL = 2 * time.Hour
	workerTokenTTL  = 6 * time.Hour
)

// VolumeTicketRequest asks for a per-volume backup ticket during a kubernetes run
type VolumeTicketRequest struct {
	// VolumeBackupID must extend the run's group: <cluster group>-pvc-<ns>-<name>
	VolumeBackupID string `json:"volume_backup_id"`
}

// VolumeTicketResponse carries the freshly minted ticket
type VolumeTicketResponse struct {
	Ticket string `json:"ticket"`
}

// WorkerTokenResponse carries a short-lived agent bearer for worker pods
type WorkerTokenResponse struct {
	AuthToken      string    `json:"auth_token"`
	TokenExpiresAt time.Time `json:"token_expires_at"`
}

var volumeBackupIDRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]*$`)

// k8sTicketContext validates the agent + session ticket pair shared by the kubernetes
// helper endpoints and confirms the agent is a kubernetes agent.
func (s *ServerAPI) k8sTicketContext(w http.ResponseWriter, r *http.Request) (*auth.AgentClaims, *auth.BackupTicketClaims, bool) {
	agent := auth.AgentFrom(r.Context())
	if agent == nil {
		s.writeError(w, http.StatusUnauthorized, "agent token required")
		return nil, nil, false
	}
	ticket := r.Header.Get(BackupTicketHeader)
	if ticket == "" {
		s.writeError(w, http.StatusBadRequest, "backup ticket header required")
		return nil, nil, false
	}
	claims, err := s.TokenManager.ValidateBackupTicket(ticket)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "invalid or expired backup ticket")
		return nil, nil, false
	}
	if claims.AgentID != agent.AgentID {
		slog.Warn("Kubernetes helper request with another agent's ticket", "agent_id", agent.AgentID, "ticket_agent_id", claims.AgentID)
		s.writeError(w, http.StatusForbidden, "backup ticket was not issued to this agent")
		return nil, nil, false
	}
	row, err := s.DB.GetAgentByID(r.Context(), agent.AgentID)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "agent not found")
		return nil, nil, false
	}
	if agentType, _ := db.NormalizeAgentType(row.AgentType); agentType != db.AgentTypeKubernetes {
		s.writeError(w, http.StatusForbidden, "only kubernetes agents may use this endpoint")
		return nil, nil, false
	}
	return agent, claims, true
}

// HandleVolumeTicket mints a per-volume backup ticket for a kubernetes run: identical
// claims to the session ticket, with the backup group swapped to the volume's group
// (which must extend the session group with "-pvc-"). Fetched just-in-time per volume
// so retried volumes always hold a fresh ticket.
func (s *ServerAPI) HandleVolumeTicket(w http.ResponseWriter, r *http.Request) {
	_, claims, ok := s.k8sTicketContext(w, r)
	if !ok {
		return
	}
	var req VolumeTicketRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	prefix := k8sbackup.VolumeGroupPrefix(claims.BackupID)
	if !strings.HasPrefix(req.VolumeBackupID, prefix) || req.VolumeBackupID == prefix || !volumeBackupIDRe.MatchString(req.VolumeBackupID) {
		s.writeError(w, http.StatusForbidden, "volume_backup_id must extend the run's backup group with -pvc-<namespace>-<name>")
		return
	}
	ticket, err := s.TokenManager.CreateBackupTicket(auth.BackupTicketClaims{
		JobID:      claims.JobID,
		AgentID:    claims.AgentID,
		TargetID:   claims.TargetID,
		Datastore:  claims.Datastore,
		Namespace:  claims.Namespace,
		BackupType: claims.BackupType,
		BackupID:   req.VolumeBackupID,
		BackupTime: claims.BackupTime,
	}, volumeTicketTTL)
	if err != nil {
		slog.Error("Failed to mint volume ticket", "error", err)
		s.writeError(w, http.StatusInternalServerError, "failed to mint volume ticket")
		return
	}
	slog.Debug("Volume ticket issued", "agent_id", claims.AgentID, "job_id", claims.JobID, "group", req.VolumeBackupID)
	s.writeJSON(w, http.StatusOK, VolumeTicketResponse{Ticket: ticket})
}

// HandleWorkerToken mints a short-lived secondary agent bearer for a run's worker pods
// (same agent identity, 6h TTL); requires the run's session ticket.
func (s *ServerAPI) HandleWorkerToken(w http.ResponseWriter, r *http.Request) {
	agent, claims, ok := s.k8sTicketContext(w, r)
	if !ok {
		return
	}
	token, expires, err := s.TokenManager.CreateAgentToken(agent.AgentID, agent.TaskQueue, agent.Version, workerTokenTTL)
	if err != nil {
		slog.Error("Failed to mint worker token", "error", err)
		s.writeError(w, http.StatusInternalServerError, "failed to mint worker token")
		return
	}
	slog.Info("Worker token issued for kubernetes run", "agent_id", agent.AgentID, "job_id", claims.JobID, "expires_at", expires)
	s.writeJSON(w, http.StatusOK, WorkerTokenResponse{AuthToken: token, TokenExpiresAt: expires})
}
