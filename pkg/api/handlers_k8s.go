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
	"github.com/osshield/fallbck/pkg/m365"
)

// Ticket/token lifetimes for kubernetes runs
const (
	volumeTicketTTL = 2 * time.Hour
	workerTokenTTL  = 6 * time.Hour
)

// SubTicketRequest asks for a per-unit backup ticket during a run that writes several
// snapshots: one per PVC of a kubernetes run, one per user / site / team of a
// Microsoft 365 run. The group must extend the run's own group.
type SubTicketRequest struct {
	BackupID string `json:"backup_id"`
	// VolumeBackupID is the field name kubernetes agents send
	VolumeBackupID string `json:"volume_backup_id"`
}

// VolumeTicketRequest is what kubernetes agents post (older name of SubTicketRequest)
type VolumeTicketRequest struct {
	// VolumeBackupID must extend the run's group: <cluster group>-pvc-<ns>-<name>
	VolumeBackupID string `json:"volume_backup_id"`
}

// VolumeTicketResponse carries the freshly minted ticket and the snapshot timestamp
// embedded in it (the worker must use the same one)
type VolumeTicketResponse struct {
	Ticket     string `json:"ticket"`
	BackupTime int64  `json:"backup_time"`
}

// SubTicketResponse is the sub-ticket answer (same shape for every job type)
type SubTicketResponse = VolumeTicketResponse

// WorkerTokenResponse carries a short-lived agent bearer for worker pods
type WorkerTokenResponse struct {
	AuthToken      string    `json:"auth_token"`
	TokenExpiresAt time.Time `json:"token_expires_at"`
}

var volumeBackupIDRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]*$`)

// ticketContext validates the agent + session ticket pair of the run helper endpoints
// and loads the agent row
func (s *ServerAPI) ticketContext(w http.ResponseWriter, r *http.Request) (*auth.AgentClaims, *auth.BackupTicketClaims, *db.Agent, bool) {
	agent := auth.AgentFrom(r.Context())
	if agent == nil {
		s.writeError(w, http.StatusUnauthorized, "agent token required")
		return nil, nil, nil, false
	}
	ticket := r.Header.Get(BackupTicketHeader)
	if ticket == "" {
		s.writeError(w, http.StatusBadRequest, "backup ticket header required")
		return nil, nil, nil, false
	}
	claims, err := s.TokenManager.ValidateBackupTicket(ticket)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "invalid or expired backup ticket")
		return nil, nil, nil, false
	}
	if claims.AgentID != agent.AgentID {
		slog.Warn("Run helper request with another agent's ticket", "agent_id", agent.AgentID, "ticket_agent_id", claims.AgentID)
		s.writeError(w, http.StatusForbidden, "backup ticket was not issued to this agent")
		return nil, nil, nil, false
	}
	row, err := s.DB.GetAgentByID(r.Context(), agent.AgentID)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "agent not found")
		return nil, nil, nil, false
	}
	return agent, claims, row, true
}

// k8sTicketContext is ticketContext plus the check that the agent is a kubernetes agent
func (s *ServerAPI) k8sTicketContext(w http.ResponseWriter, r *http.Request) (*auth.AgentClaims, *auth.BackupTicketClaims, bool) {
	agent, claims, row, ok := s.ticketContext(w, r)
	if !ok {
		return nil, nil, false
	}
	if agentType, _ := db.NormalizeAgentType(row.AgentType); agentType != db.AgentTypeKubernetes {
		s.writeError(w, http.StatusForbidden, "only kubernetes agents may use this endpoint")
		return nil, nil, false
	}
	return agent, claims, true
}

// subGroupAllowed is the rule for every sub-ticket: the requested group extends the
// run's own group (prefix) and is a valid PBS backup id, so an agent can never name
// a group outside its job
func subGroupAllowed(prefix, group string) bool {
	return strings.HasPrefix(group, prefix) && group != prefix && volumeBackupIDRe.MatchString(group)
}

// HandleSubTicket mints a per-unit backup ticket: identical claims to the session
// ticket, with the backup group swapped to the unit's group. Kubernetes runs name one
// per volume (<cluster group>-pvc-<ns>-<name>), Microsoft 365 runs one per user, site
// or team (<job group>-<kind>-<name>). Fetched just-in-time per unit so retried units
// always hold a fresh ticket, with a fresh snapshot timestamp: PBS refuses a backup
// whose time is not newer than the group's latest snapshot, so a retry after an
// attempt that finalised its snapshot must not reuse the run's time.
func (s *ServerAPI) HandleSubTicket(w http.ResponseWriter, r *http.Request) {
	_, claims, row, ok := s.ticketContext(w, r)
	if !ok {
		return
	}
	var req SubTicketRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	group := req.BackupID
	if group == "" {
		group = req.VolumeBackupID
	}
	var prefix, hint string
	if agentType, _ := db.NormalizeAgentType(row.AgentType); agentType == db.AgentTypeKubernetes {
		prefix, hint = k8sbackup.VolumeGroupPrefix(claims.BackupID), "-pvc-<namespace>-<name>"
	} else {
		job, err := s.DB.GetJobByID(r.Context(), claims.JobID)
		if err != nil {
			s.writeError(w, http.StatusNotFound, "job not found")
			return
		}
		if !job.IsM365() {
			s.writeError(w, http.StatusForbidden, "only kubernetes and Microsoft 365 runs write per-unit snapshots")
			return
		}
		prefix, hint = m365.GroupPrefix(claims.BackupID), "-<kind>-<name>"
	}
	if !subGroupAllowed(prefix, group) {
		s.writeError(w, http.StatusForbidden, "backup_id must extend the run's backup group with "+hint)
		return
	}
	backupTime := freshBackupTime(claims.BackupTime)
	ticket, err := s.TokenManager.CreateBackupTicket(auth.BackupTicketClaims{
		JobID:      claims.JobID,
		AgentID:    claims.AgentID,
		TargetID:   claims.TargetID,
		Datastore:  claims.Datastore,
		Namespace:  claims.Namespace,
		BackupType: claims.BackupType,
		BackupID:   group,
		BackupTime: backupTime,
	}, volumeTicketTTL)
	if err != nil {
		slog.Error("Failed to mint sub-ticket", "error", err)
		s.writeError(w, http.StatusInternalServerError, "failed to mint sub-ticket")
		return
	}
	slog.Debug("Sub-ticket issued", "agent_id", claims.AgentID, "job_id", claims.JobID, "group", group)
	s.writeJSON(w, http.StatusOK, SubTicketResponse{Ticket: ticket, BackupTime: backupTime})
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
