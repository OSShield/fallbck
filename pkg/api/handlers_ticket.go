package api

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/osshield/fallbck/pkg/auth"
)

// refreshedTicketTTL matches the session ticket lifetime issued by PrepareBackupSession
const refreshedTicketTTL = 2 * time.Hour

// maxTicketLifetime bounds how long a run's tickets can be refreshed after the first
// one was minted
const maxTicketLifetime = 24 * time.Hour

// TicketRefreshResponse carries a re-issued backup ticket and its snapshot timestamp
type TicketRefreshResponse struct {
	Ticket     string `json:"ticket"`
	BackupTime int64  `json:"backup_time"`
}

// freshBackupTime returns the snapshot timestamp for a new attempt: now, but never
// earlier than the previous one (clock skew between server processes must not make a
// retry look older than the first attempt to PBS)
func freshBackupTime(previous int64) int64 {
	now := time.Now().Unix()
	if now <= previous {
		return previous + 1
	}
	return now
}

// HandleRefreshTicket re-issues a run's backup ticket with a new snapshot timestamp.
// Retried backup activities call it: PBS refuses a backup whose timestamp is not newer
// than the group's latest snapshot, so an attempt that finalised its snapshot but failed
// afterwards would otherwise make every retry fail with "backup timestamp is older than
// last backup". The agent authenticates with its bearer token and presents the current
// (still valid) ticket; every other claim is carried over unchanged.
func (s *ServerAPI) HandleRefreshTicket(w http.ResponseWriter, r *http.Request) {
	agent := auth.AgentFrom(r.Context())
	if agent == nil {
		s.writeError(w, http.StatusUnauthorized, "agent token required")
		return
	}
	ticket := r.Header.Get(BackupTicketHeader)
	if ticket == "" {
		s.writeError(w, http.StatusBadRequest, "backup ticket header required")
		return
	}
	claims, err := s.TokenManager.ValidateBackupTicket(ticket)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "invalid or expired backup ticket")
		return
	}
	if claims.AgentID != agent.AgentID {
		slog.Warn("Ticket refresh with another agent's ticket", "agent_id", agent.AgentID, "ticket_agent_id", claims.AgentID)
		s.writeError(w, http.StatusForbidden, "backup ticket was not issued to this agent")
		return
	}
	if claims.Issued > 0 && time.Since(time.Unix(claims.Issued, 0)) > maxTicketLifetime {
		s.writeError(w, http.StatusForbidden, "backup ticket is too old to refresh; start a new run")
		return
	}
	// The job may have been moved to another agent or target since the run started
	if s.DB != nil {
		job, err := s.DB.GetJobByID(r.Context(), claims.JobID)
		if err != nil || job.AgentID != claims.AgentID || job.TargetID != claims.TargetID {
			slog.Warn("Ticket refresh for a job that no longer belongs to this agent and target", "agent_id", agent.AgentID, "job_id", claims.JobID)
			s.writeError(w, http.StatusForbidden, "job no longer belongs to this agent and target")
			return
		}
	}
	backupTime := freshBackupTime(claims.BackupTime)
	fresh, err := s.TokenManager.CreateBackupTicket(auth.BackupTicketClaims{
		JobID:      claims.JobID,
		AgentID:    claims.AgentID,
		TargetID:   claims.TargetID,
		Datastore:  claims.Datastore,
		Namespace:  claims.Namespace,
		BackupType: claims.BackupType,
		BackupID:   claims.BackupID,
		BackupTime: backupTime,
		Issued:     claims.Issued,
	}, refreshedTicketTTL)
	if err != nil {
		slog.Error("Failed to re-issue backup ticket", "error", err)
		s.writeError(w, http.StatusInternalServerError, "failed to re-issue backup ticket")
		return
	}
	slog.Info("Backup ticket re-issued with a new snapshot timestamp", "agent_id", claims.AgentID, "job_id", claims.JobID,
		"backup_id", claims.BackupID, "previous_time", claims.BackupTime, "backup_time", backupTime)
	s.writeJSON(w, http.StatusOK, TicketRefreshResponse{Ticket: fresh, BackupTime: backupTime})
}
