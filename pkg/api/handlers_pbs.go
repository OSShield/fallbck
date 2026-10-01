package api

import (
	"log/slog"
	"net/http"

	"github.com/osshield/fallbck/pkg/auth"
	"github.com/osshield/fallbck/pkg/pbs"
)

// HandlePBSCredentials hands an agent the PBS connection details for a run whose job is
// configured with direct_pbs. The agent authenticates with its bearer token and presents
// the run's backup ticket; the ticket must belong to the agent and the job must be in
// direct mode. Jobs using the server tunnel never expose the token.
func (s *ServerAPI) HandlePBSCredentials(w http.ResponseWriter, r *http.Request) {
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
		slog.Warn("PBS credential request with another agent's ticket", "agent_id", agent.AgentID, "ticket_agent_id", claims.AgentID)
		s.writeError(w, http.StatusForbidden, "backup ticket was not issued to this agent")
		return
	}
	job, err := s.DB.GetJobByID(r.Context(), claims.JobID)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "job not found")
		return
	}
	if !job.DirectPBS {
		s.writeError(w, http.StatusForbidden, "job is not configured for direct PBS access")
		return
	}
	target, err := s.DB.GetTargetByID(r.Context(), claims.TargetID)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "backup target not found")
		return
	}
	token, err := pbs.NormalizeAPIToken(target.AuthToken)
	if err != nil {
		s.writeError(w, http.StatusFailedDependency, "backup target has no usable PBS API token")
		return
	}
	slog.Info("Handing PBS credentials to agent for direct backup", "agent_id", agent.AgentID, "job_id", job.ID, "target", target.Name, "token_id", pbs.TokenID(token))
	s.writeJSON(w, http.StatusOK, PBSCredentials{
		Endpoint:    target.Endpoint,
		Datastore:   target.Datastore,
		Namespace:   target.Namespace,
		Fingerprint: target.Fingerprint,
		TLSVerify:   target.TLSVerify,
		APIToken:    token,
	})
}
