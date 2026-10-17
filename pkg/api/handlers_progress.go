package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/auth"
	"github.com/osshield/fallbck/pkg/db"
	"github.com/osshield/fallbck/pkg/rundetail"
)

// RunProgressRequest is posted by an agent during a run to update its live progress
type RunProgressRequest struct {
	RunID uuid.UUID `json:"run_id"`
	// Phase is the current human-readable step (optional)
	Phase string `json:"phase,omitempty"`
	// Items are per-unit statuses keyed by a stable id (PVC group, database) (optional)
	Items map[string]rundetail.ProgressItem `json:"items,omitempty"`
}

// HandleRunProgress records live progress for a run. The caller presents its agent
// bearer token and the run's backup ticket; the run must belong to the ticket's job
// and agent and still be active. Progress is best-effort — failures never fail a run.
func (s *ServerAPI) HandleRunProgress(w http.ResponseWriter, r *http.Request) {
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
		s.writeError(w, http.StatusForbidden, "backup ticket was not issued to this agent")
		return
	}
	var req RunProgressRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	run, err := s.DB.GetRunByID(r.Context(), req.RunID, db.Unscoped)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "run not found")
		return
	}
	if run.JobID != claims.JobID || run.AgentID != claims.AgentID {
		s.writeError(w, http.StatusForbidden, "run does not belong to this ticket")
		return
	}

	now := time.Now().UTC().Format(time.RFC3339)
	if req.Phase != "" {
		if err := s.DB.SetRunPhase(r.Context(), req.RunID, req.Phase, now); err != nil {
			s.writeError(w, http.StatusInternalServerError, "failed to record phase")
			return
		}
	}
	if len(req.Items) > 0 {
		encoded := make(map[string][]byte, len(req.Items))
		for k, v := range req.Items {
			b, err := json.Marshal(v)
			if err != nil {
				continue
			}
			encoded[k] = b
		}
		if err := s.DB.SetRunItems(r.Context(), req.RunID, now, encoded); err != nil {
			s.writeError(w, http.StatusInternalServerError, "failed to record items")
			return
		}
	}
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
