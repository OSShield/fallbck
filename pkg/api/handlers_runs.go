package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/db"
	"go.temporal.io/api/serviceerror"
)

// HandleGetRun returns a single backup run
func (s *ServerAPI) HandleGetRun(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid run ID")
		return
	}
	run, err := s.DB.GetRunByID(r.Context(), id)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "Run not found")
		return
	}
	s.writeJSON(w, http.StatusOK, run)
}

// HandleCancelRun cancels an in-flight backup run. The Temporal workflow is cancelled,
// which tells the agent activity to stop; the workflow then finalises the run as
// "cancelled". Until that happens the run shows as "cancelling". A run that never
// started (still pending, or no workflow) is marked cancelled immediately.
func (s *ServerAPI) HandleCancelRun(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid run ID")
		return
	}
	run, err := s.DB.GetRunByID(r.Context(), id)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "Run not found")
		return
	}
	if !run.Status.IsActive() {
		s.writeError(w, http.StatusConflict, "Run is not active (status: "+string(run.Status)+")")
		return
	}

	workflowGone := run.WorkflowID == "" || s.Temporal == nil
	if !workflowGone {
		if err := s.Temporal.CancelWorkflow(r.Context(), run.WorkflowID, run.RunID); err != nil {
			var notFound *serviceerror.NotFound
			if errors.As(err, &notFound) {
				workflowGone = true
			} else {
				slog.Error("Failed to cancel Temporal workflow", "error", err, "workflow_id", run.WorkflowID)
				s.writeError(w, http.StatusBadGateway, "Failed to cancel workflow: "+err.Error())
				return
			}
		}
	}

	status := db.RunStatusCancelling
	var endTime *time.Time
	if workflowGone || run.Status == db.RunStatusPending {
		// Nothing is (or will be) running for this row: finalise it right away
		status = db.RunStatusCancelled
		now := time.Now().UTC()
		endTime = &now
	}
	if err := s.DB.SetRunStatus(r.Context(), run.ID, status, "cancelled by operator", endTime); err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to update run status")
		return
	}
	slog.Info("Backup run cancellation requested", "run_id", run.ID, "workflow_id", run.WorkflowID, "status", status)
	s.writeJSON(w, http.StatusOK, map[string]string{"status": string(status), "run_id": run.ID.String()})
}

// HandleUpdateJob replaces a job's configuration (name, agent, target, paths, schedule,
// retention, enabled, direct_pbs). The job ID in the path wins over any in the body.
func (s *ServerAPI) HandleUpdateJob(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid job ID")
		return
	}
	existing, err := s.DB.GetJobByID(r.Context(), id)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "Job not found")
		return
	}

	var job db.BackupJob
	if err := json.NewDecoder(r.Body).Decode(&job); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if msg, err := s.validateJob(r.Context(), &job, existing); err != nil {
		s.writeError(w, http.StatusBadRequest, msg)
		return
	}

	job.ID = existing.ID
	job.CreatedAt = existing.CreatedAt
	if err := s.DB.UpdateJob(r.Context(), &job); err != nil {
		if errors.Is(err, db.ErrNotFound) {
			s.writeError(w, http.StatusNotFound, "Job not found")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "Failed to update job")
		return
	}
	updated, err := s.DB.GetJobByID(r.Context(), job.ID)
	if err != nil {
		s.writeJSON(w, http.StatusOK, job.Sanitize())
		return
	}
	s.writeJSON(w, http.StatusOK, updated.Sanitize())
}
