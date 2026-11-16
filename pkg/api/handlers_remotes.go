package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/auth"
	"github.com/osshield/fallbck/pkg/db"
	"github.com/osshield/fallbck/pkg/remote"
)

// Remotes: S3, Azure Blob, SFTP, SMB and WebDAV storage that remote jobs back up.
// The credential is sealed at rest, never returned by the API, and handed to the
// agent per run with its backup ticket. A remote can keep it on the agents instead
// (auth_method agent): then every job names an agent credential profile and the
// server never sees it. There's no server-side test: the server would need a route
// to the storage and rclone of its own. The agent tests a profile with
// `fallbck-agent remote profile test`, and every run checks access first.

// RemoteRequest creates or updates a remote (POST /remotes, PUT /remotes/{id}). On
// update, a request without a credential keeps the stored one; ClearSecrets removes
// it.
type RemoteRequest struct {
	remote.Remote
	Secrets      remote.Secrets `json:"secrets"`
	ClearSecrets bool           `json:"clear_secrets"`
}

// HandleListRemotes returns the remotes within scope (credentials redacted)
func (s *ServerAPI) HandleListRemotes(w http.ResponseWriter, r *http.Request) {
	remotes, err := s.DB.ListRemotes(r.Context(), scope(r, auth.PermRemotesRead))
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to list remotes")
		return
	}
	s.writeJSON(w, http.StatusOK, remotes)
}

// HandleGetRemote returns one remote (credential redacted)
func (s *ServerAPI) HandleGetRemote(w http.ResponseWriter, r *http.Request) {
	rem, ok := s.remoteFromPath(w, r, auth.PermRemotesRead)
	if !ok {
		return
	}
	s.writeJSON(w, http.StatusOK, rem)
}

// remoteFromPath loads the remote named in the path within remotes:read and checks
// perm on its labels
func (s *ServerAPI) remoteFromPath(w http.ResponseWriter, r *http.Request, perm string) (*remote.Remote, bool) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid remote ID")
		return nil, false
	}
	rem, err := s.DB.GetRemoteByID(r.Context(), id, scope(r, auth.PermRemotesRead))
	if err != nil {
		s.writeError(w, http.StatusNotFound, "Remote not found")
		return nil, false
	}
	if !s.allow(w, r, perm, rem.Labels) {
		return nil, false
	}
	return rem, true
}

// HandleCreateRemote registers a remote
func (s *ServerAPI) HandleCreateRemote(w http.ResponseWriter, r *http.Request) {
	var req RemoteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	rem := req.Remote
	rem.ID, rem.Secrets = uuid.Nil, req.Secrets
	rem.Labels = db.Labels(rem.Labels).OrEmpty()
	if !s.validLabels(w, rem.Labels) || !s.allow(w, r, auth.PermRemotesWrite, rem.Labels) {
		return
	}
	if err := rem.Validate(); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.DB.CreateRemote(r.Context(), &rem); err != nil {
		slog.Error("Failed to create remote", "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to create remote (is the name unique?)")
		return
	}
	slog.Info("Remote created", "remote", rem.Name, "backend", rem.Backend, "identity", rem.Identity(), "auth_method", rem.AuthMethod)
	s.audit(r, "remote.create", "remote", rem.ID.String(), rem.Name, rem.Labels,
		map[string]any{"backend": rem.Backend, "identity": rem.Identity(), "auth_method": rem.AuthMethod})
	s.writeJSON(w, http.StatusCreated, &rem)
}

// HandleUpdateRemote replaces a remote's settings; a request without a credential
// keeps the stored one. The backend can't change while jobs use the remote, and the
// credential can't move to the agents while a job relies on the stored one.
func (s *ServerAPI) HandleUpdateRemote(w http.ResponseWriter, r *http.Request) {
	existing, ok := s.remoteFromPath(w, r, auth.PermRemotesWrite)
	if !ok {
		return
	}
	var req RemoteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	labels, ok := s.newLabels(w, r, auth.PermRemotesWrite, existing.Labels, req.Labels)
	if !ok {
		return
	}
	rem := req.Remote
	rem.Labels, rem.ID, rem.CreatedAt, rem.Jobs = labels, existing.ID, existing.CreatedAt, existing.Jobs
	secretChanged := !req.Secrets.IsZero() || req.ClearSecrets
	rem.Secrets = req.Secrets
	if !secretChanged {
		rem.Secrets = existing.Secrets
	}
	if err := rem.Validate(); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Validate drops the credential of an agent-held remote
	secretChanged = secretChanged || rem.HasSecret != existing.HasSecret
	if existing.Jobs > 0 {
		if !strings.EqualFold(rem.Backend, existing.Backend) {
			s.writeError(w, http.StatusConflict, "The remote is used by backup jobs; its backend can't change")
			return
		}
		if existing.HasSecret && !rem.HasSecret {
			names, err := s.DB.RemoteJobsWithoutProfile(r.Context(), existing.ID)
			if err != nil {
				s.writeError(w, http.StatusInternalServerError, "Failed to check the jobs using the remote")
				return
			}
			if len(names) > 0 {
				s.writeError(w, http.StatusConflict, "Job "+names[0]+" uses the remote's stored credential; name an agent credential profile on the job first")
				return
			}
		}
	}
	if err := s.DB.UpdateRemote(r.Context(), &rem); err != nil {
		slog.Error("Failed to update remote", "error", err, "id", existing.ID)
		s.writeError(w, http.StatusInternalServerError, "Failed to update remote (is the name unique?)")
		return
	}
	slog.Info("Remote updated", "remote", rem.Name, "backend", rem.Backend, "identity", rem.Identity(), "auth_method", rem.AuthMethod, "secret_changed", secretChanged)
	s.audit(r, "remote.update", "remote", rem.ID.String(), rem.Name, rem.Labels, map[string]any{"old_labels": existing.Labels,
		"identity": rem.Identity(), "old_identity": existing.Identity(), "auth_method": rem.AuthMethod, "secret_changed": secretChanged})
	s.writeJSON(w, http.StatusOK, &rem)
}

// HandleDeleteRemote removes a remote no job references
func (s *ServerAPI) HandleDeleteRemote(w http.ResponseWriter, r *http.Request) {
	rem, ok := s.remoteFromPath(w, r, auth.PermRemotesDelete)
	if !ok {
		return
	}
	switch err := s.DB.DeleteRemote(r.Context(), rem.ID); {
	case err == nil:
		s.audit(r, "remote.delete", "remote", rem.ID.String(), rem.Name, rem.Labels, nil)
		s.writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	case errors.Is(err, db.ErrRemoteInUse):
		s.writeError(w, http.StatusConflict, "The remote is used by backup jobs; delete or re-point them first")
	case errors.Is(err, db.ErrNotFound):
		s.writeError(w, http.StatusNotFound, "Remote not found")
	default:
		s.writeError(w, http.StatusInternalServerError, "Failed to delete remote")
	}
}

// RemoteCredentials is what a remote job's run gets: the remote's settings and, when
// the job names no agent profile, its stored credential
type RemoteCredentials struct {
	Remote  *remote.Remote `json:"remote"`
	Secrets remote.Secrets `json:"secrets"`
}

// HandleRemoteCredentials hands an agent the remote of the job named by its backup
// ticket (agent token + ticket, like vcs-credentials). A job that names an agent
// credential profile gets the settings without the stored credential: the agent's
// own profile is the only secret that run may use, and the settings let it check the
// profile belongs to this remote.
func (s *ServerAPI) HandleRemoteCredentials(w http.ResponseWriter, r *http.Request) {
	agent, claims, _, ok := s.ticketContext(w, r)
	if !ok {
		return
	}
	job, err := s.DB.GetJobByID(r.Context(), claims.JobID, db.Unscoped)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "job not found")
		return
	}
	if !job.IsRemote() || job.RemoteConfig == nil {
		s.writeError(w, http.StatusForbidden, "job is not a remote job")
		return
	}
	rem, err := s.DB.GetRemoteByID(r.Context(), job.RemoteConfig.RemoteID, db.Unscoped)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "the job's remote no longer exists")
		return
	}
	creds := RemoteCredentials{Remote: rem}
	if job.RemoteConfig.Profile == "" {
		creds.Secrets = rem.Secrets
	}
	slog.Info("Handing remote credentials to agent", "agent_id", agent.AgentID, "job_id", job.ID, "remote", rem.Name, "identity", rem.Identity(), "agent_profile", job.RemoteConfig.Profile)
	s.writeJSON(w, http.StatusOK, creds)
}
