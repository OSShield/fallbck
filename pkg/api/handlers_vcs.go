package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/auth"
	"github.com/osshield/fallbck/pkg/db"
	"github.com/osshield/fallbck/pkg/vcs"
)

// VCS connections: a GitLab instance or git host with the token FallBCK reads it
// with. The token is sealed at rest, never returned by the API, and handed to the
// agent per run with its backup ticket (HandleVCSCredentials). It is now optional: a job
// can name an agent credential profile instead, and then the token never reaches the
// server at all.

// ConnectionRequest creates or updates a connection (POST /vcs/connections, PUT
// /vcs/connections/{id}). On update a blank token keeps the stored one; ClearToken
// removes it (agent-side profiles only, or public git repositories).
type ConnectionRequest struct {
	vcs.Connection
	Token      string `json:"token"`
	ClearToken bool   `json:"clear_token"`
}

// vcsMinGit names the oldest git a VCS job runs with, for error messages
var vcsMinGit = strconv.Itoa(vcs.MinGitMajor) + "." + strconv.Itoa(vcs.MinGitMinor)

// connectionTestTimeout bounds the API round trips of a connection test
const connectionTestTimeout = 30 * time.Second

func (s *ServerAPI) connectionID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid connection ID")
		return uuid.Nil, false
	}
	return id, true
}

// HandleListConnections returns every connection (tokens redacted)
func (s *ServerAPI) HandleListConnections(w http.ResponseWriter, r *http.Request) {
	conns, err := s.DB.ListConnections(r.Context(), scope(r, auth.PermConnectionsRead))
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to list connections")
		return
	}
	if conns == nil {
		conns = []*vcs.Connection{}
	}
	s.writeJSON(w, http.StatusOK, conns)
}

// HandleGetConnection returns one connection (token redacted)
func (s *ServerAPI) HandleGetConnection(w http.ResponseWriter, r *http.Request) {
	c, ok := s.connectionFromPath(w, r, auth.PermConnectionsRead)
	if !ok {
		return
	}
	s.writeJSON(w, http.StatusOK, c)
}

// connectionFromPath loads the connection named in the path within connections:read
// and checks perm on its labels
func (s *ServerAPI) connectionFromPath(w http.ResponseWriter, r *http.Request, perm string) (*vcs.Connection, bool) {
	id, ok := s.connectionID(w, r)
	if !ok {
		return nil, false
	}
	c, err := s.DB.GetConnectionByID(r.Context(), id, scope(r, auth.PermConnectionsRead))
	if err != nil {
		s.writeError(w, http.StatusNotFound, "Connection not found")
		return nil, false
	}
	if !s.allow(w, r, perm, c.Labels) {
		return nil, false
	}
	return c, true
}

// HandleCreateConnection registers a connection
func (s *ServerAPI) HandleCreateConnection(w http.ResponseWriter, r *http.Request) {
	var req ConnectionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	c := req.Connection
	c.ID = uuid.Nil
	c.Token = req.Token
	c.Labels = db.Labels(c.Labels).OrEmpty()
	if !s.validLabels(w, c.Labels) || !s.allow(w, r, auth.PermConnectionsWrite, c.Labels) {
		return
	}
	if err := c.Validate(); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.DB.CreateConnection(r.Context(), &c); err != nil {
		slog.Error("Failed to create VCS connection", "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to create connection (is the name unique?)")
		return
	}
	slog.Info("VCS connection created", "connection", c.Name, "provider", c.Provider, "base_url", c.BaseURL)
	s.audit(r, "connection.create", "connection", c.ID.String(), c.Name, c.Labels, map[string]any{"provider": c.Provider, "base_url": c.BaseURL})
	s.writeJSON(w, http.StatusCreated, c.Sanitize())
}

// HandleUpdateConnection replaces a connection's settings; a blank token keeps the
// stored one. The provider cannot change while jobs use the connection, a git
// connection's URL must stay a prefix of its jobs' repositories, and the token of a
// GitLab connection cannot be removed while a job relies on it.
func (s *ServerAPI) HandleUpdateConnection(w http.ResponseWriter, r *http.Request) {
	existing, ok := s.connectionFromPath(w, r, auth.PermConnectionsWrite)
	if !ok {
		return
	}
	var req ConnectionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	labels, ok := s.newLabels(w, r, auth.PermConnectionsWrite, existing.Labels, req.Labels)
	if !ok {
		return
	}
	c := req.Connection
	c.Labels = labels
	c.ID, c.CreatedAt = existing.ID, existing.CreatedAt
	c.Token = req.Token
	tokenChanged := req.Token != "" || req.ClearToken
	if !tokenChanged {
		c.Token = existing.Token
	}
	if c.TokenExpires == nil && !tokenChanged {
		c.TokenExpires = existing.TokenExpires
	}
	if err := c.Validate(); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if existing.Jobs > 0 {
		if msg := s.connectionChangeConflict(r.Context(), existing, &c); msg != "" {
			s.writeError(w, http.StatusConflict, msg)
			return
		}
	}
	if err := s.DB.UpdateConnection(r.Context(), &c); err != nil {
		slog.Error("Failed to update VCS connection", "error", err, "id", existing.ID)
		s.writeError(w, http.StatusInternalServerError, "Failed to update connection (is the name unique?)")
		return
	}
	slog.Info("VCS connection updated", "connection", c.Name, "provider", c.Provider, "token_changed", tokenChanged)
	s.audit(r, "connection.update", "connection", c.ID.String(), c.Name, c.Labels, map[string]any{"old_labels": existing.Labels, "base_url": c.BaseURL, "token_changed": tokenChanged})
	s.writeJSON(w, http.StatusOK, c.Sanitize())
}

// connectionChangeConflict explains why an update would break the jobs using the
// connection ("" when it does not)
func (s *ServerAPI) connectionChangeConflict(ctx context.Context, old, updated *vcs.Connection) string {
	if updated.Provider != old.Provider {
		return "The connection is used by backup jobs; its provider cannot change"
	}
	urlChanged := updated.Provider == vcs.ProviderGit && updated.BaseURL != old.BaseURL
	tokenRemoved := updated.Provider == vcs.ProviderGitLab && old.Token != "" && updated.Token == ""
	if !urlChanged && !tokenRemoved {
		return ""
	}
	jobs, err := s.DB.ListJobs(ctx, db.Unscoped)
	if err != nil {
		return "Failed to check the jobs using the connection"
	}
	for _, j := range jobs {
		if !j.IsVCS() || j.VCSConfig == nil || j.VCSConfig.ConnectionID != old.ID {
			continue
		}
		if tokenRemoved && j.VCSConfig.Profile == "" {
			return "Job " + j.Name + " uses the connection's token; name an agent credential profile on the job first"
		}
		if !urlChanged {
			continue
		}
		for _, repo := range j.VCSConfig.Repositories {
			if !vcs.UnderBaseURL(repo, updated.BaseURL) {
				return "Job " + j.Name + " backs up " + repo + ", which is not below " + updated.BaseURL + "; change the job first"
			}
		}
	}
	return ""
}

// HandleDeleteConnection removes a connection no job references
func (s *ServerAPI) HandleDeleteConnection(w http.ResponseWriter, r *http.Request) {
	c, ok := s.connectionFromPath(w, r, auth.PermConnectionsDelete)
	if !ok {
		return
	}
	switch err := s.DB.DeleteConnection(r.Context(), c.ID); {
	case err == nil:
		s.audit(r, "connection.delete", "connection", c.ID.String(), c.Name, c.Labels, nil)
		s.writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	case errors.Is(err, db.ErrConnectionInUse):
		s.writeError(w, http.StatusConflict, "The connection is used by backup jobs; delete or re-point them first")
	case errors.Is(err, db.ErrNotFound):
		s.writeError(w, http.StatusNotFound, "Connection not found")
	default:
		s.writeError(w, http.StatusInternalServerError, "Failed to delete connection")
	}
}

// HandleTestConnection checks a GitLab connection's token, user and scopes (POST
// /vcs/connections/{id}/test) and stores the token expiry GitLab reports. The server
// itself talks to GitLab here, so a failure can also mean the server has no route to
// it; the error says so. Git connections have no API to test, and a connection
// without a token relies on agent profiles the server can't see: in both cases the
// agent finds out when a job runs, and the answer says the test did not run.
func (s *ServerAPI) HandleTestConnection(w http.ResponseWriter, r *http.Request) {
	c, ok := s.connectionFromPath(w, r, auth.PermConnectionsWrite)
	if !ok {
		return
	}
	if c.Provider != vcs.ProviderGitLab {
		s.writeJSON(w, http.StatusOK, map[string]any{"ok": true, "tested": false, "message": "Git connections have no API to test; the agent checks access when a job runs"})
		return
	}
	if c.Token == "" {
		s.writeJSON(w, http.StatusOK, map[string]any{"ok": true, "tested": false, "message": "The connection stores no token; the agent checks its credential profile when a job runs"})
		return
	}
	creds := c.Credentials()
	client, err := creds.HTTPClient(connectionTestTimeout)
	if err != nil {
		s.writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), connectionTestTimeout)
	defer cancel()
	inst, err := vcs.TestConnection(ctx, creds, client)
	if inst != nil && inst.TokenExpires != nil && (c.TokenExpires == nil || !c.TokenExpires.Equal(*inst.TokenExpires)) {
		if err := s.DB.SetConnectionTokenExpiry(r.Context(), c.ID, inst.TokenExpires); err != nil {
			slog.Warn("Failed to store the token expiry of a VCS connection", "connection", c.Name, "error", err)
		}
	}
	if err != nil {
		slog.Warn("VCS connection test failed", "connection", c.Name, "error", err)
		s.writeJSON(w, http.StatusOK, map[string]any{"ok": false, "tested": true, "error": err.Error(), "instance": inst})
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"ok": true, "tested": true, "instance": inst})
}

// HandleVCSCredentials hands an agent the connection credentials of the VCS job
// named by its backup ticket (agent token + ticket, like m365-credentials). A job
// that names an agent credential profile gets the conf without the stored token:
// the agent's own profile is the only secret that run may use.
func (s *ServerAPI) HandleVCSCredentials(w http.ResponseWriter, r *http.Request) {
	agent, claims, _, ok := s.ticketContext(w, r)
	if !ok {
		return
	}
	job, err := s.DB.GetJobByID(r.Context(), claims.JobID, db.Unscoped)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "job not found")
		return
	}
	if !job.IsVCS() || job.VCSConfig == nil {
		s.writeError(w, http.StatusForbidden, "job is not a VCS job")
		return
	}
	c, err := s.DB.GetConnectionByID(r.Context(), job.VCSConfig.ConnectionID, db.Unscoped)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "the job's connection no longer exists")
		return
	}
	creds := c.Credentials()
	if job.VCSConfig.Profile != "" {
		creds.Token = ""
	}
	slog.Info("Handing VCS credentials to agent", "agent_id", agent.AgentID, "job_id", job.ID, "connection", c.Name, "agent_profile", job.VCSConfig.Profile)
	s.writeJSON(w, http.StatusOK, creds)
}

// cleanGitVersion keeps the version an agent reports short and printable ("2.43.0",
// "2.39.3 (Apple Git-146)"); it is shown in the UI and compared, nothing else
func cleanGitVersion(v string) string {
	v = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(v), "git version"))
	v = strings.Map(func(r rune) rune {
		if r < ' ' || r > '~' {
			return -1
		}
		return r
	}, v)
	if len(v) > 64 {
		v = v[:64]
	}
	return v
}
