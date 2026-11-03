package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/auth"
	"github.com/osshield/fallbck/pkg/db"
	"github.com/osshield/fallbck/pkg/github"
)

// GitHub account tokens are sealed at rest, never returned, and handed to the agent per
// run with its ticket. Accounts share the tenants permissions with M365 tenants.

// GitHubAccountRequest creates or updates an account (POST /github/accounts, PUT
// /github/accounts/{id}). On update a blank token keeps the stored one.
type GitHubAccountRequest struct {
	github.Account
	Token string `json:"token"`
}

const githubTestTimeout = 30 * time.Second

func (s *ServerAPI) githubAccountFromPath(w http.ResponseWriter, r *http.Request, perm string) (*github.Account, bool) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid account ID")
		return nil, false
	}
	a, err := s.DB.GetGitHubAccountByID(r.Context(), id, scope(r, auth.PermTenantsRead))
	if err != nil {
		s.writeError(w, http.StatusNotFound, "GitHub account not found")
		return nil, false
	}
	if !s.allow(w, r, perm, a.Labels) {
		return nil, false
	}
	return a, true
}

// HandleListGitHubAccounts returns every account (tokens redacted)
func (s *ServerAPI) HandleListGitHubAccounts(w http.ResponseWriter, r *http.Request) {
	accounts, err := s.DB.ListGitHubAccounts(r.Context(), scope(r, auth.PermTenantsRead))
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to list GitHub accounts")
		return
	}
	if accounts == nil {
		accounts = []*github.Account{}
	}
	s.writeJSON(w, http.StatusOK, accounts)
}

// HandleGetGitHubAccount returns one account (token redacted)
func (s *ServerAPI) HandleGetGitHubAccount(w http.ResponseWriter, r *http.Request) {
	a, ok := s.githubAccountFromPath(w, r, auth.PermTenantsRead)
	if !ok {
		return
	}
	s.writeJSON(w, http.StatusOK, a)
}

// HandleCreateGitHubAccount registers an account
func (s *ServerAPI) HandleCreateGitHubAccount(w http.ResponseWriter, r *http.Request) {
	var req GitHubAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	a := req.Account
	a.ID = uuid.Nil
	a.Token = req.Token
	a.Labels = db.Labels(a.Labels).OrEmpty()
	if !s.validLabels(w, a.Labels) || !s.allow(w, r, auth.PermTenantsWrite, a.Labels) {
		return
	}
	if err := a.Validate(); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.DB.CreateGitHubAccount(r.Context(), &a); err != nil {
		slog.Error("Failed to create GitHub account", "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to create GitHub account (is the name unique?)")
		return
	}
	slog.Info("GitHub account created", "account", a.Name, "api_url", a.APIURL)
	s.audit(r, "github_account.create", "github_account", a.ID.String(), a.Name, a.Labels, map[string]any{"api_url": a.APIURL})
	s.writeJSON(w, http.StatusCreated, a.Sanitize())
}

// HandleUpdateGitHubAccount replaces an account's settings; a blank token keeps the stored one
func (s *ServerAPI) HandleUpdateGitHubAccount(w http.ResponseWriter, r *http.Request) {
	existing, ok := s.githubAccountFromPath(w, r, auth.PermTenantsWrite)
	if !ok {
		return
	}
	var req GitHubAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	labels, ok := s.newLabels(w, r, auth.PermTenantsWrite, existing.Labels, req.Labels)
	if !ok {
		return
	}
	a := req.Account
	a.Labels = labels
	a.ID, a.CreatedAt = existing.ID, existing.CreatedAt
	a.Token = req.Token
	if a.Token == "" {
		a.Token = existing.Token
	}
	if err := a.Validate(); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.DB.UpdateGitHubAccount(r.Context(), &a); err != nil {
		slog.Error("Failed to update GitHub account", "error", err, "id", a.ID)
		s.writeError(w, http.StatusInternalServerError, "Failed to update GitHub account (is the name unique?)")
		return
	}
	slog.Info("GitHub account updated", "account", a.Name, "token_changed", req.Token != "")
	s.audit(r, "github_account.update", "github_account", a.ID.String(), a.Name, a.Labels, map[string]any{"old_labels": existing.Labels, "token_changed": req.Token != ""})
	s.writeJSON(w, http.StatusOK, a.Sanitize())
}

// HandleDeleteGitHubAccount removes an account no job references
func (s *ServerAPI) HandleDeleteGitHubAccount(w http.ResponseWriter, r *http.Request) {
	a, ok := s.githubAccountFromPath(w, r, auth.PermTenantsDelete)
	if !ok {
		return
	}
	switch err := s.DB.DeleteGitHubAccount(r.Context(), a.ID); {
	case err == nil:
		s.audit(r, "github_account.delete", "github_account", a.ID.String(), a.Name, a.Labels, nil)
		s.writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	case errors.Is(err, db.ErrAccountInUse):
		s.writeError(w, http.StatusConflict, "The account is used by backup jobs; delete or re-point them first")
	case errors.Is(err, db.ErrNotFound):
		s.writeError(w, http.StatusNotFound, "GitHub account not found")
	default:
		s.writeError(w, http.StatusInternalServerError, "Failed to delete GitHub account")
	}
}

// HandleTestGitHubAccount reads GET /user with the stored token. The server itself
// talks to GitHub here, so a failure can also mean the server has no outbound HTTPS.
func (s *ServerAPI) HandleTestGitHubAccount(w http.ResponseWriter, r *http.Request) {
	a, ok := s.githubAccountFromPath(w, r, auth.PermTenantsWrite)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), githubTestTimeout)
	defer cancel()
	v, err := github.TestConnection(ctx, a.Credentials())
	if err != nil {
		slog.Warn("GitHub account test failed", "account", a.Name, "error", err)
		s.writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"ok": true, "viewer": v})
}

// HandleGitHubCredentials hands an agent the token of the GitHub job named by its
// backup ticket (agent token + ticket, like m365-credentials)
func (s *ServerAPI) HandleGitHubCredentials(w http.ResponseWriter, r *http.Request) {
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
		slog.Warn("GitHub credential request with another agent's ticket", "agent_id", agent.AgentID, "ticket_agent_id", claims.AgentID)
		s.writeError(w, http.StatusForbidden, "backup ticket was not issued to this agent")
		return
	}
	job, err := s.DB.GetJobByID(r.Context(), claims.JobID, db.Unscoped)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "job not found")
		return
	}
	if !job.IsGitHub() || job.GitHubConfig == nil {
		s.writeError(w, http.StatusForbidden, "job is not a GitHub job")
		return
	}
	a, err := s.DB.GetGitHubAccountByID(r.Context(), job.GitHubConfig.AccountID, db.Unscoped)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "the job's GitHub account no longer exists")
		return
	}
	slog.Info("Handing GitHub credentials to agent", "agent_id", agent.AgentID, "job_id", job.ID, "account", a.Name)
	s.writeJSON(w, http.StatusOK, a.Credentials())
}
