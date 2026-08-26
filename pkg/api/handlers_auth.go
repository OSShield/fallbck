package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/auth"
	"github.com/osshield/fallbck/pkg/db"
)

// HandleRotateAgentToken issues a fresh bearer token to an authenticated agent (same
// token version, so the old token stays valid until it expires or the agent is revoked).
func (s *ServerAPI) HandleRotateAgentToken(w http.ResponseWriter, r *http.Request) {
	claims := auth.AgentFrom(r.Context())
	if claims == nil {
		s.writeError(w, http.StatusUnauthorized, "agent token required")
		return
	}
	token, expires, err := s.TokenManager.CreateAgentToken(claims.AgentID, claims.TaskQueue, claims.Version, s.Config.AgentTokens.TTL)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to issue agent token")
		return
	}
	s.writeJSON(w, http.StatusOK, RotateTokenResponse{AuthToken: token, TokenExpiresAt: expires})
}

// HandleMe returns the authenticated admin principal
func (s *ServerAPI) HandleMe(w http.ResponseWriter, r *http.Request) {
	p := auth.PrincipalFrom(r.Context())
	if p == nil {
		s.writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	s.writeJSON(w, http.StatusOK, MeResponse{Kind: string(p.Kind), Subject: p.Subject, Email: p.Email, Name: p.Name})
}

// HandleCreateAPIKey mints an admin API key
func (s *ServerAPI) HandleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	var req CreateAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Name == "" {
		req.Name = "API key " + time.Now().UTC().Format("2006-01-02 15:04")
	}
	if req.ExpiresAt != nil && req.ExpiresAt.Before(time.Now()) {
		s.writeError(w, http.StatusBadRequest, "expires_at must be in the future")
		return
	}

	createdBy := "unknown"
	if p := auth.PrincipalFrom(r.Context()); p != nil {
		createdBy = p.Display()
	}
	raw, key, err := auth.NewAPIKey(req.Name, createdBy, req.ExpiresAt)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to generate API key")
		return
	}
	if err := s.DB.CreateAPIKey(r.Context(), key); err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to save API key")
		return
	}
	s.writeJSON(w, http.StatusCreated, CreateAPIKeyResponse{ID: key.ID, Name: key.Name, RawKey: raw, ExpiresAt: key.ExpiresAt})
}

// HandleListAPIKeys lists API keys (hashes are never returned)
func (s *ServerAPI) HandleListAPIKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := s.DB.ListAPIKeys(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to list API keys")
		return
	}
	if keys == nil {
		keys = []*db.APIKey{}
	}
	s.writeJSON(w, http.StatusOK, keys)
}

// HandleRevokeAPIKey revokes an API key
func (s *ServerAPI) HandleRevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid API key ID")
		return
	}
	if err := s.DB.RevokeAPIKey(r.Context(), id); err != nil {
		if errors.Is(err, db.ErrNotFound) {
			s.writeError(w, http.StatusNotFound, "API key not found or already revoked")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "Failed to revoke API key")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}
