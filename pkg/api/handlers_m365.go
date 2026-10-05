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
	"github.com/osshield/fallbck/pkg/m365"
)

// Microsoft 365 tenants: the Entra app registration FallBCK reads a tenant with. The
// secret / private key are sealed at rest, never returned by the API, and handed to
// the agent per run with its backup ticket (HandleM365Credentials).

// TenantRequest creates or updates a tenant (POST /m365/tenants, PUT /m365/tenants/{id}).
// On update a blank secret or certificate keeps the stored one.
type TenantRequest struct {
	m365.Tenant
	Secret         string `json:"secret"`
	CertificatePEM string `json:"certificate_pem"`
	KeyPEM         string `json:"key_pem"`
}

// tenantTestTimeout bounds the token + /organization round trip of a connection test
const tenantTestTimeout = 30 * time.Second

func (s *ServerAPI) tenantID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid tenant ID")
		return uuid.Nil, false
	}
	return id, true
}

// HandleListTenants returns every tenant (credentials redacted)
func (s *ServerAPI) HandleListTenants(w http.ResponseWriter, r *http.Request) {
	tenants, err := s.DB.ListTenants(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to list tenants")
		return
	}
	if tenants == nil {
		tenants = []*m365.Tenant{}
	}
	s.writeJSON(w, http.StatusOK, tenants)
}

// HandleGetTenant returns one tenant (credentials redacted)
func (s *ServerAPI) HandleGetTenant(w http.ResponseWriter, r *http.Request) {
	id, ok := s.tenantID(w, r)
	if !ok {
		return
	}
	t, err := s.DB.GetTenantByID(r.Context(), id)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "Tenant not found")
		return
	}
	s.writeJSON(w, http.StatusOK, t)
}

// HandleCreateTenant registers a tenant
func (s *ServerAPI) HandleCreateTenant(w http.ResponseWriter, r *http.Request) {
	var req TenantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	t := req.Tenant
	t.ID = uuid.Nil
	t.Secret, t.CertificatePEM, t.KeyPEM = req.Secret, req.CertificatePEM, req.KeyPEM
	if err := t.Validate(); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.DB.CreateTenant(r.Context(), &t); err != nil {
		slog.Error("Failed to create Microsoft 365 tenant", "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to create tenant (is the name unique?)")
		return
	}
	slog.Info("Microsoft 365 tenant created", "tenant", t.Name, "tenant_id", t.TenantID, "auth", t.AuthMethod)
	s.writeJSON(w, http.StatusCreated, t.Sanitize())
}

// HandleUpdateTenant replaces a tenant's settings; blank credentials keep the stored ones
func (s *ServerAPI) HandleUpdateTenant(w http.ResponseWriter, r *http.Request) {
	id, ok := s.tenantID(w, r)
	if !ok {
		return
	}
	existing, err := s.DB.GetTenantByID(r.Context(), id)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "Tenant not found")
		return
	}
	var req TenantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	t := req.Tenant
	t.ID, t.CreatedAt = existing.ID, existing.CreatedAt
	t.Secret, t.CertificatePEM, t.KeyPEM = req.Secret, req.CertificatePEM, req.KeyPEM
	if t.Secret == "" {
		t.Secret = existing.Secret
	}
	if t.CertificatePEM == "" && t.KeyPEM == "" {
		t.CertificatePEM, t.KeyPEM = existing.CertificatePEM, existing.KeyPEM
	}
	if t.AuthMethod == m365.AuthSecret && t.SecretExpires == nil {
		t.SecretExpires = existing.SecretExpires
	}
	if err := t.Validate(); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.DB.UpdateTenant(r.Context(), &t); err != nil {
		slog.Error("Failed to update Microsoft 365 tenant", "error", err, "id", id)
		s.writeError(w, http.StatusInternalServerError, "Failed to update tenant (is the name unique?)")
		return
	}
	slog.Info("Microsoft 365 tenant updated", "tenant", t.Name, "auth", t.AuthMethod, "credential_changed", req.Secret != "" || req.KeyPEM != "")
	s.writeJSON(w, http.StatusOK, t.Sanitize())
}

// HandleDeleteTenant removes a tenant no job references
func (s *ServerAPI) HandleDeleteTenant(w http.ResponseWriter, r *http.Request) {
	id, ok := s.tenantID(w, r)
	if !ok {
		return
	}
	switch err := s.DB.DeleteTenant(r.Context(), id); {
	case err == nil:
		s.writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	case errors.Is(err, db.ErrTenantInUse):
		s.writeError(w, http.StatusConflict, "The tenant is used by backup jobs; delete or re-point them first")
	case errors.Is(err, db.ErrNotFound):
		s.writeError(w, http.StatusNotFound, "Tenant not found")
	default:
		s.writeError(w, http.StatusInternalServerError, "Failed to delete tenant")
	}
}

// HandleTestTenant acquires a Graph token with the stored credentials and reads the
// organization (POST /m365/tenants/{id}/test). The server itself talks to Microsoft
// here, so a failure can also mean the server has no outbound HTTPS; the error says so.
func (s *ServerAPI) HandleTestTenant(w http.ResponseWriter, r *http.Request) {
	id, ok := s.tenantID(w, r)
	if !ok {
		return
	}
	t, err := s.DB.GetTenantByID(r.Context(), id)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "Tenant not found")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), tenantTestTimeout)
	defer cancel()
	org, err := m365.TestConnection(ctx, t.Credentials(), "", "")
	if err != nil {
		slog.Warn("Microsoft 365 tenant test failed", "tenant", t.Name, "error", err)
		s.writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"ok": true, "organization": org})
}

// HandleM365Credentials hands an agent the tenant credentials of the Microsoft 365
// job named by its backup ticket (agent token + ticket, like db-credentials)
func (s *ServerAPI) HandleM365Credentials(w http.ResponseWriter, r *http.Request) {
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
		slog.Warn("Microsoft 365 credential request with another agent's ticket", "agent_id", agent.AgentID, "ticket_agent_id", claims.AgentID)
		s.writeError(w, http.StatusForbidden, "backup ticket was not issued to this agent")
		return
	}
	job, err := s.DB.GetJobByID(r.Context(), claims.JobID)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "job not found")
		return
	}
	if !job.IsM365() || job.M365Config == nil {
		s.writeError(w, http.StatusForbidden, "job is not a Microsoft 365 job")
		return
	}
	t, err := s.DB.GetTenantByID(r.Context(), job.M365Config.TenantID)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "the job's tenant no longer exists")
		return
	}
	slog.Info("Handing Microsoft 365 credentials to agent", "agent_id", agent.AgentID, "job_id", job.ID, "tenant", t.Name)
	s.writeJSON(w, http.StatusOK, t.Credentials())
}
