package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/auth"
	"github.com/osshield/fallbck/pkg/config"
	"github.com/osshield/fallbck/pkg/db"
	"github.com/osshield/fallbck/pkg/pbs"
	"github.com/osshield/fallbck/pkg/temporal/scheduler"
	"go.temporal.io/sdk/client"
)

// ServerAPI holds database, Temporal client, config and token services for HTTP requests
type ServerAPI struct {
	DB           *db.DB
	Temporal     client.Client
	Config       *config.ServerConfig
	TokenManager *auth.TokenManager
	// Verifier is used to invalidate cached agent state on revocation (may be nil)
	Verifier *auth.AgentVerifier
	// Scheduler keeps Temporal Schedules aligned with jobs (may be nil: tests, and a
	// server started without Temporal). A concrete pointer on purpose: a nil
	// *scheduler.Scheduler stored in an interface field would not compare equal to nil.
	Scheduler *scheduler.Scheduler
}

// NewServerAPI initializes the API service
func NewServerAPI(database *db.DB, temporalClient client.Client, cfg *config.ServerConfig, tm *auth.TokenManager, verifier *auth.AgentVerifier) *ServerAPI {
	return &ServerAPI{
		DB:           database,
		Temporal:     temporalClient,
		Config:       cfg,
		TokenManager: tm,
		Verifier:     verifier,
	}
}

// Middleware is a chi-compatible middleware
type Middleware = func(http.Handler) http.Handler

// RegisterRoutes registers all API routes onto the Chi router. admin protects the
// administrative API, agent protects agent-authenticated endpoints.
func (s *ServerAPI) RegisterRoutes(r chi.Router, admin, agent Middleware) {
	r.Route("/api/v1", func(r chi.Router) {
		// Public
		r.Get("/health", s.HandleHealth)
		r.Post("/agents/enroll", s.HandleAgentEnroll)

		// Agent-authenticated
		r.Group(func(r chi.Router) {
			r.Use(agent)
			r.Post("/agents/heartbeat", s.HandleAgentHeartbeat)
			r.Post("/agents/token/rotate", s.HandleRotateAgentToken)
			r.Get("/agents/pbs-credentials", s.HandlePBSCredentials)
			r.Get("/agents/db-credentials", s.HandleDBCredentials)
			r.Post("/agents/ticket/refresh", s.HandleRefreshTicket)
			r.Post("/agents/volume-ticket", s.HandleVolumeTicket)
			r.Post("/agents/token/worker", s.HandleWorkerToken)
			r.Post("/agents/run-progress", s.HandleRunProgress)
		})

		// Administrative
		r.Group(func(r chi.Router) {
			r.Use(admin)

			r.Get("/auth/me", s.HandleMe)

			r.Get("/agents", s.HandleListAgents)
			r.Get("/agents/{id}", s.HandleGetAgent)
			r.Delete("/agents/{id}", s.HandleDeleteAgent)
			r.Post("/agents/{id}/debug", s.HandleSetAgentDebug)
			r.Post("/agents/{id}/merge", s.HandleMergeAgent)

			// Enrollment tokens
			r.Post("/tokens", s.HandleCreateToken)
			r.Get("/tokens", s.HandleListTokens)
			r.Get("/tokens/{id}", s.HandleGetToken)
			r.Delete("/tokens/{id}", s.HandleDeleteToken)

			// API keys
			r.Post("/apikeys", s.HandleCreateAPIKey)
			r.Get("/apikeys", s.HandleListAPIKeys)
			r.Delete("/apikeys/{id}", s.HandleRevokeAPIKey)

			// Targets
			r.Post("/targets", s.HandleCreateTarget)
			r.Get("/targets", s.HandleListTargets)
			r.Get("/targets/{id}", s.HandleGetTarget)
			r.Get("/targets/{id}/credentials", s.HandleTargetCredentials)
			r.Put("/targets/{id}", s.HandleUpdateTarget)
			r.Post("/targets/{id}/clone", s.HandleCloneTarget)
			r.Delete("/targets/{id}", s.HandleDeleteTarget)

			// Jobs
			r.Post("/jobs", s.HandleCreateJob)
			r.Get("/jobs", s.HandleListJobs)
			r.Get("/jobs/{id}", s.HandleGetJob)
			r.Put("/jobs/{id}", s.HandleUpdateJob)
			r.Delete("/jobs/{id}", s.HandleDeleteJob)
			r.Post("/jobs/{id}/run", s.HandleTriggerJob)

			// Runs
			r.Get("/runs", s.HandleListRuns)
			r.Get("/runs/{id}", s.HandleGetRun)
			r.Post("/runs/{id}/cancel", s.HandleCancelRun)
		})
	})
}

// HandleHealth returns the system health status
func (s *ServerAPI) HandleHealth(w http.ResponseWriter, r *http.Request) {
	resp := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC(),
		"version":   "0.1.0",
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// HandleAgentEnroll processes an agent enrollment request with a one-time token and
// issues the agent its bearer token.
func (s *ServerAPI) HandleAgentEnroll(w http.ResponseWriter, r *http.Request) {
	var req EnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Token == "" {
		s.writeError(w, http.StatusBadRequest, "Enrollment token is required")
		return
	}

	// Validate token
	tokenHash := auth.HashToken(req.Token)
	token, err := s.DB.ValidateAndConsumeToken(r.Context(), tokenHash)
	if err != nil {
		slog.Warn("Agent enrollment rejected: invalid token", "error", err, "hostname", req.Hostname)
		s.writeError(w, http.StatusUnauthorized, "Invalid or expired enrollment token")
		return
	}

	agentType, ok := db.NormalizeAgentType(req.AgentType)
	if !ok {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Unknown agent type %q", req.AgentType))
		return
	}

	agentID := uuid.New()
	taskQueue := fmt.Sprintf("fallbck-agent-%s", agentID.String())

	// Client IP detection (RealIP middleware already applied X-Forwarded-For)
	ip := req.IPAddress
	if ip == "" {
		ip = r.RemoteAddr
		if colonIdx := strings.LastIndex(ip, ":"); colonIdx != -1 {
			ip = ip[:colonIdx]
		}
	}

	agent := &db.Agent{
		ID:         agentID,
		Hostname:   req.Hostname,
		IPAddress:  ip,
		OS:         req.OS,
		Arch:       req.Arch,
		Version:    req.Version,
		AgentType:  agentType,
		TaskQueue:  taskQueue,
		Status:     db.AgentStatusOnline,
		PVEHost:    req.PVEHost,
		DockerHost: req.DockerHost,
		DBTools:    req.DBTools,
	}

	now := time.Now().UTC()
	agent.LastSeenAt = &now

	if err := s.DB.CreateAgent(r.Context(), agent); err != nil {
		slog.Error("Failed to store agent in database", "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to register agent record")
		return
	}
	// Remember which agent the token produced: the onboarding page waits for it
	if err := s.DB.BindTokenAgent(r.Context(), token.ID, agentID); err != nil {
		slog.Warn("Failed to bind enrollment token to agent", "token", token.ID, "agent", agentID, "error", err)
	}

	const initialTokenVersion = 1
	authToken, expires, err := s.TokenManager.CreateAgentToken(agentID, taskQueue, initialTokenVersion, s.Config.AgentTokens.TTL)
	if err != nil {
		slog.Error("Failed to issue agent token", "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to issue agent credentials")
		return
	}

	var caPEM string
	if s.Config.AgentCABundlePath != "" {
		data, err := os.ReadFile(s.Config.AgentCABundlePath)
		if err != nil {
			slog.Warn("Failed to read agent CA bundle", "path", s.Config.AgentCABundlePath, "error", err)
		} else {
			caPEM = string(data)
		}
	}

	resp := EnrollResponse{
		AgentID:        agentID,
		TaskQueue:      taskQueue,
		Namespace:      s.Config.Temporal.Namespace,
		AuthToken:      authToken,
		TokenExpiresAt: expires,
		ServerURL:      strings.TrimRight(s.Config.PublicURL, "/"),
		ServerCAPEM:    caPEM,
		ProxyURL:       s.Config.ProxyURL(),
	}

	slog.Info("Successfully enrolled new agent", "agent_id", agentID, "hostname", req.Hostname, "agent_type", agentType, "token_name", token.Name)
	s.writeJSON(w, http.StatusCreated, resp)
}

// HandleAgentHeartbeat updates agent last_seen_at and status
func (s *ServerAPI) HandleAgentHeartbeat(w http.ResponseWriter, r *http.Request) {
	var req HeartbeatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	claims := auth.AgentFrom(r.Context())
	if claims == nil {
		s.writeError(w, http.StatusUnauthorized, "agent token required")
		return
	}
	if req.AgentID != uuid.Nil && req.AgentID != claims.AgentID {
		s.writeError(w, http.StatusForbidden, "agent_id does not match the authenticated agent")
		return
	}

	status := db.AgentStatusOnline
	if req.Status != "" {
		status = db.AgentStatus(req.Status)
	}

	debug, err := s.DB.UpdateAgentHeartbeat(r.Context(), claims.AgentID, status, db.AgentCapabilities{PVEHost: req.PVEHost, DockerHost: req.DockerHost, DBTools: req.DBTools})
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			s.writeError(w, http.StatusUnauthorized, "agent no longer exists")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "Failed to update heartbeat")
		return
	}

	s.writeJSON(w, http.StatusOK, HeartbeatResponse{Status: "ok", DebugLogging: debug})
}

// HandleListAgents returns all registered agents
func (s *ServerAPI) HandleListAgents(w http.ResponseWriter, r *http.Request) {
	agents, err := s.DB.ListAgents(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to fetch agents")
		return
	}
	if agents == nil {
		agents = []*db.Agent{}
	}
	s.writeJSON(w, http.StatusOK, agents)
}

// HandleGetAgent returns a single agent by ID
func (s *ServerAPI) HandleGetAgent(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid agent ID")
		return
	}

	agent, err := s.DB.GetAgentByID(r.Context(), id)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "Agent not found")
		return
	}

	s.writeJSON(w, http.StatusOK, agent)
}

// HandleDeleteAgent removes an agent
func (s *ServerAPI) HandleDeleteAgent(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid agent ID")
		return
	}

	if err := s.DB.DeleteAgent(r.Context(), id); err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to delete agent")
		return
	}
	if s.Verifier != nil {
		s.Verifier.Invalidate(id)
	}

	s.writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// HandleMergeAgent moves the jobs and run history of one agent onto another agent
// and deletes the first. Every job must be runnable by the target (type and
// capability flags), which is what makes this safe for retiring a database agent
// once the combined fallbck-agent on the same host reports database tools.
func (s *ServerAPI) HandleMergeAgent(w http.ResponseWriter, r *http.Request) {
	from, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid agent ID")
		return
	}
	var req MergeAgentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Into == uuid.Nil {
		s.writeError(w, http.StatusBadRequest, "Body must name the target agent: {\"into\": \"<agent id>\"}")
		return
	}
	if req.Into == from {
		s.writeError(w, http.StatusBadRequest, "An agent cannot be merged into itself")
		return
	}
	ctx := r.Context()
	source, err := s.DB.GetAgentByID(ctx, from)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "Agent not found")
		return
	}
	target, err := s.DB.GetAgentByID(ctx, req.Into)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "Target agent not found")
		return
	}
	jobs, err := s.DB.ListJobs(ctx)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to list jobs")
		return
	}
	for _, job := range jobs {
		if job.AgentID != from {
			continue
		}
		if !target.CanRunJob(job.JobType) {
			s.writeError(w, http.StatusConflict, fmt.Sprintf("Agent %s cannot run job %q (type %s): it has not reported the required capability (database client tools, Proxmox VE node or Docker daemon); wait for its next heartbeat or install the tools first",
				target.Hostname, job.Name, job.JobType))
			return
		}
	}
	jobsMoved, runsMoved, err := s.DB.MergeAgents(ctx, from, req.Into)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			s.writeError(w, http.StatusNotFound, "Agent not found")
			return
		}
		slog.Error("Merging agents failed", "from", from, "into", req.Into, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to merge agents")
		return
	}
	if s.Verifier != nil {
		s.Verifier.Invalidate(from)
	}
	slog.Info("Merged agent", "from", source.Hostname, "from_type", source.AgentType, "into", target.Hostname, "jobs", jobsMoved, "runs", runsMoved)
	s.writeJSON(w, http.StatusOK, MergeAgentResponse{Status: "merged", From: from, Into: req.Into, JobsMoved: jobsMoved, RunsMoved: runsMoved})
}

// HandleCreateToken creates a new one-time enrollment token
func (s *ServerAPI) HandleCreateToken(w http.ResponseWriter, r *http.Request) {
	var req CreateTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Name == "" {
		req.Name = fmt.Sprintf("Token-%s", time.Now().Format("2006-01-02-150405"))
	}
	if req.MaxUses <= 0 {
		req.MaxUses = 1
	}
	if req.ExpiresAt.IsZero() {
		req.ExpiresAt = time.Now().Add(24 * time.Hour) // 24h default expiry
	}

	rawToken, tokenHash, err := auth.GenerateSecureToken(32)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to generate token")
		return
	}

	token := &db.EnrollmentToken{
		ID:        uuid.New(),
		TokenHash: tokenHash,
		Name:      req.Name,
		MaxUses:   req.MaxUses,
		UsesCount: 0,
		ExpiresAt: req.ExpiresAt,
	}

	if err := s.DB.CreateEnrollmentToken(r.Context(), token); err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to save enrollment token")
		return
	}

	resp := CreateTokenResponse{
		ID:        token.ID,
		Name:      token.Name,
		RawToken:  rawToken,
		ExpiresAt: token.ExpiresAt,
		MaxUses:   token.MaxUses,
	}

	s.writeJSON(w, http.StatusCreated, resp)
}

// HandleSetAgentDebug toggles remote debug logging for an agent; the agent applies it
// on its next heartbeat (within ~30s), no restart needed
func (s *ServerAPI) HandleSetAgentDebug(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid agent ID")
		return
	}
	var req SetAgentDebugRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if err := s.DB.SetAgentDebugLogging(r.Context(), id, req.Enabled); err != nil {
		if errors.Is(err, db.ErrNotFound) {
			s.writeError(w, http.StatusNotFound, "Agent not found")
			return
		}
		slog.Error("Failed to set agent debug logging", "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to update agent")
		return
	}
	slog.Info("Agent debug logging toggled", "agent_id", id, "enabled", req.Enabled)
	s.writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "debug_logging": req.Enabled})
}

// HandleDeleteToken invalidates an enrollment token immediately
func (s *ServerAPI) HandleDeleteToken(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid token ID")
		return
	}
	if err := s.DB.DeleteEnrollmentToken(r.Context(), id); err != nil {
		if errors.Is(err, db.ErrNotFound) {
			s.writeError(w, http.StatusNotFound, "Token not found")
			return
		}
		slog.Error("Failed to delete enrollment token", "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to delete token")
		return
	}
	slog.Info("Enrollment token invalidated", "token_id", id)
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// HandleListTokens lists all enrollment tokens
func (s *ServerAPI) HandleListTokens(w http.ResponseWriter, r *http.Request) {
	tokens, err := s.DB.ListEnrollmentTokens(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to list tokens")
		return
	}
	if tokens == nil {
		tokens = []*db.EnrollmentToken{}
	}
	s.writeJSON(w, http.StatusOK, tokens)
}

// HandleGetToken returns one enrollment token (without its hash) including the agent
// that used it, which the onboarding page polls while waiting for an enrollment
func (s *ServerAPI) HandleGetToken(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid token ID")
		return
	}
	token, err := s.DB.GetEnrollmentToken(r.Context(), id)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			s.writeError(w, http.StatusNotFound, "Token not found")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "Failed to load token")
		return
	}
	s.writeJSON(w, http.StatusOK, token)
}

// HandleCloneTarget creates a target from an existing one with a different namespace.
// The stored API token is copied on the server; it is never returned to a client.
func (s *ServerAPI) HandleCloneTarget(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid target ID")
		return
	}
	var req CloneTargetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Namespace = strings.Trim(strings.TrimSpace(req.Namespace), "/")
	if req.Name == "" || req.Namespace == "" {
		s.writeError(w, http.StatusBadRequest, "Name and namespace are required (the clone differs from its source by namespace)")
		return
	}
	switch req.PxarFormat {
	case "", db.PxarFormatV1, db.PxarFormatV2:
	default:
		s.writeError(w, http.StatusBadRequest, "pxar_format must be v1 or v2")
		return
	}
	source, err := s.DB.GetTargetByID(r.Context(), id)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "Target not found")
		return
	}
	if req.Namespace == strings.Trim(source.Namespace, "/") {
		s.writeError(w, http.StatusBadRequest, "The clone must use a different namespace than "+source.Name)
		return
	}
	if !source.HasToken {
		s.writeError(w, http.StatusConflict, "Target "+source.Name+" has no API token stored; add one before cloning it")
		return
	}
	target, err := s.DB.CloneTarget(r.Context(), id, req.Name, req.Namespace, req.PxarFormat)
	if err != nil {
		slog.Error("Cloning target failed", "source", id, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to clone target (is the name unique?)")
		return
	}
	s.writeJSON(w, http.StatusCreated, target)
}

// HandleCreateTarget registers a new backup target
func (s *ServerAPI) HandleCreateTarget(w http.ResponseWriter, r *http.Request) {
	var req CreateTargetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Name == "" || req.Endpoint == "" || req.Datastore == "" {
		s.writeError(w, http.StatusBadRequest, "Name, Endpoint, and Datastore are required")
		return
	}
	if req.AuthToken == "" {
		s.writeError(w, http.StatusBadRequest, "A PBS API token (auth_token) is required")
		return
	}
	normalizedToken, err := pbs.NormalizeAPIToken(req.AuthToken)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid PBS API token: expected user@realm!tokenid:secret (as shown when the token was created)")
		return
	}
	if req.TargetType == "" {
		req.TargetType = "pbs"
	}
	switch req.PxarFormat {
	case "":
		req.PxarFormat = db.PxarFormatV1
	case db.PxarFormatV1, db.PxarFormatV2:
	default:
		s.writeError(w, http.StatusBadRequest, "pxar_format must be v1 or v2")
		return
	}

	target := &db.BackupTarget{
		Name:               req.Name,
		TargetType:         req.TargetType,
		Endpoint:           strings.TrimRight(req.Endpoint, "/"),
		Datastore:          req.Datastore,
		Namespace:          req.Namespace,
		AuthTokenEncrypted: normalizedToken,
		Fingerprint:        strings.TrimSpace(req.Fingerprint),
		TLSVerify:          req.TLSVerify,
		PxarFormat:         req.PxarFormat,
	}
	if err := s.DB.CreateTarget(r.Context(), target); err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to create target")
		return
	}

	s.writeJSON(w, http.StatusCreated, target.Sanitize())
}

// HandleUpdateTarget replaces a target's configuration. The API token is optional on
// update: leave auth_token blank to keep the stored token, or supply a new one to
// replace it. The path ID wins over any ID in the body.
func (s *ServerAPI) HandleUpdateTarget(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid target ID")
		return
	}
	existing, err := s.DB.GetTargetByID(r.Context(), id)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "Target not found")
		return
	}
	var req CreateTargetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Name == "" || req.Endpoint == "" || req.Datastore == "" {
		s.writeError(w, http.StatusBadRequest, "Name, Endpoint, and Datastore are required")
		return
	}
	// Token: keep the stored one when the field is blank, else normalise the new value
	token := existing.AuthTokenEncrypted
	if strings.TrimSpace(req.AuthToken) != "" {
		normalized, err := pbs.NormalizeAPIToken(req.AuthToken)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, "Invalid PBS API token: expected user@realm!tokenid:secret")
			return
		}
		token = normalized
	}
	if req.TargetType == "" {
		req.TargetType = existing.TargetType
	}
	switch req.PxarFormat {
	case "":
		req.PxarFormat = db.PxarFormatV1
	case db.PxarFormatV1, db.PxarFormatV2:
	default:
		s.writeError(w, http.StatusBadRequest, "pxar_format must be v1 or v2")
		return
	}
	target := &db.BackupTarget{
		ID:                 existing.ID,
		Name:               req.Name,
		TargetType:         req.TargetType,
		Endpoint:           strings.TrimRight(req.Endpoint, "/"),
		Datastore:          req.Datastore,
		Namespace:          req.Namespace,
		AuthTokenEncrypted: token,
		Fingerprint:        strings.TrimSpace(req.Fingerprint),
		TLSVerify:          req.TLSVerify,
		PxarFormat:         req.PxarFormat,
	}
	if err := s.DB.UpdateTarget(r.Context(), target); err != nil {
		if errors.Is(err, db.ErrNotFound) {
			s.writeError(w, http.StatusNotFound, "Target not found")
			return
		}
		slog.Error("Failed to update target", "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to update target")
		return
	}
	slog.Info("Backup target updated", "target_id", id, "name", target.Name, "namespace", target.Namespace)
	s.writeJSON(w, http.StatusOK, target.Sanitize())
}

// HandleListTargets returns all backup targets
func (s *ServerAPI) HandleListTargets(w http.ResponseWriter, r *http.Request) {
	targets, err := s.DB.ListTargets(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to list targets")
		return
	}
	if targets == nil {
		targets = []*db.BackupTarget{}
	}
	for _, t := range targets {
		t.Sanitize()
	}
	s.writeJSON(w, http.StatusOK, targets)
}

// HandleGetTarget gets target by ID
func (s *ServerAPI) HandleGetTarget(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid target ID")
		return
	}

	target, err := s.DB.GetTargetByID(r.Context(), id)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "Target not found")
		return
	}

	s.writeJSON(w, http.StatusOK, target.Sanitize())
}

// HandleDeleteTarget deletes a target
func (s *ServerAPI) HandleDeleteTarget(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid target ID")
		return
	}

	if err := s.DB.DeleteTarget(r.Context(), id); err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to delete target")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// HandleCreateJob creates a backup job
func (s *ServerAPI) HandleCreateJob(w http.ResponseWriter, r *http.Request) {
	var job db.BackupJob
	if err := json.NewDecoder(r.Body).Decode(&job); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if msg, err := s.validateJob(r.Context(), &job, nil); err != nil {
		s.writeError(w, http.StatusBadRequest, msg)
		return
	}

	if err := s.DB.CreateJob(r.Context(), &job); err != nil {
		slog.Error("Failed to create job", "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to create job")
		return
	}
	s.syncJobSchedule(r.Context(), &job)

	s.writeJSON(w, http.StatusCreated, job.Sanitize())
}

// HandleListJobs returns all jobs
func (s *ServerAPI) HandleListJobs(w http.ResponseWriter, r *http.Request) {
	jobs, err := s.DB.ListJobs(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to list jobs")
		return
	}
	if jobs == nil {
		jobs = []*db.BackupJob{}
	}
	for _, j := range jobs {
		j.Sanitize()
	}
	s.writeJSON(w, http.StatusOK, jobs)
}

// HandleGetJob returns job by ID
func (s *ServerAPI) HandleGetJob(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid job ID")
		return
	}

	job, err := s.DB.GetJobByID(r.Context(), id)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "Job not found")
		return
	}

	s.writeJSON(w, http.StatusOK, job.Sanitize())
}

// HandleDeleteJob deletes a job
func (s *ServerAPI) HandleDeleteJob(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid job ID")
		return
	}

	if err := s.DB.DeleteJob(r.Context(), id); err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to delete job")
		return
	}
	if s.Scheduler != nil {
		if err := s.Scheduler.Remove(r.Context(), id); err != nil {
			slog.Warn("Backup schedule could not be removed; the startup reconcile will retry", "job_id", id, "error", err)
		}
	}

	s.writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// HandleTriggerJob starts an on-demand backup execution for a job
func (s *ServerAPI) HandleTriggerJob(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	jobID, err := uuid.Parse(idStr)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid job ID")
		return
	}

	job, err := s.DB.GetJobByID(r.Context(), jobID)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "Job not found")
		return
	}

	workflowID := fmt.Sprintf("backup-job-%s-%d", job.ID.String(), time.Now().Unix())
	var runID string

	if s.Temporal != nil {
		workflowOptions := client.StartWorkflowOptions{
			ID:        workflowID,
			TaskQueue: "fallbck-server-queue",
		}
		we, err := s.Temporal.ExecuteWorkflow(r.Context(), workflowOptions, "BackupJobWorkflow", job.ID)
		if err != nil {
			slog.Error("Failed to trigger Temporal backup workflow", "error", err, "job_id", job.ID)
			s.writeError(w, http.StatusInternalServerError, "Failed to start Temporal workflow")
			return
		}
		runID = we.GetRunID()
	}

	// Create a pending run record in DB
	run := &db.BackupRun{
		ID:         uuid.New(),
		JobID:      job.ID,
		AgentID:    job.AgentID,
		TargetID:   job.TargetID,
		WorkflowID: workflowID,
		RunID:      runID,
		Status:     db.RunStatusPending,
	}
	_ = s.DB.CreateRun(r.Context(), run)

	s.writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"workflow_id": workflowID,
		"run_id":      runID,
		"status":      "initiated",
	})
}

// HandleListRuns returns recent backup runs
func (s *ServerAPI) HandleListRuns(w http.ResponseWriter, r *http.Request) {
	runs, err := s.DB.ListRuns(r.Context(), 50)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to list runs")
		return
	}
	if runs == nil {
		runs = []*db.BackupRun{}
	}
	s.writeJSON(w, http.StatusOK, runs)
}

// Helper methods
func (s *ServerAPI) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func (s *ServerAPI) writeError(w http.ResponseWriter, status int, message string) {
	s.writeJSON(w, status, map[string]string{"error": message})
}
