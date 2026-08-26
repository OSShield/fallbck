package api

import (
	"encoding/json"
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
		})

		// Administrative
		r.Group(func(r chi.Router) {
			r.Use(admin)

			r.Get("/auth/me", s.HandleMe)

			r.Get("/agents", s.HandleListAgents)
			r.Get("/agents/{id}", s.HandleGetAgent)
			r.Delete("/agents/{id}", s.HandleDeleteAgent)

			// Enrollment tokens
			r.Post("/tokens", s.HandleCreateToken)
			r.Get("/tokens", s.HandleListTokens)

			// API keys
			r.Post("/apikeys", s.HandleCreateAPIKey)
			r.Get("/apikeys", s.HandleListAPIKeys)
			r.Delete("/apikeys/{id}", s.HandleRevokeAPIKey)

			// Targets
			r.Post("/targets", s.HandleCreateTarget)
			r.Get("/targets", s.HandleListTargets)
			r.Get("/targets/{id}", s.HandleGetTarget)
			r.Delete("/targets/{id}", s.HandleDeleteTarget)

			// Jobs
			r.Post("/jobs", s.HandleCreateJob)
			r.Get("/jobs", s.HandleListJobs)
			r.Get("/jobs/{id}", s.HandleGetJob)
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
		ID:        agentID,
		Hostname:  req.Hostname,
		IPAddress: ip,
		OS:        req.OS,
		Arch:      req.Arch,
		Version:   req.Version,
		TaskQueue: taskQueue,
		Status:    db.AgentStatusOnline,
	}

	now := time.Now().UTC()
	agent.LastSeenAt = &now

	if err := s.DB.CreateAgent(r.Context(), agent); err != nil {
		slog.Error("Failed to store agent in database", "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to register agent record")
		return
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

	slog.Info("Successfully enrolled new agent", "agent_id", agentID, "hostname", req.Hostname, "token_name", token.Name)
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

	if err := s.DB.UpdateAgentHeartbeat(r.Context(), claims.AgentID, status); err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to update heartbeat")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
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
		AuthTokenEncrypted: strings.TrimSpace(req.AuthToken),
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

	if job.Name == "" || job.AgentID == uuid.Nil || job.TargetID == uuid.Nil {
		s.writeError(w, http.StatusBadRequest, "Name, AgentID, and TargetID are required")
		return
	}

	if err := s.DB.CreateJob(r.Context(), &job); err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to create job")
		return
	}

	s.writeJSON(w, http.StatusCreated, job)
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

	s.writeJSON(w, http.StatusOK, job)
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
