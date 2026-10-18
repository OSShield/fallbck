package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/agenthealth"
	"github.com/osshield/fallbck/pkg/agentupdate"
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
	// RBAC caches role bindings; flushed after access changes (may be nil)
	RBAC *auth.Resolver
	// Sessions caches session validity; flushed after revocations (may be nil)
	Sessions *auth.SessionChecker
	// Version is the server's build version, reported by /health
	Version string
	// Scheduler keeps Temporal Schedules aligned with jobs (may be nil: tests, and a
	// server started without Temporal). A concrete pointer on purpose: a nil
	// *scheduler.Scheduler stored in an interface field would not compare equal to nil.
	Scheduler *scheduler.Scheduler
	// Updates mirrors the agent binary of the server's release for self-updating
	// agents (nil: feature off)
	Updates *agentupdate.Cache
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
		r.With(middleware.RequestSize(64<<10), enrollLimiter()).Post("/agents/enroll", s.HandleAgentEnroll)

		// Agent-authenticated
		r.Group(func(r chi.Router) {
			r.Use(agent, middleware.RequestSize(4<<20))
			r.Post("/agents/heartbeat", s.HandleAgentHeartbeat)
			r.Post("/agents/token/rotate", s.HandleRotateAgentToken)
			r.Get("/agents/pbs-credentials", s.HandlePBSCredentials)
			r.Get("/agents/encryption-key", s.HandleAgentEncryptionKey)
			r.Get("/agents/db-credentials", s.HandleDBCredentials)
			r.Get("/agents/m365-credentials", s.HandleM365Credentials)
			r.Post("/agents/ticket/refresh", s.HandleRefreshTicket)
			r.Post("/agents/sub-ticket", s.HandleSubTicket)
			// older kubernetes agents post here
			r.Post("/agents/volume-ticket", s.HandleSubTicket)
			r.Post("/agents/token/worker", s.HandleWorkerToken)
			r.Post("/agents/run-progress", s.HandleRunProgress)
			r.Get("/agents/update/checksums", s.HandleAgentUpdateChecksums)
			r.Get("/agents/update/checksums.sigstore.json", s.HandleAgentUpdateBundle)
			r.Get("/agents/update/{os}/{arch}", s.HandleAgentUpdateBinary)
			r.Get("/agents/update/{os}/{arch}/archive", s.HandleAgentUpdateArchive)
		})

		// Administrative. Every route names the permission it needs on some selector;
		// handlers then check the object's labels (see access.go).
		r.Group(func(r chi.Router) {
			r.Use(admin)
			need := auth.RequirePerm

			r.Get("/auth/me", s.HandleMe)

			r.With(need(auth.PermAgentsRead)).Get("/agents", s.HandleListAgents)
			r.With(need(auth.PermAgentsRead)).Get("/agents/{id}", s.HandleGetAgent)
			r.With(need(auth.PermAgentsDelete)).Delete("/agents/{id}", s.HandleDeleteAgent)
			r.With(need(auth.PermAgentsWrite)).Put("/agents/{id}/labels", s.HandleSetAgentLabels)
			r.With(need(auth.PermAgentsWrite)).Post("/agents/{id}/debug", s.HandleSetAgentDebug)
			r.With(need(auth.PermAgentsWrite)).Post("/agents/{id}/auto-update", s.HandleSetAgentAutoUpdate)
			r.With(need(auth.PermAgentsWrite)).Post("/agents/{id}/update", s.HandleRequestAgentUpdate)
			r.With(need(auth.PermAgentsWrite)).Post("/agents/{id}/merge", s.HandleMergeAgent)
			r.With(need(auth.PermAgentsWrite)).Post("/agents/{id}/logs", s.HandleAgentLogs)
			r.With(need(auth.PermAgentsWrite)).Post("/agents/{id}/inventory", s.HandleAgentInventory)

			// Enrollment tokens
			r.With(need(auth.PermAgentsEnroll)).Post("/tokens", s.HandleCreateToken)
			r.With(need(auth.PermAgentsEnroll)).Get("/tokens", s.HandleListTokens)
			r.With(need(auth.PermAgentsEnroll)).Get("/tokens/{id}", s.HandleGetToken)
			r.With(need(auth.PermAgentsEnroll)).Delete("/tokens/{id}", s.HandleDeleteToken)

			// API keys
			r.With(need(auth.PermAPIKeysManage)).Post("/apikeys", s.HandleCreateAPIKey)
			r.With(need(auth.PermAPIKeysManage)).Get("/apikeys", s.HandleListAPIKeys)
			r.With(need(auth.PermAPIKeysManage)).Delete("/apikeys/{id}", s.HandleRevokeAPIKey)

			// Targets
			r.With(need(auth.PermTargetsWrite)).Post("/targets", s.HandleCreateTarget)
			r.With(need(auth.PermTargetsRead)).Get("/targets", s.HandleListTargets)
			r.With(need(auth.PermTargetsRead)).Get("/targets/{id}", s.HandleGetTarget)
			r.With(need(auth.PermTargetsCredentials)).Get("/targets/{id}/credentials", s.HandleTargetCredentials)
			r.With(need(auth.PermTargetsWrite)).Post("/targets/{id}/token-check", s.HandleCheckTargetToken)
			r.With(need(auth.PermTargetsWrite)).Put("/targets/{id}", s.HandleUpdateTarget)
			r.With(need(auth.PermTargetsWrite)).Post("/targets/{id}/clone", s.HandleCloneTarget)
			r.With(need(auth.PermTargetsRead)).Get("/targets/{id}/encryption", s.HandleGetTargetEncryption)
			r.With(need(auth.PermTargetsWrite)).Put("/targets/{id}/encryption", s.HandleSetTargetEncryption)
			r.With(need(auth.PermKeyringsWrite)).Post("/targets/{id}/encryption/rotate", s.HandleRotateTargetKey)
			r.With(need(auth.PermKeyringsExport)).Post("/targets/{id}/encryption/export", s.HandleExportTargetKey)
			r.With(need(auth.PermKeyringsWrite)).Post("/targets/{id}/encryption/import", s.HandleImportTargetKey)
			r.With(need(auth.PermTargetsDelete)).Delete("/targets/{id}", s.HandleDeleteTarget)

			// Encryption key rings (shared by the targets attached to them)
			r.With(need(auth.PermKeyringsRead)).Get("/keyrings", s.HandleListKeyRings)
			r.With(need(auth.PermKeyringsWrite)).Post("/keyrings", s.HandleCreateKeyRing)
			r.With(need(auth.PermKeyringsRead)).Get("/keyrings/{id}", s.HandleGetKeyRing)
			r.With(need(auth.PermKeyringsWrite)).Put("/keyrings/{id}", s.HandleUpdateKeyRing)
			r.With(need(auth.PermKeyringsDelete)).Delete("/keyrings/{id}", s.HandleDeleteKeyRing)
			r.With(need(auth.PermKeyringsWrite)).Post("/keyrings/{id}/rotate", s.HandleRotateKeyRing)
			r.With(need(auth.PermKeyringsExport)).Post("/keyrings/{id}/export", s.HandleExportKeyRingKey)
			r.With(need(auth.PermKeyringsWrite)).Post("/keyrings/{id}/import", s.HandleImportKeyRingKey)

			// Microsoft 365 tenants
			r.With(need(auth.PermTenantsWrite)).Post("/m365/tenants", s.HandleCreateTenant)
			r.With(need(auth.PermTenantsRead)).Get("/m365/tenants", s.HandleListTenants)
			r.With(need(auth.PermTenantsRead)).Get("/m365/tenants/{id}", s.HandleGetTenant)
			r.With(need(auth.PermTenantsWrite)).Put("/m365/tenants/{id}", s.HandleUpdateTenant)
			r.With(need(auth.PermTenantsDelete)).Delete("/m365/tenants/{id}", s.HandleDeleteTenant)
			r.With(need(auth.PermTenantsWrite)).Post("/m365/tenants/{id}/test", s.HandleTestTenant)

			// Jobs
			r.With(need(auth.PermJobsWrite)).Post("/jobs", s.HandleCreateJob)
			r.With(need(auth.PermJobsRead)).Get("/jobs", s.HandleListJobs)
			r.With(need(auth.PermJobsRead)).Get("/jobs/{id}", s.HandleGetJob)
			r.With(need(auth.PermJobsWrite)).Put("/jobs/{id}", s.HandleUpdateJob)
			r.With(need(auth.PermJobsDelete)).Delete("/jobs/{id}", s.HandleDeleteJob)
			r.With(need(auth.PermJobsRun)).Post("/jobs/{id}/run", s.HandleTriggerJob)

			// Runs: reachable exactly when their job is
			r.With(need(auth.PermJobsRead)).Get("/runs", s.HandleListRuns)
			r.With(need(auth.PermJobsRead)).Get("/runs/{id}", s.HandleGetRun)
			r.With(need(auth.PermJobsRun)).Post("/runs/{id}/cancel", s.HandleCancelRun)

			// Access control
			r.With(need(auth.PermRBACManage)).Get("/rbac/permissions", s.HandleListPermissions)
			r.With(need(auth.PermRBACManage)).Get("/rbac/roles", s.HandleListRoles)
			r.With(need(auth.PermRBACManage)).Post("/rbac/roles", s.HandleCreateRole)
			r.With(need(auth.PermRBACManage)).Put("/rbac/roles/{name}", s.HandleUpdateRole)
			r.With(need(auth.PermRBACManage)).Delete("/rbac/roles/{name}", s.HandleDeleteRole)
			r.With(need(auth.PermRBACManage)).Get("/rbac/bindings", s.HandleListBindings)
			r.With(need(auth.PermRBACManage)).Post("/rbac/bindings", s.HandleCreateBinding)
			r.With(need(auth.PermRBACManage)).Delete("/rbac/bindings/{id}", s.HandleDeleteBinding)
			r.With(need(auth.PermRBACManage)).Get("/rbac/subjects", s.HandleListSeenSubjects)
			r.With(need(auth.PermRBACManage)).Get("/rbac/sessions", s.HandleListSessions)
			r.With(need(auth.PermRBACManage)).Delete("/rbac/sessions", s.HandleRevokeUserSessions)
			r.With(need(auth.PermRBACManage)).Delete("/rbac/sessions/{id}", s.HandleRevokeSession)
			r.With(auth.RequireAnyPerm(auth.PermRBACManage, auth.PermAPIKeysManage)).Get("/rbac/selector", s.HandleParseSelector)
			// API key creation offers the roles a key can take
			r.With(need(auth.PermAPIKeysManage)).Get("/apikeys/roles", s.HandleListRoles)

			// Audit log
			r.With(need(auth.PermAuditRead)).Get("/audit", s.HandleListAudit)
		})
	})
}

// HandleHealth returns the system health status
func (s *ServerAPI) HandleHealth(w http.ResponseWriter, r *http.Request) {
	version := s.Version
	if version == "" {
		version = "dev"
	}
	resp := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC(),
		"version":   version,
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

	// Client IP: agent-reported, else the proxy-forwarded address, else the peer
	ip := req.IPAddress
	if ip == "" {
		ip = middleware.GetClientIP(r.Context())
	}
	if ip == "" {
		ip, _, _ = net.SplitHostPort(r.RemoteAddr)
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
		DBEngines:  db.CleanDBEngines(req.DBEngines),
		DBTools:    req.DBTools || len(req.DBEngines) > 0,
		// Scope comes from the token, never from the agent: an enrolling host must
		// not be able to choose who administers it
		Labels: token.Labels.OrEmpty(),
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

	st, err := s.DB.UpdateAgentHeartbeat(r.Context(), claims.AgentID, status, db.AgentCapabilities{PVEHost: req.PVEHost, DockerHost: req.DockerHost, DBTools: req.DBTools || len(req.DBEngines) > 0, DBEngines: db.CleanDBEngines(req.DBEngines), Inventory: req.Inventory,
		Version: req.Version, SelfUpdate: req.SelfUpdate, UpdateError: req.UpdateError})
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			s.writeError(w, http.StatusUnauthorized, "agent no longer exists")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "Failed to update heartbeat")
		return
	}

	resp := HeartbeatResponse{Status: "ok", DebugLogging: st.DebugLogging}
	if req.SelfUpdate {
		resp.Update = s.agentUpdate(r.Context(), claims.AgentID, req.Version, st)
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// agentUpdate decides whether the heartbeat answer carries an update: the agent is
// behind the server's release and either opted in or an administrator pressed
// "Update now". A request the agent has satisfied is cleared here.
func (s *ServerAPI) agentUpdate(ctx context.Context, id uuid.UUID, agentVersion string, st db.HeartbeatState) *AgentUpdate {
	if s.Updates == nil {
		return nil
	}
	behind, ok := agenthealth.VersionBehind(agentVersion, s.Updates.Version)
	switch {
	case !ok:
		return nil
	case !behind:
		if st.UpdateRequested {
			_ = s.DB.ClearAgentUpdateRequest(ctx, id)
		}
		return nil
	case !st.AutoUpdate && !st.UpdateRequested:
		return nil
	}
	sha, ready := s.Updates.Binary(st.OS, st.Arch)
	if !ready {
		return nil
	}
	base := "/api/v1/agents/update/"
	return &AgentUpdate{
		Version: s.Updates.Version, URL: base + st.OS + "/" + st.Arch, SHA256: sha,
		Archive: agentupdate.ArchiveName(st.OS, st.Arch), ArchiveURL: base + st.OS + "/" + st.Arch + "/archive",
		ChecksumsURL: base + "checksums", BundleURL: base + "checksums.sigstore.json",
	}
}

// HandleAgentUpdateBinary serves the mirrored agent binary for an OS/arch (agents
// from before release signing)
func (s *ServerAPI) HandleAgentUpdateBinary(w http.ResponseWriter, r *http.Request) {
	s.serveUpdateFile(w, r, func(goos, goarch string) string { return s.Updates.Path(goos, goarch) })
}

// HandleAgentUpdateArchive serves the verified release archive for an OS/arch
func (s *ServerAPI) HandleAgentUpdateArchive(w http.ResponseWriter, r *http.Request) {
	s.serveUpdateFile(w, r, func(goos, goarch string) string { return s.Updates.ArchivePath(goos, goarch) })
}

// HandleAgentUpdateChecksums serves the release's checksums file; HandleAgentUpdateBundle
// its Sigstore bundle. Both are mirrored with the first binary, so any mirrored
// platform makes them available.
func (s *ServerAPI) HandleAgentUpdateChecksums(w http.ResponseWriter, r *http.Request) {
	s.serveUpdateFile(w, r, func(string, string) string { return s.Updates.ChecksumsPath() })
}

func (s *ServerAPI) HandleAgentUpdateBundle(w http.ResponseWriter, r *http.Request) {
	s.serveUpdateFile(w, r, func(string, string) string { return s.Updates.BundlePath() })
}

func (s *ServerAPI) serveUpdateFile(w http.ResponseWriter, r *http.Request, path func(goos, goarch string) string) {
	goos, goarch := chi.URLParam(r, "os"), chi.URLParam(r, "arch")
	if goos == "" {
		// Checksums and bundle are per release, not per platform: the agent's own
		// platform tells whether the release has been mirrored at all
		goos, goarch = "linux", r.URL.Query().Get("arch")
		if goarch == "" {
			goarch = "amd64"
		}
	}
	if s.Updates == nil {
		s.writeError(w, http.StatusNotFound, "agent updates are disabled")
		return
	}
	if _, ready := s.Updates.Binary(goos, goarch); !ready {
		s.writeError(w, http.StatusNotFound, "no agent release mirrored for "+goos+"/"+goarch)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeFile(w, r, path(goos, goarch))
}

// HandleListAgents returns the agents within the principal's scope
func (s *ServerAPI) HandleListAgents(w http.ResponseWriter, r *http.Request) {
	agents, err := s.DB.ListAgents(r.Context(), scope(r, auth.PermAgentsRead))
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

	agent, err := s.DB.GetAgentByID(r.Context(), id, scope(r, auth.PermAgentsRead))
	if err != nil {
		s.writeError(w, http.StatusNotFound, "Agent not found")
		return
	}

	s.writeJSON(w, http.StatusOK, agent)
}

// HandleDeleteAgent removes an agent
func (s *ServerAPI) HandleDeleteAgent(w http.ResponseWriter, r *http.Request) {
	agent, ok := s.agentFromPath(w, r, auth.PermAgentsDelete)
	if !ok {
		return
	}
	if err := s.DB.DeleteAgent(r.Context(), agent.ID); err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to delete agent")
		return
	}
	if s.Verifier != nil {
		s.Verifier.Invalidate(agent.ID)
	}
	s.audit(r, "agent.delete", "agent", agent.ID.String(), agent.Hostname, agent.Labels, nil)

	s.writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// SetLabelsRequest replaces an object's labels (PUT /agents/{id}/labels)
type SetLabelsRequest struct {
	Labels db.Labels `json:"labels"`
}

// HandleSetAgentLabels replaces an agent's labels; agents:write is needed on the old
// and the new labels
func (s *ServerAPI) HandleSetAgentLabels(w http.ResponseWriter, r *http.Request) {
	agent, ok := s.agentFromPath(w, r, auth.PermAgentsWrite)
	if !ok {
		return
	}
	var req SetLabelsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	labels, ok := s.newLabels(w, r, auth.PermAgentsWrite, agent.Labels, req.Labels.OrEmpty())
	if !ok {
		return
	}
	if err := s.DB.SetAgentLabels(r.Context(), agent.ID, labels); err != nil {
		s.agentWriteErr(w, err, "Failed to update agent")
		return
	}
	s.audit(r, "agent.labels", "agent", agent.ID.String(), agent.Hostname, labels, map[string]any{"old": agent.Labels})
	agent.Labels = labels
	s.writeJSON(w, http.StatusOK, agent)
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
	source, err := s.DB.GetAgentByID(ctx, from, scope(r, auth.PermAgentsRead))
	if err != nil {
		s.writeError(w, http.StatusNotFound, "Agent not found")
		return
	}
	target, err := s.DB.GetAgentByID(ctx, req.Into, scope(r, auth.PermAgentsRead))
	if err != nil {
		s.writeError(w, http.StatusNotFound, "Target agent not found")
		return
	}
	if !s.allow(w, r, auth.PermAgentsWrite, source.Labels, target.Labels) {
		return
	}
	// Every job of the source moves, whoever's scope it is in: it keeps its labels
	jobs, err := s.DB.ListJobs(ctx, db.Unscoped)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to list jobs")
		return
	}
	for _, job := range jobs {
		if job.AgentID != from {
			continue
		}
		if job.IsDatabase() && job.DBConfig != nil && !target.CanRunDBEngine(job.DBConfig.Engine) {
			s.writeError(w, http.StatusConflict, fmt.Sprintf("Agent %s cannot run job %q: it has not reported the database engine %s (install the client tools and wait for its next heartbeat)",
				target.Hostname, job.Name, job.DBConfig.Engine))
			return
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
	s.audit(r, "agent.merge", "agent", source.ID.String(), source.Hostname, source.Labels, map[string]any{"into": target.ID, "into_hostname": target.Hostname, "jobs": jobsMoved, "runs": runsMoved})
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
	req.Labels = req.Labels.OrEmpty()
	if !s.validLabels(w, req.Labels) || !s.allow(w, r, auth.PermAgentsEnroll, req.Labels) {
		return
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
		Labels:    req.Labels,
	}

	if err := s.DB.CreateEnrollmentToken(r.Context(), token); err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to save enrollment token")
		return
	}
	s.audit(r, "token.create", "token", token.ID.String(), token.Name, token.Labels, map[string]any{"max_uses": token.MaxUses, "expires_at": token.ExpiresAt})

	resp := CreateTokenResponse{
		ID:        token.ID,
		Name:      token.Name,
		RawToken:  rawToken,
		ExpiresAt: token.ExpiresAt,
		MaxUses:   token.MaxUses,
		Labels:    token.Labels,
	}

	s.writeJSON(w, http.StatusCreated, resp)
}

// HandleSetAgentDebug toggles remote debug logging for an agent; the agent applies it
// on its next heartbeat (within ~30s), no restart needed
func (s *ServerAPI) HandleSetAgentDebug(w http.ResponseWriter, r *http.Request) {
	agent, ok := s.agentFromPath(w, r, auth.PermAgentsWrite)
	if !ok {
		return
	}
	id := agent.ID
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
	s.audit(r, "agent.debug", "agent", id.String(), agent.Hostname, agent.Labels, map[string]any{"enabled": req.Enabled})
	s.writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "debug_logging": req.Enabled})
}

// HandleSetAgentAutoUpdate toggles the per-agent auto-update opt-in
func (s *ServerAPI) HandleSetAgentAutoUpdate(w http.ResponseWriter, r *http.Request) {
	agent, ok := s.agentFromPath(w, r, auth.PermAgentsWrite)
	if !ok {
		return
	}
	id := agent.ID
	var req SetAgentDebugRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if err := s.DB.SetAgentAutoUpdate(r.Context(), id, req.Enabled); err != nil {
		s.agentWriteErr(w, err, "Failed to update agent")
		return
	}
	slog.Info("Agent auto-update toggled", "agent_id", id, "enabled", req.Enabled)
	s.audit(r, "agent.auto_update", "agent", id.String(), agent.Hostname, agent.Labels, map[string]any{"enabled": req.Enabled})
	s.writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "auto_update": req.Enabled})
}

// HandleRequestAgentUpdate asks an agent to update to the server's version on its
// next heartbeat
func (s *ServerAPI) HandleRequestAgentUpdate(w http.ResponseWriter, r *http.Request) {
	agent, ok := s.agentFromPath(w, r, auth.PermAgentsWrite)
	if !ok {
		return
	}
	id := agent.ID
	if s.Updates == nil || !s.Updates.Enabled() {
		s.writeError(w, http.StatusConflict, "This server is not a release build; agents cannot be updated from it")
		return
	}
	if err := s.DB.RequestAgentUpdate(r.Context(), id); err != nil {
		s.agentWriteErr(w, err, "Failed to update agent")
		return
	}
	slog.Info("Agent update requested", "agent_id", id, "version", s.Updates.Version)
	s.audit(r, "agent.update", "agent", id.String(), agent.Hostname, agent.Labels, map[string]any{"version": s.Updates.Version})
	s.writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "version": s.Updates.Version})
}

func (s *ServerAPI) agentWriteErr(w http.ResponseWriter, err error, msg string) {
	if errors.Is(err, db.ErrNotFound) {
		s.writeError(w, http.StatusNotFound, "Agent not found")
		return
	}
	slog.Error(msg, "error", err)
	s.writeError(w, http.StatusInternalServerError, msg)
}

// HandleDeleteToken invalidates an enrollment token immediately
func (s *ServerAPI) HandleDeleteToken(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid token ID")
		return
	}
	token, err := s.DB.GetEnrollmentToken(r.Context(), id, scope(r, auth.PermAgentsEnroll))
	if err != nil {
		s.writeError(w, http.StatusNotFound, "Token not found")
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
	s.audit(r, "token.delete", "token", id.String(), token.Name, token.Labels, nil)
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// HandleListTokens lists all enrollment tokens
func (s *ServerAPI) HandleListTokens(w http.ResponseWriter, r *http.Request) {
	tokens, err := s.DB.ListEnrollmentTokens(r.Context(), scope(r, auth.PermAgentsEnroll))
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
	token, err := s.DB.GetEnrollmentToken(r.Context(), id, scope(r, auth.PermAgentsEnroll))
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
	source, err := s.DB.GetTargetByID(r.Context(), id, scope(r, auth.PermTargetsRead))
	if err != nil {
		s.writeError(w, http.StatusNotFound, "Target not found")
		return
	}
	// The clone keeps the source's labels and key ring
	if !s.allow(w, r, auth.PermTargetsWrite, source.Labels) {
		return
	}
	if source.KeyRingID != nil {
		if _, err := s.DB.GetKeyRing(r.Context(), *source.KeyRingID, scope(r, auth.PermKeyringsRead)); err != nil {
			s.writeError(w, http.StatusForbidden, "The clone would share the source's key ring, which you cannot read (keyrings:read)")
			return
		}
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
	s.audit(r, "target.clone", "target", target.ID.String(), target.Name, target.Labels, map[string]any{"source": source.ID, "namespace": target.Namespace})
	s.checkTokenLater(target)
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

	switch req.EncryptionMode {
	case "", db.EncryptionNone, db.EncryptionEncrypt:
	default:
		s.writeError(w, http.StatusBadRequest, "encryption_mode must be none or encrypt")
		return
	}
	ringID, err := parseOptionalUUID(req.KeyRingID)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid key ring ID")
		return
	}
	req.Labels = req.Labels.OrEmpty()
	if !s.validLabels(w, req.Labels) || !s.allow(w, r, auth.PermTargetsWrite, req.Labels) {
		return
	}
	// Checked before anything is written, so a refusal leaves no half-made target
	if !s.checkEncryptionAccess(w, r, req.EncryptionMode, ringID, nil, req.Labels, req.MasterPublicKey) {
		return
	}
	target := &db.BackupTarget{
		Labels:      req.Labels,
		Name:        req.Name,
		TargetType:  req.TargetType,
		Endpoint:    strings.TrimRight(req.Endpoint, "/"),
		Datastore:   req.Datastore,
		Namespace:   req.Namespace,
		AuthToken:   normalizedToken,
		Fingerprint: strings.TrimSpace(req.Fingerprint),
		TLSVerify:   req.TLSVerify,
		PxarFormat:  req.PxarFormat,
	}
	if err := s.DB.CreateTarget(r.Context(), target); err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to create target")
		return
	}
	if req.EncryptionMode == db.EncryptionEncrypt {
		if err := s.applyEncryptionMode(r, target, db.EncryptionEncrypt, ringID); err != nil {
			slog.Error("Enabling encryption on new target failed", "target", target.ID, "error", err)
			s.writeError(w, http.StatusInternalServerError, "Target created, but enabling encryption failed")
			return
		}
	}
	if msg, ok := s.applyTargetMasterKey(r, target, req.MasterPublicKey); !ok {
		s.writeError(w, http.StatusBadRequest, msg)
		return
	}
	s.audit(r, "target.create", "target", target.ID.String(), target.Name, target.Labels, map[string]any{"endpoint": target.Endpoint, "datastore": target.Datastore, "namespace": target.Namespace, "encryption": target.EncryptionMode})
	s.checkTokenLater(target)

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
	existing, err := s.DB.GetTargetByID(r.Context(), id, scope(r, auth.PermTargetsRead))
	if err != nil {
		s.writeError(w, http.StatusNotFound, "Target not found")
		return
	}
	if !s.allow(w, r, auth.PermTargetsWrite, existing.Labels) {
		return
	}
	var req CreateTargetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	labels, ok := s.newLabels(w, r, auth.PermTargetsWrite, existing.Labels, req.Labels)
	if !ok {
		return
	}
	if req.Name == "" || req.Endpoint == "" || req.Datastore == "" {
		s.writeError(w, http.StatusBadRequest, "Name, Endpoint, and Datastore are required")
		return
	}
	// Token: keep the stored one when the field is blank, else normalise the new value
	token := existing.AuthToken
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
	switch req.EncryptionMode {
	case "", db.EncryptionNone, db.EncryptionEncrypt:
	default:
		s.writeError(w, http.StatusBadRequest, "encryption_mode must be none or encrypt")
		return
	}
	ringID, err := parseOptionalUUID(req.KeyRingID)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid key ring ID")
		return
	}
	if !s.checkEncryptionAccess(w, r, req.EncryptionMode, ringID, existing.KeyRingID, labels, req.MasterPublicKey) {
		return
	}
	target := &db.BackupTarget{
		Labels:          labels,
		ID:              existing.ID,
		Name:            req.Name,
		TargetType:      req.TargetType,
		Endpoint:        strings.TrimRight(req.Endpoint, "/"),
		Datastore:       req.Datastore,
		Namespace:       req.Namespace,
		AuthToken:       token,
		Fingerprint:     strings.TrimSpace(req.Fingerprint),
		TLSVerify:       req.TLSVerify,
		PxarFormat:      req.PxarFormat,
		EncryptionMode:  existing.EncryptionMode,
		KeyRingID:       existing.KeyRingID,
		KeyRingName:     existing.KeyRingName,
		EncryptionKeyID: existing.EncryptionKeyID,
		KeyFingerprint:  existing.KeyFingerprint,
		KeyCreatedAt:    existing.KeyCreatedAt,
		MasterPublicKey: existing.MasterPublicKey,
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
	// Mode change, or a different ring while encrypted, goes through applyEncryptionMode
	mode := req.EncryptionMode
	if mode == "" {
		mode = existing.EncryptionMode
	}
	ringChanged := ringID != nil && (existing.KeyRingID == nil || *existing.KeyRingID != *ringID)
	if mode != existing.EncryptionMode || (mode == db.EncryptionEncrypt && ringChanged) {
		if err := s.applyEncryptionMode(r, target, mode, ringID); err != nil {
			slog.Error("Changing target encryption failed", "target", target.ID, "error", err)
			s.writeError(w, http.StatusInternalServerError, "Target updated, but changing encryption failed")
			return
		}
	}
	if msg, ok := s.applyTargetMasterKey(r, target, req.MasterPublicKey); !ok {
		s.writeError(w, http.StatusBadRequest, msg)
		return
	}
	slog.Info("Backup target updated", "target_id", id, "name", target.Name, "namespace", target.Namespace, "encryption", target.EncryptionMode)
	s.audit(r, "target.update", "target", id.String(), target.Name, target.Labels, map[string]any{"old_labels": existing.Labels, "token_changed": strings.TrimSpace(req.AuthToken) != "", "encryption": target.EncryptionMode})
	s.checkTokenLater(target)
	s.writeJSON(w, http.StatusOK, target.Sanitize())
}

// HandleListTargets returns all backup targets
func (s *ServerAPI) HandleListTargets(w http.ResponseWriter, r *http.Request) {
	targets, err := s.DB.ListTargets(r.Context(), scope(r, auth.PermTargetsRead))
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

	target, err := s.DB.GetTargetByID(r.Context(), id, scope(r, auth.PermTargetsRead))
	if err != nil {
		s.writeError(w, http.StatusNotFound, "Target not found")
		return
	}

	s.writeJSON(w, http.StatusOK, target.Sanitize())
}

// HandleDeleteTarget deletes a target
func (s *ServerAPI) HandleDeleteTarget(w http.ResponseWriter, r *http.Request) {
	target, ok := s.targetFromPath(w, r, auth.PermTargetsDelete)
	if !ok {
		return
	}
	if err := s.DB.DeleteTarget(r.Context(), target.ID); err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to delete target")
		return
	}
	s.audit(r, "target.delete", "target", target.ID.String(), target.Name, target.Labels, nil)

	s.writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// HandleCreateJob creates a backup job
func (s *ServerAPI) HandleCreateJob(w http.ResponseWriter, r *http.Request) {
	var job db.BackupJob
	if err := json.NewDecoder(r.Body).Decode(&job); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	job.Labels = job.Labels.OrEmpty()
	if !s.validLabels(w, job.Labels) || !s.allow(w, r, auth.PermJobsWrite, job.Labels) {
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
	s.audit(r, "job.create", "job", job.ID.String(), job.Name, job.Labels, map[string]any{"type": job.JobType, "agent": job.AgentID, "target": job.TargetID})

	s.writeJSON(w, http.StatusCreated, job.Sanitize())
}

// HandleListJobs returns all jobs
func (s *ServerAPI) HandleListJobs(w http.ResponseWriter, r *http.Request) {
	jobs, err := s.DB.ListJobs(r.Context(), scope(r, auth.PermJobsRead))
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

	job, err := s.DB.GetJobByID(r.Context(), id, scope(r, auth.PermJobsRead))
	if err != nil {
		s.writeError(w, http.StatusNotFound, "Job not found")
		return
	}

	s.writeJSON(w, http.StatusOK, job.Sanitize())
}

// HandleDeleteJob deletes a job
func (s *ServerAPI) HandleDeleteJob(w http.ResponseWriter, r *http.Request) {
	job, ok := s.jobFromPath(w, r, auth.PermJobsDelete)
	if !ok {
		return
	}
	id := job.ID
	if err := s.DB.DeleteJob(r.Context(), id); err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to delete job")
		return
	}
	s.audit(r, "job.delete", "job", id.String(), job.Name, job.Labels, nil)
	if s.Scheduler != nil {
		if err := s.Scheduler.Remove(r.Context(), id); err != nil {
			slog.Warn("Backup schedule could not be removed; the startup reconcile will retry", "job_id", id, "error", err)
		}
	}

	s.writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// HandleTriggerJob starts an on-demand backup execution for a job
func (s *ServerAPI) HandleTriggerJob(w http.ResponseWriter, r *http.Request) {
	job, ok := s.jobFromPath(w, r, auth.PermJobsRun)
	if !ok {
		return
	}

	workflowID := fmt.Sprintf("backup-job-%s-%d", job.ID.String(), time.Now().Unix())

	run := &db.BackupRun{
		ID:         uuid.New(),
		JobID:      job.ID,
		AgentID:    job.AgentID,
		TargetID:   job.TargetID,
		WorkflowID: workflowID,
		Status:     db.RunStatusPending,
	}
	if err := s.DB.CreateRun(r.Context(), run); err != nil {
		slog.Error("Failed to create run record", "error", err, "job_id", job.ID)
		s.writeError(w, http.StatusInternalServerError, "Failed to create run record")
		return
	}

	if s.Temporal != nil {
		workflowOptions := client.StartWorkflowOptions{
			ID:        workflowID,
			TaskQueue: "fallbck-server-queue",
		}
		we, err := s.Temporal.ExecuteWorkflow(r.Context(), workflowOptions, "BackupJobWorkflow", job.ID)
		if err != nil {
			slog.Error("Failed to trigger Temporal backup workflow", "error", err, "job_id", job.ID)
			now := time.Now()
			_ = s.DB.SetRunStatus(r.Context(), run.ID, db.RunStatusFailed, "Failed to start Temporal workflow", &now)
			s.writeError(w, http.StatusInternalServerError, "Failed to start Temporal workflow")
			return
		}
		run.RunID = we.GetRunID()
	}

	s.audit(r, "job.run", "job", job.ID.String(), job.Name, job.Labels, map[string]any{"run": run.ID})
	s.writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"id":          run.ID,
		"workflow_id": workflowID,
		"run_id":      run.RunID,
		"status":      "initiated",
	})
}

// HandleListRuns returns recent backup runs
func (s *ServerAPI) HandleListRuns(w http.ResponseWriter, r *http.Request) {
	runs, err := s.DB.ListRuns(r.Context(), 50, scope(r, auth.PermJobsRead))
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to list runs")
		return
	}
	if runs == nil {
		runs = []*db.BackupRun{}
	}
	s.writeJSON(w, http.StatusOK, runs)
}

// jobFromPath loads the job named in the path within jobs:read and checks perm on
// its labels (404 when unreadable, 403 when readable but perm is missing)
func (s *ServerAPI) jobFromPath(w http.ResponseWriter, r *http.Request, perm string) (*db.BackupJob, bool) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid job ID")
		return nil, false
	}
	job, err := s.DB.GetJobByID(r.Context(), id, scope(r, auth.PermJobsRead))
	if err != nil {
		s.writeError(w, http.StatusNotFound, "Job not found")
		return nil, false
	}
	if !s.allow(w, r, perm, job.Labels) {
		return nil, false
	}
	return job, true
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
