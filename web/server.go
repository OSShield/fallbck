package web

import (
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/agenthealth"
	"github.com/osshield/fallbck/pkg/auth"
	"github.com/osshield/fallbck/pkg/config"
	"github.com/osshield/fallbck/pkg/db"
	temporalui "github.com/osshield/fallbck/pkg/temporal/ui"
)

// Deps are the collaborators the UI needs beyond the database and config
type Deps struct {
	TokenManager *auth.TokenManager
	// OIDC is nil when admin authentication is disabled (development)
	OIDC *auth.OIDC
	// Admin protects every administrative page; nil means "insecure, allow all"
	Admin *auth.AdminAuth
	// TemporalUI is the embedded Temporal Web UI to proxy under /temporal/ (nil = disabled)
	TemporalUI *temporalui.Server
	Version    string
}

// UIHandler manages rendering of HTML templates and static assets
type UIHandler struct {
	DB     *db.DB
	Config *config.ServerConfig
	deps   Deps

	temporalProxy http.Handler
	cookieOpts    auth.CookieOptions
}

// NewUIHandler creates a new UIHandler
func NewUIHandler(database *db.DB, cfg *config.ServerConfig, deps Deps) *UIHandler {
	if deps.TokenManager == nil {
		deps.TokenManager = auth.NewTokenManager(cfg.JWTSecret)
	}
	if deps.Admin == nil {
		deps.Admin = auth.NewAdminAuth(deps.TokenManager, nil, true)
	}
	u := &UIHandler{
		DB:         database,
		Config:     cfg,
		deps:       deps,
		cookieOpts: auth.CookieOptions{Secure: cfg.PublicURLIsHTTPS()},
	}
	if deps.TemporalUI != nil {
		target := &url.URL{Scheme: "http", Host: deps.TemporalUI.Addr()}
		u.temporalProxy = &httputil.ReverseProxy{
			Rewrite: func(pr *httputil.ProxyRequest) {
				// Path is passed through untouched: ui-server strips its own PublicPath prefix
				pr.SetURL(target)
				pr.Out.Host = target.Host
				pr.SetXForwarded()
			},
			FlushInterval: 100 * time.Millisecond,
		}
	}
	return u
}

// RegisterRoutes mounts UI page routes and static file server
func (u *UIHandler) RegisterRoutes(r chi.Router) {
	// ---- public ----
	fileServer := http.FileServer(StaticFS())
	r.Handle("/static/*", http.StripPrefix("/static/", fileServer))
	r.Get("/install-agent.sh", u.HandleInstallScript)
	r.Get("/install-agent.ps1", u.HandleInstallScriptPS)
	r.Get("/login", u.HandleLoginPage)
	r.Get("/auth/login", u.HandleAuthLogin)
	r.Get("/auth/callback", u.HandleAuthCallback)

	// ---- administrative ----
	r.Group(func(r chi.Router) {
		r.Use(u.deps.Admin.RequireAdmin)

		r.Post("/auth/logout", u.HandleLogout)

		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/dashboard", http.StatusFound)
		})
		r.Get("/dashboard", u.HandleDashboard)
		r.Get("/agents", u.HandleAgents)
		r.Get("/agents/{id}", u.HandleAgentDetail)
		r.Get("/onboarding", u.HandleOnboarding)
		r.Get("/targets", u.HandleTargets)
		r.Get("/jobs", u.HandleJobs)
		r.Get("/kubernetes", u.HandleKubernetes)
		r.Get("/runs", u.HandleRuns)
		r.Get("/runs/{id}", u.HandleRunDetail)
		r.Get("/tokens", u.HandleTokens)
		r.Get("/apikeys", u.HandleAPIKeys)

		if u.temporalProxy != nil {
			r.Get(temporalui.PublicPath, func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, temporalui.PublicPath+"/", http.StatusFound)
			})
			r.Handle(temporalui.PublicPath+"/*", u.temporalProxy)
		}
	})
}

// SecurityHeaders sets a conservative set of browser security headers. The embedded
// Temporal UI (SvelteKit) needs inline scripts/styles, so its prefix gets a looser CSP.
func SecurityHeaders(next http.Handler) http.Handler {
	const appCSP = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
	const temporalCSP = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		if strings.HasPrefix(r.URL.Path, temporalui.PublicPath+"/") {
			h.Set("Content-Security-Policy", temporalCSP)
		} else {
			h.Set("Content-Security-Policy", appCSP)
		}
		next.ServeHTTP(w, r)
	})
}

// ---------------------------------------------------------------- auth pages

// safeNext only allows same-origin relative redirects
func safeNext(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\") {
		return "/dashboard"
	}
	return next
}

// HandleLoginPage renders the sign-in page
func (u *UIHandler) HandleLoginPage(w http.ResponseWriter, r *http.Request) {
	next := safeNext(r.URL.Query().Get("next"))
	if u.deps.Admin.Insecure {
		http.Redirect(w, r, next, http.StatusFound)
		return
	}
	if _, err := u.deps.Admin.Authenticate(r); err == nil {
		http.Redirect(w, r, next, http.StatusFound)
		return
	}

	tmpl, err := template.ParseFS(Content, "templates/login.html")
	if err != nil {
		http.Error(w, fmt.Sprintf("Template rendering error: %v", err), http.StatusInternalServerError)
		return
	}
	messages := map[string]string{
		"not_authorized": "Your account is not permitted to administer this server.",
		"failed":         "Sign-in failed. Please try again.",
		"expired":        "The sign-in attempt expired. Please try again.",
		"denied":         "Sign-in was cancelled at the identity provider.",
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = tmpl.ExecuteTemplate(w, "login", map[string]any{
		"Title":   "Sign in",
		"Next":    next,
		"Error":   messages[r.URL.Query().Get("error")],
		"Version": u.deps.Version,
		"NoOIDC":  u.deps.OIDC == nil,
	})
}

// HandleAuthLogin starts the OIDC authorization-code flow
func (u *UIHandler) HandleAuthLogin(w http.ResponseWriter, r *http.Request) {
	next := safeNext(r.URL.Query().Get("next"))
	if u.deps.Admin.Insecure {
		http.Redirect(w, r, next, http.StatusFound)
		return
	}
	if u.deps.OIDC == nil {
		http.Error(w, "OIDC is not configured", http.StatusServiceUnavailable)
		return
	}
	state, err1 := auth.NewRandomToken()
	nonce, err2 := auth.NewRandomToken()
	if err1 != nil || err2 != nil {
		http.Error(w, "failed to start login", http.StatusInternalServerError)
		return
	}
	stateCookie, err := u.deps.TokenManager.CreateLoginState(state, nonce, next)
	if err != nil {
		http.Error(w, "failed to start login", http.StatusInternalServerError)
		return
	}
	auth.SetLoginStateCookie(w, stateCookie, u.cookieOpts)
	http.Redirect(w, r, u.deps.OIDC.AuthCodeURL(state, nonce), http.StatusFound)
}

// HandleAuthCallback completes the OIDC flow and establishes the session cookie
func (u *UIHandler) HandleAuthCallback(w http.ResponseWriter, r *http.Request) {
	fail := func(reason string) {
		auth.ClearLoginStateCookie(w, u.cookieOpts)
		http.Redirect(w, r, "/login?error="+reason, http.StatusFound)
	}
	if u.deps.OIDC == nil {
		http.Error(w, "OIDC is not configured", http.StatusServiceUnavailable)
		return
	}
	if q := r.URL.Query(); q.Get("error") != "" {
		slog.Warn("OIDC provider returned an error", "error", q.Get("error"), "description", q.Get("error_description"))
		fail("denied")
		return
	}

	cookie, err := r.Cookie(auth.LoginStateCookieName)
	if err != nil || cookie.Value == "" {
		fail("expired")
		return
	}
	state, err := u.deps.TokenManager.ValidateLoginState(cookie.Value)
	if err != nil {
		fail("expired")
		return
	}
	if r.URL.Query().Get("state") != state.State {
		slog.Warn("OIDC state mismatch")
		fail("failed")
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		fail("failed")
		return
	}

	identity, err := u.deps.OIDC.Exchange(r.Context(), code, state.Nonce)
	if err != nil {
		if errors.Is(err, auth.ErrNotAuthorized) {
			slog.Warn("OIDC login rejected by allow-list")
			fail("not_authorized")
			return
		}
		slog.Error("OIDC code exchange failed", "error", err)
		fail("failed")
		return
	}

	session, expires, err := u.deps.TokenManager.CreateSession(identity, u.Config.Auth.SessionTTL)
	if err != nil {
		slog.Error("Failed to create session", "error", err)
		fail("failed")
		return
	}
	auth.ClearLoginStateCookie(w, u.cookieOpts)
	auth.SetSessionCookie(w, session, expires, u.cookieOpts)
	slog.Info("Admin signed in", "subject", identity.Subject, "email", identity.Email)
	http.Redirect(w, r, safeNext(state.Next), http.StatusFound)
}

// HandleLogout clears the session (called via fetch from the UI)
func (u *UIHandler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	auth.ClearSessionCookie(w, u.cookieOpts)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"logged_out"}`))
}

// ---------------------------------------------------------------- pages

func (u *UIHandler) renderPage(w http.ResponseWriter, r *http.Request, pageTemplate string, data map[string]interface{}) {
	tmpl, err := template.New("layout").Funcs(template.FuncMap{
		"formatBytes":  formatBytes,
		"formatUBytes": func(b uint64) string { return formatBytes(int64(b)) },
		"formatTime":   formatTime,
		"since":        since,
		"uptime":       uptime,
	}).ParseFS(Content, "templates/layout.html", "templates/partials/*.html", "templates/"+pageTemplate)

	if err != nil {
		http.Error(w, fmt.Sprintf("Template rendering error: %v", err), http.StatusInternalServerError)
		return
	}

	if p := auth.PrincipalFrom(r.Context()); p != nil {
		data["User"] = p.Display()
	}
	data["InsecureAuth"] = u.deps.Admin.Insecure
	data["TemporalUI"] = u.temporalProxy != nil
	data["TemporalUIPath"] = temporalui.PublicPath + "/"
	data["Version"] = u.deps.Version

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		http.Error(w, fmt.Sprintf("Template execution error: %v", err), http.StatusInternalServerError)
	}
}

func (u *UIHandler) HandleDashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var agents []*db.Agent
	var targets []*db.BackupTarget
	var jobs []*db.BackupJob
	var runs []*db.BackupRun

	if u.DB != nil {
		agents, _ = u.DB.ListAgents(ctx)
		targets, _ = u.DB.ListTargets(ctx)
		jobs, _ = u.DB.ListJobs(ctx)
		runs, _ = u.DB.ListRuns(ctx, 10)
	}
	onlineCount := 0
	now := time.Now()
	for _, a := range agents {
		if agenthealth.EffectiveStatus(a, now) == db.AgentStatusOnline {
			onlineCount++
		}
	}

	var totalDedup float64 = 0
	dedupCount := 0
	for _, run := range runs {
		if run.DedupRatio > 0 {
			totalDedup += run.DedupRatio
			dedupCount++
		}
	}
	avgDedup := 1.00
	if dedupCount > 0 {
		avgDedup = totalDedup / float64(dedupCount)
	}

	u.renderPage(w, r, "dashboard.html", map[string]interface{}{
		"Title":            "Dashboard",
		"ActiveNav":        "dashboard",
		"AgentCount":       len(agents),
		"OnlineAgentCount": onlineCount,
		"TargetCount":      len(targets),
		"JobCount":         len(jobs),
		"AvgDedup":         fmt.Sprintf("%.2f", avgDedup),
		"RecentRuns":       runs,
	})
}

func (u *UIHandler) HandleAgents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var agents []*db.Agent
	if u.DB != nil {
		agents, _ = u.DB.ListAgents(ctx)
	}
	// The stored status only changes on heartbeats, so a vanished agent stays
	// "online" in the row; the display uses the heartbeat age instead
	now := time.Now()
	stale := map[uuid.UUID]bool{}
	for _, a := range agents {
		stale[a.ID] = agenthealth.Stale(a, now)
	}

	u.renderPage(w, r, "agents.html", map[string]interface{}{
		"Title":     "Agents",
		"ActiveNav": "agents",
		"Agents":    agents,
		"Stale":     stale,
	})
}

// HandleAgentDetail renders the status page of one agent: connectivity, alerts,
// the inventory summary it sends with heartbeats (credential profile names, client
// tools, disk space), the stored full inventory (type-specific resources), its jobs
// and recent runs. The page's Refresh and Logs buttons reach the agent through the
// API (Temporal activities on the agent's queue).
func (u *UIHandler) HandleAgentDetail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil || u.DB == nil {
		http.NotFound(w, r)
		return
	}
	agent, err := u.DB.GetAgentByID(ctx, id)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}
	now := time.Now()
	var jobs []*db.BackupJob
	if all, err := u.DB.ListJobs(ctx); err == nil {
		for _, j := range all {
			if j.AgentID == agent.ID {
				jobs = append(jobs, j)
			}
		}
	}
	last, _ := u.DB.LatestRunByJob(ctx)
	for _, j := range jobs {
		j.LastRun = last[j.ID]
	}
	runs, _ := u.DB.ListRunsByAgent(ctx, agent.ID, 20)
	alerts := agenthealth.Evaluate(agenthealth.Input{Agent: agent, Jobs: jobs, LastRuns: last, ServerVersion: u.deps.Version, Now: now})

	u.renderPage(w, r, "agent_detail.html", map[string]interface{}{
		"Title":     agent.Hostname,
		"ActiveNav": "agents",
		"Agent":     agent,
		"Status":    agenthealth.EffectiveStatus(agent, now),
		"Stale":     agenthealth.Stale(agent, now),
		"Alerts":    alerts,
		"Summary":   agenthealth.Summary(agent),
		"Detail":    agenthealth.Detail(agent),
		"Jobs":      jobs,
		"Runs":      runs,
	})
}

// HandleOnboarding renders the guided flow that installs an agent and creates its
// first backup jobs (agent type → platform → install → wait for the enrollment →
// backup type → target → contents → schedule → review, then a summary). The page
// keeps its state in the URL; existing agents and targets are listed for the
// "existing agent" shortcut and the target step.
func (u *UIHandler) HandleOnboarding(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var agents []*db.Agent
	var targets []*db.BackupTarget
	if u.DB != nil {
		agents, _ = u.DB.ListAgents(ctx)
		targets, _ = u.DB.ListTargets(ctx)
	}
	u.renderPage(w, r, "onboarding.html", map[string]interface{}{
		"Title":     "Set up a new server",
		"ActiveNav": "onboarding",
		"Timezone":  u.timezone(),
		"Agents":    agents,
		"Targets":   targets,
	})
}

func (u *UIHandler) HandleTargets(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var targets []*db.BackupTarget
	if u.DB != nil {
		targets, _ = u.DB.ListTargets(ctx)
	}

	u.renderPage(w, r, "targets.html", map[string]interface{}{
		"Title":     "PBS Targets",
		"ActiveNav": "targets",
		"Targets":   targets,
	})
}

func (u *UIHandler) HandleJobs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var jobs []*db.BackupJob
	var agents []*db.Agent
	var targets []*db.BackupTarget

	if u.DB != nil {
		jobs, _ = u.DB.ListJobs(ctx)
		agents, _ = u.DB.ListAgents(ctx)
		targets, _ = u.DB.ListTargets(ctx)
	}
	// Every job type is listed here (filtered client-side); the newest run per job feeds
	// the last-run column and filter
	if u.DB != nil {
		if last, err := u.DB.LatestRunByJob(ctx); err == nil {
			for _, j := range jobs {
				j.LastRun = last[j.ID]
			}
		}
	}

	u.renderPage(w, r, "jobs.html", map[string]interface{}{
		"Title":         "Backup Jobs",
		"ActiveNav":     "jobs",
		"Timezone":      u.timezone(),
		"Jobs":          jobs,
		"Agents":        agents,
		"AgentProfiles": agentProfiles(agents),
		"Targets":       targets,
	})
}

// HandleKubernetes keeps old links working: cluster jobs are listed on the Backup Jobs
// page (filter type=kubernetes) and cluster agents on the Agents page
func (u *UIHandler) HandleKubernetes(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/jobs?type=kubernetes", http.StatusFound)
}

func (u *UIHandler) timezone() string {
	if u.Config != nil && u.Config.Timezone != "" {
		return u.Config.Timezone
	}
	return "UTC"
}

func (u *UIHandler) HandleRuns(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var runs []*db.BackupRun
	if u.DB != nil {
		runs, _ = u.DB.ListRuns(ctx, 100)
	}

	u.renderPage(w, r, "runs.html", map[string]interface{}{
		"Title":     "History & Runs",
		"ActiveNav": "runs",
		"Runs":      runs,
	})
}

// HandleRunDetail renders the per-run detail page; the page loads the run (with its
// type-specific details blob) from the API and renders client-side.
func (u *UIHandler) HandleRunDetail(w http.ResponseWriter, r *http.Request) {
	u.renderPage(w, r, "run_detail.html", map[string]interface{}{
		"Title":     "Run Details",
		"ActiveNav": "runs",
		"RunID":     chi.URLParam(r, "id"),
	})
}

func (u *UIHandler) HandleTokens(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var tokens []*db.EnrollmentToken
	if u.DB != nil {
		tokens, _ = u.DB.ListEnrollmentTokens(ctx)
	}
	// Used-up and expired tokens are hidden unless asked for (?all=1)
	showAll := r.URL.Query().Get("all") == "1"
	hidden := 0
	if !showAll {
		active := tokens[:0:0]
		for _, t := range tokens {
			if t.Status() == "active" {
				active = append(active, t)
			} else {
				hidden++
			}
		}
		tokens = active
	}

	u.renderPage(w, r, "tokens.html", map[string]interface{}{
		"Title":     "Enrollment Tokens",
		"ActiveNav": "tokens",
		"Tokens":    tokens,
		"ShowAll":   showAll,
		"Hidden":    hidden,
	})
}

func (u *UIHandler) HandleAPIKeys(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var keys []*db.APIKey
	if u.DB != nil {
		keys, _ = u.DB.ListAPIKeys(ctx)
	}

	u.renderPage(w, r, "apikeys.html", map[string]interface{}{
		"Title":     "API Keys",
		"ActiveNav": "apikeys",
		"Keys":      keys,
	})
}

func (u *UIHandler) HandleInstallScript(w http.ResponseWriter, r *http.Request) {
	serverURL := u.Config.PublicURL
	if serverURL == "" {
		serverURL = "http://" + r.Host
	}

	script := fmt.Sprintf(`#!/bin/sh
# FallBCK enrollment helper for the guided installation on the Agents page. It
# enrolls the installed fallbck-agent package with the server and enables its systemd
# or OpenRC service. --type database only adds a check of the database client tools
# (the agent runs database jobs itself). POSIX sh so it also runs on Alpine; install
# the package first (deb/rpm/apk or a manual install).
set -e

SERVER_URL="%s"
TOKEN=""
TYPE="files"
AGENT="fallbck-agent"
DATA_DIR="/var/lib/fallbck/agent"

while [ $# -gt 0 ]; do
  case "$1" in
    --server)
      SERVER_URL="$2"
      shift 2
      ;;
    --token)
      TOKEN="$2"
      shift 2
      ;;
    --type)
      # files (default) or database
      case "$2" in
        database|db) TYPE="database" ;;
      esac
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

if [ -z "$TOKEN" ]; then
  echo "Error: --token is required" >&2
  exit 1
fi
if [ "$(id -u)" -ne 0 ]; then
  echo "Error: run this script as root (sudo)" >&2
  exit 1
fi
if ! command -v "$AGENT" >/dev/null 2>&1; then
  echo "==> $AGENT is not installed; install the package first (deb/rpm/apk), then re-run this script" >&2
  exit 1
fi

echo "==> Enrolling $AGENT with $SERVER_URL..."
"$AGENT" enroll --server "$SERVER_URL" --token "$TOKEN" --data-dir "$DATA_DIR"

if [ "$TYPE" = "database" ]; then
  echo "==> Database client tools (the agent reports them to the server with its heartbeat):"
  "$AGENT" tools || true
fi

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemctl enable "$AGENT" >/dev/null 2>&1 || true
  systemctl restart "$AGENT"
  echo "==> $AGENT service enabled and started (logs: journalctl -u $AGENT)"
elif command -v rc-service >/dev/null 2>&1; then
  rc-update add "$AGENT" default >/dev/null 2>&1 || true
  rc-service "$AGENT" restart
  echo "==> $AGENT service enabled and started (logs: /var/log/fallbck/)"
else
  echo "==> No systemd or OpenRC found; start the agent yourself: $AGENT run --config $DATA_DIR/agent.yaml"
fi
`, serverURL)

	w.Header().Set("Content-Type", "text/x-shellscript")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(script))
}

// HandleInstallScriptPS serves the Windows installer: downloads the agent MSI from
// the GitHub release and installs it with the enrollment parameters, which makes the
// MSI enroll the agent and start the service.
func (u *UIHandler) HandleInstallScriptPS(w http.ResponseWriter, r *http.Request) {
	serverURL := u.Config.PublicURL
	if serverURL == "" {
		serverURL = "http://" + r.Host
	}
	// No backticks in the script: they would end this raw string literal
	script := fmt.Sprintf(`<#
.SYNOPSIS
  Installs the FallBCK backup agent on Windows and enrolls it with %[1]s.
.EXAMPLE
  & ([scriptblock]::Create((iwr -useb %[1]s/install-agent.ps1).Content)) -Token <enrollment token>
#>
param(
  [string]$Server = "%[1]s",
  [Parameter(Mandatory = $true)][string]$Token,
  [string]$MsiUrl = "https://github.com/osshield/fallbck/releases/latest/download/fallbck-agent_Windows_x86_64.msi",
  [string]$MsiPath = "",
  [string]$CaCert = ""
)
$ErrorActionPreference = "Stop"
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw "Run this script from an elevated (administrator) PowerShell"
}
if ($MsiPath -eq "") {
  $MsiPath = Join-Path $env:TEMP "fallbck-agent.msi"
  Write-Host "==> Downloading $MsiUrl"
  Invoke-WebRequest -UseBasicParsing -Uri $MsiUrl -OutFile $MsiPath
}
$log = Join-Path $env:TEMP "fallbck-agent-install.log"
$msiArgs = @("/i", ('"' + $MsiPath + '"'), "/qn", "/norestart", "/l*v", ('"' + $log + '"'), "SERVER_URL=$Server", "TOKEN=$Token")
if ($CaCert -ne "") { $msiArgs += "CA_CERT=$CaCert" }
Write-Host "==> Installing and enrolling the FallBCK agent (log: $log)"
$p = Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -PassThru
if ($p.ExitCode -ne 0) { throw ("msiexec failed with exit code " + $p.ExitCode + "; see " + $log) }
Write-Host "==> Done. Service status:"
& (Join-Path $env:ProgramFiles "FallBCK\fallbck-agent.exe") service status
`, serverURL)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(script))
}

// Template Format Helpers
func formatBytes(b int64) string {
	if b == 0 {
		return "0 B"
	}
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	units := []string{"KB", "MB", "GB", "TB", "PB"}
	return fmt.Sprintf("%.2f %s", float64(b)/float64(div), units[exp])
}

func formatTime(t interface{}) string {
	switch v := t.(type) {
	case time.Time:
		if v.IsZero() {
			return "-"
		}
		return v.Format("2006-01-02 15:04:05")
	case *time.Time:
		if v == nil || v.IsZero() {
			return "-"
		}
		return v.Format("2006-01-02 15:04:05")
	case string:
		return strings.TrimSpace(v)
	default:
		return fmt.Sprintf("%v", t)
	}
}

// since renders how long ago t was ("3m ago"); "-" for nil
func since(t *time.Time) string {
	if t == nil || t.IsZero() {
		return "-"
	}
	d := time.Since(*t)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh %dm ago", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%dd ago", int(d.Hours()/24))
}

// uptime renders seconds as "3d 4h" / "4h 12m" / "12m"
func uptime(seconds int64) string {
	d := time.Duration(seconds) * time.Second
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%dd %dh", int(d.Hours()/24), int(d.Hours())%24)
}

// agentProfiles lists each agent's credential profiles as "name:engine,..." for the
// job form's profile picker (data-db-profiles); the names are all the agent reports
func agentProfiles(agents []*db.Agent) map[uuid.UUID]string {
	out := map[uuid.UUID]string{}
	for _, a := range agents {
		s := agenthealth.Summary(a)
		if s == nil {
			continue
		}
		parts := make([]string, 0, len(s.Profiles))
		for _, p := range s.Profiles {
			parts = append(parts, p.Name+":"+p.Engine)
		}
		out[a.ID] = strings.Join(parts, ",")
	}
	return out
}
