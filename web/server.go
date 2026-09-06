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
		"formatBytes": formatBytes,
		"formatTime":  formatTime,
	}).ParseFS(Content, "templates/layout.html", "templates/"+pageTemplate)

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
	for _, a := range agents {
		if a.Status == db.AgentStatusOnline {
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

	u.renderPage(w, r, "agents.html", map[string]interface{}{
		"Title":     "Agents",
		"ActiveNav": "agents",
		"Agents":    agents,
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
	// Kubernetes jobs and agents live on their own page
	jobs = filterJobs(jobs, func(j *db.BackupJob) bool { return !j.IsKubernetes() })
	agents = filterAgents(agents, func(a *db.Agent) bool { return a.AgentType != db.AgentTypeKubernetes })

	u.renderPage(w, r, "jobs.html", map[string]interface{}{
		"Title":     "Backup Jobs",
		"ActiveNav": "jobs",
		"Timezone":  u.timezone(),
		"Jobs":      jobs,
		"Agents":    agents,
		"Targets":   targets,
	})
}

// HandleKubernetes renders the Kubernetes backup section (cluster jobs + agents)
func (u *UIHandler) HandleKubernetes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var jobs []*db.BackupJob
	var agents []*db.Agent
	var targets []*db.BackupTarget

	if u.DB != nil {
		jobs, _ = u.DB.ListJobs(ctx)
		agents, _ = u.DB.ListAgents(ctx)
		targets, _ = u.DB.ListTargets(ctx)
	}
	jobs = filterJobs(jobs, func(j *db.BackupJob) bool { return j.IsKubernetes() })
	agents = filterAgents(agents, func(a *db.Agent) bool { return a.AgentType == db.AgentTypeKubernetes })

	u.renderPage(w, r, "kubernetes.html", map[string]interface{}{
		"Title":     "Kubernetes",
		"ActiveNav": "kubernetes",
		"Timezone":  u.timezone(),
		"Jobs":      jobs,
		"Agents":    agents,
		"Targets":   targets,
	})
}

func (u *UIHandler) timezone() string {
	if u.Config != nil && u.Config.Timezone != "" {
		return u.Config.Timezone
	}
	return "UTC"
}

func filterJobs(in []*db.BackupJob, keep func(*db.BackupJob) bool) []*db.BackupJob {
	out := in[:0]
	for _, j := range in {
		if keep(j) {
			out = append(out, j)
		}
	}
	return out
}

func filterAgents(in []*db.Agent, keep func(*db.Agent) bool) []*db.Agent {
	out := in[:0]
	for _, a := range in {
		if keep(a) {
			out = append(out, a)
		}
	}
	return out
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

	u.renderPage(w, r, "tokens.html", map[string]interface{}{
		"Title":     "Enrollment Tokens",
		"ActiveNav": "tokens",
		"Tokens":    tokens,
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

	script := fmt.Sprintf(`#!/usr/bin/env bash
set -e

SERVER_URL="%s"
TOKEN=""
AGENT="fallbck-agent"

while [[ $# -gt 0 ]]; do
  case $1 in
    --server)
      SERVER_URL="$2"
      shift 2
      ;;
    --token)
      TOKEN="$2"
      shift 2
      ;;
    --type)
      # filesystem (default) or database
      case "$2" in database|db) AGENT="fallbck-db-agent" ;; esac
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

if [ -z "$TOKEN" ]; then
  echo "Error: --token is required"
  exit 1
fi

echo "==> Enrolling $AGENT..."
if command -v "$AGENT" &> /dev/null; then
  "$AGENT" enroll --server "$SERVER_URL" --token "$TOKEN"
else
  echo "==> $AGENT is not installed; install the package first (deb/rpm/apk), then re-run this script"
  exit 1
fi
`, serverURL)

	w.Header().Set("Content-Type", "text/x-shellscript")
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
