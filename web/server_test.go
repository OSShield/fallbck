package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/agenthealth"
	"github.com/osshield/fallbck/pkg/auth"
	"github.com/osshield/fallbck/pkg/config"
	"github.com/osshield/fallbck/pkg/db"
	"github.com/osshield/fallbck/pkg/dbbackup"
	"github.com/osshield/fallbck/pkg/inventory"
)

func TestUIRenderRoutes(t *testing.T) {
	cfg := config.DefaultServerConfig()
	// Zero Deps → insecure (development) admin auth, no OIDC, no Temporal UI
	ui := NewUIHandler(nil, cfg, Deps{Version: "test"})

	r := chi.NewRouter()
	r.Use(SecurityHeaders)
	ui.RegisterRoutes(r)

	testCases := []struct {
		path         string
		expectedCode int
		contains     string
	}{
		{"/", http.StatusFound, ""},
		{"/dashboard", http.StatusOK, "Connected Agents"},
		{"/agents", http.StatusOK, "Enrolled Agents"},
		{"/targets", http.StatusOK, "PBS Targets"},
		{"/targets", http.StatusOK, `id="target-form"`},
		{"/targets", http.StatusOK, `id="clone-target-form"`},
		{"/tokens", http.StatusOK, "Used By"},
		{"/jobs", http.StatusOK, "Backup Jobs"},
		{"/jobs", http.StatusOK, `name="job_type"`},
		{"/jobs", http.StatusOK, "runs in "},
		{"/kubernetes", http.StatusFound, ""}, // cluster jobs live on the Backup Jobs page now
		{"/jobs", http.StatusOK, `name="k8s_volumes_mode"`},
		{"/jobs", http.StatusOK, `id="k8s-job-form"`},
		{"/jobs", http.StatusOK, `<option value="mssql">Microsoft SQL Server</option>`},
		{"/onboarding", http.StatusOK, `name="ms_backup_dir"`},
		{"/onboarding", http.StatusOK, `data-value="windows" data-types="files,database,m365"`},
		{"/jobs", http.StatusOK, `href="/onboarding"`},
		{"/tokens", http.StatusOK, "Show used and expired"},
		{"/tokens?all=1", http.StatusOK, "Hide used and expired"},
		{"/onboarding", http.StatusOK, `data-kind="start" data-value="existing"`},
		{"/onboarding", http.StatusOK, `data-step="existing"`},
		{"/dashboard", http.StatusOK, `href="/onboarding"`},
		{"/runs", http.StatusOK, "Duration"},
		{"/runs/00000000-0000-0000-0000-000000000000", http.StatusOK, "run-detail-root"},
		{"/agents", http.StatusOK, `href="/onboarding"`},
		{"/onboarding", http.StatusOK, "Database agent"},
		{"/onboarding", http.StatusOK, `id="onboarding"`},
		{"/onboarding", http.StatusOK, `data-kind="platform" data-value="proxmox"`},
		{"/onboarding", http.StatusOK, `data-kind="platform" data-value="docker-container"`},
		{"/onboarding", http.StatusOK, `data-step="summary"`},
		{"/onboarding", http.StatusOK, `id="job-form"`},
		{"/onboarding", http.StatusOK, `id="target-form"`},
		{"/onboarding", http.StatusOK, `name="k8s_volumes_mode"`},
		{"/onboarding", http.StatusOK, "onboarding.js"},
		{"/jobs", http.StatusOK, `id="job-docker-fields"`},
		{"/runs", http.StatusOK, "Backup Executions"},
		{"/tokens", http.StatusOK, "Enrollment Tokens"},
		{"/apikeys", http.StatusOK, "API Keys"},
		{"/access", http.StatusOK, "Add binding"},
		{"/audit", http.StatusOK, "Audit Log"},
		{"/install-agent.sh", http.StatusOK, "#!/bin/sh"},
		{"/install-agent.sh", http.StatusOK, "systemctl restart"},
		{"/install-agent.sh", http.StatusOK, "rc-service"},
		{"/install-agent.ps1", http.StatusOK, "msiexec.exe"},
		{"/login", http.StatusFound, ""},      // insecure mode skips the login page
		{"/auth/login", http.StatusFound, ""}, // ... and the OIDC redirect
		{"/temporal/", http.StatusNotFound, ""},
	}

	for _, tc := range testCases {
		t.Run(tc.path, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, tc.path, nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)

			if rr.Code != tc.expectedCode {
				t.Errorf("Path %s expected status %d, got %d", tc.path, tc.expectedCode, rr.Code)
			}

			if tc.contains != "" && !strings.Contains(rr.Body.String(), tc.contains) {
				t.Errorf("Path %s response expected to contain '%s'", tc.path, tc.contains)
			}
			if rr.Code == http.StatusOK && rr.Header().Get("Content-Security-Policy") == "" {
				t.Errorf("Path %s missing CSP header", tc.path)
			}
		})
	}
}

// aliceIsAdmin binds the admin role to alice@example.com and nothing to anyone else
type aliceIsAdmin struct{}

func (aliceIsAdmin) BindingsFor(_ context.Context, email string, _ []string) ([]*db.RoleBinding, error) {
	if email != "alice@example.com" {
		return nil, nil
	}
	return []*db.RoleBinding{{Kind: db.BindingUser, Subject: email, Role: auth.RoleAdmin, Permissions: auth.AllPermissions()}}, nil
}

func (aliceIsAdmin) GetRole(context.Context, string) (*db.Role, error) { return nil, db.ErrNotFound }

func TestUIRequiresAdminWhenSecured(t *testing.T) {
	cfg := config.DefaultServerConfig()
	cfg.PublicURL = "https://backup.example.com"
	tm := auth.NewTokenManager("test-secret-key-must-be-very-long-123456")
	admin := auth.NewAdminAuth(tm, nil, false)
	admin.RBAC = auth.NewResolver(aliceIsAdmin{}, time.Minute)
	ui := NewUIHandler(nil, cfg, Deps{TokenManager: tm, Admin: admin})

	r := chi.NewRouter()
	ui.RegisterRoutes(r)

	// Browser navigation without a session → login redirect carrying the original path
	req := httptest.NewRequest(http.MethodGet, "/jobs", nil)
	req.Header.Set("Accept", "text/html")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusFound || !strings.Contains(rr.Header().Get("Location"), "/auth/login?next=%2Fjobs") {
		t.Errorf("expected login redirect, got %d %s", rr.Code, rr.Header().Get("Location"))
	}

	// Login page renders (no OIDC configured → explanatory message)
	rr = httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/login?next=/jobs", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "Single sign-on is not configured") {
		t.Errorf("login page: %d %s", rr.Code, rr.Body.String())
	}

	// A valid session cookie grants access and shows the user
	session, _, err := tm.CreateSession(&auth.Identity{Subject: "s", Email: "alice@example.com"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: session})
	rr = httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "alice@example.com") {
		t.Errorf("dashboard with session: %d", rr.Code)
	}

	// A valid session without any role binding is refused
	bob, _, err := tm.CreateSession(&auth.Identity{Subject: "b", Email: "bob@example.com"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/dashboard", "/jobs", "/access"} {
		req = httptest.NewRequest(http.MethodGet, path, nil)
		req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: bob})
		rr = httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Errorf("%s without a binding: %d, want 403", path, rr.Code)
		}
	}

	// Logout clears the cookie
	req = httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: session})
	req.Header.Set(auth.CSRFHeader, auth.CSRFHeaderValue)
	rr = httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("logout: %d", rr.Code)
	}
	cleared := false
	for _, c := range rr.Result().Cookies() {
		if c.Name == auth.SessionCookieName && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("logout did not clear the session cookie")
	}

	// Public endpoints stay public
	rr = httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/install-agent.sh", nil))
	if rr.Code != http.StatusOK {
		t.Errorf("install script should be public, got %d", rr.Code)
	}
}

func TestSafeNext(t *testing.T) {
	cases := map[string]string{"": "/dashboard", "/jobs": "/jobs", "//evil.com": "/dashboard", "https://evil.com": "/dashboard", "/\\evil": "/dashboard",
		"/%09/evil.com": "/dashboard", "/\t/evil.com": "/dashboard", "/%5Cevil.com": "/dashboard", "//evil.com/%2F..": "/dashboard", "/jobs?x=1#frag": "/jobs?x=1#frag"}
	for in, want := range cases {
		if got := safeNext(in); got != want {
			t.Errorf("safeNext(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestAgentDetailRenders executes the status page template with a fully populated
// agent (summary, detail, alerts, jobs, runs) so template errors surface here
// rather than in a browser
func TestAgentDetailRenders(t *testing.T) {
	ui := NewUIHandler(nil, config.DefaultServerConfig(), Deps{Version: "1.2.0"})
	now := time.Now()
	old := now.Add(-10 * time.Minute)
	summary := inventory.Summary{
		At: now, UptimeSeconds: 262800,
		Profiles: []dbbackup.ProfileSummary{{Name: "prod", Engine: "postgresql", User: "backup", Host: "db.local"}},
		Tools:    map[string][]inventory.Tool{"postgresql": {{Name: "pg_dump", Path: "/usr/bin/pg_dump", Version: "16.3"}}},
		Spool:    &inventory.Disk{Path: "/var/spool/fallbck", FreeBytes: 100 << 20, MinFreeBytes: 1 << 30},
		Counts:   map[string]int{"containers": 3},
	}
	detail := inventory.Detail{Summary: summary, Hostname: "db1", ConfigPath: "/etc/fallbck/agent.yaml", Settings: map[string]string{"spool_dir": "/var/spool/fallbck"},
		Docker:     &inventory.DockerDetail{Version: "27.1", Containers: []inventory.DockerContainer{{Name: "web", Image: "nginx", State: "running", Project: "site"}}, Volumes: []inventory.DockerVolume{{Name: "data", Driver: "local"}}},
		Kubernetes: &inventory.KubernetesDetail{ServerVersion: "v1.31", Namespaces: []inventory.KubernetesNamespace{{Name: "default", PVCs: 2}}},
		PVE:        &inventory.PVEDetail{Version: "8.2", Node: "pve1"}}
	sj, _ := json.Marshal(summary)
	dj, _ := json.Marshal(detail)
	agent := &db.Agent{ID: uuid.New(), Hostname: "db1", AgentType: db.AgentTypeFilesystem, Version: "1.1.0", OS: "linux", Arch: "amd64", Status: db.AgentStatusOnline, LastSeenAt: &old, DBTools: true, DBEngines: []string{"postgres"}, Inventory: sj, InventoryAt: &old, InventoryDetail: dj, InventoryDetailAt: &old, TaskQueue: "agent-x"}
	job := &db.BackupJob{ID: uuid.New(), AgentID: agent.ID, Name: "nightly", Enabled: true, JobType: db.JobTypeDatabase, DBConfig: &dbbackup.Spec{Engine: "postgresql", Profile: "missing"}, ScheduleCron: "0 2 * * *"}
	job.LastRun = &db.JobLastRun{RunID: uuid.New(), Status: db.RunStatusFailed, At: old}
	run := &db.BackupRun{ID: uuid.New(), JobID: job.ID, AgentID: agent.ID, Status: db.RunStatusFailed, JobName: "nightly", ErrorMessage: "boom", CreatedAt: old}
	alerts := agenthealth.Evaluate(agenthealth.Input{Agent: agent, Jobs: []*db.BackupJob{job}, LastRuns: map[uuid.UUID]*db.JobLastRun{job.ID: job.LastRun}, ServerVersion: "1.2.0", Now: now})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/agents/"+agent.ID.String(), nil)
	ui.renderPage(rr, req, "agent_detail.html", map[string]interface{}{
		"Title": agent.Hostname, "ActiveNav": "agents", "Agent": agent,
		"Status": agenthealth.EffectiveStatus(agent, now), "Stale": true, "Alerts": alerts,
		"Summary": agenthealth.Summary(agent), "Detail": agenthealth.Detail(agent),
		"Jobs": []*db.BackupJob{job}, "Runs": []*db.BackupRun{run},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{
		"Agent is offline", "Spool directory is low on space", "Agent version is behind the server",
		`Credential profile &#34;missing&#34; is not configured`, `Last run of &#34;nightly&#34; failed`,
		"<strong>prod</strong>", "db.local", "pg_dump", "16.3", "nginx", "pve1", "v1.31", "/etc/fallbck/agent.yaml",
		"refreshAgentInventory(", "loadAgentLogs(", "agent-logs-pre", "boom", "3d 1h",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q", want)
		}
	}
	// The stored password of a profile must never be on the page (the summary has
	// no field for it; this guards against one being added)
	if strings.Contains(body, "password\"") {
		t.Error("page contains a password field")
	}
}

func TestLoginRefusalReasons(t *testing.T) {
	cases := []struct {
		id   auth.Identity
		want string
	}{
		{auth.Identity{Email: "a@example.com"}, "no_access"},
		{auth.Identity{Email: "a@example.com", EmailUnverified: true}, "email_unverified"},
		{auth.Identity{}, "no_email"},
		{auth.Identity{EmailUnverified: true}, "no_email"},
	}
	for _, tc := range cases {
		if got := refusalReason(&tc.id); got != tc.want {
			t.Errorf("%+v: %s, want %s", tc.id, got, tc.want)
		}
	}

	tm := auth.NewTokenManager("test-secret-key-must-be-very-long-123456")
	ui := NewUIHandler(nil, config.DefaultServerConfig(), Deps{TokenManager: tm, Admin: auth.NewAdminAuth(tm, nil, false)})
	r := chi.NewRouter()
	ui.RegisterRoutes(r)
	for key, text := range map[string]string{"email_unverified": "marks your email address as unverified", "no_email": "sent no email address", "failed": "Sign-in failed"} {
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/login?error="+key, nil))
		if !strings.Contains(rr.Body.String(), text) {
			t.Errorf("login page for %s does not explain it (want %q)", key, text)
		}
	}
}
