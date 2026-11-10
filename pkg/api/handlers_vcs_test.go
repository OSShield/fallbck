package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/auth"
	"github.com/osshield/fallbck/pkg/config"
	"github.com/osshield/fallbck/pkg/db"
	"github.com/osshield/fallbck/pkg/secrets"
	"github.com/osshield/fallbck/pkg/vcs"
)

func TestCreateVCSJobValidation(t *testing.T) {
	r := newTestRouter()
	post := func(body string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/jobs", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(rr, req)
		return rr
	}
	agent, target, conn := "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222", "33333333-3333-3333-3333-333333333333"
	head := `{"name":"j","agent_id":"` + agent + `","target_id":"` + target + `","job_type":"vcs"`
	cases := map[string]string{
		"no config":        head + `}`,
		"no connection":    head + `,"vcs_config":{}}`,
		"with paths":       head + `,"backup_paths":["/etc"],"vcs_config":{"connection_id":"` + conn + `"}}`,
		"foreign config":   head + `,"m365_config":{},"vcs_config":{"connection_id":"` + conn + `"}}`,
		"bad group":        head + `,"vcs_config":{"connection_id":"` + conn + `","groups":["../x"]}}`,
		"http repository":  head + `,"vcs_config":{"connection_id":"` + conn + `","repositories":["http://git.example.com/a.git"]}}`,
		"fs job vcs cfg":   `{"name":"j","agent_id":"` + agent + `","target_id":"` + target + `","backup_paths":["/etc"],"vcs_config":{"connection_id":"` + conn + `"}}`,
		"m365 job vcs cfg": `{"name":"j","agent_id":"` + agent + `","target_id":"` + target + `","job_type":"m365","m365_config":{"tenant_id":"` + conn + `"},"vcs_config":{"connection_id":"` + conn + `"}}`,
	}
	for name, body := range cases {
		if rr := post(body); rr.Code != http.StatusBadRequest {
			t.Errorf("%s: expected 400, got %d: %s", name, rr.Code, rr.Body.String())
		}
	}
}

func TestCleanGitVersion(t *testing.T) {
	cases := map[string]string{
		"git version 2.43.0\n":   "2.43.0",
		"2.39.3 (Apple Git-146)": "2.39.3 (Apple Git-146)",
		"2.45\x00\x1b[31m":       "2.45[31m",
		"":                       "",
	}
	for in, want := range cases {
		if got := cleanGitVersion(in); got != want {
			t.Errorf("cleanGitVersion(%q) = %q, want %q", in, got, want)
		}
	}
	if got := cleanGitVersion(strings.Repeat("9", 100)); len(got) != 64 {
		t.Errorf("long version not capped: %d", len(got))
	}
}

// TestLiveVCSConnections runs the connection API and a VCS job against Postgres:
// sealing, redaction, the git capability gate, the provider rules, in-use
// protection and the agent credential hand-off
func TestLiveVCSConnections(t *testing.T) {
	d := liveDB(t)
	sealer, err := secrets.New(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	d.Sealer = sealer
	f := seed(t, d)
	ctx := context.Background()
	h := liveRouter(d, &auth.Principal{Kind: auth.PrincipalSession, Email: "root@example.com", Bindings: auth.AdminBindings()})

	// Create: the token is sealed at rest and never returned
	code, body := call(t, h, http.MethodPost, "/api/v1/vcs/connections", map[string]any{
		"name": "internal", "provider": "gitlab", "base_url": "https://gitlab.example.com/", "token": "glpat-secret"})
	if code != http.StatusCreated {
		t.Fatalf("create connection: %d %s", code, body)
	}
	if bytes.Contains(body, []byte("glpat-secret")) {
		t.Fatal("token returned by the API")
	}
	var gl vcs.Connection
	_ = json.Unmarshal(body, &gl)
	if gl.BaseURL != "https://gitlab.example.com" || !gl.HasToken {
		t.Errorf("created: %+v", gl)
	}
	var stored string
	if err := d.Pool.QueryRow(ctx, `SELECT token_sealed FROM vcs_connections WHERE id = $1`, gl.ID).Scan(&stored); err != nil || !secrets.IsSealed(stored) {
		t.Fatalf("token not sealed at rest: %q %v", stored, err)
	}
	// Without a token the secret stays on the agents (credential profiles)
	code, body = call(t, h, http.MethodPost, "/api/v1/vcs/connections", map[string]any{"name": "agent-side", "provider": "gitlab", "base_url": "https://gitlab.example.com"})
	if code != http.StatusCreated {
		t.Fatalf("GitLab connection without token: %d %s", code, body)
	}
	var agentSide vcs.Connection
	_ = json.Unmarshal(body, &agentSide)
	if agentSide.HasToken {
		t.Error("agent-side connection reports a token")
	}

	code, body = call(t, h, http.MethodPost, "/api/v1/vcs/connections", map[string]any{
		"name": "githost", "provider": "git", "base_url": "https://git.example.com/team"})
	if code != http.StatusCreated {
		t.Fatalf("create git connection: %d %s", code, body)
	}
	var git vcs.Connection
	_ = json.Unmarshal(body, &git)

	// A VCS job needs an agent that reported git 2.31+
	gitJob := map[string]any{"name": "git-repos", "agent_id": f.agentA.ID, "target_id": f.targetA.ID, "job_type": "vcs",
		"vcs_config": map[string]any{"connection_id": git.ID, "repositories": []string{"https://git.example.com/team/app.git"}}}
	if code, body := call(t, h, http.MethodPost, "/api/v1/jobs", gitJob); code != http.StatusBadRequest || !strings.Contains(string(body), "git") {
		t.Fatalf("job on an agent without git: %d %s", code, body)
	}
	if _, err := d.UpdateAgentHeartbeat(ctx, f.agentA.ID, db.AgentStatusOnline, db.AgentCapabilities{GitVersion: "2.43.0", GitLFS: true}); err != nil {
		t.Fatal(err)
	}
	agent, _ := d.GetAgentByID(ctx, f.agentA.ID, db.Unscoped)
	if agent.GitVersion != "2.43.0" || !agent.GitLFS {
		t.Fatalf("git capability not stored: %+v", agent)
	}
	code, body = call(t, h, http.MethodPost, "/api/v1/jobs", gitJob)
	if code != http.StatusCreated {
		t.Fatalf("create vcs job: %d %s", code, body)
	}
	var createdGit db.BackupJob
	_ = json.Unmarshal(body, &createdGit)
	loaded, err := d.GetJobByID(ctx, createdGit.ID, db.Unscoped)
	if err != nil || !loaded.IsVCS() || loaded.VCSConfig == nil || loaded.VCSConfig.ConnectionID != git.ID || len(loaded.VCSConfig.Repositories) != 1 {
		t.Fatalf("stored job: %+v %v", loaded, err)
	}
	if loaded.BackupID != "" || loaded.Summary() != "1 repository" {
		t.Errorf("backup_id %q, summary %q", loaded.BackupID, loaded.Summary())
	}

	// Provider rules: a git connection takes repositories below its URL only
	outside := map[string]any{"name": "git-outside", "agent_id": f.agentA.ID, "target_id": f.targetA.ID, "job_type": "vcs",
		"vcs_config": map[string]any{"connection_id": git.ID, "repositories": []string{"https://git.example.com/other/app.git"}}}
	if code, body := call(t, h, http.MethodPost, "/api/v1/jobs", outside); code != http.StatusBadRequest {
		t.Errorf("repository outside the connection URL: %d %s", code, body)
	}

	// GitLab jobs need an agent that reports the gitlab provider (older agents only
	// list git repositories)
	glJob := map[string]any{"name": "repos-api", "agent_id": f.agentA.ID, "target_id": f.targetA.ID, "job_type": "vcs",
		"vcs_config": map[string]any{"connection_id": gl.ID, "groups": []string{"platform"}}}
	if code, body := call(t, h, http.MethodPost, "/api/v1/jobs", glJob); code != http.StatusBadRequest || !strings.Contains(string(body), "update the agent") {
		t.Errorf("GitLab job on an agent without the provider: %d %s", code, body)
	}
	if _, err := d.UpdateAgentHeartbeat(ctx, f.agentA.ID, db.AgentStatusOnline, db.AgentCapabilities{GitVersion: "2.43.0", GitLFS: true, VCSProviders: vcs.AgentProviders}); err != nil {
		t.Fatal(err)
	}
	code, body = call(t, h, http.MethodPost, "/api/v1/jobs", glJob)
	if code != http.StatusCreated {
		t.Fatalf("GitLab job: %d %s", code, body)
	}
	var glCreated db.BackupJob
	_ = json.Unmarshal(body, &glCreated)
	if code, body := call(t, h, http.MethodDelete, "/api/v1/jobs/"+glCreated.ID.String(), nil); code >= 300 {
		t.Fatalf("delete GitLab job: %d %s", code, body)
	}
	// The connection and profile rules still apply
	glJob["vcs_config"] = map[string]any{"connection_id": agentSide.ID, "groups": []string{"platform"}}
	if code, body := call(t, h, http.MethodPost, "/api/v1/jobs", glJob); code != http.StatusBadRequest || !strings.Contains(string(body), "profile") {
		t.Errorf("job on a tokenless connection without a profile: %d %s", code, body)
	}

	// The rest of the GitLab behaviour runs on jobs stored directly
	storeJob := func(name string, conn uuid.UUID, profile string) *db.BackupJob {
		t.Helper()
		j := &db.BackupJob{Name: name, AgentID: f.agentA.ID, TargetID: f.targetA.ID, JobType: db.JobTypeVCS,
			VCSConfig: &vcs.Spec{ConnectionID: conn, Groups: []string{"platform"}, Profile: profile}}
		if err := d.CreateJob(ctx, j); err != nil {
			t.Fatal(err)
		}
		return j
	}
	created := storeJob("repos", gl.ID, "")
	storeJob("repos-agent-side", agentSide.ID, "gitlab-internal")
	// A job naming a profile never gets the server-held token, even when there is one
	ownProfile := storeJob("repos-own-profile", gl.ID, "gitlab-internal")

	// In use: no delete, no provider change, no base URL that drops a job's repository
	if code, _ := call(t, h, http.MethodDelete, "/api/v1/vcs/connections/"+gl.ID.String(), nil); code != http.StatusConflict {
		t.Errorf("delete in-use connection: %d", code)
	}
	if code, body := call(t, h, http.MethodPut, "/api/v1/vcs/connections/"+gl.ID.String(), map[string]any{"name": "internal", "provider": "git", "base_url": "https://gitlab.example.com"}); code != http.StatusConflict {
		t.Errorf("provider change on in-use connection: %d %s", code, body)
	}
	if code, body := call(t, h, http.MethodPut, "/api/v1/vcs/connections/"+git.ID.String(), map[string]any{"name": "githost", "provider": "git", "base_url": "https://git.example.com/elsewhere"}); code != http.StatusConflict {
		t.Errorf("base URL that excludes a job's repository: %d %s", code, body)
	}
	if code, body := call(t, h, http.MethodPut, "/api/v1/vcs/connections/"+gl.ID.String(), map[string]any{"name": "internal", "provider": "gitlab", "base_url": "https://gitlab.example.com", "clear_token": true}); code != http.StatusConflict || !strings.Contains(string(body), "repos") {
		t.Errorf("removing the token a job relies on: %d %s", code, body)
	}

	// Update with a blank token keeps the stored one (and its expiry)
	expires := time.Date(2099, 1, 31, 0, 0, 0, 0, time.UTC)
	if err := d.SetConnectionTokenExpiry(ctx, gl.ID, &expires); err != nil {
		t.Fatal(err)
	}
	if code, body := call(t, h, http.MethodPut, "/api/v1/vcs/connections/"+gl.ID.String(), map[string]any{"name": "internal-renamed", "provider": "gitlab", "base_url": "https://gitlab.example.com"}); code != http.StatusOK {
		t.Fatalf("rename: %d %s", code, body)
	}
	again, err := d.GetConnectionByID(ctx, gl.ID, db.Unscoped)
	if err != nil || again.Token != "glpat-secret" || again.Name != "internal-renamed" || again.TokenExpires == nil || !again.TokenExpires.Equal(expires) || again.Jobs != 2 {
		t.Fatalf("after rename: %+v %v", again, err)
	}

	// The agent gets the credentials with a ticket of a VCS job only
	tm := auth.NewTokenManager("test-secret-key-must-be-very-long-123456")
	ticket, err := tm.CreateBackupTicket(auth.BackupTicketClaims{JobID: created.ID, AgentID: f.agentA.ID, TargetID: f.targetA.ID, BackupType: "host", BackupID: "vcs-internal", BackupTime: time.Now().Unix()}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	api := NewServerAPI(d, nil, config.DefaultServerConfig(), tm, nil)
	fetch := func(ticket string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/vcs-credentials", nil)
		req.Header.Set(BackupTicketHeader, ticket)
		req = req.WithContext(auth.WithAgent(req.Context(), &auth.AgentClaims{AgentID: f.agentA.ID}))
		rr := httptest.NewRecorder()
		api.HandleVCSCredentials(rr, req)
		return rr
	}
	rr := fetch(ticket)
	var creds vcs.Credentials
	if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &creds) != nil || creds.Token != "glpat-secret" || creds.Provider != vcs.ProviderGitLab {
		t.Fatalf("credentials: %d %s", rr.Code, rr.Body.String())
	}
	profileTicket, _ := tm.CreateBackupTicket(auth.BackupTicketClaims{JobID: ownProfile.ID, AgentID: f.agentA.ID, TargetID: f.targetA.ID, BackupType: "host", BackupID: "vcs-internal", BackupTime: time.Now().Unix()}, time.Hour)
	creds = vcs.Credentials{}
	if rr = fetch(profileTicket); rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &creds) != nil || creds.Token != "" || creds.BaseURL != "https://gitlab.example.com" {
		t.Errorf("credentials for a profile job must carry no token: %d %s", rr.Code, rr.Body.String())
	}
	fsTicket, _ := tm.CreateBackupTicket(auth.BackupTicketClaims{JobID: f.jobA.ID, AgentID: f.agentA.ID, TargetID: f.targetA.ID, BackupType: "host", BackupID: "x", BackupTime: time.Now().Unix()}, time.Hour)
	if rr = fetch(fsTicket); rr.Code != http.StatusForbidden {
		t.Errorf("credentials for a filesystem job's ticket: %d %s", rr.Code, rr.Body.String())
	}

	// A git connection test needs no network
	code, body = call(t, h, http.MethodPost, "/api/v1/vcs/connections/"+git.ID.String()+"/test", nil)
	if code != http.StatusOK || !strings.Contains(string(body), `"tested":false`) {
		t.Errorf("git connection test: %d %s", code, body)
	}
	code, body = call(t, h, http.MethodPost, "/api/v1/vcs/connections/"+agentSide.ID.String()+"/test", nil)
	if code != http.StatusOK || !strings.Contains(string(body), `"tested":false`) {
		t.Errorf("tokenless connection test: %d %s", code, body)
	}

	// Scoped operator: a connection outside the scope is invisible
	scoped := &auth.Principal{Kind: auth.PrincipalSession, Email: "op@example.com",
		Bindings: []auth.Binding{{Role: auth.RoleOperator, Permissions: auth.BuiltinRoles()[auth.RoleOperator], Selector: db.MustSelector("team=a")}}}
	hs := liveRouter(d, scoped)
	if code, _ := call(t, hs, http.MethodGet, "/api/v1/vcs/connections/"+gl.ID.String(), nil); code != http.StatusNotFound {
		t.Errorf("unlabelled connection visible to a scoped operator: %d", code)
	}
}

// TestLiveHeartbeatListsVCSJobs: the heartbeat answer carries exactly the agent's
// VCS jobs, and an empty list (not an absent field) for an agent without any
func TestLiveHeartbeatListsVCSJobs(t *testing.T) {
	d := liveDB(t)
	f := seed(t, d)
	ctx := context.Background()
	conn := &vcs.Connection{Name: "githost", Provider: vcs.ProviderGit, BaseURL: "https://git.example.com"}
	if err := d.CreateConnection(ctx, conn); err != nil {
		t.Fatal(err)
	}
	job := &db.BackupJob{Name: "repos", AgentID: f.agentA.ID, TargetID: f.targetA.ID, JobType: db.JobTypeVCS,
		VCSConfig: &vcs.Spec{ConnectionID: conn.ID, Repositories: []string{"https://git.example.com/a.git"}}}
	if err := d.CreateJob(ctx, job); err != nil {
		t.Fatal(err)
	}
	api := NewServerAPI(d, nil, config.DefaultServerConfig(), auth.NewTokenManager("test-secret-key-must-be-very-long-123456"), nil)
	beat := func(agent uuid.UUID) *[]uuid.UUID {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/agents/heartbeat", strings.NewReader(`{"status":"online"}`))
		req = req.WithContext(auth.WithAgent(req.Context(), &auth.AgentClaims{AgentID: agent}))
		rr := httptest.NewRecorder()
		api.HandleAgentHeartbeat(rr, req)
		var resp HeartbeatResponse
		if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &resp) != nil {
			t.Fatalf("heartbeat: %d %s", rr.Code, rr.Body.String())
		}
		return resp.VCSJobs
	}
	if got := beat(f.agentA.ID); got == nil || len(*got) != 1 || (*got)[0] != job.ID {
		t.Errorf("agent A: %v", got)
	}
	if got := beat(f.agentB.ID); got == nil || len(*got) != 0 {
		t.Errorf("agent B must get an empty list, got %v", got)
	}
}

// TestLiveVCSGitHubApp: an App connection keeps its key sealed, mints a token per run
// limited to what the job reads, and refuses what an App can't back up
func TestLiveVCSGitHubApp(t *testing.T) {
	d := liveDB(t)
	sealer, err := secrets.New(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	d.Sealer = sealer
	f := seed(t, d)
	ctx := context.Background()
	h := liveRouter(d, &auth.Principal{Kind: auth.PrincipalSession, Email: "root@example.com", Bindings: auth.AdminBindings()})

	var perms map[string]string
	gh := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v3/app":
			_, _ = w.Write([]byte(`{"slug":"fallbck-backup"}`))
		case "/api/v3/app/installations/9/access_tokens":
			var body struct{ Permissions map[string]string }
			_ = json.NewDecoder(r.Body).Decode(&body)
			perms = body.Permissions
			_, _ = w.Write([]byte(`{"token":"ghs_minted","expires_at":"` + time.Now().Add(time.Hour).UTC().Format(time.RFC3339) + `"}`))
		case "/api/v3/installation/repositories":
			_, _ = w.Write([]byte(`{"total_count":3}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer gh.Close()
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: gh.Certificate().Raw}))
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))

	code, body := call(t, h, http.MethodPost, "/api/v1/vcs/connections", map[string]any{"name": "gh-app", "provider": "github", "base_url": gh.URL,
		"auth_type": "github_app", "app_id": 5, "installation_id": 9, "app_key": pemKey, "ca_pem": caPEM})
	if code != http.StatusCreated {
		t.Fatalf("create App connection: %d %s", code, body)
	}
	if bytes.Contains(body, []byte("PRIVATE KEY")) {
		t.Fatal("App key returned by the API")
	}
	var app vcs.Connection
	_ = json.Unmarshal(body, &app)
	if app.AuthType != vcs.AuthGitHubApp || !app.HasToken || app.AppID != 5 || app.InstallationID != 9 {
		t.Errorf("created %+v", app)
	}
	var stored string
	if err := d.Pool.QueryRow(ctx, `SELECT app_key_sealed FROM vcs_connections WHERE id = $1`, app.ID).Scan(&stored); err != nil || !secrets.IsSealed(stored) {
		t.Fatalf("App key not sealed at rest: %v", err)
	}
	// A blank key on update keeps the stored one
	if code, body := call(t, h, http.MethodPut, "/api/v1/vcs/connections/"+app.ID.String(), map[string]any{"name": "gh-app", "provider": "github", "base_url": gh.URL,
		"auth_type": "github_app", "app_id": 5, "installation_id": 9, "ca_pem": caPEM}); code != http.StatusOK {
		t.Fatalf("update without key: %d %s", code, body)
	}
	if again, err := d.GetConnectionByID(ctx, app.ID, db.Unscoped); err != nil || again.AppKey != strings.TrimSpace(pemKey) {
		t.Fatalf("key lost on update: %v", err)
	}

	code, body = call(t, h, http.MethodPost, "/api/v1/vcs/connections/"+app.ID.String()+"/test", nil)
	if code != http.StatusOK || !strings.Contains(string(body), `"tested":true`) || !strings.Contains(string(body), "app fallbck-backup") {
		t.Errorf("App connection test: %d %s", code, body)
	}

	// Stars and gists need a user: refused on job creation
	if _, err := d.UpdateAgentHeartbeat(ctx, f.agentA.ID, db.AgentStatusOnline, db.AgentCapabilities{GitVersion: "2.43.0", VCSProviders: vcs.AgentProviders}); err != nil {
		t.Fatal(err)
	}
	starred := map[string]any{"name": "stars", "agent_id": f.agentA.ID, "target_id": f.targetA.ID, "job_type": "vcs",
		"vcs_config": map[string]any{"connection_id": app.ID, "starred": true}}
	if code, body := call(t, h, http.MethodPost, "/api/v1/jobs", starred); code != http.StatusBadRequest || !strings.Contains(string(body), "GitHub App") {
		t.Errorf("starred job on an App connection: %d %s", code, body)
	}

	// The agent gets a fresh token, limited to the job's reads, never the key
	job := &db.BackupJob{Name: "acme", AgentID: f.agentA.ID, TargetID: f.targetA.ID, JobType: db.JobTypeVCS,
		VCSConfig: &vcs.Spec{ConnectionID: app.ID, Groups: []string{"acme"}, Workloads: vcs.Workloads{Metadata: true}}}
	if err := d.CreateJob(ctx, job); err != nil {
		t.Fatal(err)
	}
	tm := auth.NewTokenManager("test-secret-key-must-be-very-long-123456")
	ticket, _ := tm.CreateBackupTicket(auth.BackupTicketClaims{JobID: job.ID, AgentID: f.agentA.ID, TargetID: f.targetA.ID, BackupType: "host", BackupID: "vcs-gh-app", BackupTime: time.Now().Unix()}, time.Hour)
	api := NewServerAPI(d, nil, config.DefaultServerConfig(), tm, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/vcs-credentials", nil)
	req.Header.Set(BackupTicketHeader, ticket)
	req = req.WithContext(auth.WithAgent(req.Context(), &auth.AgentClaims{AgentID: f.agentA.ID}))
	rr := httptest.NewRecorder()
	api.HandleVCSCredentials(rr, req)
	var creds vcs.Credentials
	if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &creds) != nil || strings.Contains(rr.Body.String(), "PRIVATE KEY") {
		t.Fatalf("credentials: %d %s", rr.Code, rr.Body.String())
	}
	if creds.Token != "ghs_minted" || creds.Username != vcs.GitHubAppUsername || creds.ExpiresAt == nil || creds.AuthType != vcs.AuthGitHubApp {
		t.Errorf("credentials %+v", creds)
	}
	if perms["contents"] != "read" || perms["issues"] != "read" || len(perms) != 4 {
		t.Errorf("token permissions %v", perms)
	}

	// A token connection whose job backs up stars can't switch to an App
	code, body = call(t, h, http.MethodPost, "/api/v1/vcs/connections", map[string]any{"name": "gh-token", "provider": "github", "base_url": "https://github.com", "token": "ghp_x"})
	if code != http.StatusCreated {
		t.Fatalf("token connection: %d %s", code, body)
	}
	var tok vcs.Connection
	_ = json.Unmarshal(body, &tok)
	if err := d.CreateJob(ctx, &db.BackupJob{Name: "stars", AgentID: f.agentA.ID, TargetID: f.targetA.ID, JobType: db.JobTypeVCS,
		VCSConfig: &vcs.Spec{ConnectionID: tok.ID, Starred: true}}); err != nil {
		t.Fatal(err)
	}
	if code, body := call(t, h, http.MethodPut, "/api/v1/vcs/connections/"+tok.ID.String(), map[string]any{"name": "gh-token", "provider": "github", "base_url": "https://github.com",
		"auth_type": "github_app", "app_id": 5, "installation_id": 9, "app_key": pemKey}); code != http.StatusConflict || !strings.Contains(string(body), "stars") {
		t.Errorf("switch to an App under a starred job: %d %s", code, body)
	}
}
