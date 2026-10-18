package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/osshield/fallbck/pkg/audit"
	"github.com/osshield/fallbck/pkg/auth"
	"github.com/osshield/fallbck/pkg/config"
	"github.com/osshield/fallbck/pkg/db"
	"github.com/osshield/fallbck/pkg/pbs"
)

// Live check against PostgreSQL. Set FALLBCK_TEST_DATABASE_URL to an empty database
// the test may wipe, e.g.
//
//	docker run -d --rm -e POSTGRES_PASSWORD=test -e POSTGRES_DB=fallbck -p 127.0.0.1:55432:5432 postgres:16-alpine
//	FALLBCK_TEST_DATABASE_URL=postgres://postgres:test@127.0.0.1:55432/fallbck go test ./pkg/api -run Live
func liveDB(t *testing.T) *db.DB {
	t.Helper()
	url := os.Getenv("FALLBCK_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("FALLBCK_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatal(err)
	}
	d := &db.DB{Pool: pool}
	if err := d.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := d.SyncBuiltinRoles(ctx, auth.BuiltinRoles(), auth.BuiltinDescriptions); err != nil {
		t.Fatal(err)
	}
	return d
}

type liveFixture struct {
	agentA, agentB   *db.Agent
	targetA, targetB *db.BackupTarget
	jobA, jobB       *db.BackupJob
	runA, runB       *db.BackupRun
}

func seed(t *testing.T, d *db.DB) *liveFixture {
	t.Helper()
	ctx := context.Background()
	f := &liveFixture{}
	mk := func(team string) (*db.Agent, *db.BackupTarget, *db.BackupJob, *db.BackupRun) {
		l := db.Labels{"team": team}
		a := &db.Agent{Hostname: "host-" + team, TaskQueue: "q-" + team, Labels: l}
		if err := d.CreateAgent(ctx, a); err != nil {
			t.Fatal(err)
		}
		tg := &db.BackupTarget{Name: "pbs-" + team, TargetType: "pbs", Endpoint: "https://pbs", Datastore: "ds", AuthToken: "u@pbs!t:secret", Labels: l}
		if err := d.CreateTarget(ctx, tg); err != nil {
			t.Fatal(err)
		}
		j := &db.BackupJob{Name: "job-" + team, AgentID: a.ID, TargetID: tg.ID, BackupPaths: []string{"/etc"}, JobType: db.JobTypeFilesystem, Labels: l}
		if err := d.CreateJob(ctx, j); err != nil {
			t.Fatal(err)
		}
		run := &db.BackupRun{JobID: j.ID, AgentID: a.ID, TargetID: tg.ID, Status: db.RunStatusRunning}
		if err := d.CreateRun(ctx, run); err != nil {
			t.Fatal(err)
		}
		return a, tg, j, run
	}
	f.agentA, f.targetA, f.jobA, f.runA = mk("a")
	f.agentB, f.targetB, f.jobB, f.runB = mk("b")
	return f
}

func liveRouter(d *db.DB, p *auth.Principal) http.Handler {
	s := NewServerAPI(d, nil, config.DefaultServerConfig(), auth.NewTokenManager("test-secret-key-must-be-very-long-123456"), nil)
	r := chi.NewRouter()
	s.RegisterRoutes(r, asPrincipal(p), passthrough)
	return r
}

func call(t *testing.T, h http.Handler, method, path string, body any) (int, []byte) {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(method, path, rd))
	return rr.Code, rr.Body.Bytes()
}

func TestLiveScopedOperator(t *testing.T) {
	d := liveDB(t)
	f := seed(t, d)
	op := &auth.Principal{Kind: auth.PrincipalSession, Email: "op@example.com", Bindings: []auth.Binding{
		{Role: auth.RoleOperator, Permissions: auth.BuiltinRoles()[auth.RoleOperator], Selector: db.MustSelector("team=a")},
	}}
	h := liveRouter(d, op)

	names := func(path string, field string) []string {
		code, body := call(t, h, http.MethodGet, path, nil)
		if code != http.StatusOK {
			t.Fatalf("GET %s: %d %s", path, code, body)
		}
		var rows []map[string]any
		_ = json.Unmarshal(body, &rows)
		var out []string
		for _, r := range rows {
			out = append(out, r[field].(string))
		}
		return out
	}
	if got := names("/api/v1/jobs", "name"); !slices.Equal(got, []string{"job-a"}) {
		t.Errorf("jobs: %v", got)
	}
	if got := names("/api/v1/agents", "hostname"); !slices.Equal(got, []string{"host-a"}) {
		t.Errorf("agents: %v", got)
	}
	if got := names("/api/v1/targets", "name"); !slices.Equal(got, []string{"pbs-a"}) {
		t.Errorf("targets: %v", got)
	}
	if got := names("/api/v1/runs", "job_name"); !slices.Equal(got, []string{"job-a"}) {
		t.Errorf("runs: %v", got)
	}

	// Out of scope looks exactly like missing
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/jobs/" + f.jobB.ID.String()},
		{http.MethodGet, "/api/v1/runs/" + f.runB.ID.String()},
		{http.MethodPost, "/api/v1/runs/" + f.runB.ID.String() + "/cancel"},
		{http.MethodPost, "/api/v1/jobs/" + f.jobB.ID.String() + "/run"},
		{http.MethodDelete, "/api/v1/jobs/" + f.jobB.ID.String()},
		{http.MethodGet, "/api/v1/agents/" + f.agentB.ID.String()},
		{http.MethodGet, "/api/v1/targets/" + f.targetB.ID.String()},
	} {
		if code, body := call(t, h, c.method, c.path, nil); code != http.StatusNotFound {
			t.Errorf("%s %s: %d %s, want 404", c.method, c.path, code, body)
		}
	}
	// In scope
	if code, body := call(t, h, http.MethodGet, "/api/v1/runs/"+f.runA.ID.String(), nil); code != http.StatusOK {
		t.Errorf("own run: %d %s", code, body)
	}

	// Relabel out of scope: refused; the job keeps its labels
	job := *f.jobA
	job.Labels = db.Labels{"team": "b"}
	if code, body := call(t, h, http.MethodPut, "/api/v1/jobs/"+f.jobA.ID.String(), job); code != http.StatusForbidden {
		t.Errorf("relabel to team=b: %d %s", code, body)
	}
	// A job on another team's target: the target is not found for this principal
	job = db.BackupJob{Name: "sneaky", AgentID: f.agentA.ID, TargetID: f.targetB.ID, BackupPaths: []string{"/etc"}, Labels: db.Labels{"team": "a"}}
	if code, body := call(t, h, http.MethodPost, "/api/v1/jobs", job); code != http.StatusBadRequest || !bytes.Contains(body, []byte("target not found")) {
		t.Errorf("job on foreign target: %d %s", code, body)
	}
	// Operators do not reveal credentials, even in scope
	if code, _ := call(t, h, http.MethodGet, "/api/v1/targets/"+f.targetA.ID.String()+"/credentials", nil); code != http.StatusForbidden {
		t.Errorf("credentials as operator: %d", code)
	}
	// ...and cannot create a key ring outside their labels
	if code, _ := call(t, h, http.MethodPost, "/api/v1/keyrings", map[string]any{"name": "r", "labels": map[string]string{}}); code != http.StatusForbidden {
		t.Errorf("unscoped key ring as operator: %d", code)
	}
}

func TestLiveAuditAndKeys(t *testing.T) {
	d := liveDB(t)
	f := seed(t, d)
	ctx := context.Background()
	admin := &auth.Principal{Kind: auth.PrincipalSession, Email: "root@example.com", Bindings: auth.AdminBindings()}
	h := liveRouter(d, admin)

	job := db.BackupJob{Name: "new", AgentID: f.agentA.ID, TargetID: f.targetA.ID, BackupPaths: []string{"/srv"}, Labels: db.Labels{"team": "a"}}
	if code, body := call(t, h, http.MethodPost, "/api/v1/jobs", job); code != http.StatusCreated {
		t.Fatalf("create job: %d %s", code, body)
	}
	if code, body := call(t, h, http.MethodGet, "/api/v1/targets/"+f.targetA.ID.String()+"/credentials", nil); code != http.StatusOK {
		t.Fatalf("credentials: %d %s", code, body)
	}
	entries, err := d.ListAudit(ctx, db.AuditFilter{}, db.Unscoped)
	if err != nil {
		t.Fatal(err)
	}
	var actions []string
	for _, e := range entries {
		actions = append(actions, e.Action)
		if e.Actor != "root@example.com" {
			t.Errorf("%s actor %q", e.Action, e.Actor)
		}
	}
	for _, want := range []string{"job.create", "target.credentials"} {
		if !slices.Contains(actions, want) {
			t.Errorf("no %s audit row in %v", want, actions)
		}
	}
	// Scoped audit readers see only entries recorded with their labels
	scoped, _ := d.ListAudit(ctx, db.AuditFilter{}, db.Scope{Selectors: []db.Selector{db.MustSelector("team=b")}})
	if len(scoped) != 0 {
		t.Errorf("team=b sees %d team=a entries", len(scoped))
	}
	// Append-only
	if _, err := d.Pool.Exec(ctx, `UPDATE audit_log SET actor = 'x'`); err == nil {
		t.Error("audit_log accepted an UPDATE")
	}
	if _, err := d.Pool.Exec(ctx, `DELETE FROM audit_log`); err == nil {
		t.Error("audit_log accepted a DELETE")
	}

	// API keys: role and selector round-trip; a scoped operator cannot mint a wider key
	code, body := call(t, h, http.MethodPost, "/api/v1/apikeys", map[string]any{"name": "ci", "role": "viewer", "selector": map[string]string{"team": "a"}})
	if code != http.StatusCreated {
		t.Fatalf("create key: %d %s", code, body)
	}
	var created CreateAPIKeyResponse
	_ = json.Unmarshal(body, &created)
	key, err := auth.LookupAPIKey(ctx, d, created.RawKey)
	if err != nil || key.Role != "viewer" || key.Selector.String() != "team=a" {
		t.Fatalf("stored key: %+v %v", key, err)
	}
	if code, _ := call(t, h, http.MethodPost, "/api/v1/apikeys", map[string]any{"name": "bad", "role": "admin", "selector": map[string]string{"team": "a"}}); code != http.StatusForbidden {
		t.Errorf("admin key on a selector: %d, want 403", code)
	}
	bindings, err := auth.NewResolver(d, time.Minute).APIKey(ctx, key)
	if err != nil || len(bindings) != 1 || !slices.Contains(bindings[0].Permissions, auth.PermJobsRead) {
		t.Errorf("key bindings: %+v %v", bindings, err)
	}
}

func TestLiveBindingsAndBootstrap(t *testing.T) {
	d := liveDB(t)
	ctx := context.Background()
	created, err := d.BootstrapAdmin(ctx, "first@example.com", auth.RoleAdmin)
	if err != nil || !created {
		t.Fatalf("bootstrap on empty: %v %v", created, err)
	}
	if again, _ := d.BootstrapAdmin(ctx, "second@example.com", auth.RoleAdmin); again {
		t.Error("bootstrap ran twice")
	}
	res := auth.NewResolver(d, time.Minute)
	b, err := res.Session(ctx, "FIRST@example.com", false, nil, nil)
	if err != nil || len(b) != 1 || len(b[0].Selector) != 0 {
		t.Fatalf("first admin bindings: %+v %v", b, err)
	}
	if b, _ := res.Session(ctx, "first@example.com", true, nil, nil); len(b) != 0 {
		t.Error("an unverified email matched a user binding")
	}
	if err := d.CreateBinding(ctx, &db.RoleBinding{Kind: db.BindingGroup, Subject: "ops", Role: auth.RoleViewer, Selector: db.MustSelector("team=a")}); err != nil {
		t.Fatal(err)
	}
	if b, _ := res.Session(ctx, "nobody@example.com", false, []string{"ops"}, nil); len(b) != 1 || b[0].Selector.String() != "team=a" {
		t.Errorf("group binding: %+v", b)
	}
	all, _ := d.ListBindings(ctx)
	var adminID uuid.UUID
	for _, x := range all {
		if x.Role == auth.RoleAdmin {
			adminID = x.ID
		}
	}
	if err := d.DeleteBinding(ctx, adminID); !errors.Is(err, db.ErrLastAdmin) {
		t.Errorf("deleting the last admin: %v", err)
	}
	if err := d.DeleteRole(ctx, auth.RoleViewer); !errors.Is(err, db.ErrNotFound) {
		t.Errorf("deleting a built-in role: %v", err)
	}
}

// TestLiveScopeAgreesWithSQL is the agreement check between the two forms of the
// decision: Scope.Matches in Go and Scope.SQL in PostgreSQL
func TestLiveScopeAgreesWithSQL(t *testing.T) {
	d := liveDB(t)
	ctx := context.Background()
	objects := []db.Labels{{}, {"team": "a"}, {"team": "b"}, {"team": "a", "env": "prod"}, {"env": "prod"}, {"team": "A"}, {"fallbck.io/x": "1", "team": "a"}, {"env": "stage"}, {"team": "a", "env": "stage"}, {"team": ""}}
	sel := func(texts ...string) db.Scope {
		var out db.Scope
		for _, t := range texts {
			out.Selectors = append(out.Selectors, db.MustSelector(t))
		}
		return out
	}
	scopes := []db.Scope{
		{}, db.Unscoped,
		sel("team=a"), sel("team=a, env=prod"), sel("team=b", "env=prod"), sel("fallbck.io/x=1"), sel("team="),
		sel("team in (a, b)"), sel("team notin (a)"), sel("team!=b"), sel("team"), sel("!team"), sel("!env, team"),
		sel("team in (a, A), env notin (prod, stage)"), sel(""), sel("team in (b)", "!team"),
	}
	for _, s := range scopes {
		for _, o := range objects {
			where, args := s.SQL("$1::jsonb", []any{o.JSON()})
			var got bool
			if err := d.Pool.QueryRow(ctx, `SELECT (`+where+`) IS NOT DISTINCT FROM TRUE OR ($1::jsonb IS NULL)`, args...).Scan(&got); err != nil {
				t.Fatalf("%+v: %v", s, err)
			}
			var isNull bool
			if err := d.Pool.QueryRow(ctx, `SELECT ($1::jsonb IS NULL) OR (`+where+`) IS NULL`, args...).Scan(&isNull); err != nil || isNull {
				t.Errorf("scope %+v on %v renders NULL (%v)", s, o, err)
			}
			if want := s.Matches(o); got != want {
				t.Errorf("scope %+v on %v: SQL %v, Go %v", s, o, got, want)
			}
		}
	}
}

// TestLiveSelectorMigration upgrades bindings and API keys written by migration 022
// (label objects) to the canonical selector strings of 023
func TestLiveSelectorMigration(t *testing.T) {
	url := os.Getenv("FALLBCK_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("FALLBCK_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;
		CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`); err != nil {
		t.Fatal(err)
	}
	migrations, _ := db.LoadMigrations()
	for _, m := range migrations {
		if m.Version > 22 {
			break
		}
		if _, err := pool.Exec(ctx, m.SQL); err != nil {
			t.Fatalf("%s: %v", m.Name, err)
		}
		_, _ = pool.Exec(ctx, `INSERT INTO schema_migrations (version, name) VALUES ($1, $2)`, m.Version, m.Name)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO role_bindings (id, kind, subject, role, selector) VALUES
			(gen_random_uuid(), 'group', 'ops', 'viewer', '{"team": "a", "env": "prod", "Zone": "x"}'),
			(gen_random_uuid(), 'user', 'root@example.com', 'admin', '{}');
		INSERT INTO api_keys (id, name, key_hash, created_by, role, selector) VALUES (gen_random_uuid(), 'k', 'h', 'test', 'viewer', '{"team": "a"}')`); err != nil {
		t.Fatal(err)
	}
	d := &db.DB{Pool: pool}
	if err := d.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	bindings, err := d.ListBindings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, b := range bindings {
		got[b.Subject] = b.Selector.String()
	}
	if got["ops"] != "Zone=x, env=prod, team=a" || got["root@example.com"] != "" {
		t.Errorf("migrated selectors: %v", got)
	}
	var raw string
	_ = pool.QueryRow(ctx, `SELECT selector FROM role_bindings WHERE subject = 'ops'`).Scan(&raw)
	if raw != db.MustSelector("team=a, env=prod, Zone=x").String() {
		t.Errorf("stored %q is not the canonical form the server writes", raw)
	}
	_ = pool.QueryRow(ctx, `SELECT selector FROM api_keys`).Scan(&raw)
	if raw != "team=a" {
		t.Errorf("api key selector %q", raw)
	}
	// The unique constraint survived the type change
	if err := d.CreateBinding(ctx, &db.RoleBinding{Kind: db.BindingGroup, Subject: "ops", Role: auth.RoleViewer, Selector: db.MustSelector("env=prod, team=a, Zone=x")}); err == nil {
		t.Error("a duplicate binding was accepted after the migration")
	}
}

func TestLiveClaimBindingsAndLastSeen(t *testing.T) {
	d := liveDB(t)
	ctx := context.Background()
	if err := d.CreateBinding(ctx, &db.RoleBinding{Kind: db.BindingClaim, Subject: "roles=Backup.Operator", Role: auth.RoleOperator, Selector: db.MustSelector("team in (a, b)")}); err != nil {
		t.Fatal(err)
	}
	if err := d.CreateBinding(ctx, &db.RoleBinding{Kind: db.BindingUser, Subject: "Old@Example.com", Role: auth.RoleViewer}); err != nil {
		t.Fatal(err)
	}
	res := auth.NewResolver(d, time.Minute)
	b, err := res.Session(ctx, "x@example.com", false, nil, []string{"roles=Backup.Operator"})
	if err != nil || len(b) != 1 || b[0].Selector.String() != "team in (a, b)" {
		t.Fatalf("claim binding: %+v %v", b, err)
	}
	if b, _ := res.Session(ctx, "x@example.com", false, nil, []string{"roles=Other"}); len(b) != 0 {
		t.Error("another claim value matched")
	}

	if err := d.RecordSignIn(ctx, "old@example.com", []string{"ops"}, []string{"roles=Backup.Operator"}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Pool.Exec(ctx, `UPDATE idp_subjects SET last_seen = NOW() - interval '100 days' WHERE kind = 'user'`); err != nil {
		t.Fatal(err)
	}
	bindings, _ := d.ListBindings(ctx)
	for _, x := range bindings {
		switch x.Kind {
		case db.BindingUser:
			if x.LastSeen == nil || !x.Stale {
				t.Errorf("user binding not seen for 100 days: last_seen %v stale %v", x.LastSeen, x.Stale)
			}
		case db.BindingClaim:
			if x.LastSeen == nil || x.Stale {
				t.Errorf("claim binding just seen: last_seen %v stale %v", x.LastSeen, x.Stale)
			}
		}
	}
	seen, _ := d.ListSeenSubjects(ctx)
	if len(seen) != 3 {
		t.Errorf("seen subjects: %+v", seen)
	}

	// The API refuses claim bindings on claims the server does not read
	admin := &auth.Principal{Kind: auth.PrincipalSession, Email: "root@example.com", Bindings: auth.AdminBindings()}
	h := liveRouter(d, admin)
	if code, body := call(t, h, http.MethodPost, "/api/v1/rbac/bindings", map[string]any{"kind": "claim", "subject": "department=IT", "role": "viewer", "selector": ""}); code != http.StatusBadRequest {
		t.Errorf("unconfigured claim: %d %s", code, body)
	}
	if code, body := call(t, h, http.MethodPost, "/api/v1/rbac/bindings", map[string]any{"kind": "group", "subject": "web", "role": "viewer", "selector": "team in (web, api), !legacy"}); code != http.StatusCreated {
		t.Errorf("set-based binding: %d %s", code, body)
	}
	if code, body := call(t, h, http.MethodGet, "/api/v1/rbac/selector?q=team+in+(b,a)", nil); code != http.StatusOK || !bytes.Contains(body, []byte(`"team in (a, b)"`)) {
		t.Errorf("selector preview: %d %s", code, body)
	}
}

func TestLiveAuditPrune(t *testing.T) {
	d := liveDB(t)
	ctx := context.Background()
	if _, err := d.Pool.Exec(ctx, `INSERT INTO audit_log (at, actor_kind, actor, action) VALUES
		(NOW() - interval '400 days', 'session', 'a', 'job.create'),
		(NOW() - interval '380 days', 'session', 'b', 'job.delete'),
		(NOW() - interval '10 days', 'session', 'c', 'job.run')`); err != nil {
		t.Fatal(err)
	}
	// A failing export keeps everything
	failing := func(context.Context, []*db.AuditEntry) error { return errors.New("sink down") }
	if n, err := audit.Prune(ctx, d, 365*24*time.Hour, failing, "test"); err == nil || n != 0 {
		t.Fatalf("prune with a failing export: %d %v", n, err)
	}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	export, err := audit.NewExport(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	n, err := audit.Prune(ctx, d, 365*24*time.Hour, export, path)
	if err != nil || n != 2 {
		t.Fatalf("prune: %d %v", n, err)
	}
	data, _ := os.ReadFile(path)
	if strings.Count(string(data), "\n") != 2 || !strings.Contains(string(data), `"job.create"`) || strings.Contains(string(data), `"job.run"`) {
		t.Errorf("export file: %s", data)
	}
	left, _ := d.ListAudit(ctx, db.AuditFilter{}, db.Unscoped)
	var actions []string
	for _, e := range left {
		actions = append(actions, e.Action)
	}
	if !slices.Equal(actions, []string{"audit.prune", "job.run"}) {
		t.Errorf("left after prune: %v", actions)
	}
	if _, err := d.Pool.Exec(ctx, `DELETE FROM audit_log`); err == nil {
		t.Error("a plain DELETE got past the append-only trigger")
	}
}

func TestLiveTargetTokenCheck(t *testing.T) {
	d := liveDB(t)
	ctx := context.Background()
	answer := `{"data":{"/datastore/ds":{"Datastore.Backup":true}}}`
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(answer))
	}))
	defer srv.Close()
	sum := sha256.Sum256(srv.Certificate().Raw)
	pin := hex.EncodeToString(sum[:])
	target := &db.BackupTarget{Name: "pbs", TargetType: "pbs", Endpoint: srv.URL, Datastore: "ds", AuthToken: "fb@pbs!t:secret", Fingerprint: pin, Labels: db.Labels{"team": "a"}}
	if err := d.CreateTarget(ctx, target); err != nil {
		t.Fatal(err)
	}
	admin := &auth.Principal{Kind: auth.PrincipalSession, Email: "root@example.com", Bindings: auth.AdminBindings()}
	h := liveRouter(d, admin)
	path := "/api/v1/targets/" + target.ID.String() + "/token-check"
	auditCount := func() int {
		entries, _ := d.ListAudit(ctx, db.AuditFilter{Action: "target.token_check"}, db.Unscoped)
		return len(entries)
	}
	check := func(want string) {
		t.Helper()
		code, body := call(t, h, http.MethodPost, path, nil)
		if code != http.StatusOK || !bytes.Contains(body, []byte(`"status":"`+want+`"`)) {
			t.Fatalf("check: %d %s, want %s", code, body, want)
		}
	}

	check(pbs.TokenOK)
	check(pbs.TokenOK)
	if n := auditCount(); n != 1 {
		t.Errorf("%d audit entries after ok, ok; want 1 (only the first is a change)", n)
	}
	answer = `{"data":{"/":{"Sys.Audit":true},"/datastore/ds":{"Datastore.Backup":true,"Sys.Audit":true}}}`
	check(pbs.TokenExcess)
	if n := auditCount(); n != 2 {
		t.Errorf("%d audit entries after the change to excess; want 2", n)
	}
	code, body := call(t, h, http.MethodGet, "/api/v1/targets/"+target.ID.String(), nil)
	if code != http.StatusOK || !bytes.Contains(body, []byte(`"token_check":{"status":"excess"`)) || !bytes.Contains(body, []byte(`everything on this PBS`)) {
		t.Errorf("target shows %d %s", code, body)
	}
	// The PBS going away is an error, never ok
	srv.Close()
	check(pbs.TokenError)

	viewer := &auth.Principal{Kind: auth.PrincipalSession, Bindings: []auth.Binding{{Role: auth.RoleViewer, Permissions: auth.BuiltinRoles()[auth.RoleViewer]}}}
	if code, _ := call(t, liveRouter(d, viewer), http.MethodPost, path, nil); code != http.StatusForbidden {
		t.Errorf("viewer ran a token check: %d", code)
	}
}

func TestLiveSessionRevocation(t *testing.T) {
	d := liveDB(t)
	ctx := context.Background()
	mk := func(email string, ttl time.Duration) *db.AdminSession {
		s := &db.AdminSession{ID: uuid.New(), Subject: "sub-" + email, Email: email, ExpiresAt: time.Now().Add(ttl)}
		if err := d.CreateAdminSession(ctx, s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	alice1, alice2, bob := mk("Alice@example.com", time.Hour), mk("alice@example.com", time.Hour), mk("bob@example.com", time.Hour)
	expired := mk("old@example.com", -time.Minute)
	checker := auth.NewSessionChecker(d, time.Minute)
	for _, s := range []*db.AdminSession{alice1, alice2, bob} {
		if ok, err := checker.Active(ctx, s.ID.String()); !ok || err != nil {
			t.Fatalf("%s should be active: %v", s.Email, err)
		}
	}
	if ok, _ := checker.Active(ctx, expired.ID.String()); ok {
		t.Error("an expired session is active")
	}
	if ok, _ := checker.Active(ctx, "not-a-uuid"); ok {
		t.Error("a garbage session id is active")
	}

	admin := &auth.Principal{Kind: auth.PrincipalSession, Email: "root@example.com", Bindings: auth.AdminBindings(), SessionID: bob.ID.String()}
	s := NewServerAPI(d, nil, config.DefaultServerConfig(), auth.NewTokenManager("test-secret-key-must-be-very-long-123456"), nil)
	s.Sessions = checker
	r := chi.NewRouter()
	s.RegisterRoutes(r, asPrincipal(admin), passthrough)

	code, body := call(t, r, http.MethodGet, "/api/v1/rbac/sessions", nil)
	if code != http.StatusOK || bytes.Count(body, []byte(`"id"`)) != 3 || !bytes.Contains(body, []byte(`"current":true`)) {
		t.Errorf("list: %d %s", code, body)
	}
	if code, body := call(t, r, http.MethodDelete, "/api/v1/rbac/sessions/"+bob.ID.String(), nil); code != http.StatusOK {
		t.Fatalf("revoke one: %d %s", code, body)
	}
	if ok, _ := checker.Active(ctx, bob.ID.String()); ok {
		t.Error("revoked session still active on this server")
	}
	if code, _ := call(t, r, http.MethodDelete, "/api/v1/rbac/sessions/"+bob.ID.String(), nil); code != http.StatusNotFound {
		t.Errorf("revoking twice: %d, want 404", code)
	}
	code, body = call(t, r, http.MethodDelete, "/api/v1/rbac/sessions?email=ALICE@example.com", nil)
	if code != http.StatusOK || !bytes.Contains(body, []byte(`"sessions":2`)) {
		t.Errorf("revoke by email: %d %s", code, body)
	}
	for _, x := range []*db.AdminSession{alice1, alice2} {
		if ok, _ := checker.Active(ctx, x.ID.String()); ok {
			t.Error("a session of the signed-out user is still active")
		}
	}
	entries, _ := d.ListAudit(ctx, db.AuditFilter{Action: "session."}, db.Unscoped)
	if len(entries) != 2 {
		t.Errorf("%d session audit entries, want 2", len(entries))
	}
}

func TestLiveJobOneFileSystem(t *testing.T) {
	d := liveDB(t)
	f := seed(t, d)
	h := liveRouter(d, &auth.Principal{Kind: auth.PrincipalSession, Email: "root@example.com", Bindings: auth.AdminBindings()})
	job := db.BackupJob{Name: "root-fs", AgentID: f.agentA.ID, TargetID: f.targetA.ID, BackupPaths: []string{"/"}, OneFileSystem: true}
	code, body := call(t, h, http.MethodPost, "/api/v1/jobs", job)
	if code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, body)
	}
	var created db.BackupJob
	_ = json.Unmarshal(body, &created)
	stored, err := d.GetJobByID(context.Background(), created.ID, db.Unscoped)
	if err != nil || !stored.OneFileSystem {
		t.Fatalf("stored one_file_system: %+v %v", stored, err)
	}
	stored.OneFileSystem = false
	if code, body := call(t, h, http.MethodPut, "/api/v1/jobs/"+created.ID.String(), stored); code != http.StatusOK {
		t.Fatalf("update: %d %s", code, body)
	}
	if again, _ := d.GetJobByID(context.Background(), created.ID, db.Unscoped); again.OneFileSystem {
		t.Error("one_file_system did not switch off")
	}
}
