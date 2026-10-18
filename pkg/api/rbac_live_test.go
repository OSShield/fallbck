package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/osshield/fallbck/pkg/auth"
	"github.com/osshield/fallbck/pkg/config"
	"github.com/osshield/fallbck/pkg/db"
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
		{Role: auth.RoleOperator, Permissions: auth.BuiltinRoles()[auth.RoleOperator], Selector: db.Labels{"team": "a"}},
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
	scoped, _ := d.ListAudit(ctx, db.AuditFilter{}, db.Scope{Selectors: []db.Labels{{"team": "b"}}})
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
	if err != nil || key.Role != "viewer" || key.Selector["team"] != "a" {
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
	b, err := res.Session(ctx, "FIRST@example.com", false, nil)
	if err != nil || len(b) != 1 || len(b[0].Selector) != 0 {
		t.Fatalf("first admin bindings: %+v %v", b, err)
	}
	if b, _ := res.Session(ctx, "first@example.com", true, nil); len(b) != 0 {
		t.Error("an unverified email matched a user binding")
	}
	if err := d.CreateBinding(ctx, &db.RoleBinding{Kind: db.BindingGroup, Subject: "ops", Role: auth.RoleViewer, Selector: db.Labels{"team": "a"}}); err != nil {
		t.Fatal(err)
	}
	if b, _ := res.Session(ctx, "nobody@example.com", false, []string{"ops"}); len(b) != 1 || b[0].Selector["team"] != "a" {
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
	objects := []db.Labels{{}, {"team": "a"}, {"team": "b"}, {"team": "a", "env": "prod"}, {"env": "prod"}, {"team": "A"}, {"fallbck.io/x": "1", "team": "a"}}
	scopes := []db.Scope{
		{}, db.Unscoped,
		{Selectors: []db.Labels{{"team": "a"}}},
		{Selectors: []db.Labels{{"team": "a", "env": "prod"}}},
		{Selectors: []db.Labels{{"team": "b"}, {"env": "prod"}}},
		{Selectors: []db.Labels{{"fallbck.io/x": "1"}}},
		{Selectors: []db.Labels{{"team": ""}}},
	}
	for _, s := range scopes {
		for _, o := range objects {
			where, args := s.SQL("$1::jsonb", []any{o.JSON()})
			var got bool
			if err := d.Pool.QueryRow(ctx, `SELECT $1::jsonb IS NOT NULL AND `+where, args...).Scan(&got); err != nil {
				t.Fatalf("%+v: %v", s, err)
			}
			if want := s.Matches(o); got != want {
				t.Errorf("scope %+v on %v: SQL %v, Go %v", s, o, got, want)
			}
		}
	}
}
