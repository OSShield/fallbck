package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/auth"
	"github.com/osshield/fallbck/pkg/config"
	"github.com/osshield/fallbck/pkg/db"
	"github.com/osshield/fallbck/pkg/remote"
	"github.com/osshield/fallbck/pkg/secrets"
)

// The remotes repository: a round trip with the credential sealed at rest and never
// in the JSON model, scoping by labels, and no delete while a job uses the remote
func TestLiveRemoteRepository(t *testing.T) {
	d := liveDB(t)
	sealer, err := secrets.New(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	d.Sealer = sealer
	f := seed(t, d)
	ctx := context.Background()

	r := &remote.Remote{Name: "minio", Backend: remote.BackendS3, Endpoint: "http://minio:9000", PathStyle: true,
		Secrets: remote.Secrets{AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: "very-secret-key"}, Labels: map[string]string{"team": "a"}}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := d.CreateRemote(ctx, r); err != nil {
		t.Fatal(err)
	}
	agentHeld := &remote.Remote{Name: "nas-b", Backend: remote.BackendSMB, Host: "fs01", AuthMethod: remote.AuthAgent, Labels: map[string]string{"team": "b"}}
	if err := agentHeld.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := d.CreateRemote(ctx, agentHeld); err != nil {
		t.Fatal(err)
	}

	// At rest: the credential column is sealed and holds neither key
	var stored string
	if err := d.Pool.QueryRow(ctx, `SELECT secrets_sealed FROM remotes WHERE id = $1`, r.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if !secrets.IsSealed(stored) || strings.Contains(stored, "very-secret-key") || strings.Contains(stored, "AKIAEXAMPLE") {
		t.Errorf("credential not sealed at rest: %q", stored)
	}
	if err := d.Pool.QueryRow(ctx, `SELECT secrets_sealed FROM remotes WHERE id = $1`, agentHeld.ID).Scan(&stored); err != nil || stored != "" {
		t.Errorf("agent-held remote stored a credential: %q %v", stored, err)
	}
	if ok, err := d.HasSealedSecrets(ctx); err != nil || !ok {
		t.Errorf("HasSealedSecrets missed the remote: %v %v", ok, err)
	}

	// Round trip: settings and credential come back; the JSON model has no secret
	got, err := d.GetRemoteByID(ctx, r.ID, db.Unscoped)
	if err != nil {
		t.Fatal(err)
	}
	if got.Endpoint != "http://minio:9000" || !got.PathStyle || got.Provider != remote.S3Other || got.Secrets != r.Secrets || !got.HasSecret || got.Identity() != "http://minio:9000" {
		t.Errorf("round trip: %+v", got)
	}
	data, _ := json.Marshal(got)
	if bytes.Contains(data, []byte("very-secret-key")) || bytes.Contains(data, []byte("AKIAEXAMPLE")) || !bytes.Contains(data, []byte(`"has_secret":true`)) {
		t.Errorf("JSON model: %s", data)
	}

	// Scope: team=a sees only its remote
	teamA := db.Scope{Selectors: []db.Selector{db.MustSelector("team=a")}}
	list, err := d.ListRemotes(ctx, teamA)
	if err != nil || len(list) != 1 || list[0].ID != r.ID {
		t.Errorf("scoped list: %v %v", list, err)
	}
	if _, err := d.GetRemoteByID(ctx, agentHeld.ID, teamA); !errors.Is(err, db.ErrNotFound) {
		t.Errorf("out-of-scope get: %v", err)
	}

	// Update: a renamed remote keeps its id; clearing the credential stores none
	got.Name, got.AuthMethod, got.Secrets = "minio-2", remote.AuthAgent, remote.Secrets{}
	if err := got.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := d.UpdateRemote(ctx, got); err != nil {
		t.Fatal(err)
	}
	if again, err := d.GetRemoteByID(ctx, r.ID, db.Unscoped); err != nil || again.Name != "minio-2" || again.HasSecret {
		t.Errorf("after update: %+v %v", again, err)
	}
	if err := d.CreateRemote(ctx, &remote.Remote{Name: "minio-2", Backend: remote.BackendS3, AuthMethod: remote.AuthAgent}); err == nil {
		t.Error("duplicate name accepted")
	}

	// Delete: refused while a job uses it, by the repository and by the foreign key
	if _, err := d.Pool.Exec(ctx, `UPDATE backup_jobs SET remote_id = $1 WHERE id = $2`, r.ID, f.jobA.ID); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteRemote(ctx, r.ID); !errors.Is(err, db.ErrRemoteInUse) {
		t.Errorf("delete in use: %v", err)
	}
	if again, _ := d.GetRemoteByID(ctx, r.ID, db.Unscoped); again == nil || again.Jobs != 1 {
		t.Errorf("job count: %+v", again)
	}
	if _, err := d.Pool.Exec(ctx, `DELETE FROM remotes WHERE id = $1`, r.ID); err == nil {
		t.Error("the foreign key let a used remote go")
	}
	if _, err := d.Pool.Exec(ctx, `UPDATE backup_jobs SET remote_id = NULL WHERE id = $1`, f.jobA.ID); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteRemote(ctx, r.ID); err != nil {
		t.Errorf("delete unused: %v", err)
	}
	if err := d.DeleteRemote(ctx, r.ID); !errors.Is(err, db.ErrNotFound) {
		t.Errorf("delete twice: %v", err)
	}
}

// The remotes API: an operator works within their labels, a credential is never
// echoed back, an update without one keeps it, the changes that would break jobs
// are refused, and every write is audited
func TestLiveRemotesAPI(t *testing.T) {
	d := liveDB(t)
	f := seed(t, d)
	ctx := context.Background()
	op := &auth.Principal{Kind: auth.PrincipalSession, Email: "op@example.com", Bindings: []auth.Binding{
		{Role: auth.RoleOperator, Permissions: auth.BuiltinRoles()[auth.RoleOperator], Selector: db.MustSelector("team=a")},
	}}
	h := liveRouter(d, op)
	admin := liveRouter(d, &auth.Principal{Kind: auth.PrincipalSession, Email: "root@example.com", Bindings: auth.AdminBindings()})

	body := map[string]any{"name": "minio", "backend": "s3", "endpoint": "http://minio:9000", "labels": map[string]string{"team": "a"},
		"secrets": map[string]string{"access_key_id": "AKIAEXAMPLE", "secret_access_key": "very-secret-key"}}
	code, resp := call(t, h, http.MethodPost, "/api/v1/remotes", body)
	if code != http.StatusCreated || bytes.Contains(resp, []byte("very-secret-key")) || bytes.Contains(resp, []byte("AKIAEXAMPLE")) {
		t.Fatalf("create: %d %s", code, resp)
	}
	var created remote.Remote
	_ = json.Unmarshal(resp, &created)
	path := "/api/v1/remotes/" + created.ID.String()

	// Out of the operator's labels: refused on create, invisible otherwise
	body["labels"], body["name"] = map[string]string{"team": "b"}, "other"
	if code, resp := call(t, h, http.MethodPost, "/api/v1/remotes", body); code != http.StatusForbidden {
		t.Errorf("create for team=b: %d %s", code, resp)
	}
	code, resp = call(t, admin, http.MethodPost, "/api/v1/remotes", body)
	var foreign remote.Remote
	if code != http.StatusCreated || json.Unmarshal(resp, &foreign) != nil {
		t.Fatalf("admin create: %d %s", code, resp)
	}
	if code, _ := call(t, h, http.MethodGet, "/api/v1/remotes/"+foreign.ID.String(), nil); code != http.StatusNotFound {
		t.Errorf("foreign remote: %d", code)
	}
	code, resp = call(t, h, http.MethodGet, "/api/v1/remotes", nil)
	var list []remote.Remote
	if code != http.StatusOK || json.Unmarshal(resp, &list) != nil || len(list) != 1 || list[0].ID != created.ID {
		t.Errorf("list: %d %s", code, resp)
	}
	// An invalid remote is a 400 with the reason
	if code, resp := call(t, h, http.MethodPost, "/api/v1/remotes", map[string]any{"name": "x", "backend": "sftp", "host": "nas", "user": "u",
		"labels": map[string]string{"team": "a"}, "secrets": map[string]string{"password": "p"}}); code != http.StatusBadRequest || !bytes.Contains(resp, []byte("known_hosts")) {
		t.Errorf("sftp without host key: %d %s", code, resp)
	}

	// An update without a credential keeps it
	update := map[string]any{"name": "minio", "backend": "s3", "endpoint": "http://minio:9001", "labels": map[string]string{"team": "a"}}
	if code, resp := call(t, h, http.MethodPut, path, update); code != http.StatusOK || !bytes.Contains(resp, []byte(`"has_secret":true`)) {
		t.Errorf("update: %d %s", code, resp)
	}
	if got, _ := d.GetRemoteByID(ctx, created.ID, db.Unscoped); got == nil || got.Secrets.SecretAccessKey != "very-secret-key" || got.Endpoint != "http://minio:9001" {
		t.Errorf("after update: %+v", got)
	}

	// With a job on it: no backend change, no moving the credential to the agents
	// while the job relies on it, no delete
	if _, err := d.Pool.Exec(ctx, `UPDATE backup_jobs SET remote_id = $1, remote_config = '{}' WHERE id = $2`, created.ID, f.jobA.ID); err != nil {
		t.Fatal(err)
	}
	if code, resp := call(t, h, http.MethodPut, path, map[string]any{"name": "minio", "backend": "webdav", "url": "https://dav", "labels": map[string]string{"team": "a"}}); code != http.StatusConflict {
		t.Errorf("backend change: %d %s", code, resp)
	}
	toAgent := map[string]any{"name": "minio", "backend": "s3", "endpoint": "http://minio:9001", "auth_method": "agent", "labels": map[string]string{"team": "a"}}
	if code, resp := call(t, h, http.MethodPut, path, toAgent); code != http.StatusConflict || !bytes.Contains(resp, []byte(f.jobA.Name)) {
		t.Errorf("to agent with a job on the stored credential: %d %s", code, resp)
	}
	if code, _ := call(t, admin, http.MethodDelete, path, nil); code != http.StatusConflict {
		t.Errorf("delete in use: %d", code)
	}
	if _, err := d.Pool.Exec(ctx, `UPDATE backup_jobs SET remote_config = '{"profile": "minio"}' WHERE id = $1`, f.jobA.ID); err != nil {
		t.Fatal(err)
	}
	if code, resp := call(t, h, http.MethodPut, path, toAgent); code != http.StatusOK || !bytes.Contains(resp, []byte(`"has_secret":false`)) {
		t.Errorf("to agent once the job has a profile: %d %s", code, resp)
	}

	// Operators don't delete; admins do once nothing uses the remote
	if _, err := d.Pool.Exec(ctx, `UPDATE backup_jobs SET remote_id = NULL WHERE id = $1`, f.jobA.ID); err != nil {
		t.Fatal(err)
	}
	if code, _ := call(t, h, http.MethodDelete, path, nil); code != http.StatusForbidden {
		t.Errorf("operator delete: %d", code)
	}
	if code, resp := call(t, admin, http.MethodDelete, path, nil); code != http.StatusOK {
		t.Errorf("delete: %d %s", code, resp)
	}

	entries, err := d.ListAudit(ctx, db.AuditFilter{Action: "remote."}, db.Unscoped)
	if err != nil {
		t.Fatal(err)
	}
	var actions []string
	for _, e := range entries {
		actions = append(actions, e.Action)
		if bytes.Contains(e.Details, []byte("very-secret-key")) {
			t.Errorf("%s audit details carry the secret: %s", e.Action, e.Details)
		}
	}
	var details struct {
		SecretChanged bool `json:"secret_changed"`
	}
	if last := entries[1]; last.Action != "remote.update" || json.Unmarshal(last.Details, &details) != nil || !details.SecretChanged {
		t.Errorf("moving the credential to the agents isn't recorded as a change: %s %s", last.Action, last.Details)
	}
	for _, want := range []string{"remote.create", "remote.update", "remote.delete"} {
		if !slices.Contains(actions, want) {
			t.Errorf("audit misses %s: %v", want, actions)
		}
	}
}

// Remote jobs: accepted on a filesystem agent that reports the remote's backend and
// stored with the remote_id link, refused on an agent without the backend, without
// a profile on an agent-held remote, and on a kubernetes agent
func TestLiveRemoteJobs(t *testing.T) {
	d := liveDB(t)
	sealer, err := secrets.New(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	d.Sealer = sealer
	f := seed(t, d)
	ctx := context.Background()
	h := liveRouter(d, &auth.Principal{Kind: auth.PrincipalSession, Email: "root@example.com", Bindings: auth.AdminBindings()})

	if _, err := d.UpdateAgentHeartbeat(ctx, f.agentA.ID, db.AgentStatusOnline, db.AgentCapabilities{RemoteBackends: remote.Backends}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.UpdateAgentHeartbeat(ctx, f.agentB.ID, db.AgentStatusOnline, db.AgentCapabilities{RemoteBackends: []string{remote.BackendS3}}); err != nil {
		t.Fatal(err)
	}
	k8s := &db.Agent{Hostname: "cluster", TaskQueue: "q-k8s", AgentType: db.AgentTypeKubernetes}
	if err := d.CreateAgent(ctx, k8s); err != nil {
		t.Fatal(err)
	}
	mkRemote := func(r *remote.Remote) *remote.Remote {
		if err := r.Validate(); err != nil {
			t.Fatal(err)
		}
		if err := d.CreateRemote(ctx, r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	s3 := mkRemote(&remote.Remote{Name: "minio", Backend: remote.BackendS3, Endpoint: "http://minio:9000",
		Secrets: remote.Secrets{AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: "very-secret-key"}})
	sftp := mkRemote(&remote.Remote{Name: "nas", Backend: remote.BackendSFTP, Host: "nas", User: "backup", AuthMethod: remote.AuthAgent,
		KnownHosts: []string{"nas ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"}})

	job := func(agent uuid.UUID, spec map[string]any) map[string]any {
		return map[string]any{"name": "remote-" + uuid.NewString()[:8], "agent_id": agent, "target_id": f.targetA.ID,
			"job_type": "remote", "remote_config": spec}
	}
	code, resp := call(t, h, http.MethodPost, "/api/v1/jobs", job(f.agentA.ID, map[string]any{"remote_id": s3.ID, "roots": []string{"/photos/2026/"}}))
	if code != http.StatusCreated {
		t.Fatalf("capable agent: %d %s", code, resp)
	}
	var created db.BackupJob
	if err := json.Unmarshal(resp, &created); err != nil {
		t.Fatal(err)
	}
	got, err := d.GetJobByID(ctx, created.ID, db.Unscoped)
	if err != nil || got.RemoteConfig == nil || got.RemoteConfig.RemoteID != s3.ID || !slices.Equal(got.RemoteConfig.Roots, []string{"photos/2026"}) || got.RemoteConfig.Split != remote.SplitSingle {
		t.Fatalf("stored job: %+v %v", got, err)
	}
	if err := d.DeleteRemote(ctx, s3.ID); !errors.Is(err, db.ErrRemoteInUse) {
		t.Errorf("remote_id not linked: delete gave %v", err)
	}
	upd := job(f.agentA.ID, map[string]any{"remote_id": s3.ID, "roots": []string{"photos", "docs"}, "split": "per_root"})
	upd["name"] = created.Name
	if code, resp := call(t, h, http.MethodPut, "/api/v1/jobs/"+created.ID.String(), upd); code != http.StatusOK {
		t.Errorf("update: %d %s", code, resp)
	} else if got, _ := d.GetJobByID(ctx, created.ID, db.Unscoped); got == nil || len(got.RemoteConfig.Roots) != 2 || got.RemoteConfig.Split != remote.SplitPerRoot {
		t.Errorf("after update: %+v", got.RemoteConfig)
	}

	for name, tc := range map[string]struct {
		body map[string]any
		want string
	}{
		"agent lacks the backend":    {job(f.agentB.ID, map[string]any{"remote_id": sftp.ID, "profile": "nas"}), "cannot back up sftp"},
		"agent-held without profile": {job(f.agentA.ID, map[string]any{"remote_id": sftp.ID}), "credential profile"},
		"kubernetes agent":           {job(k8s.ID, map[string]any{"remote_id": s3.ID, "roots": []string{"photos"}}), "cannot run remote jobs"},
		"backup paths": {func() map[string]any {
			b := job(f.agentA.ID, map[string]any{"remote_id": s3.ID})
			b["backup_paths"] = []string{"/etc"}
			return b
		}(), "backup paths"},
	} {
		code, resp := call(t, h, http.MethodPost, "/api/v1/jobs", tc.body)
		if code != http.StatusBadRequest || !bytes.Contains(resp, []byte(tc.want)) {
			t.Errorf("%s: %d %s", name, code, resp)
		}
	}
	// No roots: every bucket, found at each run; stored as no roots
	if code, resp := call(t, h, http.MethodPost, "/api/v1/jobs", job(f.agentA.ID, map[string]any{"remote_id": s3.ID})); code != http.StatusCreated {
		t.Errorf("every bucket: %d %s", code, resp)
	} else {
		var j db.BackupJob
		if err := json.Unmarshal(resp, &j); err != nil || j.RemoteConfig == nil || len(j.RemoteConfig.Roots) != 0 {
			t.Errorf("every bucket: %s %v", resp, err)
		}
	}
	// An agent that predates remote jobs
	if _, err := d.UpdateAgentHeartbeat(ctx, f.agentB.ID, db.AgentStatusOnline, db.AgentCapabilities{}); err != nil {
		t.Fatal(err)
	}
	if code, resp := call(t, h, http.MethodPost, "/api/v1/jobs", job(f.agentB.ID, map[string]any{"remote_id": s3.ID, "roots": []string{"photos"}})); code != http.StatusBadRequest || !bytes.Contains(resp, []byte("update the agent")) {
		t.Errorf("old agent: %d %s", code, resp)
	}

	// Credentials: the stored one for a job without a profile, none for a job that
	// names one, and nothing for another job's or another agent's ticket
	code, resp = call(t, h, http.MethodPost, "/api/v1/jobs", job(f.agentA.ID, map[string]any{"remote_id": sftp.ID, "profile": "nas"}))
	if code != http.StatusCreated {
		t.Fatalf("profile job: %d %s", code, resp)
	}
	var profileJob db.BackupJob
	if err := json.Unmarshal(resp, &profileJob); err != nil {
		t.Fatal(err)
	}
	tm := auth.NewTokenManager("test-secret-key-must-be-very-long-123456")
	ticket := func(jobID, agentID uuid.UUID) string {
		tk, err := tm.CreateBackupTicket(auth.BackupTicketClaims{JobID: jobID, AgentID: agentID, TargetID: f.targetA.ID, BackupType: "host", BackupID: "remote-x", BackupTime: time.Now().Unix()}, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return tk
	}
	api := NewServerAPI(d, nil, config.DefaultServerConfig(), tm, nil)
	fetch := func(ticket string) (int, remote.RunCredentials, string) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/remote-credentials", nil)
		req.Header.Set(BackupTicketHeader, ticket)
		req = req.WithContext(auth.WithAgent(req.Context(), &auth.AgentClaims{AgentID: f.agentA.ID}))
		rr := httptest.NewRecorder()
		api.HandleRemoteCredentials(rr, req)
		var c remote.RunCredentials
		_ = json.Unmarshal(rr.Body.Bytes(), &c)
		return rr.Code, c, rr.Body.String()
	}
	if code, c, body := fetch(ticket(created.ID, f.agentA.ID)); code != http.StatusOK || c.Secrets.SecretAccessKey != "very-secret-key" || c.Secrets.AccessKeyID != "AKIAEXAMPLE" || c.Remote == nil || c.Remote.Endpoint != "http://minio:9000" {
		t.Errorf("stored credential: %d %s", code, body)
	}
	if code, c, body := fetch(ticket(profileJob.ID, f.agentA.ID)); code != http.StatusOK || !c.Secrets.IsZero() || c.Remote == nil || c.Remote.Identity() != "sftp://nas:22" || len(c.Remote.KnownHosts) != 1 {
		t.Errorf("profile job: %d %s", code, body)
	}
	if code, _, body := fetch(ticket(f.jobA.ID, f.agentA.ID)); code != http.StatusForbidden {
		t.Errorf("a filesystem job's ticket: %d %s", code, body)
	}
	if code, _, body := fetch(ticket(created.ID, f.agentB.ID)); code != http.StatusForbidden {
		t.Errorf("another agent's ticket: %d %s", code, body)
	}

	// Sub-tickets (split per_root): only groups that extend the run's own group
	subTicket := func(jobID uuid.UUID, runGroup, group string) int {
		tk, err := tm.CreateBackupTicket(auth.BackupTicketClaims{JobID: jobID, AgentID: f.agentA.ID, TargetID: f.targetA.ID, BackupType: "host", BackupID: runGroup, BackupTime: time.Now().Unix()}, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(SubTicketRequest{BackupID: group})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/agents/sub-ticket", bytes.NewReader(body))
		req.Header.Set(BackupTicketHeader, tk)
		req = req.WithContext(auth.WithAgent(req.Context(), &auth.AgentClaims{AgentID: f.agentA.ID}))
		rr := httptest.NewRecorder()
		api.HandleSubTicket(rr, req)
		return rr.Code
	}
	if code := subTicket(created.ID, "remote-minio", "remote-minio-photos"); code != http.StatusOK {
		t.Errorf("the job's own root group: %d", code)
	}
	if code := subTicket(created.ID, "remote-minio", "remote-nas-photos"); code != http.StatusForbidden {
		t.Errorf("another job's group: %d", code)
	}
	if code := subTicket(f.jobA.ID, "host-a", "host-a-photos"); code != http.StatusForbidden {
		t.Errorf("a filesystem job's ticket: %d", code)
	}
}
