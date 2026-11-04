package agent_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/db"
	"github.com/osshield/fallbck/pkg/proxy/pbstest"
	"github.com/osshield/fallbck/pkg/rundetail"
	"github.com/osshield/fallbck/pkg/temporal"
	"github.com/osshield/fallbck/pkg/temporal/activities"
	"github.com/osshield/fallbck/pkg/vcs"
	"go.temporal.io/sdk/testsuite"
	"go.temporal.io/sdk/worker"
)

func testGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "user.name=FallBCK Test", "-c", "user.email=test@example.invalid", "-c", "init.defaultBranch=main"}, args...)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// httpsGitHost serves bare repositories under root over HTTPS (git http-backend)
// and requires token as basic authentication
func httpsGitHost(t *testing.T, root, token string) (*httptest.Server, string) {
	t.Helper()
	backend := filepath.Join(testGit(t, "", "--exec-path"), "git-http-backend")
	if _, err := os.Stat(backend); err != nil {
		t.Skip("git-http-backend not available")
	}
	h := &cgi.Handler{Path: backend, Root: "/", InheritEnv: []string{"PATH"},
		Env: []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + os.DevNull}}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("oauth2:"+token))
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != want {
			w.Header().Set("WWW-Authenticate", `Basic realm="git"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
}

func runVCSActivity(ctx context.Context, acts *activities.AgentActivities, session *temporal.BackupSessionInfo) (*temporal.BackupExecutionResult, error) {
	env := (&testsuite.WorkflowTestSuite{}).NewTestActivityEnvironment()
	env.SetWorkerOptions(worker.Options{BackgroundActivityContext: ctx})
	env.RegisterActivity(acts.ExecuteVCSBackup)
	val, err := env.ExecuteActivity(acts.ExecuteVCSBackup, session)
	if err != nil {
		return nil, err
	}
	var result temporal.BackupExecutionResult
	if err := val.Get(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

// TestEndToEndVCSBackup runs the real VCS activity: the agent fetches a repository
// from an HTTPS git host with the connection's token and CA, and streams one v2
// snapshot with the manifest blob through the server tunnel to a fake PBS
func TestEndToEndVCSBackup(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	const token = "glpat-e2e"
	gitRoot := t.TempDir()
	bare := filepath.Join(gitRoot, "team", "app.git")
	testGit(t, "", "init", "--bare", "--quiet", bare)
	work := t.TempDir()
	testGit(t, work, "init", "--quiet")
	if err := os.WriteFile(filepath.Join(work, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	testGit(t, work, "add", ".")
	testGit(t, work, "commit", "--quiet", "-m", "initial")
	testGit(t, work, "push", "--quiet", bare, "main")
	gitSrv, caPEM := httpsGitHost(t, gitRoot, token)

	fake := pbstest.New(t)
	target := &db.BackupTarget{
		ID: uuid.New(), Name: "fake-pbs", Endpoint: fake.URL(), Datastore: "backup-store",
		AuthToken: "PBSAPIToken=backup@pbs!fallbck=secret", Fingerprint: fake.Fingerprint(), PxarFormat: db.PxarFormatV2,
	}
	h := startTunnel(t, target)

	acts := activities.NewAgentActivities()
	acts.Tunnel = h.conn
	acts.SpoolDir = t.TempDir()
	acts.CacheDir = t.TempDir()
	acts.VCSStateDir = t.TempDir()
	acts.VCSCredentials = func(context.Context, string) (*vcs.Credentials, error) {
		return &vcs.Credentials{Provider: vcs.ProviderGit, BaseURL: gitSrv.URL, Token: token, CAPEM: caPEM}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// The job id names the job's mirror directory: every run of the job uses it
	jobID := uuid.New()
	run := func(backupTime int64) *temporal.BackupExecutionResult {
		t.Helper()
		session := h.session(t, "vcs-team", backupTime)
		session.JobID = jobID
		session.JobType = db.JobTypeVCS
		session.VCSConfig = &vcs.Spec{ConnectionID: uuid.New(), Repositories: []string{gitSrv.URL + "/team/app.git"}}
		result, err := runVCSActivity(ctx, acts, session)
		if err != nil {
			t.Fatalf("ExecuteVCSBackup: %v", err)
		}
		return result
	}
	now := time.Now().UTC().Unix()
	result := run(now)
	if result.Status != db.RunStatusCompleted || !strings.HasPrefix(result.SnapshotID, "host/vcs-team/") || result.BytesScanned == 0 {
		t.Fatalf("result %+v", result)
	}
	manifest := func(result *temporal.BackupExecutionResult) vcs.Manifest {
		t.Helper()
		var detail struct {
			Type     string       `json:"type"`
			Manifest vcs.Manifest `json:"manifest"`
		}
		if err := json.Unmarshal(result.Details, &detail); err != nil || detail.Type != rundetail.TypeVCS {
			t.Fatalf("details %s: %v", result.Details, err)
		}
		return detail.Manifest
	}
	if m := manifest(result); m.Totals.Completed != 1 || len(m.Repositories) != 1 || !strings.HasSuffix(m.Repositories[0].Path, "/team/app") || !m.Repositories[0].Changed {
		t.Errorf("manifest %+v", m)
	}
	idx := fake.Indexes()
	for _, name := range []string{"vcs.mpxar.didx", "vcs.ppxar.didx"} {
		if _, ok := idx[name]; !ok {
			t.Errorf("index %s missing (have %v)", name, keys(idx))
		}
	}
	if _, ok := fake.Blobs()[vcs.ManifestBlobName+".blob"]; !ok {
		t.Errorf("manifest blob missing (have %v)", keys(fake.Blobs()))
	}

	// The mirror stays in the job's state directory: the next run finds the
	// repository unchanged and does not fetch it again
	second := run(now + 60)
	if second.Status != db.RunStatusCompleted {
		t.Fatalf("second run %+v", second)
	}
	if m := manifest(second); len(m.Repositories) != 1 || m.Repositories[0].Changed {
		t.Errorf("second run should reuse the mirror: %+v", m.Repositories)
	}
	if fake.Finished() != 2 {
		t.Errorf("finished sessions = %d", fake.Finished())
	}
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
