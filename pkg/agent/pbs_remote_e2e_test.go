//go:build pbse2e

package agent_test

// A remote (S3) job end to end: the real activity reads an rclone serve s3 server
// (started here with -vv, so its log shows every request) and uploads to the
// ephemeral PBS through the tunnel.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	mrand "math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/agent/remote/backends"
	"github.com/osshield/fallbck/pkg/auth"
	"github.com/osshield/fallbck/pkg/db"
	"github.com/osshield/fallbck/pkg/remote"
	"github.com/osshield/fallbck/pkg/temporal"
	"github.com/osshield/fallbck/pkg/temporal/activities"
	"go.temporal.io/sdk/testsuite"
	"go.temporal.io/sdk/worker"
)

const s3Image = "rclone/rclone:1.74.3"

// startS3 serves dir over S3 (every top-level directory is a bucket) and returns the
// endpoint and a function returning the server's log so far
func startS3(t *testing.T, dir string) (endpoint string, logs func() string) {
	t.Helper()
	name := "fallbck-pbse2e-s3-" + uuid.NewString()[:8]
	out, err := exec.Command("docker", "run", "-d", "--name", name, "-v", dir+":/data:ro", "-p", "127.0.0.1::9000",
		s3Image, "serve", "s3", "/data", "--addr", ":9000", "--auth-key", "fbk,fbk-secret", "-vv").CombinedOutput()
	if err != nil {
		t.Fatalf("starting %s: %v\n%s", s3Image, err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })
	logs = func() string {
		out, _ := exec.Command("docker", "logs", name).CombinedOutput()
		return string(out)
	}
	port, err := exec.Command("docker", "port", name, "9000/tcp").Output()
	if err != nil {
		t.Fatalf("docker port: %v", err)
	}
	endpoint = "http://" + strings.Fields(string(port))[0]
	for i := 0; i < 50 && !strings.Contains(logs(), "Starting s3 server"); i++ {
		time.Sleep(200 * time.Millisecond)
	}
	return endpoint, logs
}

// remoteRun runs ExecuteRemoteBackup for spec into host/<backupID>; sub-tickets come
// from the harness's token manager, as the server's /agents/sub-ticket would mint them
func remoteRun(t *testing.T, r *remote.Remote, s *remote.Spec, backupID, stateDir string) *temporal.BackupExecutionResult {
	t.Helper()
	target := srv.Target("backup", e2eNamespace)
	target.PxarFormat = db.PxarFormatV2
	h := startTunnel(t, target)
	session := h.session(t, backupID, nextBackupTime())
	session.BackupPaths = nil
	session.JobType, session.RemoteConfig = db.JobTypeRemote, s

	acts := activities.NewAgentActivities()
	acts.Tunnel = h.conn
	acts.CacheDir = filepath.Join(stateDir, "cache")
	acts.RemoteStateDir = filepath.Join(stateDir, "remote-state")
	acts.RemoteOpen = backends.NewSession
	acts.RemoteCredentials = func(context.Context, string) (*remote.RunCredentials, error) {
		return &remote.RunCredentials{Remote: r, Secrets: remote.Secrets{AccessKeyID: "fbk", SecretAccessKey: "fbk-secret"}}, nil
	}
	acts.SubTicket = func(_ context.Context, _ string, group string) (string, int64, error) {
		bt := nextBackupTime()
		ticket, err := h.tm.CreateBackupTicket(auth.BackupTicketClaims{
			JobID: session.JobID, AgentID: h.agentID, TargetID: target.ID, Datastore: target.Datastore, Namespace: target.Namespace,
			BackupType: "host", BackupID: group, BackupTime: bt,
		}, time.Hour)
		return ticket, bt, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	env := (&testsuite.WorkflowTestSuite{}).NewTestActivityEnvironment()
	env.SetWorkerOptions(worker.Options{BackgroundActivityContext: ctx})
	env.RegisterActivity(acts.ExecuteRemoteBackup)
	val, err := env.ExecuteActivity(acts.ExecuteRemoteBackup, session)
	if err != nil {
		t.Fatalf("remote backup %s: %v", backupID, err)
	}
	var res temporal.BackupExecutionResult
	if err := val.Get(&res); err != nil {
		t.Fatal(err)
	}
	if res.Status != db.RunStatusCompleted {
		t.Fatalf("remote backup %s: status %s: %s", backupID, res.Status, res.ErrorMessage)
	}
	return &res
}

// getObject and headObject match rclone serve s3's -vv lines for an object read and
// an object HEAD (listings log LIST BUCKET)
var (
	getObject  = regexp.MustCompile(`GET OBJECT Bucket: \S+ Object: \S+`)
	headObject = regexp.MustCompile(`HEAD OBJECT \S+ \S+`)
)

// TestPBSRemoteS3: two runs of the same S3 job; the second reads no object and adds
// next to nothing to the datastore. Then a per_root run writes a group per bucket.
func TestPBSRemoteS3(t *testing.T) {
	data := t.TempDir()
	write := func(p string, b []byte) {
		full := filepath.Join(data, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	big := make([]byte, 4<<20)
	_, _ = mrand.NewChaCha8([32]byte{7}).Read(big)
	sum := sha256.Sum256(big)
	write("photos/2026/big.bin", big)
	write("photos/a.jpg", []byte("jpeg a"))
	write("archive/2025/report.pdf", []byte("pdf"))
	if err := os.Chmod(data, 0o755); err != nil {
		t.Fatal(err)
	}

	endpoint, logs := startS3(t, data)
	r := &remote.Remote{ID: uuid.New(), Name: "rclone", Backend: remote.BackendS3, Provider: remote.S3Other, Endpoint: endpoint, PathStyle: true}
	single := &remote.Spec{RemoteID: r.ID, Roots: []string{"photos", "archive"}, Split: remote.SplitSingle}
	state := t.TempDir()

	first := remoteRun(t, r, single, "remote-rclone", state)
	gets := len(getObject.FindAllString(logs(), -1))
	if gets < 3 {
		t.Fatalf("the first run read %d objects, want 3; the GET pattern may not match this rclone's log:\n%s", gets, tail(logs(), 40))
	}
	before, err := srv.Chunks()
	if err != nil {
		t.Fatal(err)
	}
	mark := len(logs())

	second := remoteRun(t, r, single, "remote-rclone", state)
	after, err := srv.Chunks()
	if err != nil {
		t.Fatal(err)
	}
	if got := getObject.FindAllString(logs()[mark:], -1); len(got) > 0 {
		t.Errorf("the second run read objects: %v", got)
	}
	if got := headObject.FindAllString(logs()[mark:], -1); len(got) > 0 {
		t.Errorf("the second run asked about single objects: %v", got)
	}
	if added := after - before; added > 3 {
		t.Errorf("the second run added %d chunks to the datastore", added)
	}
	t.Logf("first %s, second %s: %d chunks added, %d object reads before", first.SnapshotID, second.SnapshotID, after-before, gets)

	// The second snapshot restores the big object intact
	out := "/tmp/restore-remote"
	if msg, err := srv.Client(nil, "restore", "--ns", e2eNamespace, second.SnapshotID, "remote.mpxar", out); err != nil {
		t.Fatalf("restore: %v\n%s", err, msg)
	}
	got, err := srv.Exec(nil, nil, "sha256sum", out+"/photos/2026/big.bin")
	if err != nil || strings.Fields(got)[0] != hex.EncodeToString(sum[:]) {
		t.Fatalf("restored big.bin: %s %v", got, err)
	}

	perRoot := &remote.Spec{RemoteID: r.ID, Roots: []string{"photos", "archive"}, Split: remote.SplitPerRoot}
	res := remoteRun(t, r, perRoot, "remote-rclone-split", state)
	groups, err := srv.Client(nil, "list", "--ns", e2eNamespace)
	if err != nil {
		t.Fatalf("list: %v\n%s", err, groups)
	}
	for _, g := range []string{"host/remote-rclone-split-photos", "host/remote-rclone-split-archive", "host/remote-rclone-split"} {
		if !regexp.MustCompile(regexp.QuoteMeta(g) + `\b[^-]`).MatchString(groups) {
			t.Errorf("group %s missing:\n%s", g, groups)
		}
	}
	t.Logf("per_root run %s", res.SnapshotID)
}

func tail(s string, n int) string {
	lines := strings.Split(s, "\n")
	return strings.Join(lines[max(0, len(lines)-n):], "\n")
}
