package k8sbackup

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	dbspec "github.com/osshield/fallbck/pkg/dbbackup"
	"github.com/osshield/fallbck/pkg/temporal"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

func TestDBWorkerPodSpec(t *testing.T) {
	pod := dbWorkerPod("fb-1", "clusterdb", map[string]string{labelRunID: "r1"}, DBWorkerConfig{
		Image: "postgres:17", AgentImage: "cr.osshield.eu/fallbck/k8s-agent:1.2.3", ImagePullPolicy: "Always",
		ResourcesJSON: `{"limits":{"memory":"1Gi"}}`, SpoolSizeLimit: "5Gi",
		Env: []corev1.EnvVar{{Name: EnvWorkerDBPassword, Value: "pw"}},
	})
	if pod.Spec.AutomountServiceAccountToken == nil || *pod.Spec.AutomountServiceAccountToken {
		t.Error("dump pod must not get a service account token")
	}
	if len(pod.Spec.InitContainers) != 1 || pod.Spec.InitContainers[0].Image != "cr.osshield.eu/fallbck/k8s-agent:1.2.3" {
		t.Fatalf("init container: %+v", pod.Spec.InitContainers)
	}
	init := pod.Spec.InitContainers[0]
	if strings.Join(init.Command, " ") != "cp /usr/local/bin/fallbck-k8s-agent /fallbck/fallbck-k8s-agent" {
		t.Errorf("init command %v", init.Command)
	}
	main := pod.Spec.Containers[0]
	if main.Image != "postgres:17" || main.Command[0] != "/fallbck/fallbck-k8s-agent" || main.Args[0] != "db-worker" {
		t.Errorf("main container %v %v %v", main.Image, main.Command, main.Args)
	}
	if main.ImagePullPolicy != corev1.PullAlways {
		t.Errorf("pull policy %v", main.ImagePullPolicy)
	}
	if main.Resources.Limits.Memory().String() != "1Gi" {
		t.Errorf("resources not applied: %v", main.Resources)
	}
	if main.SecurityContext == nil || main.SecurityContext.ReadOnlyRootFilesystem == nil || !*main.SecurityContext.ReadOnlyRootFilesystem {
		t.Error("rootfs must be read-only")
	}
	env := map[string]string{}
	for _, e := range main.Env {
		env[e.Name] = e.Value
	}
	if env[EnvWorkerSpool] != "/spool" || env["HOME"] != "/tmp" {
		t.Errorf("env %v", env)
	}
	if _, inSpec := env[EnvWorkerDBPassword]; inSpec {
		t.Error("credentials must not be in Pod.spec")
	}
	if len(main.EnvFrom) != 1 || main.EnvFrom[0].SecretRef == nil || main.EnvFrom[0].SecretRef.Name != "fb-1" {
		t.Errorf("env must come from the per-run secret: %+v", main.EnvFrom)
	}
	var spool *corev1.Volume
	for i := range pod.Spec.Volumes {
		if pod.Spec.Volumes[i].Name == "spool" {
			spool = &pod.Spec.Volumes[i]
		}
	}
	if spool == nil || spool.EmptyDir == nil || spool.EmptyDir.SizeLimit == nil || spool.EmptyDir.SizeLimit.String() != "5Gi" {
		t.Errorf("spool volume %+v", spool)
	}
	for _, mount := range []string{"/fallbck", "/spool", "/tmp"} {
		found := false
		for _, m := range main.VolumeMounts {
			if m.MountPath == mount {
				found = true
			}
		}
		if !found {
			t.Errorf("mount %s missing", mount)
		}
	}
}

func TestRenderDBWorkerImage(t *testing.T) {
	cases := []struct {
		override, engine, flavor string
		major                    int
		want                     string
	}{
		{"", "postgres", "postgres", 16, "postgres:16"},
		{"", "postgres", "", 0, "postgres:latest"},
		{"", "mysql", "mariadb", 11, "mariadb:11"},
		{"", "mysql", "mysql", 8, "mysql:8"},
		{"", "mongodb", "", 0, "mongo:latest"},
		{"registry.local/pg:17-custom", "postgres", "postgres", 16, "registry.local/pg:17-custom"},
	}
	for _, c := range cases {
		if got := RenderDBWorkerImage(c.override, nil, c.engine, c.flavor, c.major); got != c.want {
			t.Errorf("RenderDBWorkerImage(%q, nil, %q, %q, %d) = %q, want %q", c.override, c.engine, c.flavor, c.major, got, c.want)
		}
	}
	custom := map[string]string{"postgres": "mirror.local/postgres:{major}-alpine", "mariadb": "mirror.local/mariadb:{major}"}
	if got := RenderDBWorkerImage("", custom, "postgres", "postgres", 15); got != "mirror.local/postgres:15-alpine" {
		t.Errorf("custom template: %q", got)
	}
	if got := RenderDBWorkerImage("", custom, "mysql", "mariadb", 10); got != "mirror.local/mariadb:10" {
		t.Errorf("custom flavor template: %q", got)
	}
	if got := RenderDBWorkerImage("", custom, "mysql", "mysql", 8); got != "mysql:8" {
		t.Errorf("missing template falls back to the default: %q", got)
	}
}

// TestBackupDatabaseOutcome drives the dump-pod supervision with a fake API server
func TestBackupDatabaseOutcome(t *testing.T) {
	fastPolling(t)
	ctx := context.Background()
	req := func(c *Clients) DBBackupRequest {
		return DBBackupRequest{Namespace: "clusterdb", BackupID: "db-postgres-clusterdb-pg", RunID: "11111111-2222", AgentID: "a1",
			Timeout: 5 * time.Second, Worker: DBWorkerConfig{Image: "postgres:17", AgentImage: "agent"}}
	}

	t.Run("completed with state", func(t *testing.T) {
		core := k8sfake.NewSimpleClientset()
		msg, _ := json.Marshal(workerOutcome{
			Result: &temporal.BackupExecutionResult{SnapshotID: "host/db/2026-01-01T00:00:00Z", BytesUploaded: 42},
			State:  &dbspec.JobState{JobID: "j", Engine: "postgres", LastSuccess: &dbspec.JobStateRecord{RunID: "r", Postgres: &dbspec.PostgresState{WALEndLSN: "0/1"}}},
		})
		succeedPods(core, corev1.PodSucceeded, string(msg))
		c := &Clients{Core: core}
		out, err := BackupDatabase(ctx, c, req(c))
		if err != nil {
			t.Fatal(err)
		}
		if out.Result.BytesUploaded != 42 || out.State == nil || out.State.LastSuccess.Postgres.WALEndLSN != "0/1" {
			t.Fatalf("outcome %+v", out)
		}
		pods, _ := core.CoreV1().Pods("clusterdb").List(ctx, metav1.ListOptions{})
		if len(pods.Items) != 0 {
			t.Errorf("dump pod not cleaned up: %d left", len(pods.Items))
		}
	})

	t.Run("precheck failure is flagged", func(t *testing.T) {
		core := k8sfake.NewSimpleClientset()
		msg, _ := json.Marshal(workerOutcome{Error: "connecting to PostgreSQL: password authentication failed", Phase: "precheck", Precheck: true})
		succeedPods(core, corev1.PodFailed, string(msg))
		c := &Clients{Core: core}
		out, err := BackupDatabase(ctx, c, req(c))
		if err == nil || out == nil || !out.Precheck {
			t.Fatalf("expected a precheck-flagged failure, got out=%+v err=%v", out, err)
		}
		if !strings.Contains(err.Error(), "password authentication failed") || !strings.Contains(err.Error(), "[phase: precheck]") {
			t.Errorf("error text: %v", err)
		}
	})
}

// TestReportOutcomeOverflowsToLog: an outcome larger than the termination-message cap
// is logged in full and the message carries a slim copy flagged details_in_log
func TestReportOutcomeOverflowsToLog(t *testing.T) {
	resultPath := filepath.Join(t.TempDir(), "termination-log")
	t.Setenv(EnvWorkerResult, resultPath)
	big := strings.Repeat("x", 6000)
	outcome := workerOutcome{
		Result: &temporal.BackupExecutionResult{SnapshotID: "s", Details: json.RawMessage(`{"type":"database","manifest":{"blob":"` + big + `"}}`)},
		State:  &dbspec.JobState{JobID: "j"},
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w
	reportErr := reportOutcome(outcome)
	w.Close()
	os.Stdout = orig
	if reportErr != nil {
		t.Fatalf("reportOutcome: %v", reportErr)
	}
	logged := make([]byte, 0, 16000)
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		logged = append(logged, buf[:n]...)
		if err != nil {
			break
		}
	}

	msg, err := os.ReadFile(resultPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(msg) > maxTerminationMessage {
		t.Fatalf("termination message is %d bytes, over the cap", len(msg))
	}
	var slim workerOutcome
	if err := json.Unmarshal(msg, &slim); err != nil {
		t.Fatal(err)
	}
	if !slim.DetailsInLog || slim.Result == nil || slim.Result.Details != nil || slim.State != nil || slim.Result.SnapshotID != "s" {
		t.Fatalf("slim message: %s", msg)
	}
	line := ""
	for _, l := range strings.Split(string(logged), "\n") {
		if strings.HasPrefix(l, outcomeLogMarker) {
			line = strings.TrimPrefix(l, outcomeLogMarker)
		}
	}
	if line == "" {
		t.Fatal("full outcome not written to the log")
	}
	var full workerOutcome
	if err := json.Unmarshal([]byte(line), &full); err != nil {
		t.Fatal(err)
	}
	if full.State == nil || !strings.Contains(string(full.Result.Details), big) {
		t.Fatal("logged outcome is not the full one")
	}
}
