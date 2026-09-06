package k8sbackup

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/osshield/fallbck/pkg/agent/backup"
	"github.com/osshield/fallbck/pkg/proxy/pbstest"
	"github.com/osshield/fallbck/pkg/temporal"
)

// TestWorkerDirectCarriesNamespace proves the full worker direct-PBS path preserves the
// target's PBS namespace: workerEnv marshals DirectOptions → env → runWorker unmarshals
// → engine → gopbs sends ns=. A CT (kubernetes) backup must not land in the root namespace.
func TestWorkerDirectCarriesNamespace(t *testing.T) {
	fake := pbstest.New(t)
	fake.ExpectAuthorization = "PBSAPIToken=backup@pbs!fallbck:s3cret"

	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, "file.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	session := temporal.BackupSessionInfo{
		Datastore: "FALLBCK", BackupType: "ct", BackupID: "k8s-cluster01-pvc-db-data", BackupTime: time.Now().Unix(),
		PxarFormat: "v1",
	}
	sessionJSON, _ := json.Marshal(session)
	// Exactly what the k8s activity puts in the pod env for a direct-mode volume
	direct := backup.DirectOptions{Endpoint: fake.URL(), Namespace: "cluster01", Fingerprint: "SHA256:" + fake.Fingerprint(), APIToken: "backup@pbs!fallbck=s3cret"}
	directJSON, _ := json.Marshal(direct)

	t.Setenv(EnvWorkerSession, string(sessionJSON))
	t.Setenv(EnvWorkerTicket, "unused-in-direct-mode")
	t.Setenv(EnvWorkerPBSDirect, string(directJSON))
	t.Setenv(EnvWorkerPath, dataDir)
	t.Setenv(EnvWorkerResult, filepath.Join(t.TempDir(), "result"))

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := RunWorker(ctx); err != nil {
		t.Fatalf("RunWorker: %v", err)
	}
	ups := fake.Upgrades()
	if len(ups) != 1 {
		t.Fatalf("expected one PBS session, got %d", len(ups))
	}
	q := ups[0].URL.Query()
	if ns := q.Get("ns"); ns != "cluster01" {
		t.Errorf("CT backup used namespace %q, want the target's %q (regression: lands in root)", ns, "cluster01")
	}
	if q.Get("backup-type") != "ct" {
		t.Errorf("backup-type %q, want ct", q.Get("backup-type"))
	}
}

// TestPBSDirectOptionsNamespaceRoundTrip guards the JSON round-trip the worker relies on
func TestPBSDirectOptionsNamespaceRoundTrip(t *testing.T) {
	in := backup.DirectOptions{Endpoint: "https://pbs:8007", Namespace: "cluster01", APIToken: "u@r!t=s"}
	data, _ := json.Marshal(in)
	var out backup.DirectOptions
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if out.Namespace != "cluster01" {
		t.Errorf("namespace lost in JSON round-trip: %q (json: %s)", out.Namespace, data)
	}
}
