package agent_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/db"
	"github.com/osshield/fallbck/pkg/proxy/pbstest"
	"github.com/osshield/fallbck/pkg/temporal/activities"
)

// TestEndToEndBackupFlow runs the real agent activity: the server side (gateway +
// tunnel) opens a session on a fake PBS with the target's token, and the agent streams
// a real pxar archive through it with gopbs.
func TestEndToEndBackupFlow(t *testing.T) {
	fake := pbstest.New(t)
	fake.ExpectAuthorization = "PBSAPIToken=backup@pbs!fallbck:secret"

	target := &db.BackupTarget{
		ID: uuid.New(), Name: "fake-pbs", Endpoint: fake.URL(), Datastore: "backup-store", Namespace: "prod",
		AuthToken: "PBSAPIToken=backup@pbs!fallbck=secret", Fingerprint: fake.Fingerprint(), PxarFormat: db.PxarFormatV1,
	}
	h := startTunnel(t, target)

	backupDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(backupDir, "app.conf"), []byte("[app]\nname=fallbck\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 3*1024*1024)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	if err := os.WriteFile(filepath.Join(backupDir, "data.bin"), payload, 0o644); err != nil {
		t.Fatal(err)
	}
	session := h.session(t, "web-01", time.Now().UTC().Unix(), backupDir)

	acts := activities.NewAgentActivities()
	acts.Tunnel = h.conn

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	result, err := runActivity(ctx, acts, session)
	if err != nil {
		t.Fatalf("ExecuteFilesystemBackup: %v", err)
	}
	if result.Status != db.RunStatusCompleted || result.ChunkCount == 0 || result.BytesScanned < int64(len(payload)) {
		t.Errorf("unexpected result %+v", result)
	}
	if !strings.HasPrefix(result.SnapshotID, "host/web-01/") {
		t.Errorf("snapshot id %q", result.SnapshotID)
	}

	// The fake PBS saw one session, opened with the target's token and the ticket's identity
	ups := fake.Upgrades()
	if len(ups) != 1 {
		t.Fatalf("expected 1 PBS session, got %d", len(ups))
	}
	q := ups[0].URL.Query()
	if q.Get("store") != "backup-store" || q.Get("ns") != "prod" || q.Get("backup-id") != "web-01" {
		t.Errorf("session scoped incorrectly: %s", ups[0].URL.RawQuery)
	}
	if fake.Finished() != 1 {
		t.Error("session was not finished")
	}
	idx := fake.Indexes()
	for _, name := range []string{"catalog.pcat1.didx"} {
		if _, ok := idx[name]; !ok {
			t.Errorf("index %s missing", name)
		}
	}
	pxarFound := false
	for name := range idx {
		if strings.HasSuffix(name, ".pxar.didx") {
			pxarFound = true
		}
	}
	if !pxarFound {
		t.Errorf("no pxar index uploaded: %v", idx)
	}
	if _, ok := fake.Blobs()["index.json.blob"]; !ok {
		t.Error("manifest missing")
	}
}
