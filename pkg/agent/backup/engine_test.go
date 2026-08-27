package backup

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/osshield/fallbck/pkg/db"
	"github.com/osshield/fallbck/pkg/proxy"
	"github.com/osshield/fallbck/pkg/proxy/pbstest"
	"github.com/osshield/fallbck/pkg/temporal"
	"github.com/osshield/gopbs/pbs"
)

func makeTree(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.conf"), []byte("[app]\nkey=value\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	big := make([]byte, 5*1024*1024)
	for i := range big {
		big[i] = byte(i * 7)
	}
	if err := os.WriteFile(filepath.Join(dir, "data", "blob.bin"), big, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// directDial plays the server's role: open the PBS session straight on the fake
func directDial(fake *pbstest.Server, session *temporal.BackupSessionInfo) func(context.Context, pbs.SnapshotRef) (net.Conn, error) {
	target := &db.BackupTarget{Endpoint: fake.URL(), Fingerprint: fake.Fingerprint(), AuthTokenEncrypted: "root@pam!t=s"}
	return func(ctx context.Context, ref pbs.SnapshotRef) (net.Conn, error) {
		return proxy.OpenBackupSession(ctx, target, proxy.SessionParams{
			Datastore: session.Datastore, Namespace: session.Namespace,
			BackupType: session.BackupType, BackupID: session.BackupID, BackupTime: session.BackupTime,
		})
	}
}

func TestRunFormats(t *testing.T) {
	for _, format := range []string{db.PxarFormatV1, db.PxarFormatV2} {
		t.Run(format, func(t *testing.T) {
			fake := pbstest.New(t)
			dir := makeTree(t)
			session := &temporal.BackupSessionInfo{
				Datastore: "store1", BackupType: "host", BackupID: "node6", BackupTime: time.Now().Unix(),
				PxarFormat: format, BackupPaths: []string{dir},
			}
			var progressCalls int
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			res, err := Run(ctx, Options{
				Session:     session,
				Dial:        directDial(fake, session),
				ArchiveName: "root",
				OnProgress:  func(string, pbs.UploadStats, bool) { progressCalls++ },
			})
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if res.Status != db.RunStatusCompleted || res.ChunkCount == 0 || res.BytesScanned < 5*1024*1024 {
				t.Errorf("unexpected result %+v", res)
			}
			if !strings.HasPrefix(res.SnapshotID, "host/node6/") {
				t.Errorf("snapshot id %q", res.SnapshotID)
			}
			if progressCalls == 0 {
				t.Error("no progress reported")
			}
			if fake.Finished() != 1 {
				t.Errorf("finished sessions = %d", fake.Finished())
			}
			indexes := fake.Indexes()
			want := []string{"root.pxar.didx", "catalog.pcat1.didx"}
			if format == db.PxarFormatV2 {
				want = []string{"root.mpxar.didx", "root.ppxar.didx"}
			}
			for _, name := range want {
				idx, ok := indexes[name]
				if !ok || !idx.Closed || idx.ChunkCount == 0 {
					t.Errorf("index %s missing or not closed: %+v", name, idx)
				}
			}
			if _, ok := fake.Blobs()["index.json.blob"]; !ok {
				t.Error("manifest not uploaded")
			}
		})
	}
}

func TestRunValidation(t *testing.T) {
	ctx := context.Background()
	if _, err := Run(ctx, Options{}); err == nil {
		t.Error("nil session must fail")
	}
	s := &temporal.BackupSessionInfo{BackupPaths: []string{"/definitely/missing/path"}, BackupType: "host", BackupID: "x", BackupTime: 1}
	if _, err := Run(ctx, Options{Session: s, Dial: func(context.Context, pbs.SnapshotRef) (net.Conn, error) { return nil, nil }}); err == nil {
		t.Error("missing path must fail before opening a session")
	}
}

func TestRunDirect(t *testing.T) {
	fake := pbstest.New(t)
	fake.ExpectAuthorization = "PBSAPIToken=backup@pbs!fallbck:s3cret"
	dir := makeTree(t)
	session := &temporal.BackupSessionInfo{
		Datastore: "store1", BackupType: "host", BackupID: "node6", BackupTime: time.Now().Unix(),
		PxarFormat: db.PxarFormatV1, BackupPaths: []string{dir},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := Run(ctx, Options{
		Session:     session,
		ArchiveName: "root",
		Direct:      &DirectOptions{Endpoint: fake.URL(), Fingerprint: "SHA256:" + fake.Fingerprint(), APIToken: "backup@pbs!fallbck=s3cret"},
	})
	if err != nil {
		t.Fatalf("Run direct: %v", err)
	}
	if res.Status != db.RunStatusCompleted || fake.Finished() != 1 {
		t.Errorf("direct backup did not complete: %+v finished=%d", res, fake.Finished())
	}
	if q := fake.Upgrades()[0].URL.Query(); q.Get("store") != "store1" || q.Get("backup-id") != "node6" {
		t.Errorf("unexpected upgrade query %s", fake.Upgrades()[0].URL.RawQuery)
	}
}

func TestRunMultiplePathsGetsDefaultArchiveName(t *testing.T) {
	fake := pbstest.New(t)
	dirA, dirB := makeTree(t), makeTree(t)
	session := &temporal.BackupSessionInfo{
		Datastore: "store1", BackupType: "host", BackupID: "node6", BackupTime: time.Now().Unix(),
		PxarFormat: db.PxarFormatV1, BackupPaths: []string{dirA, filepath.Join(dirB, "data")},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if _, err := Run(ctx, Options{Session: session, Dial: directDial(fake, session)}); err != nil {
		t.Fatalf("Run with multiple roots: %v", err)
	}
	if _, ok := fake.Indexes()["root.pxar.didx"]; !ok {
		t.Errorf("expected root.pxar.didx for a multi-root job, got %v", fake.Indexes())
	}
}
