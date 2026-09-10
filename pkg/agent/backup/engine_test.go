package backup

import (
	"context"
	"errors"
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
	"github.com/osshield/gopbs"
	"github.com/osshield/gopbs/archive"
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
			var phases []string
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			res, err := Run(ctx, Options{
				Session:     session,
				Dial:        directDial(fake, session),
				ArchiveName: "root",
				OnPhase:     func(p string) { phases = append(phases, p) },
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
			joined := strings.Join(phases, ",")
			if !strings.Contains(joined, "opening PBS session") || !strings.Contains(joined, "uploading root.") || !strings.Contains(joined, "finalizing snapshot") {
				t.Errorf("phases not reported: %v", phases)
			}
			if len(res.Details) == 0 || !strings.Contains(string(res.Details), `"type":"filesystem"`) || !strings.Contains(string(res.Details), `"archives"`) {
				t.Errorf("run details missing filesystem archives: %s", res.Details)
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
		// A stale/forged session namespace must be ignored; the effective namespace
		// comes from the direct credentials (target), not the session.
		Namespace:  "default",
		PxarFormat: db.PxarFormatV1, BackupPaths: []string{dir},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := Run(ctx, Options{
		Session:     session,
		ArchiveName: "root",
		Direct:      &DirectOptions{Endpoint: fake.URL(), Namespace: "production", Fingerprint: "SHA256:" + fake.Fingerprint(), APIToken: "backup@pbs!fallbck=s3cret"},
	})
	if err != nil {
		t.Fatalf("Run direct: %v", err)
	}
	if res.Status != db.RunStatusCompleted || fake.Finished() != 1 {
		t.Errorf("direct backup did not complete: %+v finished=%d", res, fake.Finished())
	}
	q := fake.Upgrades()[0].URL.Query()
	if q.Get("store") != "store1" || q.Get("backup-id") != "node6" {
		t.Errorf("unexpected upgrade query %s", fake.Upgrades()[0].URL.RawQuery)
	}
	if q.Get("ns") != "production" {
		t.Errorf("direct backup used namespace %q, want the target's %q (session namespace must be ignored)", q.Get("ns"), "production")
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

func TestRunDuplicateBasenames(t *testing.T) {
	fake := pbstest.New(t)
	base := t.TempDir()
	for _, d := range []string{"etc/mydir", "var/lib/mydir"} {
		if err := os.MkdirAll(filepath.Join(base, d), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(base, d, "file.txt"), []byte(d), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	session := &temporal.BackupSessionInfo{
		Datastore: "store1", BackupType: "host", BackupID: "node6", BackupTime: time.Now().Unix(),
		PxarFormat:  db.PxarFormatV1,
		BackupPaths: []string{filepath.Join(base, "etc/mydir"), filepath.Join(base, "var/lib/mydir")},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if _, err := Run(ctx, Options{Session: session, Dial: directDial(fake, session)}); err != nil {
		t.Fatalf("Run with duplicate basenames: %v", err)
	}
	if fake.Finished() != 1 {
		t.Error("backup did not finish")
	}
	if _, ok := fake.Indexes()["root.pxar.didx"]; !ok {
		t.Errorf("expected root.pxar.didx, got %v", fake.Indexes())
	}
}

func TestRunUploadsBlobs(t *testing.T) {
	fake := pbstest.New(t)
	dir := makeTree(t)
	session := &temporal.BackupSessionInfo{
		Datastore: "store1", BackupType: "host", BackupID: "db-postgres-db01", BackupTime: time.Now().Unix(),
		PxarFormat: db.PxarFormatV1, BackupPaths: []string{dir},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	result, err := Run(ctx, Options{
		Session:     session,
		Dial:        directDial(fake, session),
		ArchiveName: "db",
		Blobs:       []gopbs.Blob{{Name: "fallbck-db.json", Data: []byte(`{"schema_version":1}`)}},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Status != db.RunStatusCompleted {
		t.Fatalf("status %s", result.Status)
	}
	if _, ok := fake.Indexes()["db.pxar.didx"]; !ok {
		t.Errorf("archive not named db.pxar.didx: %v", fake.Indexes())
	}
	if _, ok := fake.Blobs()["fallbck-db.json.blob"]; !ok {
		t.Errorf("manifest blob missing: %v", fake.Blobs())
	}
	if _, err := Run(ctx, Options{Session: session, Dial: directDial(fake, session), Blobs: []gopbs.Blob{{Name: "index.json"}}}); err == nil {
		t.Error("reserved blob name accepted")
	}
}

func TestRunAppliesExcludePatterns(t *testing.T) {
	run := func(exclude []string) *temporal.BackupExecutionResult {
		fake := pbstest.New(t)
		dir := makeTree(t)
		session := &temporal.BackupSessionInfo{
			Datastore: "store1", BackupType: "host", BackupID: "node6", BackupTime: time.Now().Unix(),
			PxarFormat: db.PxarFormatV1, BackupPaths: []string{dir}, ExcludePaths: exclude,
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		result, err := Run(ctx, Options{Session: session, Dial: directDial(fake, session)})
		if err != nil {
			t.Fatalf("Run(exclude=%v): %v", exclude, err)
		}
		return result
	}
	full := run(nil)
	// makeTree puts a 3 MiB blob at data/blob.bin; excluding it must shrink the archive
	excluded := run([]string{"*.bin"})
	if excluded.BytesScanned >= full.BytesScanned || full.BytesScanned-excluded.BytesScanned < 2*1024*1024 {
		t.Errorf("exclude had no effect: full=%d excluded=%d", full.BytesScanned, excluded.BytesScanned)
	}

	// Invalid patterns fail before anything is uploaded
	fake := pbstest.New(t)
	session := &temporal.BackupSessionInfo{
		Datastore: "store1", BackupType: "host", BackupID: "node6", BackupTime: time.Now().Unix(),
		PxarFormat: db.PxarFormatV1, BackupPaths: []string{t.TempDir()}, ExcludePaths: []string{"[unclosed"},
	}
	if _, err := Run(context.Background(), Options{Session: session, Dial: directDial(fake, session)}); err == nil {
		t.Error("invalid exclude pattern accepted")
	}
	if len(fake.Upgrades()) != 0 {
		t.Error("session opened despite invalid pattern")
	}
}

// TestWarningMessageWithoutError covers the archiver warnings that carry no error
// (files changing while read): they used to panic the worker after a finished upload
func TestWarningMessageWithoutError(t *testing.T) {
	warnings := []archive.Warning{
		{Kind: archive.WarnSizeChanged, Path: "/data/pg_wal/0001", Bound: 100, Actual: 90},
		{Kind: archive.WarnTorn, Path: "/data/journal/WiredTigerLog.1", Bound: 100, Actual: 120},
		{Kind: archive.WarnTorn, Path: "/data/gone", Err: errors.New("stat: no such file")},
		{Kind: archive.WarnSkipped, Path: "/data/denied", Err: errors.New("permission denied")},
		{Kind: archive.WarnSkipped, Path: "/data/odd"},
		{Kind: archive.WarnBadPattern, Path: "/data/.pxarexclude", Err: errors.New("bad pattern")},
		{Kind: archive.WarnBadPattern, Path: "/data/.pxarexclude"},
	}
	out := detailWarnings(warnings)
	if len(out) != len(warnings) {
		t.Fatalf("expected %d warnings, got %d", len(warnings), len(out))
	}
	for i, w := range out {
		if w.Path != warnings[i].Path || w.Message == "" {
			t.Errorf("warning %d: path=%q message=%q", i, w.Path, w.Message)
		}
	}
	if !strings.Contains(out[0].Message, "100") || !strings.Contains(out[0].Message, "90") {
		t.Errorf("size-changed message should carry both sizes: %q", out[0].Message)
	}
	if !strings.Contains(out[2].Message, "no such file") || !strings.Contains(out[3].Message, "permission denied") {
		t.Errorf("errors should be included: %q / %q", out[2].Message, out[3].Message)
	}
}
