//go:build pbse2e

package agent_test

// End-to-end runs against a real PBS (pkg/pbse2e): the real agent activity uploads
// through the in-process tunnel with the least-privilege token (DatastoreBackup on the
// e2e namespace only), and proxmox-backup-client inside the PBS container restores,
// as an operator would. The tests share one datastore and run in file order.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	mrand "math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/osshield/fallbck/pkg/agent/backup"
	"github.com/osshield/fallbck/pkg/db"
	"github.com/osshield/fallbck/pkg/pbs"
	"github.com/osshield/fallbck/pkg/pbse2e"
	"github.com/osshield/fallbck/pkg/rundetail"
	"github.com/osshield/fallbck/pkg/temporal"
	"github.com/osshield/fallbck/pkg/temporal/activities"
)

var srv *pbse2e.PBS

func TestMain(m *testing.M) { os.Exit(pbse2e.Main(m, &srv)) }

const e2eNamespace = "e2e"

// lastBackupTime keeps snapshot times strictly increasing: PBS refuses a snapshot
// that isn't newer than the group's last one
var lastBackupTime int64

func nextBackupTime() int64 {
	lastBackupTime = max(time.Now().Unix(), lastBackupTime+1)
	return lastBackupTime
}

// testKey is a target key as the server holds it; encryption() hands the agent a
// fresh copy per run, since the activity wipes it afterwards
type testKey struct {
	raw         [32]byte
	fingerprint string
	masterPub   string
}

func newKey(t *testing.T, masterPub string) *testKey {
	t.Helper()
	raw, fp, err := pbs.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return &testKey{raw: raw, fingerprint: fp, masterPub: masterPub}
}

func (k *testKey) encryption() (*backup.Encryption, error) {
	return backup.NewEncryption(base64.StdEncoding.EncodeToString(k.raw[:]), k.fingerprint, time.Now(), k.masterPub)
}

// masterKey returns an RSA master key pair as PEM (public PKIX, private PKCS#1)
func masterKey(t *testing.T, bits int) (pub, priv string) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pub = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	priv = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}))
	return pub, priv
}

// writeTree fills a directory with a config file and size bytes of incompressible
// data from seed (same seed, same chunks); returns the data file's SHA-256
func writeTree(t *testing.T, size int, seed uint64) (dir, sum string) {
	t.Helper()
	dir = t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.conf"), []byte("[app]\nname=fallbck\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, size)
	r := mrand.NewChaCha8([32]byte{byte(seed), byte(seed >> 8)})
	_, _ = r.Read(data)
	if err := os.WriteFile(filepath.Join(dir, "data.bin"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	s := sha256.Sum256(data)
	return dir, hex.EncodeToString(s[:])
}

type runOpts struct {
	format   string   // pxar format, default v1
	key      *testKey // nil: plaintext
	cacheDir string   // metadata change detection cache, "" disables it
}

// backupRun runs the filesystem activity for dir into host/<backupID> in the e2e
// namespace with the backup@pbs!fallbck token, through the tunnel
func backupRun(t *testing.T, backupID, dir string, o runOpts) *temporal.BackupExecutionResult {
	t.Helper()
	target := srv.Target("backup", e2eNamespace)
	if o.format != "" {
		target.PxarFormat = o.format
	}
	h := startTunnel(t, target)
	session := h.session(t, backupID, nextBackupTime(), dir)
	acts := activities.NewAgentActivities()
	acts.Tunnel = h.conn
	acts.CacheDir = o.cacheDir
	if o.key != nil {
		session.Encrypted, session.KeyFingerprint = true, o.key.fingerprint
		acts.EncryptionKey = func(context.Context, string) (*backup.Encryption, error) { return o.key.encryption() }
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	res, err := runActivity(ctx, acts, session)
	if err != nil {
		t.Fatalf("backup %s: %v", backupID, err)
	}
	if res.Status != db.RunStatusCompleted {
		t.Fatalf("backup %s: status %s: %s", backupID, res.Status, res.ErrorMessage)
	}
	want := ""
	if o.key != nil {
		want = o.key.fingerprint
	}
	if res.KeyFingerprint != want {
		t.Errorf("run key fingerprint %q, want %q", res.KeyFingerprint, want)
	}
	return res
}

func details(t *testing.T, res *temporal.BackupExecutionResult) rundetail.Filesystem {
	t.Helper()
	var d rundetail.Filesystem
	if err := json.Unmarshal(res.Details, &d); err != nil {
		t.Fatalf("run details: %v", err)
	}
	return d
}

// archiveName is the name proxmox-backup-client restores the run's pxar archive by
// (x.pxar, or x.mpxar for a split v2 archive)
func archiveName(t *testing.T, res *temporal.BackupExecutionResult) string {
	t.Helper()
	for _, a := range details(t, res).Archives {
		if a.Kind == "pxar" {
			return strings.TrimSuffix(a.Name, ".didx")
		}
	}
	t.Fatalf("no pxar archive in %s", res.Details)
	return ""
}

// restore restores the run's archive in the container (keyfile "" = plaintext) and
// returns the SHA-256 of the restored data.bin
func restore(t *testing.T, res *temporal.BackupExecutionResult, keyfile, passphrase string) (string, error) {
	t.Helper()
	out := "/tmp/restore-" + strings.ReplaceAll(res.SnapshotID, "/", "_")
	args := []string{"restore", "--ns", e2eNamespace, res.SnapshotID, archiveName(t, res), out}
	var env []string
	if keyfile != "" {
		args = append(args, "--keyfile", keyfile)
		env = append(env, "PBS_ENCRYPTION_PASSWORD="+passphrase)
	}
	_, _ = srv.Exec(nil, nil, "rm", "-rf", out)
	if msg, err := srv.Client(env, args...); err != nil {
		return "", &restoreError{err, msg}
	}
	sum, err := srv.Exec(nil, nil, "sh", "-c", `sha256sum "$(find "$1" -name data.bin)"`, "sh", out)
	if err != nil {
		t.Fatalf("hashing restored data: %v\n%s", err, sum)
	}
	return strings.Fields(sum)[0], nil
}

type restoreError struct {
	err error
	out string
}

func (e *restoreError) Error() string { return e.err.Error() + "\n" + e.out }

// snapshotFiles maps each file of the snapshot to its crypt mode
func snapshotFiles(t *testing.T, res *temporal.BackupExecutionResult) map[string]string {
	t.Helper()
	group := res.SnapshotID[:strings.LastIndex(res.SnapshotID, "/")]
	out, err := srv.Client(nil, "snapshot", "list", group, "--ns", e2eNamespace, "--output-format", "json")
	if err != nil {
		t.Fatalf("snapshot list: %v\n%s", err, out)
	}
	var snaps []struct {
		Type  string `json:"backup-type"`
		ID    string `json:"backup-id"`
		Time  int64  `json:"backup-time"`
		Files []struct {
			Name      string `json:"filename"`
			CryptMode string `json:"crypt-mode"`
		} `json:"files"`
	}
	if err := json.Unmarshal([]byte(out), &snaps); err != nil {
		t.Fatalf("snapshot list: %v\n%s", err, out)
	}
	for _, s := range snaps {
		if s.Type+"/"+s.ID+"/"+time.Unix(s.Time, 0).UTC().Format("2006-01-02T15:04:05Z") == res.SnapshotID {
			files := map[string]string{}
			for _, f := range s.Files {
				files[f.Name] = f.CryptMode
			}
			return files
		}
	}
	t.Fatalf("snapshot %s not listed", res.SnapshotID)
	return nil
}

// TestPBSIncrementalLeastPrivilege: two v2 runs with a DatastoreBackup-only token; the
// second downloads the previous index, reuses every unchanged file and adds next to
// nothing to the datastore. (BytesUploaded is an estimate from chunk counts, so the
// datastore's chunk count is the measure.)
func TestPBSIncrementalLeastPrivilege(t *testing.T) {
	dir, sum := writeTree(t, 8<<20, 1)
	opts := runOpts{format: db.PxarFormatV2, cacheDir: t.TempDir()}
	backupRun(t, "incremental", dir, opts)
	before, err := srv.Chunks()
	if err != nil {
		t.Fatal(err)
	}
	second := backupRun(t, "incremental", dir, opts)
	after, err := srv.Chunks()
	if err != nil {
		t.Fatal(err)
	}

	reuse := details(t, second).Reuse
	if reuse == nil || reuse.ReusedFiles != reuse.Files || reuse.ReusedBytes < 8<<20 {
		t.Fatalf("second run did not reuse everything: %s", second.Details)
	}
	// the new metadata archive and the payload stream's start and end markers
	if added := after - before; added > 3 {
		t.Errorf("second run added %d chunks to the datastore", added)
	}
	got, err := restore(t, second, "", "")
	if err != nil || got != sum {
		t.Fatalf("restore of the incremental snapshot: sum %s want %s, err %v", got, sum, err)
	}
}

// TestPBSEncryptedRestore: an encrypted snapshot restores with the exported key file,
// not without it, and the key comes back from the snapshot with the RSA master key
func TestPBSEncryptedRestore(t *testing.T) {
	for _, bits := range []int{4096, 2048} {
		t.Run(strconv.Itoa(bits)+"-bit master key", func(t *testing.T) {
			pub, priv := masterKey(t, bits)
			key := newKey(t, pub)
			dir, sum := writeTree(t, 4<<20, 2)
			res := backupRun(t, "crypt-"+strconv.Itoa(bits), dir, runOpts{key: key})

			files := snapshotFiles(t, res)
			if files[archiveName(t, res)+".didx"] != "encrypt" {
				t.Errorf("archive not encrypted: %v", files)
			}
			if _, ok := files["rsa-encrypted.key.blob"]; !ok {
				t.Errorf("no master-key wrapped key in the snapshot: %v", files)
			}

			if _, err := restore(t, res, "", ""); err == nil {
				t.Error("restore without the key succeeded")
			}

			const passphrase = "correct horse battery"
			keyfile, err := pbs.ExportKeyFile(key.raw, passphrase, "pbse2e")
			if err != nil {
				t.Fatal(err)
			}
			if err := srv.WriteFile("/tmp/exported.json", keyfile); err != nil {
				t.Fatal(err)
			}
			if got, err := restore(t, res, "/tmp/exported.json", passphrase); err != nil || got != sum {
				t.Fatalf("restore with the exported key: sum %s want %s, err %v", got, sum, err)
			}

			// Recovery: the wrapped key from the snapshot, opened with the master private key
			if err := srv.WriteFile("/tmp/master.pem", []byte(priv)); err != nil {
				t.Fatal(err)
			}
			_, _ = srv.Exec(nil, nil, "rm", "-f", "/tmp/blob", "/tmp/recovered.json")
			for _, args := range [][]string{
				{"restore", "--ns", e2eNamespace, res.SnapshotID, "rsa-encrypted.key.blob", "/tmp/blob"},
				{"key", "import-with-master-key", "/tmp/recovered.json", "--encrypted-keyfile", "/tmp/blob", "--master-keyfile", "/tmp/master.pem", "--kdf", "none"},
			} {
				if out, err := srv.Client(nil, args...); err != nil {
					t.Fatalf("%s: %v\n%s", args[0], err, out)
				}
			}
			if got, err := restore(t, res, "/tmp/recovered.json", ""); err != nil || got != sum {
				t.Fatalf("restore with the recovered key: sum %s want %s, err %v", got, sum, err)
			}
		})
	}
}

// TestPBSKeyRingDedup: hosts sharing a key (one ring) store the same data once; a
// different key (another ring) stores it again
func TestPBSKeyRingDedup(t *testing.T) {
	dir, _ := writeTree(t, 16<<20, 3)
	ring, other := newKey(t, ""), newKey(t, "")
	added := func(backupID string, key *testKey) int {
		t.Helper()
		before, err := srv.Chunks()
		if err != nil {
			t.Fatal(err)
		}
		backupRun(t, backupID, dir, runOpts{key: key})
		after, err := srv.Chunks()
		if err != nil {
			t.Fatal(err)
		}
		return after - before
	}
	first := added("ring-a", ring)
	same := added("ring-b", ring)
	different := added("ring-c", other)
	t.Logf("new chunks: first %d, same key %d, other key %d", first, same, different)
	if first < 3 {
		t.Fatalf("first run added only %d chunks; the data is too small to tell", first)
	}
	if same*4 > first {
		t.Errorf("a second host on the same key added %d chunks of %d", same, first)
	}
	if different*2 < first {
		t.Errorf("another key added only %d chunks of %d: dedup across keys?", different, first)
	}
}

// TestPBSMixedGroup: a group that switches from plaintext to encrypted keeps working,
// metadata cache included, and each snapshot restores its own way
func TestPBSMixedGroup(t *testing.T) {
	dir, sum := writeTree(t, 4<<20, 4)
	cache := t.TempDir()
	plain := backupRun(t, "mixed", dir, runOpts{format: db.PxarFormatV2, cacheDir: cache})
	key := newKey(t, "")
	crypt := backupRun(t, "mixed", dir, runOpts{format: db.PxarFormatV2, cacheDir: cache, key: key})

	if got, err := restore(t, plain, "", ""); err != nil || got != sum {
		t.Fatalf("plaintext snapshot: sum %s want %s, err %v", got, sum, err)
	}
	const passphrase = "correct horse battery"
	keyfile, err := pbs.ExportKeyFile(key.raw, passphrase, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.WriteFile("/tmp/mixed.json", keyfile); err != nil {
		t.Fatal(err)
	}
	if got, err := restore(t, crypt, "/tmp/mixed.json", passphrase); err != nil || got != sum {
		t.Fatalf("encrypted snapshot: sum %s want %s, err %v", got, sum, err)
	}
}

// TestPBSVerifyAndPrune runs last: a PBS verify of everything the tests wrote, then a
// prune with root (FallBCK's token can't, by design)
func TestPBSVerifyAndPrune(t *testing.T) {
	out, err := srv.Exec(nil, nil, "proxmox-backup-manager", "verify", pbse2e.Datastore)
	if err != nil || !strings.Contains(out, "TASK OK") {
		t.Fatalf("verify: %v\n%s", err, out)
	}
	if out, err := srv.Client(nil, "prune", "host/mixed", "--ns", e2eNamespace, "--keep-last", "1"); err != nil {
		t.Fatalf("prune: %v\n%s", err, out)
	}
	out, err = srv.Client(nil, "snapshot", "list", "host/mixed", "--ns", e2eNamespace, "--output-format", "json")
	if err != nil {
		t.Fatalf("snapshot list: %v\n%s", err, out)
	}
	var snaps []json.RawMessage
	if err := json.Unmarshal([]byte(out), &snaps); err != nil || len(snaps) != 1 {
		t.Fatalf("after prune: %d snapshots (%v)\n%s", len(snaps), err, out)
	}
}
