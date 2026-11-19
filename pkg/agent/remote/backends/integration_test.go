//go:build remoteintegration

// End-to-end runs of the remote backup against librc's test services, into a fake
// uploader that reads every file like gopbs does:
//
//	docker compose -f .bin/librc/tests/compose.yml up -d s3 sftp webdav azurite smb
//	go test -tags remoteintegration ./pkg/agent/remote/backends/
package backends

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	libfs "github.com/scheiblingco/librc/fs"
	"github.com/scheiblingco/librc/remote/azure"
	"github.com/scheiblingco/librc/remote/s3"
	"github.com/scheiblingco/librc/remote/sftp"
	"github.com/scheiblingco/librc/remote/smb"
	"github.com/scheiblingco/librc/remote/webdav"
	"golang.org/x/crypto/ssh"

	"github.com/osshield/fallbck/pkg/agent/remote"
	spec "github.com/osshield/fallbck/pkg/remote"
	"github.com/osshield/fallbck/pkg/temporal"
	"github.com/osshield/gopbs"
	"github.com/osshield/gopbs/scan"
)

const azuriteKey = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="

// seeded is what every backend gets below its base, and what a run should read
// (tmp.part is excluded by the job)
var seeded = map[string]string{
	"photos/a.jpg":      "jpeg a",
	"photos/2026/b.jpg": "jpeg b, a little longer",
	"docs/c.txt":        "plain text",
	"docs/tmp.part":     "half an upload",
}

type backendCase struct {
	remote  *spec.Remote
	secrets spec.Secrets
	seed    func(ctx context.Context, t *testing.T) libfs.Filesystem
	base    string // the roots' common prefix, as the job names them
}

func sftpHostKey(t *testing.T, addr string) string {
	t.Helper()
	var key ssh.PublicKey
	errGot := errors.New("got the key")
	_, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: "x", Timeout: 10 * time.Second,
		HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error { key = k; return errGot }})
	if key == nil {
		t.Fatalf("sftp host key from %s: %v", addr, err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

func cases(t *testing.T) map[string]backendCase {
	return map[string]backendCase{
		"s3": {
			remote:  &spec.Remote{Name: "s3", Backend: spec.BackendS3, Provider: spec.S3Other, Endpoint: "http://127.0.0.1:9000", PathStyle: true},
			secrets: spec.Secrets{AccessKeyID: "minioadmin", SecretAccessKey: "minioadmin123"},
			seed: func(ctx context.Context, t *testing.T) libfs.Filesystem {
				f, err := s3.New(ctx, s3.Config{Name: "seed-s3", Bucket: "librc-test/fbk", Provider: s3.ProviderOther,
					AccessKeyID: "minioadmin", SecretAccessKey: "minioadmin123", Endpoint: "http://127.0.0.1:9000", ForcePathStyle: true})
				if err != nil {
					t.Fatal(err)
				}
				return f
			},
			base: "librc-test/fbk/",
		},
		"azureblob": {
			remote:  &spec.Remote{Name: "azure", Backend: spec.BackendAzure, Account: "devstoreaccount1", Endpoint: "http://127.0.0.1:10000/devstoreaccount1"},
			secrets: spec.Secrets{AccountKey: azuriteKey},
			seed: func(ctx context.Context, t *testing.T) libfs.Filesystem {
				f, err := azure.New(ctx, azure.Config{Name: "seed-azure", Container: "fbk-test", Account: "devstoreaccount1", Key: azuriteKey,
					Endpoint: "http://127.0.0.1:10000/devstoreaccount1"})
				if err != nil {
					t.Fatal(err)
				}
				_ = f.Mkdir(ctx, "") // the container; it may exist from an earlier run
				return f
			},
			base: "fbk-test/",
		},
		"sftp": {
			remote: &spec.Remote{Name: "sftp", Backend: spec.BackendSFTP, Host: "127.0.0.1", Port: 2222, User: "testuser",
				KnownHosts: []string{sftpHostKey(t, "127.0.0.1:2222")}},
			secrets: spec.Secrets{Password: "testpass"},
			seed: func(ctx context.Context, t *testing.T) libfs.Filesystem {
				f, err := sftp.New(ctx, sftp.Config{Name: "seed-sftp", Host: "127.0.0.1", Port: 2222, User: "testuser", Password: "testpass", Root: "/upload/fbk"})
				if err != nil {
					t.Fatal(err)
				}
				return f
			},
			base: "upload/fbk/",
		},
		"smb": {
			remote:  &spec.Remote{Name: "smb", Backend: spec.BackendSMB, Host: "127.0.0.1", User: "testuser"},
			secrets: spec.Secrets{Password: "testpass"},
			seed: func(ctx context.Context, t *testing.T) libfs.Filesystem {
				f, err := smb.New(ctx, smb.Config{Name: "seed-smb", Host: "127.0.0.1", User: "testuser", Password: "testpass", Share: "share/fbk"})
				if err != nil {
					t.Fatal(err)
				}
				return f
			},
			base: "share/fbk/",
		},
		"webdav": {
			remote:  &spec.Remote{Name: "webdav", Backend: spec.BackendWebDAV, URL: "http://127.0.0.1:18080", Vendor: "rclone", User: "testuser"},
			secrets: spec.Secrets{Password: "testpass"},
			seed: func(ctx context.Context, t *testing.T) libfs.Filesystem {
				f, err := webdav.New(ctx, webdav.Config{Name: "seed-webdav", URL: "http://127.0.0.1:18080", Vendor: webdav.VendorRclone,
					User: "testuser", Password: "testpass", Root: "fbk"})
				if err != nil {
					t.Fatal(err)
				}
				return f
			},
			base: "fbk/",
		},
	}
}

// upload reads the tree like gopbs does and records each group's files, keyed by
// their path below the archive root
type upload struct{ groups map[string]map[string]string }

func (u *upload) fn(_ context.Context, group string, tree *scan.Node, blobs []gopbs.Blob) (*temporal.BackupExecutionResult, error) {
	files := map[string]string{}
	var walk func(n *scan.Node, path string) error
	walk = func(n *scan.Node, path string) error {
		if n.Stream != nil {
			data, err := io.ReadAll(n.Stream)
			if err != nil {
				return err
			}
			files[path] = string(data)
		}
		for _, c := range n.Children {
			if err := walk(c, strings.TrimPrefix(path+"/"+c.Name, "/")); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(tree, ""); err != nil {
		return nil, err
	}
	if len(blobs) != 1 || blobs[0].Name != spec.ManifestBlobName {
		return nil, errors.New("no manifest blob")
	}
	u.groups[group] = files
	return &temporal.BackupExecutionResult{SnapshotID: "host/" + group + "/2026-11-19T02:00:00Z"}, nil
}

func run(t *testing.T, r *spec.Remote, secrets spec.Secrets, roots []string, split string) (*temporal.BackupExecutionResult, *upload, error) {
	r.ID = uuid.New()
	up := &upload{groups: map[string]map[string]string{}}
	res, err := remote.Run(context.Background(), remote.RunOptions{
		Session:     &temporal.BackupSessionInfo{JobID: uuid.New(), JobName: "it", BackupID: "remote-" + r.Name, RunID: uuid.NewString()},
		Spec:        &spec.Spec{RemoteID: r.ID, Roots: roots, Exclude: []string{"*.part"}, Split: split},
		Credentials: spec.RunCredentials{Remote: r, Secrets: secrets},
		Open:        NewSession,
		Upload:      up.fn,
		StateDir:    t.TempDir(),
	})
	return res, up, err
}

func TestRemoteBackends(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	for name, c := range cases(t) {
		t.Run(name, func(t *testing.T) {
			f := c.seed(ctx, t)
			for p, data := range seeded {
				if err := f.Put(ctx, p, strings.NewReader(data), int64(len(data)), time.Now()); err != nil {
					t.Fatalf("seed %s: %v", p, err)
				}
			}
			roots := []string{c.base + "photos", c.base + "docs"}

			res, up, err := run(t, c.remote, c.secrets, roots, spec.SplitSingle)
			if err != nil || res.Status != "completed" {
				t.Fatalf("single: %v %+v", err, res)
			}
			got := up.groups["remote-"+c.remote.Name]
			want := map[string]string{}
			for p, data := range seeded {
				if !strings.HasSuffix(p, ".part") {
					want[c.base+p] = data
				}
			}
			if len(got) != len(want) {
				t.Fatalf("single: got %v, want %v", got, want)
			}
			for p, data := range want {
				if got[p] != data {
					t.Errorf("single: %s = %q, want %q", p, got[p], data)
				}
			}

			res, up, err = run(t, c.remote, c.secrets, roots, spec.SplitPerRoot)
			if err != nil || res.Status != "completed" {
				t.Fatalf("per_root: %v %+v", err, res)
			}
			photos := up.groups["remote-"+c.remote.Name+"-"+strings.ReplaceAll(c.base+"photos", "/", "-")]
			if photos["a.jpg"] != seeded["photos/a.jpg"] || photos["2026/b.jpg"] != seeded["photos/2026/b.jpg"] || len(photos) != 2 {
				t.Errorf("per_root photos group: %v (groups %v)", photos, keys(up.groups))
			}
			if len(up.groups) != 3 {
				t.Errorf("per_root: groups %v, want two roots and the job's", keys(up.groups))
			}

			// No roots: every bucket, container or share the credential can see
			if _, ok := spec.DiscoversRoots(c.remote.Backend); !ok {
				return
			}
			res, up, err = run(t, c.remote, c.secrets, nil, spec.SplitSingle)
			if err != nil || res.Status != "completed" || !strings.Contains(string(res.Details), `"discovered":true`) {
				t.Fatalf("no roots: %v %+v", err, res)
			}
			got = up.groups["remote-"+c.remote.Name]
			for p, data := range want {
				if got[p] != data {
					t.Errorf("no roots: %s = %q, want %q", p, got[p], data)
				}
			}
			for p := range got {
				if strings.Contains(strings.SplitN(p, "/", 2)[0], "$") {
					t.Errorf("no roots: an administrative share was backed up: %s", p)
				}
			}
		})
	}
}

// A server whose key isn't the remote's is refused during the key exchange, before
// the agent sends the password
func TestSFTPWrongHostKey(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	key, _ := ssh.NewPublicKey(pub)
	r := &spec.Remote{Name: "sftp", Backend: spec.BackendSFTP, Host: "127.0.0.1", Port: 2222, User: "testuser",
		KnownHosts: []string{strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))}}
	res, _, err := run(t, r, spec.Secrets{Password: "testpass"}, []string{"upload"}, spec.SplitSingle)
	if err == nil {
		t.Fatalf("a wrong host key was accepted: %+v", res)
	}
	if !strings.Contains(err.Error(), "key mismatch") && !strings.Contains(err.Error(), "host key") {
		t.Fatalf("want a host key error, got %v", err)
	}
	t.Log(err)
}

func keys(m map[string]map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
