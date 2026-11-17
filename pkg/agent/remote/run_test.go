package remote

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/osshield/gopbs"
	"github.com/osshield/gopbs/scan"

	dbrun "github.com/osshield/fallbck/pkg/agent/dbbackup"
	spec "github.com/osshield/fallbck/pkg/remote"
	"github.com/osshield/fallbck/pkg/rundetail"
	"github.com/osshield/fallbck/pkg/temporal"
)

// fakeOpener serves roots from fake filesystems; a missing root fails to open
type fakeOpener struct {
	roots  map[string]*fakeFS
	creds  Credentials
	closed bool
}

func (f *fakeOpener) Open(_ context.Context, root string) (Source, error) {
	if fs, ok := f.roots[root]; ok {
		return fs, nil
	}
	return nil, errors.New("no such bucket")
}

func (f *fakeOpener) Close() error { f.closed = true; return nil }

// fakeUpload reads the whole tree like gopbs does and records the files of the last
// snapshot, and the groups written in order; failGroup makes that group's upload fail
type fakeUpload struct {
	files     map[string]string
	manifest  spec.Manifest
	groups    []string
	byGroup   map[string]map[string]string
	failGroup string
}

func (u *fakeUpload) upload(_ context.Context, group string, tree *scan.Node, blobs []gopbs.Blob) (*temporal.BackupExecutionResult, error) {
	if group == u.failGroup {
		return nil, errors.New("datastore full")
	}
	u.files = map[string]string{}
	var walk func(n *scan.Node, path string) error
	walk = func(n *scan.Node, path string) error {
		if n.Stream != nil {
			data, err := io.ReadAll(n.Stream)
			if err != nil {
				return err
			}
			u.files[path] = string(data)
		}
		for _, c := range n.Children {
			if err := walk(c, path+"/"+c.Name); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(tree, tree.Name); err != nil {
		return nil, err
	}
	if len(blobs) != 1 || blobs[0].Name != spec.ManifestBlobName || json.Unmarshal(blobs[0].Data, &u.manifest) != nil {
		return nil, errors.New("no manifest blob")
	}
	u.groups = append(u.groups, group)
	if u.byGroup == nil {
		u.byGroup = map[string]map[string]string{}
	}
	u.byGroup[group] = u.files
	return &temporal.BackupExecutionResult{SnapshotID: "host/" + group + "/2026-11-17T02:00:00Z", BytesScanned: 10, BytesUploaded: 5}, nil
}

type runEnv struct {
	opener *fakeOpener
	up     *fakeUpload
	opts   RunOptions
}

func newRun(roots []string, fs map[string]*fakeFS) *runEnv {
	e := &runEnv{opener: &fakeOpener{roots: fs}, up: &fakeUpload{}}
	r := &spec.Remote{Name: "minio", Backend: spec.BackendS3, Endpoint: "http://minio:9000"}
	e.opts = RunOptions{
		Session:     &temporal.BackupSessionInfo{JobID: uuid.New(), JobName: "photos", BackupID: "remote-minio"},
		Spec:        &spec.Spec{RemoteID: uuid.New(), Roots: roots},
		Credentials: spec.RunCredentials{Remote: r, Secrets: spec.Secrets{AccessKeyID: "AKIA", SecretAccessKey: "server-secret"}},
		Open: func(_ *spec.Remote, c Credentials) (Opener, error) {
			e.opener.creds = c
			return e.opener, nil
		},
		Upload: e.up.upload,
	}
	return e
}

func details(t *testing.T, res *temporal.BackupExecutionResult) spec.Manifest {
	t.Helper()
	var w struct {
		Type     string        `json:"type"`
		Manifest spec.Manifest `json:"manifest"`
	}
	if err := json.Unmarshal(res.Details, &w); err != nil || w.Type != rundetail.TypeRemote {
		t.Fatalf("details %s: %v", res.Details, err)
	}
	return w.Manifest
}

func TestRunSingleSnapshot(t *testing.T) {
	mt := time.Unix(1700000000, 0)
	e := newRun([]string{"photos/2026", "docs"}, map[string]*fakeFS{
		"photos/2026": {mtime: mt, objects: map[string]string{"a.jpg": "aaa", "trip/b.jpg": "bb"}},
		"docs":        {mtime: mt, objects: map[string]string{"c.txt": "c"}},
	})
	res, err := Run(context.Background(), e.opts)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "completed" || res.SnapshotID == "" || res.ErrorMessage != "" {
		t.Fatalf("result %+v", res)
	}
	want := map[string]string{"remote/photos/2026/a.jpg": "aaa", "remote/photos/2026/trip/b.jpg": "bb", "remote/docs/c.txt": "c"}
	if len(e.up.files) != len(want) {
		t.Errorf("files %v", e.up.files)
	}
	for p, data := range want {
		if e.up.files[p] != data {
			t.Errorf("%s: %q", p, e.up.files[p])
		}
	}
	m := e.up.manifest
	if m.Remote.Identity != "http://minio:9000" || m.Remote.Backend != spec.BackendS3 || m.Job.Group != "remote-minio" ||
		m.Totals != (spec.Totals{Roots: 2, Objects: 3, Bytes: 6}) || m.Roots[0].Root != "photos/2026" || m.Roots[0].Objects != 2 {
		t.Errorf("manifest %+v", m)
	}
	if d := details(t, res); d.Totals != m.Totals {
		t.Errorf("details totals %+v", d.Totals)
	}
	if strings.Contains(string(res.Details), "server-secret") || e.opener.creds.SecretAccessKey != "server-secret" || !e.opener.closed {
		t.Errorf("credentials: %+v closed=%v", e.opener.creds, e.opener.closed)
	}
}

// An object that shrank after listing is padded, and the run ends partial with the
// warning in its detail
func TestRunSizeGuardWarningIsPartial(t *testing.T) {
	fs := &fakeFS{objects: map[string]string{"a": "hello", "b": "ok"}}
	e := newRun([]string{"bucket"}, map[string]*fakeFS{"bucket": fs})
	inner := e.opts.Upload
	e.opts.Upload = func(ctx context.Context, group string, tree *scan.Node, blobs []gopbs.Blob) (*temporal.BackupExecutionResult, error) {
		fs.objects["a"] = "he"
		return inner(ctx, group, tree, blobs)
	}
	res, err := Run(context.Background(), e.opts)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "partial" || !strings.Contains(res.ErrorMessage, "shrank") {
		t.Fatalf("result %+v", res)
	}
	if e.up.files["remote/bucket/a"] != "he\x00\x00\x00" {
		t.Errorf("padded content %q", e.up.files["remote/bucket/a"])
	}
	if d := details(t, res); len(d.Warnings) != 1 || !strings.HasPrefix(d.Warnings[0], "bucket/a shrank") {
		t.Errorf("detail warnings %v", d.Warnings)
	}
}

func TestRunRootFailures(t *testing.T) {
	e := newRun([]string{"good", "gone"}, map[string]*fakeFS{"good": {objects: map[string]string{"x": "1"}}})
	res, err := Run(context.Background(), e.opts)
	if err != nil || res.Status != "partial" || !strings.Contains(res.ErrorMessage, "gone: no such bucket") {
		t.Fatalf("one root failed: %+v %v", res, err)
	}
	if r := e.up.manifest.Roots[1]; r.Status != spec.RootFailed || e.up.manifest.Totals.Failed != 1 {
		t.Errorf("manifest roots %+v", e.up.manifest.Roots)
	}

	e = newRun([]string{"gone"}, nil)
	res, err = Run(context.Background(), e.opts)
	if err == nil || res == nil || res.Status != "failed" || e.up.files != nil {
		t.Errorf("all roots failed: %+v %v", res, err)
	}
}

// A job that names a profile uses the profile's credential, never the server's, and
// only when the profile is for this remote
func TestRunProfile(t *testing.T) {
	e := newRun([]string{"bucket"}, map[string]*fakeFS{"bucket": {objects: map[string]string{"x": "1"}}})
	e.opts.Spec.Profile = "minio"
	e.opts.Credentials.Secrets = spec.Secrets{}
	profiles := map[string]*spec.Profile{
		"minio": {Backend: spec.BackendS3, Endpoint: "http://minio:9000", Secrets: spec.Secrets{AccessKeyID: "AKIA", SecretAccessKey: "agent-secret"}},
		"other": {Backend: spec.BackendS3, Endpoint: "http://elsewhere:9000", Secrets: spec.Secrets{AccessKeyID: "AKIA", SecretAccessKey: "x"}},
	}
	e.opts.Profile = func(name string) (*spec.Profile, error) {
		if p, ok := profiles[name]; ok {
			return p, nil
		}
		return nil, errors.New("not found")
	}
	if res, err := Run(context.Background(), e.opts); err != nil || res.Status != "completed" || e.opener.creds.SecretAccessKey != "agent-secret" {
		t.Fatalf("profile run: %+v %v creds %+v", res, err, e.opener.creds)
	}
	for _, name := range []string{"other", "missing"} {
		e.opts.Spec.Profile = name
		_, err := Run(context.Background(), e.opts)
		if !dbrun.IsPrecheck(err) {
			t.Errorf("profile %s: %v", name, err)
		}
	}
	e.opts.Spec.Profile, e.opts.Profile = "minio", nil
	if _, err := Run(context.Background(), e.opts); !dbrun.IsPrecheck(err) {
		t.Errorf("no credential store: %v", err)
	}
}

// One snapshot per root in <job group>-<root>, each root at the top of its
// snapshot, then the run manifest in the job's group
func TestRunPerRoot(t *testing.T) {
	e := newRun([]string{"photos/2026", "docs"}, map[string]*fakeFS{
		"photos/2026": {objects: map[string]string{"a.jpg": "aaa"}},
		"docs":        {objects: map[string]string{"c.txt": "c"}},
	})
	e.opts.Spec.Split = spec.SplitPerRoot
	e.opts.StateDir = t.TempDir()
	res, err := Run(context.Background(), e.opts)
	if err != nil || res.Status != "completed" {
		t.Fatalf("%+v %v", res, err)
	}
	want := []string{"remote-minio-photos-2026", "remote-minio-docs", "remote-minio"}
	if !slices.Equal(e.up.groups, want) {
		t.Fatalf("groups %v, want %v", e.up.groups, want)
	}
	if e.up.byGroup[want[0]]["remote/a.jpg"] != "aaa" || e.up.byGroup[want[1]]["remote/c.txt"] != "c" {
		t.Errorf("root snapshots %v", e.up.byGroup)
	}
	if f := e.up.byGroup["remote-minio"]; len(f) != 1 || f["remote/"+spec.ManifestBlobName] == "" {
		t.Errorf("manifest snapshot %v", f)
	}
	if res.SnapshotID != "host/remote-minio/2026-11-17T02:00:00Z" || res.BytesScanned != 30 || res.BytesUploaded != 15 {
		t.Errorf("result %+v", res)
	}
	d := details(t, res)
	if r := d.Roots[0]; r.Group != want[0] || r.SnapshotID != "host/"+want[0]+"/2026-11-17T02:00:00Z" || r.Objects != 1 {
		t.Errorf("root result %+v", r)
	}
}

// A retried attempt of the same run skips the roots the earlier one finished; a new
// run reads everything again
func TestRunPerRootResume(t *testing.T) {
	fs := map[string]*fakeFS{"aaa": {objects: map[string]string{"x": "1"}}, "bbb": {objects: map[string]string{"y": "2"}}}
	e := newRun([]string{"aaa", "bbb"}, fs)
	e.opts.Spec.Split = spec.SplitPerRoot
	e.opts.StateDir = t.TempDir()
	e.up.failGroup = "remote-minio-bbb"
	res, err := Run(context.Background(), e.opts)
	if err != nil || res.Status != "partial" || !strings.Contains(res.ErrorMessage, "bbb: datastore full") {
		t.Fatalf("first attempt: %+v %v", res, err)
	}

	e.up.failGroup, e.up.groups = "", nil
	res, err = Run(context.Background(), e.opts)
	if err != nil || res.Status != "completed" || !slices.Equal(e.up.groups, []string{"remote-minio-bbb", "remote-minio"}) {
		t.Fatalf("retry: %+v %v groups %v", res, err, e.up.groups)
	}
	if r := details(t, res).Roots[0]; r.Status != spec.RootCompleted || r.SnapshotID == "" || r.Note == "" {
		t.Errorf("resumed root %+v", r)
	}

	e.up.groups = nil
	e.opts.Session.BackupRunID = uuid.New()
	if _, err := Run(context.Background(), e.opts); err != nil || len(e.up.groups) != 3 {
		t.Errorf("new run: %v groups %v", err, e.up.groups)
	}
}
