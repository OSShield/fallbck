package vcs

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	dbrun "github.com/osshield/fallbck/pkg/agent/dbbackup"
	"github.com/osshield/fallbck/pkg/rundetail"
	"github.com/osshield/fallbck/pkg/temporal"
	spec "github.com/osshield/fallbck/pkg/vcs"
	"github.com/osshield/gopbs"
	"github.com/osshield/gopbs/scan"
)

// recorder stands in for the backup engine: it keeps what each run would upload
type recorder struct {
	mu       sync.Mutex
	paths    map[string]*scan.Node
	manifest spec.Manifest
	calls    int
}

func (r *recorder) upload(_ context.Context, tree *scan.Node, blobs []gopbs.Blob) (*temporal.BackupExecutionResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	r.paths = flatten(tree, "", map[string]*scan.Node{})
	r.manifest = spec.Manifest{}
	for _, b := range blobs {
		if b.Name == spec.ManifestBlobName {
			if err := json.Unmarshal(b.Data, &r.manifest); err != nil {
				return nil, err
			}
		}
	}
	return &temporal.BackupExecutionResult{SnapshotID: "host/vcs-test/2026-11-04T02:00:00Z", BytesScanned: 1}, nil
}

func (r *recorder) has(path string) bool { return r.paths[path] != nil }

func (r *recorder) repo(path string) spec.RepoResult {
	for _, rr := range r.manifest.Repositories {
		if rr.Path == path {
			return rr
		}
	}
	return spec.RepoResult{}
}

type runEnv struct {
	h     *gitHost
	state string
	rec   *recorder
	job   uuid.UUID
}

func newRunEnv(t *testing.T) *runEnv {
	return &runEnv{h: newGitHost(t), state: t.TempDir(), rec: &recorder{}, job: uuid.New()}
}

func (e *runEnv) opts(t *testing.T, repos ...string) RunOptions {
	t.Helper()
	urls := make([]string, len(repos))
	for i, r := range repos {
		urls[i] = e.h.url(r)
	}
	return RunOptions{
		Session:     &temporal.BackupSessionInfo{JobID: e.job, BackupRunID: uuid.New(), BackupType: "host", BackupID: "vcs-test", JobName: "repos"},
		Spec:        &spec.Spec{ConnectionID: uuid.New(), Repositories: urls},
		Credentials: spec.Credentials{Provider: spec.ProviderGit, BaseURL: e.h.srv.URL, Token: testToken, CAPEM: e.h.caPEM},
		StateDir:    e.state, TempDir: t.TempDir(),
		Upload: e.rec.upload,
	}
}

// dir is a repository's directory in the archive (<host>_<port>/<path>)
func (e *runEnv) dir(t *testing.T, repo string) string {
	t.Helper()
	_, d, err := spec.ParseRepoURL(e.h.url(repo))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestRunBacksUpRepositories(t *testing.T) {
	e := newRunEnv(t)
	e.h.repo(t, "team/app.git")
	e.h.repo(t, "team/lib.git")
	var items []map[string]rundetail.ProgressItem
	var mu sync.Mutex
	o := e.opts(t, "team/app.git", "team/lib.git")
	o.Items = func(m map[string]rundetail.ProgressItem) { mu.Lock(); items = append(items, m); mu.Unlock() }

	res, err := Run(ctx(t), o)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "completed" || res.SnapshotID == "" {
		t.Fatalf("result %+v", res)
	}
	app, lib := e.dir(t, "team/app.git"), e.dir(t, "team/lib.git")
	for _, want := range []string{app + "/repository.git/HEAD", lib + "/repository.git/packed-refs", RestoreReadme, RestoreScript} {
		if !e.rec.has(want) {
			t.Errorf("snapshot lacks %s", want)
		}
	}
	m := e.rec.manifest
	if m.Totals.Repositories != 2 || m.Totals.Completed != 2 || m.Source.Provider != spec.ProviderGit || m.Generator.GitVersion == "" {
		t.Errorf("manifest %+v", m)
	}
	if r := e.rec.repo(app); !r.Changed || r.Refs != 3 || r.Bytes == 0 || r.LastFetched == nil {
		t.Errorf("app result %+v", r)
	}
	var wrapped rundetail.Wrapper
	if err := json.Unmarshal(res.Details, &wrapped); err != nil || wrapped.Type != rundetail.TypeVCS {
		t.Errorf("details %s: %v", res.Details, err)
	}
	if len(items) == 0 {
		t.Error("no progress items reported")
	}

	// Nothing changed upstream: refs are compared with ls-remote, nothing is fetched,
	// and both mirrors are in the snapshot again
	fetches := e.h.fetches.Load()
	if fetches != 2 {
		t.Fatalf("the first run should download one pack per repository, counted %d", fetches)
	}
	res, err = Run(ctx(t), e.opts(t, "team/app.git", "team/lib.git"))
	if err != nil || res.Status != "completed" {
		t.Fatalf("second run: %+v %v", res, err)
	}
	if got := e.h.fetches.Load(); got != fetches {
		t.Errorf("an unchanged run downloaded %d packs", got-fetches)
	}
	if r := e.rec.repo(app); r.Changed || r.Status != spec.RepoCompleted {
		t.Errorf("unchanged app result %+v", r)
	}
	if !e.rec.has(app+"/repository.git/HEAD") || !e.rec.has(lib+"/repository.git/HEAD") {
		t.Error("unchanged mirrors missing from the second snapshot")
	}
	idx, err := State{Dir: e.state}.Load()
	if err != nil || len(idx.Projects) != 2 {
		t.Fatalf("index %+v %v", idx, err)
	}
}

func TestRunPartialAndStale(t *testing.T) {
	e := newRunEnv(t)
	_, appBare := e.h.repo(t, "team/app.git")
	e.h.repo(t, "team/lib.git")
	app, lib, missing := e.dir(t, "team/app.git"), e.dir(t, "team/lib.git"), e.dir(t, "team/missing.git")

	// A repository that does not exist fails on first sight and is left out
	res, err := Run(ctx(t), e.opts(t, "team/app.git", "team/lib.git", "team/missing.git"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "partial" || !strings.Contains(res.ErrorMessage, "1 of 3 repositories failed") || !strings.Contains(res.ErrorMessage, missing) {
		t.Fatalf("result %+v", res)
	}
	if r := e.rec.repo(missing); r.Status != spec.RepoFailed || r.Error == "" {
		t.Errorf("missing result %+v", r)
	}
	if e.rec.has(missing) {
		t.Error("a repository that was never fetched must not be in the snapshot")
	}

	// The repository disappears upstream after a good run: its last mirror stays in
	// the snapshot, marked stale
	if err := os.RemoveAll(appBare); err != nil {
		t.Fatal(err)
	}
	res, err = Run(ctx(t), e.opts(t, "team/app.git", "team/lib.git"))
	if err != nil {
		t.Fatal(err)
	}
	r := e.rec.repo(app)
	if res.Status != "partial" || r.Status != spec.RepoStale || r.LastFetched == nil {
		t.Fatalf("stale run: %+v, app %+v", res, r)
	}
	if !e.rec.has(app+"/repository.git/HEAD") || !e.rec.has(lib+"/repository.git/HEAD") {
		t.Error("the stale mirror must stay in the snapshot")
	}
	if e.rec.manifest.Totals.Stale != 1 || e.rec.manifest.Totals.Completed != 1 {
		t.Errorf("totals %+v", e.rec.manifest.Totals)
	}
}

// A repository whose archive path is reserved fails alone; the other repos are backed up
func TestRunReservedPathFailsAlone(t *testing.T) {
	e := newRunEnv(t)
	e.h.repo(t, "team/app.git")
	e.h.repo(t, "team/wiki.git.git") // archive path <host>/team/wiki.git
	res, err := Run(ctx(t), e.opts(t, "team/app.git", "team/wiki.git.git"))
	if err != nil || res.Status != "partial" {
		t.Fatalf("result %+v %v", res, err)
	}
	if r := e.rec.repo(e.dir(t, "team/wiki.git.git")); r.Status != spec.RepoFailed || !strings.Contains(r.Error, "reserved") {
		t.Errorf("reserved result %+v", r)
	}
	if e.h.fetches.Load() != 1 || !e.rec.has(e.dir(t, "team/app.git")+"/repository.git/HEAD") {
		t.Errorf("%d fetches; app in snapshot: %v", e.h.fetches.Load(), e.rec.has(e.dir(t, "team/app.git")+"/repository.git/HEAD"))
	}
}

func TestRunAllFailed(t *testing.T) {
	e := newRunEnv(t)
	res, err := Run(ctx(t), e.opts(t, "team/nope.git", "team/gone.git"))
	if err == nil || res == nil || res.Status != "failed" || !strings.Contains(err.Error(), "all 2 repositories failed") {
		t.Fatalf("expected the run to fail: %+v %v", res, err)
	}
	if e.rec.calls != 0 {
		t.Error("nothing to back up must not upload a snapshot")
	}
}

func TestRunForgetsRemovedProjects(t *testing.T) {
	e := newRunEnv(t)
	e.h.repo(t, "team/app.git")
	e.h.repo(t, "team/lib.git")
	if _, err := Run(ctx(t), e.opts(t, "team/app.git", "team/lib.git")); err != nil {
		t.Fatal(err)
	}
	state := State{Dir: e.state}
	libKey := urlKey(e.h.url("team/lib.git"))
	if _, err := os.Stat(state.RepoDir(libKey)); err != nil {
		t.Fatalf("lib mirror: %v", err)
	}
	for i := 1; i <= 2; i++ {
		o := e.opts(t, "team/app.git")
		o.ForgetAfter = 2
		if _, err := Run(ctx(t), o); err != nil {
			t.Fatal(err)
		}
		_, err := os.Stat(state.RepoDir(libKey))
		if i == 1 && err != nil {
			t.Errorf("after one run without lib its mirror should stay: %v", err)
		}
		if i == 2 && !os.IsNotExist(err) {
			t.Errorf("after two runs without lib its mirror should be gone: %v", err)
		}
		if e.rec.has(e.dir(t, "team/lib.git")) {
			t.Error("a project no longer selected must not be in the snapshot")
		}
	}
	idx, _ := state.Load()
	if _, ok := idx.Projects[libKey]; ok || len(idx.Projects) != 1 {
		t.Errorf("index still lists lib: %+v", idx.Projects)
	}
}

func TestRunPrechecks(t *testing.T) {
	e := newRunEnv(t)
	e.h.repo(t, "team/app.git")
	cases := map[string]func(*RunOptions){
		"agent profile": func(o *RunOptions) { o.Spec.Profile = "gitlab-internal" },
		"gitlab provider": func(o *RunOptions) {
			o.Credentials.Provider = spec.ProviderGitLab
			o.Spec.Repositories = nil
		},
		"repository outside the connection": func(o *RunOptions) {
			o.Credentials.BaseURL = e.h.srv.URL + "/other"
		},
		"no git":     func(o *RunOptions) { o.GitPath = filepath.Join(t.TempDir(), "git") },
		"bad config": func(o *RunOptions) { o.Spec.Concurrency = -1 },
	}
	for name, mutate := range cases {
		o := e.opts(t, "team/app.git")
		mutate(&o)
		if _, err := Run(ctx(t), o); !dbrun.IsPrecheck(err) {
			t.Errorf("%s: expected a precheck error, got %v", name, err)
		}
	}
	if e.rec.calls != 0 {
		t.Error("a failed precheck must not upload")
	}
}

// profiles is an in-memory credential store for runs
func profiles(m map[string]spec.Profile) func(string) (*spec.Profile, error) {
	return func(name string) (*spec.Profile, error) {
		p, ok := m[name]
		if !ok {
			return nil, errors.New("profile not found")
		}
		return &p, nil
	}
}

func TestRunWithAgentProfile(t *testing.T) {
	e := newRunEnv(t)
	e.h.repo(t, "team/app.git")

	// The server hands out no token for a profile job; the agent's profile has it
	o := e.opts(t, "team/app.git")
	o.Credentials.Token = ""
	o.Spec.Profile = "git-internal"
	o.Profile = profiles(map[string]spec.Profile{"git-internal": {URL: e.h.srv.URL, Token: testToken}})
	res, err := Run(ctx(t), o)
	if err != nil || res.Status != "completed" {
		t.Fatalf("run with an agent profile: %+v %v", res, err)
	}
	if e.h.unauthenticated.Load() != 0 {
		t.Errorf("%d requests went without the profile's token", e.h.unauthenticated.Load())
	}

	// A token file is read at run time
	file := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(file, []byte(testToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	o = e.opts(t, "team/app.git")
	o.Credentials.Token = ""
	o.Spec.Profile = "git-internal"
	o.Profile = profiles(map[string]spec.Profile{"git-internal": {URL: e.h.srv.URL, TokenFile: file}})
	if res, err := Run(ctx(t), o); err != nil || res.Status != "completed" {
		t.Fatalf("run with a token file: %+v %v", res, err)
	}
}

// TestRunProfileOnlyForItsURL: the server decides the connection URL. Pointing a job
// at another host must not make the agent send a profile's token there.
func TestRunProfileOnlyForItsURL(t *testing.T) {
	trusted := newRunEnv(t)
	other := newGitHost(t)
	other.repo(t, "team/app.git")

	o := trusted.opts(t)
	o.Spec.Repositories = []string{other.url("team/app.git")}
	o.Credentials = spec.Credentials{Provider: spec.ProviderGit, BaseURL: other.srv.URL, CAPEM: other.caPEM}
	o.Spec.Profile = "git-internal"
	o.Profile = profiles(map[string]spec.Profile{"git-internal": {URL: trusted.h.srv.URL, Token: testToken}})
	_, err := Run(ctx(t), o)
	if !dbrun.IsPrecheck(err) || !strings.Contains(err.Error(), "is for "+trusted.h.srv.URL) {
		t.Fatalf("expected a URL mismatch precheck, got %v", err)
	}
	if n := other.requests.Load(); n != 0 {
		t.Errorf("the other host received %d requests", n)
	}

	// A profile the agent does not have is a precheck error naming the fix
	o.Profile = profiles(nil)
	if _, err := Run(ctx(t), o); !dbrun.IsPrecheck(err) || !strings.Contains(err.Error(), "fallbck-agent vcs profile create") {
		t.Errorf("missing profile: %v", err)
	}
}
