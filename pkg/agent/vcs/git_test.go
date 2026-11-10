package vcs

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testToken = "glpat-test-token"

// hostGit runs the test's own git (setting up upstream repositories), isolated from
// the user's configuration
func hostGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "user.name=FallBCK Test", "-c", "user.email=test@example.invalid", "-c", "init.defaultBranch=main"}, args...)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func needGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
}

// gitHost is an HTTPS git server (git http-backend) that requires the test token
type gitHost struct {
	srv   *httptest.Server
	root  string
	caPEM string
	// unauthenticated counts requests that came without the expected header
	unauthenticated atomic.Int64
	// fetches counts pack downloads (POST git-upload-pack), not ref listings
	fetches atomic.Int64
	// requests counts every request
	requests atomic.Int64
	// accepted are the Authorization headers let in (the test tokens by default)
	accepted sync.Map
}

// accept lets another user/token pair in (rotated tokens)
func (h *gitHost) accept(user, token string) {
	h.accepted.Store("Basic "+base64.StdEncoding.EncodeToString([]byte(user+":"+token)), true)
}

func newGitHost(t *testing.T) *gitHost {
	t.Helper()
	needGit(t)
	execPath := hostGit(t, "", "--exec-path")
	backend := filepath.Join(execPath, "git-http-backend")
	if _, err := os.Stat(backend); err != nil {
		t.Skip("git-http-backend not available")
	}
	h := &gitHost{root: t.TempDir()}
	cgiHandler := &cgi.Handler{Path: backend, Root: "/",
		Env:        []string{"GIT_PROJECT_ROOT=" + h.root, "GIT_HTTP_EXPORT_ALL=1", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + os.DevNull},
		InheritEnv: []string{"PATH"}}
	h.accept(DefaultUsername, testToken)
	h.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.requests.Add(1)
		if _, ok := h.accepted.Load(r.Header.Get("Authorization")); !ok {
			h.unauthenticated.Add(1)
			w.Header().Set("WWW-Authenticate", `Basic realm="git"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git-upload-pack") {
			// Protocol v2 also posts here for ls-remote (command=ls-refs); only
			// command=fetch downloads a pack
			body, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(body))
			if bytes.Contains(body, []byte("command=fetch")) {
				h.fetches.Add(1)
			}
		}
		cgiHandler.ServeHTTP(w, r)
	}))
	t.Cleanup(h.srv.Close)
	h.caPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: h.srv.Certificate().Raw}))
	return h
}

// repo creates a bare upstream repository at <root>/<name> with one commit on main,
// an annotated tag, a merge request head and GitLab-internal refs that must not be
// mirrored. It returns a work tree pushing to it.
func (h *gitHost) repo(t *testing.T, name string) (work, bare string) {
	t.Helper()
	bare = filepath.Join(h.root, name)
	hostGit(t, "", "init", "--bare", "--quiet", bare)
	work = t.TempDir()
	hostGit(t, work, "init", "--quiet")
	if err := os.WriteFile(filepath.Join(work, "README.md"), []byte("# app\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	hostGit(t, work, "add", ".")
	hostGit(t, work, "commit", "--quiet", "-m", "initial")
	hostGit(t, work, "tag", "-a", "v1.0.0", "-m", "release")
	hostGit(t, work, "push", "--quiet", bare, "main", "v1.0.0")
	head := hostGit(t, work, "rev-parse", "HEAD")
	for _, ref := range []string{"refs/merge-requests/7/head", "refs/environments/production", "refs/pipelines/42"} {
		hostGit(t, bare, "update-ref", ref, head)
	}
	return work, bare
}

func (h *gitHost) url(name string) string { return h.srv.URL + "/" + name }

func (h *gitHost) git(t *testing.T, token string) *Git {
	t.Helper()
	g, err := NewGit("", Auth{BaseURL: h.srv.URL, Token: token, CAPEM: h.caPEM}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	return g
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	return c
}

func refsOf(t *testing.T, mirror string) string {
	t.Helper()
	return hostGit(t, mirror, "for-each-ref", "--format=%(refname)")
}

func TestMirrorFetch(t *testing.T) {
	h := newGitHost(t)
	work, bare := h.repo(t, "team/app.git")
	g := h.git(t, testToken)
	m := g.NewMirror(filepath.Join(t.TempDir(), "101.git"), h.url("team/app.git"))

	var progress []string
	res, err := m.Fetch(ctx(t), func(l string) { progress = append(progress, l) })
	if err != nil {
		t.Fatal(err)
	}
	if !res.Created || !res.Changed || res.Refs != 3 {
		t.Fatalf("first fetch: %+v", res)
	}
	refs := refsOf(t, m.Dir)
	for _, want := range []string{"refs/heads/main", "refs/tags/v1.0.0", "refs/merge-requests/7/head"} {
		if !strings.Contains(refs, want) {
			t.Errorf("mirror lacks %s:\n%s", want, refs)
		}
	}
	for _, internal := range []string{"refs/environments", "refs/pipelines"} {
		if strings.Contains(refs, internal) {
			t.Errorf("mirror holds GitLab-internal %s refs:\n%s", internal, refs)
		}
	}
	if _, err := os.Stat(filepath.Join(m.Dir, "FETCH_HEAD")); !os.IsNotExist(err) {
		t.Errorf("FETCH_HEAD must not be written: %v", err)
	}
	if got := hostGit(t, m.Dir, "config", "--get", "gc.auto"); got != "0" {
		t.Errorf("gc.auto = %q", got)
	}
	if len(progress) == 0 {
		t.Error("no progress lines reported")
	}
	if m.PackCount() != 1 {
		t.Errorf("objects should arrive as one pack, have %d", m.PackCount())
	}

	// Change detection without fetching: the remote digest equals the local one
	remote, n, err := g.RemoteRefs(ctx(t), m.URL)
	if err != nil || remote != res.Digest || n != 3 {
		t.Fatalf("remote refs %s/%d vs local %s: %v", remote, n, res.Digest, err)
	}

	// Nothing new upstream: unchanged, nothing rewritten
	again, err := m.Fetch(ctx(t), nil)
	if err != nil || again.Created || again.Changed {
		t.Fatalf("no-op fetch: %+v %v", again, err)
	}

	// New commit, a deleted merge request ref: the digest moves, the fetch adds a
	// pack (no loose objects) and prunes the ref
	if err := os.WriteFile(filepath.Join(work, "README.md"), []byte("# app\n\nmore\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	hostGit(t, work, "commit", "--quiet", "-am", "more")
	hostGit(t, work, "push", "--quiet", bare, "main")
	hostGit(t, bare, "update-ref", "-d", "refs/merge-requests/7/head")
	if moved, _, _ := g.RemoteRefs(ctx(t), m.URL); moved == res.Digest {
		t.Error("remote digest did not change after a push")
	}
	third, err := m.Fetch(ctx(t), nil)
	if err != nil || !third.Changed || third.Refs != 2 {
		t.Fatalf("fetch after push: %+v %v", third, err)
	}
	if strings.Contains(refsOf(t, m.Dir), "merge-requests") {
		t.Error("deleted merge request ref was not pruned")
	}
	if m.PackCount() != 2 {
		t.Errorf("the second fetch should add a pack, have %d", m.PackCount())
	}
	if loose := hostGit(t, m.Dir, "count-objects"); !strings.HasPrefix(loose, "0 objects") {
		t.Errorf("loose objects in the mirror: %s", loose)
	}
	if h.unauthenticated.Load() != 0 {
		t.Errorf("%d requests came without the token", h.unauthenticated.Load())
	}
}

func TestMirrorRenamedProjectKeepsMirror(t *testing.T) {
	h := newGitHost(t)
	_, bare := h.repo(t, "team/app.git")
	g := h.git(t, testToken)
	dir := filepath.Join(t.TempDir(), "101.git")
	if _, err := g.NewMirror(dir, h.url("team/app.git")).Fetch(ctx(t), nil); err != nil {
		t.Fatal(err)
	}
	// GitLab renames the project; the mirror (keyed by id) follows the new URL
	if err := os.MkdirAll(filepath.Join(h.root, "platform"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(bare, filepath.Join(h.root, "platform", "api.git")); err != nil {
		t.Fatal(err)
	}
	res, err := g.NewMirror(dir, h.url("platform/api.git")).Fetch(ctx(t), nil)
	if err != nil || res.Created || res.Changed {
		t.Fatalf("fetch from the new URL: %+v %v", res, err)
	}
	if got := hostGit(t, dir, "config", "--get", "remote.origin.url"); got != h.url("platform/api.git") {
		t.Errorf("remote.origin.url = %s", got)
	}
}

func TestMirrorWrongToken(t *testing.T) {
	h := newGitHost(t)
	h.repo(t, "team/app.git")
	g := h.git(t, "glpat-wrong-token")
	m := g.NewMirror(filepath.Join(t.TempDir(), "101.git"), h.url("team/app.git"))
	_, err := m.Fetch(ctx(t), nil)
	var ge *GitError
	if !errors.As(err, &ge) || !strings.Contains(ge.Hint, "rejected the token") {
		t.Fatalf("expected a token hint, got %v", err)
	}
	if strings.Contains(err.Error(), "glpat-wrong-token") || strings.Contains(err.Error(), basicCredentials(DefaultUsername, "glpat-wrong-token")) {
		t.Errorf("the token leaked into the error: %v", err)
	}
	if m.Exists() {
		t.Error("a mirror whose first fetch failed must be removed")
	}
	if _, _, err := g.RemoteRefs(ctx(t), m.URL); err == nil {
		t.Error("ls-remote with a wrong token should fail")
	}
}

func TestMirrorOnlyHTTPS(t *testing.T) {
	h := newGitHost(t)
	_, bare := h.repo(t, "team/app.git")
	g := h.git(t, testToken)
	for _, url := range []string{"file://" + bare, bare, "http://127.0.0.1:1/team/app.git"} {
		m := g.NewMirror(filepath.Join(t.TempDir(), "x.git"), url)
		if _, err := m.Fetch(ctx(t), nil); err == nil {
			t.Errorf("fetch from %s should be refused", url)
		}
		if m.Exists() {
			t.Errorf("mirror left behind after refusing %s", url)
		}
	}
}

// git lfs gets the token for the repository's LFS API only: GitLab answers with its
// own Authorization header for each download, and two headers are refused
func TestGitEnvironmentLFSScope(t *testing.T) {
	g, err := NewGit("/usr/bin/git", Auth{BaseURL: "https://gitlab.example.com", Token: testToken}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	for url, key := range map[string]string{
		"https://gitlab.example.com/team/app.git": "http.https://gitlab.example.com/team/app.git/info/lfs/.extraHeader",
		"https://gitlab.example.com/team/app":     "http.https://gitlab.example.com/team/app.git/info/lfs/.extraHeader",
		// Never wider than, or outside, the connection URL
		"https://elsewhere.example.com/app.git": "http.https://gitlab.example.com/.extraHeader",
	} {
		env := strings.Join(g.env(lfsEndpoint(url)), "\n")
		if !strings.Contains(env, "="+key+"\n") {
			t.Errorf("%s: environment lacks %s:\n%s", url, key, env)
		}
	}
}

func TestGitEnvironment(t *testing.T) {
	t.Setenv("FALLBCK_AGENT_SECRET", "must-not-leak")
	t.Setenv("GIT_DIR", "/elsewhere")
	g, err := NewGit("/usr/bin/git", Auth{BaseURL: "https://gitlab.example.com/", Token: testToken, CAPEM: "-----BEGIN CERTIFICATE-----\n"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	env := strings.Join(g.env(""), "\n")
	for _, want := range []string{
		"GIT_ALLOW_PROTOCOL=https", "GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_KEY_2=http.https://gitlab.example.com/.extraHeader",
		"GIT_CONFIG_VALUE_2=Authorization: Basic " + basicCredentials(DefaultUsername, testToken),
		"GIT_CONFIG_KEY_3=http.https://gitlab.example.com/.sslCAInfo",
		"GIT_CONFIG_KEY_0=credential.helper", "GIT_CONFIG_VALUE_0=\n",
	} {
		if !strings.Contains(env+"\n", want) {
			t.Errorf("environment lacks %q:\n%s", want, env)
		}
	}
	for _, leak := range []string{"FALLBCK_AGENT_SECRET", "GIT_DIR="} {
		if strings.Contains(env, leak) {
			t.Errorf("the agent's %s reached git", leak)
		}
	}
	ca, err := os.ReadFile(g.caFile)
	if err != nil || !strings.HasPrefix(string(ca), "-----BEGIN") {
		t.Errorf("CA file: %v", err)
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(g.caFile); !os.IsNotExist(err) {
		t.Error("Close must remove the CA file")
	}
}

func TestRepackMergesSmallPacks(t *testing.T) {
	h := newGitHost(t)
	work, bare := h.repo(t, "team/app.git")
	g := h.git(t, testToken)
	m := g.NewMirror(filepath.Join(t.TempDir(), "101.git"), h.url("team/app.git"))
	for i := 0; i < 5; i++ {
		if err := os.WriteFile(filepath.Join(work, "f.txt"), []byte(strings.Repeat("x", i+1)), 0o644); err != nil {
			t.Fatal(err)
		}
		hostGit(t, work, "add", ".")
		hostGit(t, work, "commit", "--quiet", "-m", "c")
		hostGit(t, work, "push", "--quiet", bare, "main")
		if _, err := m.Fetch(ctx(t), nil); err != nil {
			t.Fatal(err)
		}
	}
	before := m.PackCount()
	if ran, err := m.Repack(ctx(t), before); err != nil || ran {
		t.Fatalf("repack at the threshold should not run: %v %v", ran, err)
	}
	ran, err := m.Repack(ctx(t), 2)
	if err != nil || !ran {
		t.Fatalf("repack: %v %v", ran, err)
	}
	if after := m.PackCount(); after >= before {
		t.Errorf("packs %d → %d", before, after)
	}
	hostGit(t, m.Dir, "fsck", "--no-progress")
}

func TestFetchLFSWithoutPointers(t *testing.T) {
	h := newGitHost(t)
	h.repo(t, "team/app.git")
	g := h.git(t, testToken)
	if _, err := g.LFSVersion(ctx(t)); err != nil {
		t.Skip("git-lfs not installed")
	}
	m := g.NewMirror(filepath.Join(t.TempDir(), "101.git"), h.url("team/app.git"))
	if _, err := m.Fetch(ctx(t), nil); err != nil {
		t.Fatal(err)
	}
	if err := m.FetchLFS(ctx(t), nil); err != nil {
		t.Fatalf("lfs fetch on a repository without LFS: %v", err)
	}
}

func TestVersionAndHelpers(t *testing.T) {
	needGit(t)
	g, err := NewGit("", Auth{}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	v, err := g.Version(ctx(t))
	if err != nil || v == "" || strings.HasPrefix(v, "git") {
		t.Errorf("Version = %q, %v", v, err)
	}
	for ref, want := range map[string]bool{
		"refs/heads/main":                 true,
		"refs/heads/feature/x":            true,
		"refs/tags/v1":                    true,
		"refs/merge-requests/12/head":     true,
		"refs/merge-requests/12/merge":    false,
		"refs/environments/production":    false,
		"refs/pipelines/42":               false,
		"refs/heads/":                     false,
		"refs/merge-requests//head":       false,
		"refs/keep-around/0123456789abcd": false,
	} {
		if got := selectedRef(ref); got != want {
			t.Errorf("selectedRef(%q) = %v", ref, got)
		}
	}
	if got := redact("token glpat-x and Z2xwYXQteA==", []string{"glpat-x", "Z2xwYXQteA=="}); got != "token *** and ***" {
		t.Error(got)
	}
	if got := lastLines("a\rb\n\nc\rd\n", 2); got != "c; d" {
		t.Error(got)
	}
	if hintFor("Receiving objects: (404/1000)") != "" {
		t.Error("a progress counter must not look like an HTTP 404")
	}
}
