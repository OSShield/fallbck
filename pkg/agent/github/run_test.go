package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	spec "github.com/osshield/fallbck/pkg/github"
	"github.com/osshield/fallbck/pkg/rundetail"
	"github.com/osshield/fallbck/pkg/temporal"
	"github.com/osshield/gopbs"
)

func gitCmd(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// newRemote creates a bare repository with one commit and returns its file:// URL
func newRemote(t *testing.T, root, name, content string) string {
	t.Helper()
	bare := filepath.Join(root, name)
	if err := os.MkdirAll(bare, 0o755); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, bare, "init", "--bare", "--quiet", "--initial-branch=main")
	commit(t, bare, content)
	return "file://" + bare
}

// commit adds a commit on main of the bare repository
func commit(t *testing.T, bare, content string) string {
	t.Helper()
	work := t.TempDir()
	gitCmd(t, work, "clone", "--quiet", bare, ".")
	gitCmd(t, work, "checkout", "--quiet", "-B", "main")
	if err := os.WriteFile(filepath.Join(work, "README.md"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, work, "add", "README.md")
	gitCmd(t, work, "commit", "--quiet", "-m", content)
	gitCmd(t, work, "tag", "-f", "v-"+fmt.Sprint(time.Now().UnixNano()))
	gitCmd(t, work, "push", "--quiet", "--tags", "origin", "main")
	return gitCmd(t, work, "rev-parse", "HEAD")
}

type fakeAPI struct {
	mu    sync.Mutex
	gists map[string]map[string]any // id → gist object
	own   []string
	starG []string
	repos map[string]map[string]any // full name → repo object
	orgs  map[string][]string
	user  []string
	stars []string
	calls map[string]int
}

func (f *fakeAPI) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls[r.URL.Path]++
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		list := func(names []string) {
			var out []map[string]any
			for _, n := range names {
				out = append(out, f.repos[n])
			}
			if out == nil {
				out = []map[string]any{}
			}
			_ = json.NewEncoder(w).Encode(out)
		}
		p := r.URL.Path
		switch {
		case p == "/user":
			fmt.Fprint(w, `{"login":"me"}`)
		case p == "/user/repos":
			if r.URL.Query().Get("affiliation") != "owner" {
				t.Errorf("own repos must be listed with affiliation=owner: %s", r.URL.RawQuery)
			}
			list(f.user)
		case p == "/user/starred":
			list(f.stars)
		case p == "/gists" || p == "/gists/starred" || strings.HasPrefix(p, "/users/"):
			ids := f.own
			if p == "/gists/starred" {
				ids = f.starG
			}
			if strings.HasPrefix(p, "/users/") {
				ids = nil
				for id, g := range f.gists {
					if g["public"] == true && g["owner"].(map[string]string)["login"] == strings.Split(p, "/")[2] {
						ids = append(ids, id)
					}
				}
			}
			out := []map[string]any{}
			for _, id := range ids {
				out = append(out, f.gists[id])
			}
			_ = json.NewEncoder(w).Encode(out)
		case strings.HasPrefix(p, "/gists/") && strings.HasSuffix(p, "/comments"):
			fmt.Fprint(w, `[{"id":1,"body":"nice"}]`)
		case strings.HasPrefix(p, "/gists/"):
			g, ok := f.gists[strings.TrimPrefix(p, "/gists/")]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(g)
		case strings.HasPrefix(p, "/orgs/") && strings.HasSuffix(p, "/repos"):
			names, ok := f.orgs[strings.TrimSuffix(strings.TrimPrefix(p, "/orgs/"), "/repos")]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			list(names)
		case strings.HasPrefix(p, "/repos/"):
			parts := strings.SplitN(strings.TrimPrefix(p, "/repos/"), "/", 3)
			full := parts[0] + "/" + parts[1]
			repo, ok := f.repos[full]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				fmt.Fprint(w, `{"message":"Not Found"}`)
				return
			}
			if len(parts) == 2 {
				_ = json.NewEncoder(w).Encode(repo)
				return
			}
			switch parts[2] {
			case "issues":
				fmt.Fprint(w, `[{"number":1,"title":"bug"},{"number":2,"title":"pr","pull_request":{}}]`)
			case "pulls":
				fmt.Fprint(w, `[{"number":2,"title":"pr"}]`)
			case "issues/comments":
				fmt.Fprint(w, `[{"id":10,"body":"hi"}]`)
			default:
				fmt.Fprint(w, `[]`)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func repoObj(full, cloneURL string, extra map[string]any) map[string]any {
	owner, name, _ := strings.Cut(full, "/")
	o := map[string]any{"full_name": full, "name": name, "owner": map[string]string{"login": owner},
		"clone_url": cloneURL, "has_wiki": true, "has_issues": true, "default_branch": "main"}
	for k, v := range extra {
		o[k] = v
	}
	return o
}

type upload struct {
	group, archive string
	files          map[string]bool
	blob           []byte
}

type recorder struct {
	mu      sync.Mutex
	uploads []upload
	n       int
}

func (r *recorder) upload(ctx context.Context, u *Unit, dir string, blobs []gopbs.Blob) (*temporal.BackupExecutionResult, error) {
	files := map[string]bool{}
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err == nil {
			rel, _ := filepath.Rel(dir, p)
			files[filepath.ToSlash(rel)] = true
		}
		return nil
	})
	r.mu.Lock()
	defer r.mu.Unlock()
	r.n++
	up := upload{group: u.Group, archive: u.Archive, files: files}
	if len(blobs) > 0 {
		up.blob = blobs[0].Data
	}
	r.uploads = append(r.uploads, up)
	ts := time.Date(2026, 11, 3, 12, 0, r.n, 0, time.UTC)
	return &temporal.BackupExecutionResult{SnapshotID: "host/" + u.Group + "/" + ts.Format("2006-01-02T15:04:05Z"), BytesScanned: 100, BytesUploaded: 10}, nil
}

func (r *recorder) find(group string) *upload {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := len(r.uploads) - 1; i >= 0; i-- {
		if r.uploads[i].group == group {
			return &r.uploads[i]
		}
	}
	return nil
}

func TestRun(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	remotes := t.TempDir()
	webURL := newRemote(t, remotes, "acme/web.git", "web v1")
	newRemote(t, remotes, "acme/web.wiki.git", "wiki home")
	forkURL := newRemote(t, remotes, "acme/fork.git", "fork")
	dotURL := newRemote(t, remotes, "me/dotfiles.git", "dots")
	libURL := newRemote(t, remotes, "other/lib.git", "lib")
	explicitURL := newRemote(t, remotes, "other/explicit-fork.git", "explicit")

	api := &fakeAPI{calls: map[string]int{}, repos: map[string]map[string]any{
		"acme/web":            repoObj("acme/web", webURL, map[string]any{"private": true}),
		"acme/fork":           repoObj("acme/fork", forkURL, map[string]any{"fork": true}),
		"me/dotfiles":         repoObj("me/dotfiles", dotURL, map[string]any{"has_wiki": false}),
		"other/lib":           repoObj("other/lib", libURL, nil),
		"other/explicit-fork": repoObj("other/explicit-fork", explicitURL, map[string]any{"fork": true}),
	}, orgs: map[string][]string{"acme": {"acme/web", "acme/fork"}}, user: []string{"me/dotfiles"}, stars: []string{"other/lib", "acme/web"}}
	srv := httptest.NewServer(api.handler(t))
	defer srv.Close()

	s := &spec.Spec{AccountID: uuid.New(), Sources: spec.Sources{
		Orgs: []spec.OrgSource{{Name: "acme"}}, Users: []string{"me"}, Repos: []string{"other/explicit-fork"}, Starred: true,
	}, SkipForks: true, Concurrency: 2}
	state := t.TempDir()
	session := &temporal.BackupSessionInfo{JobID: uuid.New(), BackupRunID: uuid.New(), BackupType: "host", BackupID: "github-acme"}
	rec := &recorder{}
	var progress []map[string]rundetail.ProgressItem
	var pmu sync.Mutex
	opts := RunOptions{Session: session, Spec: s, Credentials: spec.Credentials{APIURL: srv.URL, Token: "tok"}, StateDir: state,
		Upload: rec.upload, AllowFileRemotes: true,
		Items: func(items map[string]rundetail.ProgressItem) {
			pmu.Lock()
			progress = append(progress, items)
			pmu.Unlock()
		}}

	res, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Status != "completed" || res.SnapshotID == "" {
		t.Fatalf("result: %+v", res)
	}
	var w rundetail.Wrapper
	if err := json.Unmarshal(res.Details, &w); err != nil || w.Type != rundetail.TypeGitHub {
		t.Fatalf("details: %v %s", err, res.Details)
	}
	var m spec.Manifest
	if err := json.Unmarshal(w.Manifest, &m); err != nil {
		t.Fatal(err)
	}
	got := map[string]spec.RepoResult{}
	for _, r := range m.Repos {
		got[r.FullName] = r
	}
	// acme/fork is a fork from an org listing (skipped); the explicit fork is kept
	if len(got) != 4 || got["acme/fork"].FullName != "" || got["other/explicit-fork"].Status != "completed" {
		t.Fatalf("selection: %+v", m.Repos)
	}
	web := got["acme/web"]
	if web.Group != "github-acme-acme-web" || !web.Wiki || web.Issues != 1 || web.Pulls != 1 || web.Comments != 1 || web.Refs < 2 || web.HeadCommit == "" || !web.Private {
		t.Errorf("acme/web result: %+v", web)
	}
	if strings.Join(web.Sources, ",") != "org:acme,starred" {
		t.Errorf("acme/web sources: %v", web.Sources)
	}
	if got["other/lib"].Wiki || len(got["other/lib"].Warnings) != 0 {
		t.Errorf("a missing wiki is no warning: %+v", got["other/lib"])
	}

	up := rec.find("github-acme-acme-web")
	if up == nil || up.archive != spec.ArchiveRepo {
		t.Fatalf("web upload: %+v", up)
	}
	for _, f := range []string{"repo.git/HEAD", "repo.git/config", "wiki.git/HEAD", "metadata/repository.json", "metadata/issues.json", "metadata/pulls.json", "metadata/releases.json", spec.RepoManifestName, "RESTORE.md"} {
		if !up.files[f] {
			t.Errorf("web snapshot lacks %s", f)
		}
	}
	idx := rec.find("github-acme")
	if idx == nil || idx.archive != spec.ArchiveIndex || !idx.files[spec.ManifestBlobName] || !idx.files["RESTORE.md"] || len(idx.blob) == 0 {
		t.Fatalf("index upload: %+v", idx)
	}
	// The token never lands in the mirror config
	cfg, _ := os.ReadFile(filepath.Join(state, "github-acme-acme-web", "repo.git", "config"))
	if strings.Contains(string(cfg), "tok") || strings.Contains(string(cfg), "extraHeader") {
		t.Errorf("mirror config carries credentials:\n%s", cfg)
	}

	// Retry of the same run: completed repositories are not uploaded again
	before := rec.n
	if _, err := Run(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	if rec.n != before+1 {
		t.Errorf("retry re-uploaded repositories: %d uploads, want only the index", rec.n-before)
	}

	// Next run: incremental fetch into the kept mirror, a broken remote fails one
	// repository (partial), a repository that left the selection is pruned
	marker := filepath.Join(state, "github-acme-acme-web", "repo.git", "fallbck-marker")
	_ = os.WriteFile(marker, nil, 0o600)
	head2 := commit(t, strings.TrimPrefix(webURL, "file://"), "web v2")
	api.mu.Lock()
	api.repos["other/lib"]["clone_url"] = "file://" + filepath.Join(remotes, "missing.git")
	api.user = nil
	api.mu.Unlock()
	opts.Session = &temporal.BackupSessionInfo{JobID: session.JobID, BackupRunID: uuid.New(), BackupType: "host", BackupID: "github-acme"}
	res, err = Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if res.Status != "partial" || !strings.Contains(res.ErrorMessage, "other/lib") {
		t.Errorf("second run: %s %s", res.Status, res.ErrorMessage)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Error("the kept mirror was cloned again instead of fetched")
	}
	_ = json.Unmarshal(res.Details, &w)
	_ = json.Unmarshal(w.Manifest, &m)
	for _, r := range m.Repos {
		if r.FullName == "acme/web" && r.HeadCommit != head2 {
			t.Errorf("acme/web head = %s, want %s", r.HeadCommit, head2)
		}
		if r.FullName == "me/dotfiles" {
			t.Error("me/dotfiles left the selection but was backed up")
		}
	}
	if _, err := os.Stat(filepath.Join(state, "github-acme-me-dotfiles")); !os.IsNotExist(err) {
		t.Errorf("the mirror of a deselected repository was kept: %v", err)
	}

	// keep_mirrors=false clones into a scratch directory and removes it afterwards
	off := false
	opts.Spec = &spec.Spec{AccountID: s.AccountID, Sources: spec.Sources{Repos: []string{"acme/web"}}, KeepMirrors: &off}
	opts.Session = &temporal.BackupSessionInfo{JobID: session.JobID, BackupRunID: uuid.New(), BackupType: "host", BackupID: "github-acme"}
	if res, err = Run(context.Background(), opts); err != nil || res.Status != "completed" {
		t.Fatalf("keep_mirrors=false: %v %+v", err, res)
	}
	if _, err := os.Stat(filepath.Join(state, "github-acme-acme-web")); !os.IsNotExist(err) {
		t.Errorf("scratch mirror kept: %v", err)
	}
	if len(progress) == 0 {
		t.Error("no progress items reported")
	}
}

func TestRunPrechecks(t *testing.T) {
	session := &temporal.BackupSessionInfo{JobID: uuid.New(), BackupRunID: uuid.New(), BackupType: "host", BackupID: "g"}
	rec := &recorder{}
	_, err := Run(context.Background(), RunOptions{Session: session, Spec: &spec.Spec{}, StateDir: t.TempDir(), Upload: rec.upload})
	if err == nil || !strings.Contains(err.Error(), "invalid job configuration") {
		t.Errorf("invalid spec: %v", err)
	}
	s := &spec.Spec{AccountID: uuid.New(), Sources: spec.Sources{Starred: true}}
	_, err = Run(context.Background(), RunOptions{Session: session, Spec: s, StateDir: t.TempDir(), Upload: rec.upload, GitPath: "/nonexistent/git"})
	if err == nil || !strings.Contains(err.Error(), "git") {
		t.Errorf("missing git: %v", err)
	}
}

func TestCheckRemote(t *testing.T) {
	cases := []struct {
		clone, api string
		file, ok   bool
	}{
		{"https://github.com/a/b.git", "https://api.github.com", false, true},
		{"https://ghe.example.com/a/b.git", "https://ghe.example.com/api/v3", false, true},
		{"https://evil.example/a/b.git", "https://api.github.com", false, false},
		{"https://gist.github.com/0123.git", "https://api.github.com", false, true},
		{"https://gist.evil.example/0123.git", "https://api.github.com", false, false},
		{"file:///tmp/x", "https://api.github.com", false, false},
		{"file:///tmp/x", "http://127.0.0.1:1234", true, true},
		{"ssh://git@github.com/a/b", "https://api.github.com", false, false},
	}
	for _, c := range cases {
		if err := checkRemote(c.clone, c.api, c.file); (err == nil) != c.ok {
			t.Errorf("checkRemote(%s, %s) = %v", c.clone, c.api, err)
		}
	}
}

func TestGitEnvScopesToken(t *testing.T) {
	g := &Git{Token: "secret"}
	env := strings.Join(g.env("https://github.com/a/b.git"), "\n")
	if !strings.Contains(env, "http.https://github.com/.extraHeader") || strings.Contains(env, "secret") {
		t.Errorf("token header not scoped or leaked in clear:\n%s", env)
	}
	if strings.Contains(strings.Join(g.env("file:///x"), "\n"), "extraHeader") {
		t.Error("non-HTTP remotes must not get the header")
	}
}

func TestOrgSourceThatIsAUser(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dotURL := newRemote(t, t.TempDir(), "me/dotfiles.git", "dots")
	api := &fakeAPI{calls: map[string]int{}, repos: map[string]map[string]any{"me/dotfiles": repoObj("me/dotfiles", dotURL, nil)},
		orgs: map[string][]string{}, user: []string{"me/dotfiles"}}
	srv := httptest.NewServer(api.handler(t))
	defer srv.Close()
	rec := &recorder{}
	res, err := Run(context.Background(), RunOptions{
		Session:     &temporal.BackupSessionInfo{JobID: uuid.New(), BackupRunID: uuid.New(), BackupType: "host", BackupID: "gh"},
		Spec:        &spec.Spec{AccountID: uuid.New(), Sources: spec.Sources{Orgs: []spec.OrgSource{{Name: "me"}}}},
		Credentials: spec.Credentials{APIURL: srv.URL, Token: "tok"}, StateDir: t.TempDir(), Upload: rec.upload, AllowFileRemotes: true,
	})
	if err != nil || res.Status != "completed" || rec.find("gh-me-dotfiles") == nil {
		t.Fatalf("org fallback: %v %+v", err, res)
	}
	if !strings.Contains(string(res.Details), "is a user, not an organization") {
		t.Error("no warning about the user fallback")
	}
}

func TestGists(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	remotes := t.TempDir()
	const secret, starred, explicit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "cccccccccccccccccccccccccccccccc"
	gist := func(id, owner string, public bool) map[string]any {
		return map[string]any{"id": id, "public": public, "description": "d", "owner": map[string]string{"login": owner},
			"git_pull_url": newRemote(t, remotes, id+".git", "gist "+id), "files": map[string]any{"a.txt": map[string]any{}}}
	}
	api := &fakeAPI{calls: map[string]int{}, repos: map[string]map[string]any{}, orgs: map[string][]string{},
		gists: map[string]map[string]any{secret: gist(secret, "me", false), starred: gist(starred, "other", true), explicit: gist(explicit, "other", true)},
		own:   []string{secret}, starG: []string{starred}}
	srv := httptest.NewServer(api.handler(t))
	defer srv.Close()
	rec := &recorder{}
	s := &spec.Spec{AccountID: uuid.New(), Sources: spec.Sources{Gists: spec.Gists{Own: true, Starred: true, Users: []string{"other"},
		IDs: []string{"https://gist.github.com/other/" + explicit + "#file-a-txt"}}}}
	res, err := Run(context.Background(), RunOptions{
		Session: &temporal.BackupSessionInfo{JobID: uuid.New(), BackupRunID: uuid.New(), BackupType: "host", BackupID: "gh"},
		Spec:    s, Credentials: spec.Credentials{APIURL: srv.URL, Token: "tok"}, StateDir: t.TempDir(), Upload: rec.upload, AllowFileRemotes: true,
	})
	if err != nil || res.Status != "completed" {
		t.Fatalf("Run: %v %+v", err, res)
	}
	var w rundetail.Wrapper
	var m spec.Manifest
	_ = json.Unmarshal(res.Details, &w)
	_ = json.Unmarshal(w.Manifest, &m)
	got := map[string]spec.RepoResult{}
	for _, r := range m.Repos {
		got[r.FullName] = r
	}
	if len(got) != 3 {
		t.Fatalf("gists: %+v", m.Repos)
	}
	own := got["gist:me/"+secret]
	if own.Kind != "gist" || !own.Private || own.Group != "gh-gist-me-"+secret || own.Comments != 1 || own.Refs == 0 {
		t.Errorf("own gist: %+v", own)
	}
	// Listed as starred, by user and explicitly: one unit, three sources
	if src := strings.Join(got["gist:other/"+explicit].Sources, ","); src != "gists:other,gist" {
		t.Errorf("explicit gist sources: %s", src)
	}
	if src := strings.Join(got["gist:other/"+starred].Sources, ","); src != "starred gists,gists:other" {
		t.Errorf("starred gist sources: %s", src)
	}
	up := rec.find("gh-gist-me-" + secret)
	if up == nil || !up.files["repo.git/HEAD"] || !up.files["metadata/gist.json"] || !up.files["metadata/comments.json"] || up.files["wiki.git"] {
		t.Errorf("gist snapshot: %+v", up)
	}
}
