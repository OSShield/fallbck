package vcs

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/temporal"
	spec "github.com/osshield/fallbck/pkg/vcs"
)

const (
	gistOwn     = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	gistStarred = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// fakeGitHubAPI serves the REST endpoints a GitHub job lists. Repository listings
// are paginated one per page, with next links to another host on the last page to
// check that they are not followed.
func fakeGitHubAPI(t *testing.T) *httptest.Server {
	t.Helper()
	type obj = map[string]any
	repo := func(id int, owner, name string, extra obj) obj {
		o := obj{"id": id, "name": name, "full_name": owner + "/" + name, "owner": obj{"login": owner}, "has_wiki": true, "size": 1}
		for k, v := range extra {
			o[k] = v
		}
		return o
	}
	repos := map[string]obj{
		"acme/web":       repo(1, "acme", "web", obj{"private": true}),
		"acme/fork":      repo(2, "acme", "fork", obj{"fork": true}),
		"acme/old":       repo(3, "acme", "old", obj{"archived": true}),
		"me/dotfiles":    repo(4, "me", "dotfiles", obj{"has_wiki": false}),
		"other/lib":      repo(5, "other", "lib", nil),
		"other/explicit": repo(6, "other", "explicit", obj{"fork": true}),
		"other/disabled": repo(7, "other", "disabled", obj{"disabled": true}),
	}
	gist := func(id, owner string, public bool) obj {
		return obj{"id": id, "public": public, "owner": obj{"login": owner}, "files": obj{"a.txt": obj{}}}
	}
	gists := map[string]obj{gistOwn: gist(gistOwn, "me", false), gistStarred: gist(gistStarred, "other", true)}
	list := func(w http.ResponseWriter, r *http.Request, items []obj) {
		page := 0
		_, _ = fmt.Sscan(r.URL.Query().Get("page"), &page)
		if page+1 < len(items) {
			q := r.URL.Query()
			q.Set("page", fmt.Sprint(page+1))
			w.Header().Set("Link", fmt.Sprintf(`<http://%s%s?%s>; rel="next"`, r.Host, r.URL.Path, q.Encode()))
		} else {
			w.Header().Set("Link", `<https://elsewhere.example/steal>; rel="next"`)
		}
		if len(items) == 0 {
			_, _ = w.Write([]byte("[]"))
			return
		}
		_ = json.NewEncoder(w).Encode(items[page : page+1])
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		p := strings.TrimPrefix(r.URL.Path, "/api/v3")
		switch {
		case p == "/user":
			w.Header().Set("X-OAuth-Scopes", "repo, read:org, gist")
			_, _ = w.Write([]byte(`{"login":"me"}`))
		case p == "/orgs/acme/repos":
			list(w, r, []obj{repos["acme/web"], repos["acme/fork"], repos["acme/old"]})
		case p == "/orgs/me/repos", p == "/orgs/missing/repos", p == "/users/missing/repos":
			w.WriteHeader(http.StatusNotFound)
		case p == "/user/repos":
			if r.URL.Query().Get("affiliation") != "owner" {
				t.Error("the token's own repositories must be listed with affiliation=owner")
			}
			list(w, r, []obj{repos["me/dotfiles"]})
		case p == "/user/starred":
			list(w, r, []obj{repos["other/lib"], repos["acme/web"], repos["other/disabled"]})
		case p == "/gists":
			list(w, r, []obj{gists[gistOwn]})
		case p == "/gists/starred":
			list(w, r, []obj{gists[gistStarred]})
		case strings.HasPrefix(p, "/gists/") && strings.HasSuffix(p, "/comments"):
			_, _ = w.Write([]byte(`[{"id":1,"body":"nice"}]`))
		case strings.HasPrefix(p, "/gists/"):
			g, ok := gists[strings.TrimPrefix(p, "/gists/")]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(g)
		case strings.HasPrefix(p, "/repos/"):
			parts := strings.SplitN(strings.TrimPrefix(p, "/repos/"), "/", 3)
			rp, ok := repos[parts[0]+"/"+parts[1]]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if len(parts) == 2 {
				_ = json.NewEncoder(w).Encode(rp)
				return
			}
			switch parts[2] {
			case "issues":
				_, _ = w.Write([]byte(`[{"number":1,"title":"bug"},{"number":2,"title":"pr","pull_request":{}}]`))
			case "pulls":
				_, _ = w.Write([]byte(`[{"number":2}]`))
			case "issues/comments":
				_, _ = w.Write([]byte(`[{"id":10}]`))
			case "releases":
				w.WriteHeader(http.StatusInternalServerError)
			default:
				_, _ = w.Write([]byte(`[]`))
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func githubAPI(srv *httptest.Server) *spec.GitHubClient {
	return &spec.GitHubClient{APIURL: srv.URL + "/api/v3", Token: testToken, HTTP: srv.Client(),
		Sleep: func(context.Context, time.Duration) error { return nil }}
}

func TestGitHubProviderProjects(t *testing.T) {
	srv := fakeGitHubAPI(t)
	base := "https://ghe.example.com"
	no := false
	s := &spec.Spec{Groups: []string{"acme", "me", "missing"}, Repositories: []string{base + "/other/explicit"},
		Starred: true, Forks: &no, Archived: &no, Exclude: []string{"*/nothing"},
		Gists: &spec.Gists{Own: true, Starred: true, IDs: []string{gistStarred}}}
	p := &GitHubProvider{Spec: s, Credentials: spec.Credentials{Provider: spec.ProviderGitHub, BaseURL: base, Token: testToken}, API: githubAPI(srv)}
	projects, warnings, err := p.Projects(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, pr := range projects {
		paths = append(paths, pr.Path)
	}
	want := []string{"acme/web", "me/dotfiles", "other/lib", "other/explicit", GistsDir + "/me/" + gistOwn, GistsDir + "/other/" + gistStarred}
	if !slices.Equal(paths, want) {
		t.Fatalf("projects = %v, want %v (fork, archived, disabled and duplicates out; the explicit fork kept)", paths, want)
	}
	web := projects[0]
	if web.Key != "r1" || web.URL != base+"/acme/web.git" || web.WikiURL != base+"/acme/web.wiki.git" || web.Size != 1024 || web.Ref != "acme/web" {
		t.Errorf("acme/web = %+v", web)
	}
	if projects[1].WikiURL != "" {
		t.Error("a repository without a wiki must not get a wiki URL")
	}
	gist := projects[4]
	if gist.Kind != "gist" || gist.Key != "g"+gistOwn || gist.URL != base+"/gist/"+gistOwn+".git" {
		t.Errorf("gist = %+v", gist)
	}
	joined := strings.Join(warnings, "\n")
	if !strings.Contains(joined, "owner missing") || !strings.Contains(joined, "disabled") {
		t.Errorf("warnings = %v", warnings)
	}
	if strings.Contains(joined, "me is a user") {
		t.Error("the token's own login is not worth a warning")
	}
	var src spec.SourceInfo
	p.Describe(&src)
	if src.Username != "me" {
		t.Errorf("source = %+v", src)
	}
	if len(p.ExtraURLs()) != 0 {
		t.Error("an Enterprise connection serves gists below its own URL")
	}
	gh := &GitHubProvider{Spec: s, Credentials: spec.Credentials{BaseURL: "https://github.com"}}
	if !slices.Equal(gh.ExtraURLs(), []string{"https://gist.github.com"}) {
		t.Errorf("github.com gists need the token on gist.github.com: %v", gh.ExtraURLs())
	}

	// Nothing can be listed: the run has nothing to back up
	p = &GitHubProvider{Spec: &spec.Spec{Groups: []string{"missing"}}, Credentials: p.Credentials, API: githubAPI(srv)}
	if _, _, err := p.Projects(ctx(t)); err == nil {
		t.Error("expected an error when no source can be listed")
	}
	// A wrong token stops the listing
	api := githubAPI(srv)
	api.Token = "wrong"
	p = &GitHubProvider{Spec: s, Credentials: p.Credentials, API: api}
	if _, _, err := p.Projects(ctx(t)); err == nil || !strings.Contains(err.Error(), "rejected the token") {
		t.Errorf("wrong token: %v", err)
	}
}

func TestGitHubRun(t *testing.T) {
	e := newRunEnv(t)
	api := fakeGitHubAPI(t)
	for _, name := range []string{"acme/web.git", "acme/web.wiki.git", "me/dotfiles.git", "other/lib.git", "other/explicit.git", "gist/" + gistOwn + ".git", "gist/" + gistStarred + ".git"} {
		_, bare := e.h.repo(t, name)
		head := hostGit(t, bare, "rev-parse", "main")
		hostGit(t, bare, "update-ref", "refs/pull/3/head", head)
	}
	no := false
	s := &spec.Spec{ConnectionID: uuid.New(), Groups: []string{"acme", "me"}, Starred: true, Forks: &no, Archived: &no,
		Gists: &spec.Gists{Own: true, Starred: true}, Workloads: spec.Workloads{Metadata: true}}
	creds := spec.Credentials{Provider: spec.ProviderGitHub, BaseURL: e.h.srv.URL, Token: testToken, CAPEM: e.h.caPEM}
	o := e.opts(t)
	o.Spec, o.Credentials = s, creds
	o.Provider = &GitHubProvider{Spec: s, Credentials: creds, API: githubAPI(api)}
	res, err := Run(ctx(t), o)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "completed" {
		t.Fatalf("status %s: %s", res.Status, res.ErrorMessage)
	}
	for _, p := range []string{
		"acme/web/repository.git/HEAD", "acme/web/wiki.git/HEAD",
		"acme/web/_metadata/issues.json", "acme/web/_metadata/pulls.json", "acme/web/_metadata/issue-comments.json",
		"me/dotfiles/repository.git/HEAD", "other/lib/repository.git/HEAD",
		GistsDir + "/me/" + gistOwn + "/repository.git/HEAD",
		GistsDir + "/me/" + gistOwn + "/_metadata/gist.json",
		GistsDir + "/me/" + gistOwn + "/_metadata/comments.json",
	} {
		if !e.rec.has(p) {
			t.Errorf("the snapshot lacks %s", p)
		}
	}
	if e.rec.has("acme/web/_metadata/releases.json") {
		t.Error("a failed list must not produce a file")
	}
	web := e.rec.repo("acme/web")
	if web.Issues != 1 || web.Pulls != 1 || web.Comments != 1 || !web.Wiki || !slices.ContainsFunc(web.Warnings, func(w string) bool { return strings.Contains(w, "releases") }) {
		t.Errorf("acme/web result: %+v", web)
	}
	if g := e.rec.repo(GistsDir + "/me/" + gistOwn); g.Kind != "gist" || g.Comments != 1 || g.Status != spec.RepoCompleted {
		t.Errorf("gist result: %+v", g)
	}
	if refs := refsOf(t, State{Dir: e.state}.RepoDir("r1")); !strings.Contains(refs, "refs/pull/3/head") {
		t.Errorf("pull request heads must be mirrored: %s", refs)
	}
	if e.rec.manifest.Source.Username != "me" || e.h.unauthenticated.Load() != 0 {
		t.Errorf("source %+v, unauthenticated git requests %d", e.rec.manifest.Source, e.h.unauthenticated.Load())
	}

	// The metadata workload switched off: the next snapshot stops carrying it
	s.Workloads.Metadata = false
	o.Session = &temporal.BackupSessionInfo{JobID: e.job, BackupRunID: uuid.New(), BackupType: "host", BackupID: "vcs-test"}
	if _, err := Run(ctx(t), o); err != nil {
		t.Fatal(err)
	}
	if e.rec.has("acme/web/_metadata/issues.json") {
		t.Error("metadata kept after the workload was switched off")
	}
}

func TestGitEnvironmentExtraURLs(t *testing.T) {
	g, err := NewGit("/bin/true", Auth{BaseURL: "https://github.com", Token: "ghp_x", ExtraURLs: []string{"https://gist.github.com/"}}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	env := strings.Join(g.env(""), "\n")
	if !strings.Contains(env, "http.https://github.com/.extraHeader") || !strings.Contains(env, "http.https://gist.github.com/.extraHeader") {
		t.Errorf("the header must cover the connection and the gist host:\n%s", env)
	}
	plain, _ := NewGit("/bin/true", Auth{BaseURL: "https://github.com", Token: "ghp_x"}, t.TempDir())
	if strings.Contains(strings.Join(plain.env(""), "\n"), "gist.github.com") {
		t.Error("without gists the token must not go to gist.github.com")
	}

	// This would cause an error on projects named "_metadata", which is a valid project name on GitHub and GitLab
	// if _, err := projectPath("acme/" + MetadataDir); err == nil {
	// 	t.Error("a project path must not reach the metadata directory")
	// }
}

// Make sure the metadata files are kept in case a run is cancelled since we can't determine what is stale and what isn't
func TestGitHubMetadataKeepsFilesWhenCancelled(t *testing.T) {
	srv := fakeGitHubAPI(t)
	dir := t.TempDir()
	old := filepath.Join(dir, "pulls.json")
	if err := os.WriteFile(old, []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p := &GitHubProvider{Spec: &spec.Spec{}, Credentials: spec.Credentials{BaseURL: srv.URL, Token: testToken}, API: githubAPI(srv)}
	if err := p.Metadata(ctx, Project{Ref: "acme/web"}, dir, &spec.RepoResult{}); err == nil {
		t.Fatal("a cancelled run must return an error")
	}
	if _, err := os.Stat(old); err != nil {
		t.Error("a cancelled run must keep the previous run's files:", err)
	}
}
