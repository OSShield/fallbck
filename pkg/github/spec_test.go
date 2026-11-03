package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSpecValidate(t *testing.T) {
	acc := uuid.New()
	ok := &Spec{AccountID: acc, Sources: Sources{
		Orgs:  []OrgSource{{Name: " acme "}, {Name: "ACME"}, {Name: "labs", Type: "Sources"}},
		Users: []string{"octocat", "OctoCat", " "},
		Repos: []string{"acme/web", "https://github.com/torvalds/linux.git", "ACME/web"},
	}, Include: []string{" acme/* "}}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid spec: %v", err)
	}
	if len(ok.Sources.Orgs) != 2 || ok.Sources.Orgs[0].Type != OrgTypeAll || ok.Sources.Orgs[1].Type != OrgTypeSources {
		t.Errorf("orgs not normalised: %+v", ok.Sources.Orgs)
	}
	if len(ok.Sources.Users) != 1 || len(ok.Sources.Repos) != 2 || ok.Sources.Repos[1] != "torvalds/linux" {
		t.Errorf("users/repos not normalised: %v %v", ok.Sources.Users, ok.Sources.Repos)
	}
	if ok.Include[0] != "acme/*" {
		t.Errorf("include not trimmed: %q", ok.Include[0])
	}

	bad := map[string]*Spec{
		"no account":  {Sources: Sources{Starred: true}},
		"no source":   {AccountID: acc},
		"bad org":     {AccountID: acc, Sources: Sources{Orgs: []OrgSource{{Name: "a b"}}}},
		"bad type":    {AccountID: acc, Sources: Sources{Orgs: []OrgSource{{Name: "a", Type: "everything"}}}},
		"bad repo":    {AccountID: acc, Sources: Sources{Repos: []string{"justaname"}}},
		"dotdot repo": {AccountID: acc, Sources: Sources{Repos: []string{"a/.."}}},
		"bad glob":    {AccountID: acc, Sources: Sources{Starred: true}, Exclude: []string{"[x"}},
		"concurrency": {AccountID: acc, Sources: Sources{Starred: true}, Concurrency: 99},
		"backup id":   {AccountID: acc, Sources: Sources{Starred: true}, BackupID: "a/b"},
	}
	for name, s := range bad {
		if err := s.Validate(); !errors.Is(err, ErrInvalidSpec) {
			t.Errorf("%s: expected ErrInvalidSpec, got %v", name, err)
		}
	}
}

func TestNamingAndSelection(t *testing.T) {
	if g := RepoGroup("github-acme", "1ARdotNO", "My.Repo"); g != "github-acme-1ardotno-my.repo" {
		t.Errorf("RepoGroup = %q", g)
	}
	if !strings.HasPrefix(RepoGroup("x", "o", "n"), GroupPrefix("x")) {
		t.Error("repo groups must extend the job group")
	}
	if DefaultBackupID("ACME Corp") != "github-acme-corp" {
		t.Errorf("DefaultBackupID = %q", DefaultBackupID("ACME Corp"))
	}
	if SafeName("...") != "unnamed" || SafeName("-x") != "x" {
		t.Errorf("SafeName edge cases: %q %q", SafeName("..."), SafeName("-x"))
	}
	if !Selected("Acme/Web", []string{"acme/*"}, nil) || Selected("acme/web", []string{"acme/*"}, []string{"*/WEB"}) || Selected("other/x", []string{"acme/*"}, nil) {
		t.Error("Selected globs")
	}
	s := &Spec{Sources: Sources{Orgs: []OrgSource{{Name: "acme", Type: "all"}, {Name: "labs", Type: "sources"}}, Users: []string{"me"}, Repos: []string{"a/b", "c/d"}, Starred: true}}
	if got := s.Summary(); got != "org acme, org labs (sources), user me, 2 repositories, starred" {
		t.Errorf("Summary = %q", got)
	}
	c := s.Clone()
	c.Sources.Orgs[0].Name = "changed"
	c.Sources.Repos[0] = "changed"
	if s.Sources.Orgs[0].Name != "acme" || s.Sources.Repos[0] != "a/b" {
		t.Error("Clone shares slices")
	}
}

func TestAccountValidate(t *testing.T) {
	a := &Account{Name: " acme ", Token: " ghp_x ", APIURL: "https://ghe.example.com/api/v3/"}
	if err := a.Validate(); err != nil || a.APIURL != "https://ghe.example.com/api/v3" || a.Name != "acme" || a.Token != "ghp_x" {
		t.Fatalf("Validate: %v %+v", err, a)
	}
	b := &Account{Name: "x", Token: "t"}
	if err := b.Validate(); err != nil || b.APIURL != DefaultAPIURL {
		t.Errorf("default API URL: %v %q", err, b.APIURL)
	}
	for _, bad := range []*Account{{Token: "t"}, {Name: "x"}, {Name: "x", Token: "t", APIURL: "ftp://x"}, {Name: "x", Token: "t", APIURL: "https://u:p@x"}} {
		if err := bad.Validate(); !errors.Is(err, ErrInvalidAccount) {
			t.Errorf("%+v: expected ErrInvalidAccount, got %v", bad, err)
		}
	}
}

func TestClientPaginationAndRateLimit(t *testing.T) {
	var limited bool
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/user":
			w.Header().Set("X-OAuth-Scopes", "repo, read:org")
			fmt.Fprint(w, `{"login":"me"}`)
		case "/orgs/acme/repos":
			if !limited {
				limited = true
				w.Header().Set("X-RateLimit-Remaining", "0")
				w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(2*time.Second).Unix(), 10))
				w.WriteHeader(http.StatusForbidden)
				fmt.Fprint(w, `{"message":"API rate limit exceeded"}`)
				return
			}
			page, _ := strconv.Atoi(r.URL.Query().Get("page"))
			if page == 0 {
				page = 1
			}
			if page < 3 {
				w.Header().Set("Link", fmt.Sprintf(`<%s/orgs/acme/repos?page=%d&per_page=100>; rel="next", <https://evil.example/x>; rel="last"`, srv.URL, page+1))
			}
			json.NewEncoder(w).Encode([]map[string]any{{"full_name": fmt.Sprintf("acme/r%d", page), "name": fmt.Sprintf("r%d", page), "owner": map[string]string{"login": "acme"}}})
		case "/orgs/evil/repos":
			w.Header().Set("Link", `<https://evil.example/steal>; rel="next"`)
			fmt.Fprint(w, `[]`)
		case "/repos/acme/r1/issues":
			w.WriteHeader(http.StatusGone)
			fmt.Fprint(w, `{"message":"Issues are disabled for this repo"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	c, err := NewClient(Credentials{APIURL: srv.URL, Token: "tok"})
	if err != nil {
		t.Fatal(err)
	}
	var slept time.Duration
	c.sleep = func(ctx context.Context, d time.Duration) error { slept += d; return nil }

	v, err := c.Viewer(context.Background())
	if err != nil || v.Login != "me" || len(v.Scopes) != 2 {
		t.Fatalf("Viewer: %v %+v", err, v)
	}
	repos, err := c.OrgRepos(context.Background(), "acme", "all")
	if err != nil || len(repos) != 3 || repos[2].FullName != "acme/r3" || len(repos[0].Raw) == 0 {
		t.Fatalf("OrgRepos: %v %+v", err, repos)
	}
	if slept <= 0 || slept > 5*time.Second {
		t.Errorf("rate limit wait = %s", slept)
	}
	if _, err := c.OrgRepos(context.Background(), "evil", ""); err != nil {
		t.Errorf("a foreign next link must be ignored, not followed: %v", err)
	}
	if items, err := c.RepoList(context.Background(), "acme", "r1", "issues", nil); err != nil || items != nil {
		t.Errorf("disabled issues must read as empty: %v %v", items, err)
	}
	if _, err := c.Repo(context.Background(), "acme", "missing"); !IsNotFound(err) {
		t.Errorf("missing repo: %v", err)
	}
	c.Token = "wrong"
	if _, err := TestConnection(context.Background(), Credentials{APIURL: srv.URL, Token: "wrong"}); err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Errorf("bad token: %v", err)
	}
	if got := string(MarshalList(nil)); got != "[]\n" {
		t.Errorf("MarshalList(nil) = %q", got)
	}
}

func TestGistSpec(t *testing.T) {
	id := "0123456789abcdef0123456789ABCDEF"
	for raw, want := range map[string]string{
		id:                                       strings.ToLower(id),
		"https://gist.github.com/octo/" + id:     strings.ToLower(id),
		"https://gist.github.com/" + id + ".git": strings.ToLower(id),
		"https://gist.github.com/octo/" + id + "#file-x-go":   strings.ToLower(id),
		"https://gist.github.com/octo/" + id + "/":            strings.ToLower(id),
		"https://gist.github.com/octo/" + id + "/revisions?x": "",
		"not-a-gist": "",
	} {
		got, ok := GistID(raw)
		if got != want || ok != (want != "") {
			t.Errorf("GistID(%q) = %q %v, want %q", raw, got, ok, want)
		}
	}
	s := &Spec{AccountID: uuid.New(), Sources: Sources{Gists: Gists{Own: true, Users: []string{"octo", "OCTO"}, IDs: []string{id, "https://gist.github.com/octo/" + id}}}}
	if err := s.Validate(); err != nil {
		t.Fatalf("gist-only spec: %v", err)
	}
	if len(s.Sources.Gists.Users) != 1 || len(s.Sources.Gists.IDs) != 1 {
		t.Errorf("gists not deduplicated: %+v", s.Sources.Gists)
	}
	if got := s.Summary(); got != "own gists, gists of octo, 1 gists" {
		t.Errorf("Summary = %q", got)
	}
	bad := &Spec{AccountID: uuid.New(), Sources: Sources{Gists: Gists{IDs: []string{"nope"}}}}
	if err := bad.Validate(); !errors.Is(err, ErrInvalidSpec) {
		t.Errorf("bad gist id: %v", err)
	}
	if g := GistGroup("github-x", "Octo", strings.ToLower(id)); g != "github-x-gist-octo-"+strings.ToLower(id) {
		t.Errorf("GistGroup = %q", g)
	}
}
