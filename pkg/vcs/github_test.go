package vcs

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestGitHubClient(t *testing.T) {
	limited := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch strings.TrimPrefix(r.URL.Path, "/api/v3") {
		case "/user":
			w.Header().Set("X-OAuth-Scopes", "repo")
			w.Header().Set("GitHub-Authentication-Token-Expiration", "2026-11-20 10:00:00 UTC")
			fmt.Fprint(w, `{"login":"me"}`)
		case "/orgs/acme/repos":
			if !limited {
				limited = true
				w.Header().Set("X-RateLimit-Remaining", "0")
				w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(2*time.Second).Unix(), 10))
				w.WriteHeader(http.StatusForbidden)
				return
			}
			page, _ := strconv.Atoi(r.URL.Query().Get("page"))
			if page < 2 {
				w.Header().Set("Link", fmt.Sprintf(`<http://%s/api/v3/orgs/acme/repos?page=%d>; rel="next"`, r.Host, page+1))
			} else {
				w.Header().Set("Link", `<https://evil.example/steal>; rel="next"`)
			}
			fmt.Fprintf(w, `[{"id":%d,"name":"r%d","owner":{"login":"acme"}}]`, page+1, page)
		case "/repos/acme/r1/issues":
			w.WriteHeader(http.StatusGone)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	slept := time.Duration(0)
	c := &GitHubClient{APIURL: srv.URL + "/api/v3", Token: "tok", HTTP: srv.Client(),
		Sleep: func(_ context.Context, d time.Duration) error { slept += d; return nil }}
	ctx := context.Background()
	repos, user, err := c.OwnerRepos(ctx, "acme", "me")
	if err != nil || user || len(repos) != 3 || len(repos[2].Raw) == 0 {
		t.Fatalf("OwnerRepos: %v %v %+v", err, user, repos)
	}
	if slept <= 0 || slept > 5*time.Second {
		t.Errorf("rate limit wait = %s", slept)
	}
	if items, err := c.RepoList(ctx, "acme", "r1", "issues", nil); err != nil || items != nil {
		t.Errorf("disabled issues must read as empty: %v %v", items, err)
	}
	if _, _, err := c.OwnerRepos(ctx, "nobody", "me"); !IsGitHubNotFound(err) {
		t.Errorf("unknown owner: %v", err)
	}
	inst, err := TestGitHubConnection(ctx, Credentials{Provider: ProviderGitHub, BaseURL: srv.URL, Token: "tok"}, srv.Client())
	if err != nil || inst.Username != "me" || inst.TokenExpires == nil || inst.TokenExpires.Day() != 20 {
		t.Fatalf("connection test: %v %+v", err, inst)
	}
	joined := strings.Join(inst.Warnings, "\n")
	if !strings.Contains(joined, "read:org") || !strings.Contains(joined, "expires") {
		t.Errorf("warnings = %v", inst.Warnings)
	}
	if _, err := TestConnection(ctx, Credentials{Provider: ProviderGitHub, BaseURL: srv.URL, Token: "bad"}, srv.Client()); err == nil || !strings.Contains(err.Error(), "rejected the token") {
		t.Errorf("bad token: %v", err)
	}
}
