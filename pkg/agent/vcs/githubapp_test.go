package vcs

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	dbrun "github.com/osshield/fallbck/pkg/agent/dbbackup"
	spec "github.com/osshield/fallbck/pkg/vcs"
)

// A rotated token goes into the next git process, and every token stays redacted
func TestGitRenewsToken(t *testing.T) {
	next := "ghs_second"
	g, err := NewGit("/bin/true", Auth{BaseURL: "https://github.com", Token: "ghs_first", Username: spec.GitHubAppUsername,
		Tokens: func(context.Context) (string, error) { return next, nil }}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := g.renewToken(context.Background()); err != nil {
		t.Fatal(err)
	}
	env := strings.Join(g.env(""), "\n")
	if !strings.Contains(env, basicCredentials(spec.GitHubAppUsername, "ghs_second")) || strings.Contains(env, basicCredentials(spec.GitHubAppUsername, "ghs_first")) {
		t.Errorf("the header must carry the renewed token:\n%s", env)
	}
	for _, tok := range []string{"ghs_first", "ghs_second"} {
		if !slices.Contains(g.secrets, tok) {
			t.Errorf("%s is not redacted", tok)
		}
	}
	g.auth.Tokens = func(context.Context) (string, error) { return "", errors.New("server unreachable") }
	if err := g.run(context.Background(), "", nil, nil, "version"); err == nil || !strings.Contains(err.Error(), "server unreachable") {
		t.Errorf("a failed renewal must fail the git command: %v", err)
	}
}

// A server-side GitHub App token about to expire is renewed through the server before
// git uses it; the renewed one is then reused
func TestRunRenewsShortLivedToken(t *testing.T) {
	e := newRunEnv(t)
	e.h.repo(t, "team/app.git")
	e.h.accept(spec.GitHubAppUsername, "ghs_renewed")
	o := e.opts(t, "team/app.git")
	soon := time.Now().Add(2 * time.Minute)
	o.Credentials.Token, o.Credentials.Username, o.Credentials.ExpiresAt = "ghs_expiring", spec.GitHubAppUsername, &soon
	var refreshes atomic.Int64
	o.RefreshCredentials = func(context.Context) (*spec.Credentials, error) {
		refreshes.Add(1)
		exp := time.Now().Add(time.Hour)
		return &spec.Credentials{Token: "ghs_renewed", ExpiresAt: &exp}, nil
	}
	res, err := Run(ctx(t), o)
	if err != nil || res.Status != "completed" {
		t.Fatalf("run: %+v %v", res, err)
	}
	if refreshes.Load() != 1 || e.h.unauthenticated.Load() != 0 {
		t.Errorf("%d renewals, %d unauthenticated requests", refreshes.Load(), e.h.unauthenticated.Load())
	}
}

func appTestKey(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
}

// An App profile mints its first installation token in the precheck
func TestApplyGitHubAppProfile(t *testing.T) {
	var minted atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v3/app/installations/7/access_tokens" || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ey") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		minted.Add(1)
		_, _ = w.Write([]byte(`{"token":"ghs_local","expires_at":"` + time.Now().Add(time.Hour).UTC().Format(time.RFC3339) + `"}`))
	}))
	defer srv.Close()
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	creds := spec.Credentials{Provider: spec.ProviderGitHub, BaseURL: srv.URL, CAPEM: caPEM}
	profile := &spec.Profile{URL: srv.URL, AuthType: spec.AuthGitHubApp, AppID: 1, InstallationID: 7, AppKey: appTestKey(t)}
	lookup := func(string) (*spec.Profile, error) { return profile, nil }

	auth := Auth{BaseURL: srv.URL}
	authType, err := applyProfile(context.Background(), &auth, &spec.Spec{Profile: "gh-app"}, creds, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if authType != spec.AuthGitHubApp || auth.Token != "ghs_local" || auth.Username != spec.GitHubAppUsername || auth.Tokens == nil {
		t.Fatalf("auth %+v, type %s", auth, authType)
	}
	if tok, err := auth.Tokens(context.Background()); err != nil || tok != "ghs_local" || minted.Load() != 1 {
		t.Errorf("the fresh token must be reused: %q %v, %d minted", tok, err, minted.Load())
	}

	// The precheck names the problem: a wrong installation, a non-GitHub connection
	profile.InstallationID = 8
	auth = Auth{BaseURL: srv.URL}
	if _, err := applyProfile(context.Background(), &auth, &spec.Spec{Profile: "gh-app"}, creds, lookup); !dbrun.IsPrecheck(err) || !strings.Contains(err.Error(), "installation") {
		t.Errorf("wrong installation: %v", err)
	}
	creds.Provider = spec.ProviderGitLab
	if _, err := applyProfile(context.Background(), &auth, &spec.Spec{Profile: "gh-app"}, creds, lookup); !dbrun.IsPrecheck(err) {
		t.Errorf("App profile on a GitLab connection: %v", err)
	}
}

// With an App token the provider lists owners without asking who the user is
func TestGitHubAppProjectsSkipViewer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v3/orgs/acme/repos":
			_, _ = w.Write([]byte(`[{"id":1,"name":"web","full_name":"acme/web","owner":{"login":"acme"}}]`))
		default:
			// GET /user answers an installation token with 403
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer srv.Close()
	creds := spec.Credentials{Provider: spec.ProviderGitHub, BaseURL: "https://github.example.com", AuthType: spec.AuthGitHubApp, Token: "ghs_x"}
	p := &GitHubProvider{Spec: &spec.Spec{Groups: []string{"acme"}}, Credentials: creds,
		API: &spec.GitHubClient{APIURL: srv.URL + "/api/v3", Token: "ghs_x", HTTP: srv.Client()}}
	projects, _, err := p.Projects(context.Background())
	if err != nil || len(projects) != 1 || projects[0].Path != "acme/web" {
		t.Fatalf("projects %+v %v", projects, err)
	}
	var src spec.SourceInfo
	p.Describe(&src)
	if src.Username != "GitHub App" {
		t.Errorf("manifest source user %q", src.Username)
	}
}
