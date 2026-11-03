package vcs

import (
	"context"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestConnectionValidate(t *testing.T) {
	c := &Connection{Name: " internal ", Provider: "GitLab", BaseURL: "https://GitLab.Example.com/gitlab/", Token: " glpat-abc "}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.Name != "internal" || c.Provider != ProviderGitLab || c.BaseURL != "https://gitlab.example.com/gitlab" || c.Token != "glpat-abc" {
		t.Errorf("not normalised: %+v", c)
	}
	if !c.Sanitize().HasToken {
		t.Error("HasToken")
	}

	bad := []Connection{
		{Provider: ProviderGitLab, BaseURL: "https://x", Token: "t"},
		{Name: "n", Provider: "github", BaseURL: "https://x", Token: "t"},
		{Name: "n", Provider: ProviderGitLab, BaseURL: "http://x", Token: "t"},
		{Name: "n", Provider: ProviderGitLab, BaseURL: "https://u:p@x", Token: "t"},
		{Name: "n", Provider: ProviderGitLab, BaseURL: "https://x/?a=b", Token: "t"},
		{Name: "n", Provider: ProviderGitLab, BaseURL: "https://x"},
		{Name: "n", Provider: ProviderGitLab, BaseURL: "https://x", Token: "a\r\nX-Evil: 1"},
		{Name: "n", Provider: ProviderGit, BaseURL: "https://x", CAPEM: "not a pem"},
	}
	for i, b := range bad {
		if err := b.Validate(); !errors.Is(err, ErrInvalidConnection) {
			t.Errorf("case %d: expected ErrInvalidConnection, got %v", i, err)
		}
	}
	public := &Connection{Name: "public", Provider: ProviderGit, BaseURL: "https://git.example.com"}
	if err := public.Validate(); err != nil {
		t.Errorf("a git connection may go without a token: %v", err)
	}
}

func TestExpiry(t *testing.T) {
	soon := time.Now().Add(10 * 24 * time.Hour)
	past := time.Now().Add(-time.Hour)
	if c := (&Connection{TokenExpires: &soon}); !c.ExpiringSoon() || c.Expired() {
		t.Error("expiring soon")
	}
	if c := (&Connection{TokenExpires: &past}); !c.Expired() {
		t.Error("expired")
	}
	if c := (&Connection{}); c.ExpiringSoon() {
		t.Error("no expiry")
	}
}

// fakeGitLab answers the three endpoints TestConnection reads
func fakeGitLab(t *testing.T, scopes string, admin bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("PRIVATE-TOKEN") != "glpat-good" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"message":"401 Unauthorized"}`))
			return
		}
		switch r.URL.Path {
		case "/api/v4/version":
			_, _ = w.Write([]byte(`{"version":"17.5.1-ee","revision":"abc"}`))
		case "/api/v4/user":
			if admin {
				_, _ = w.Write([]byte(`{"username":"backup-bot","is_admin":true}`))
			} else {
				_, _ = w.Write([]byte(`{"username":"backup-bot"}`))
			}
		case "/api/v4/personal_access_tokens/self":
			if scopes == "" {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write([]byte(`{"name":"fallbck","scopes":` + scopes + `,"expires_at":"2099-01-31","active":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func creds(t *testing.T, srv *httptest.Server, token string) (Credentials, *http.Client) {
	t.Helper()
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	c := Credentials{Provider: ProviderGitLab, BaseURL: srv.URL, Token: token, CAPEM: ca}
	client, err := c.HTTPClient(5 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return c, client
}

func TestTestConnection(t *testing.T) {
	ctx := context.Background()

	srv := fakeGitLab(t, `["read_api","read_repository"]`, true)
	c, client := creds(t, srv, "glpat-good")
	inst, err := TestConnection(ctx, c, client)
	if err != nil {
		t.Fatal(err)
	}
	if inst.Version != "17.5.1-ee" || inst.Username != "backup-bot" || !inst.IsAdmin || inst.TokenExpires == nil || inst.TokenExpires.Year() != 2099 {
		t.Errorf("instance: %+v", inst)
	}
	if len(inst.Warnings) != 0 {
		t.Errorf("unexpected warnings: %v", inst.Warnings)
	}

	// The CA bundle is what makes the TLS server trusted
	if _, err := TestConnection(ctx, Credentials{Provider: ProviderGitLab, BaseURL: srv.URL, Token: "glpat-good"}, &http.Client{Timeout: 5 * time.Second}); err == nil || !strings.Contains(err.Error(), "outbound HTTPS") {
		t.Errorf("untrusted certificate should fail with a network hint: %v", err)
	}

	if _, err := TestConnection(ctx, Credentials{Provider: ProviderGitLab, BaseURL: srv.URL, Token: "wrong", CAPEM: c.CAPEM}, client); err == nil || !strings.Contains(err.Error(), "rejected the token") {
		t.Errorf("wrong token: %v", err)
	}

	broad := fakeGitLab(t, `["api"]`, false)
	c, client = creds(t, broad, "glpat-good")
	inst, err = TestConnection(ctx, c, client)
	if err != nil {
		t.Fatal(err)
	}
	if w := strings.Join(inst.Warnings, "\n"); !strings.Contains(w, "broader scopes") || !strings.Contains(w, "not an administrator") {
		t.Errorf("warnings: %v", inst.Warnings)
	}

	narrow := fakeGitLab(t, `["read_api"]`, true)
	c, client = creds(t, narrow, "glpat-good")
	if _, err := TestConnection(ctx, c, client); err == nil || !strings.Contains(err.Error(), ScopeReadRepository) {
		t.Errorf("missing read_repository: %v", err)
	}

	old := fakeGitLab(t, "", true)
	c, client = creds(t, old, "glpat-good")
	inst, err = TestConnection(ctx, c, client)
	if err != nil || len(inst.Warnings) != 1 || !strings.Contains(inst.Warnings[0], "15.5") {
		t.Errorf("no token endpoint: %+v %v", inst, err)
	}

	if _, err := TestConnection(ctx, Credentials{Provider: ProviderGit}, client); err == nil {
		t.Error("git connections have no API test")
	}
}

func TestManifestTally(t *testing.T) {
	m := &Manifest{Repositories: []RepoResult{
		{Status: RepoCompleted, Bytes: 10, LFSBytes: 5},
		{Status: RepoStale, Bytes: 7},
		{Status: RepoFailed},
		{Status: RepoSkipped},
	}}
	m.Tally()
	if m.Totals != (ManifestTotals{Repositories: 4, Completed: 1, Stale: 1, Failed: 1, Skipped: 1, Bytes: 22}) {
		t.Errorf("totals: %+v", m.Totals)
	}
}
