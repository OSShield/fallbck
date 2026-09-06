package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/osshield/fallbck/pkg/auth"
	"github.com/osshield/fallbck/pkg/config"
)

func TestUIRenderRoutes(t *testing.T) {
	cfg := config.DefaultServerConfig()
	// Zero Deps → insecure (development) admin auth, no OIDC, no Temporal UI
	ui := NewUIHandler(nil, cfg, Deps{Version: "test"})

	r := chi.NewRouter()
	r.Use(SecurityHeaders)
	ui.RegisterRoutes(r)

	testCases := []struct {
		path         string
		expectedCode int
		contains     string
	}{
		{"/", http.StatusFound, ""},
		{"/dashboard", http.StatusOK, "Connected Agents"},
		{"/agents", http.StatusOK, "Enrolled Agents"},
		{"/targets", http.StatusOK, "PBS Targets"},
		{"/jobs", http.StatusOK, "Backup Jobs"},
		{"/jobs", http.StatusOK, `name="job_type"`},
		{"/jobs", http.StatusOK, "runs in "},
		{"/kubernetes", http.StatusOK, "Kubernetes Backup Jobs"},
		{"/kubernetes", http.StatusOK, `name="k8s_volumes_mode"`},
		{"/runs", http.StatusOK, "Duration"},
		{"/runs/00000000-0000-0000-0000-000000000000", http.StatusOK, "run-detail-root"},
		{"/agents", http.StatusOK, "Database agent"},
		{"/runs", http.StatusOK, "Backup Executions"},
		{"/tokens", http.StatusOK, "Enrollment Tokens"},
		{"/apikeys", http.StatusOK, "API Keys"},
		{"/install-agent.sh", http.StatusOK, "#!/usr/bin/env bash"},
		{"/login", http.StatusFound, ""},      // insecure mode skips the login page
		{"/auth/login", http.StatusFound, ""}, // ... and the OIDC redirect
		{"/temporal/", http.StatusNotFound, ""},
	}

	for _, tc := range testCases {
		t.Run(tc.path, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, tc.path, nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)

			if rr.Code != tc.expectedCode {
				t.Errorf("Path %s expected status %d, got %d", tc.path, tc.expectedCode, rr.Code)
			}

			if tc.contains != "" && !strings.Contains(rr.Body.String(), tc.contains) {
				t.Errorf("Path %s response expected to contain '%s'", tc.path, tc.contains)
			}
			if rr.Code == http.StatusOK && rr.Header().Get("Content-Security-Policy") == "" {
				t.Errorf("Path %s missing CSP header", tc.path)
			}
		})
	}
}

func TestUIRequiresAdminWhenSecured(t *testing.T) {
	cfg := config.DefaultServerConfig()
	cfg.PublicURL = "https://backup.example.com"
	tm := auth.NewTokenManager("test-secret-key-must-be-very-long-123456")
	ui := NewUIHandler(nil, cfg, Deps{TokenManager: tm, Admin: auth.NewAdminAuth(tm, nil, false)})

	r := chi.NewRouter()
	ui.RegisterRoutes(r)

	// Browser navigation without a session → login redirect carrying the original path
	req := httptest.NewRequest(http.MethodGet, "/jobs", nil)
	req.Header.Set("Accept", "text/html")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusFound || !strings.Contains(rr.Header().Get("Location"), "/auth/login?next=%2Fjobs") {
		t.Errorf("expected login redirect, got %d %s", rr.Code, rr.Header().Get("Location"))
	}

	// Login page renders (no OIDC configured → explanatory message)
	rr = httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/login?next=/jobs", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "Single sign-on is not configured") {
		t.Errorf("login page: %d %s", rr.Code, rr.Body.String())
	}

	// A valid session cookie grants access and shows the user
	session, _, err := tm.CreateSession(&auth.Identity{Subject: "s", Email: "alice@example.com"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: session})
	rr = httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "alice@example.com") {
		t.Errorf("dashboard with session: %d", rr.Code)
	}

	// Logout clears the cookie
	req = httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: session})
	req.Header.Set(auth.CSRFHeader, auth.CSRFHeaderValue)
	rr = httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("logout: %d", rr.Code)
	}
	cleared := false
	for _, c := range rr.Result().Cookies() {
		if c.Name == auth.SessionCookieName && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("logout did not clear the session cookie")
	}

	// Public endpoints stay public
	rr = httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/install-agent.sh", nil))
	if rr.Code != http.StatusOK {
		t.Errorf("install script should be public, got %d", rr.Code)
	}
}

func TestSafeNext(t *testing.T) {
	cases := map[string]string{"": "/dashboard", "/jobs": "/jobs", "//evil.com": "/dashboard", "https://evil.com": "/dashboard", "/\\evil": "/dashboard"}
	for in, want := range cases {
		if got := safeNext(in); got != want {
			t.Errorf("safeNext(%q) = %q, want %q", in, got, want)
		}
	}
}
