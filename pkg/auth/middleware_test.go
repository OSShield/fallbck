package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/db"
)

type fakeKeyStore struct {
	keys    map[string]*db.APIKey
	touched int
}

func (f *fakeKeyStore) CreateAPIKey(_ context.Context, key *db.APIKey) error {
	f.keys[key.KeyHash] = key
	return nil
}

func (f *fakeKeyStore) GetAPIKeyByHash(_ context.Context, hash string) (*db.APIKey, error) {
	k, ok := f.keys[hash]
	if !ok {
		return nil, db.ErrNotFound
	}
	return k, nil
}

func (f *fakeKeyStore) TouchAPIKey(_ context.Context, _ uuid.UUID) error {
	f.touched++
	return nil
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := PrincipalFrom(r.Context())
		if p == nil {
			http.Error(w, "no principal", http.StatusInternalServerError)
			return
		}
		w.Header().Set("X-Principal", string(p.Kind)+":"+p.Display())
		w.WriteHeader(http.StatusOK)
	})
}

func TestRequireAdmin(t *testing.T) {
	tm := NewTokenManager("test-secret-key-must-be-very-long-123456")
	store := &fakeKeyStore{keys: map[string]*db.APIKey{}}
	admin := NewAdminAuth(tm, store, false)
	h := admin.RequireAdmin(okHandler())

	raw, key, err := NewAPIKey("ci", "alice@example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(raw, APIKeyPrefix) {
		t.Errorf("api key should carry prefix, got %q", raw)
	}
	_ = store.CreateAPIKey(context.Background(), key)

	session, _, err := tm.CreateSession(&Identity{Subject: "sub-1", Email: "alice@example.com"}, "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		method     string
		path       string
		setup      func(r *http.Request)
		wantStatus int
		wantPrinc  string
	}{
		{"api no auth", http.MethodGet, "/api/v1/agents", nil, http.StatusUnauthorized, ""},
		{"page no auth redirects", http.MethodGet, "/dashboard", func(r *http.Request) { r.Header.Set("Accept", "text/html") }, http.StatusFound, ""},
		{"api key ok", http.MethodPost, "/api/v1/tokens", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+raw) }, http.StatusOK, "apikey:ci"},
		{"unknown api key", http.MethodGet, "/api/v1/agents", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+APIKeyPrefix+"nope") }, http.StatusUnauthorized, ""},
		{"non api-key bearer rejected", http.MethodGet, "/api/v1/agents", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+session) }, http.StatusUnauthorized, ""},
		{"session GET ok", http.MethodGet, "/api/v1/agents", func(r *http.Request) { r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: session}) }, http.StatusOK, "session:alice@example.com"},
		{"session POST without CSRF header", http.MethodPost, "/api/v1/tokens", func(r *http.Request) { r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: session}) }, http.StatusForbidden, ""},
		{"session POST with CSRF header", http.MethodPost, "/api/v1/tokens", func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: session})
			r.Header.Set(CSRFHeader, CSRFHeaderValue)
		}, http.StatusOK, "session:alice@example.com"},
		{"garbage session cookie", http.MethodGet, "/api/v1/agents", func(r *http.Request) { r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "x.y.z"}) }, http.StatusUnauthorized, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, tc.path, nil)
			if tc.setup != nil {
				tc.setup(r)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body %s)", w.Code, tc.wantStatus, w.Body.String())
			}
			if tc.wantPrinc != "" && w.Header().Get("X-Principal") != tc.wantPrinc {
				t.Errorf("principal = %q, want %q", w.Header().Get("X-Principal"), tc.wantPrinc)
			}
			if tc.wantStatus == http.StatusFound && !strings.HasPrefix(w.Header().Get("Location"), "/auth/login?next=") {
				t.Errorf("redirect location = %q", w.Header().Get("Location"))
			}
		})
	}

	if store.touched == 0 {
		t.Error("expected API key usage to be recorded")
	}

	// revoked / expired keys
	now := time.Now()
	key.RevokedAt = &now
	r := httptest.NewRequest(http.MethodGet, "/api/v1/agents", nil)
	r.Header.Set("Authorization", "Bearer "+raw)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("revoked key: status = %d", w.Code)
	}

	// insecure mode admits everyone
	insecure := NewAdminAuth(tm, store, true).RequireAdmin(okHandler())
	r = httptest.NewRequest(http.MethodPost, "/api/v1/tokens", nil)
	w = httptest.NewRecorder()
	insecure.ServeHTTP(w, r)
	if w.Code != http.StatusOK || w.Header().Get("X-Principal") != "insecure:Development admin" {
		t.Errorf("insecure mode: status %d principal %q", w.Code, w.Header().Get("X-Principal"))
	}
}

func TestRequireAgent(t *testing.T) {
	tm := NewTokenManager("test-secret-key-must-be-very-long-123456")
	agentID := uuid.New()
	store := &fakeAgentStore{states: map[uuid.UUID]*db.AgentAuthState{
		agentID: {ID: agentID, TaskQueue: "q", TokenVersion: 1},
	}}
	mw := &AgentAuth{Verifier: NewAgentVerifier(tm, store, time.Second)}
	h := mw.RequireAgent(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := AgentFrom(r.Context())
		if c == nil || c.AgentID != agentID {
			http.Error(w, "no agent", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))

	token, _, _ := tm.CreateAgentToken(agentID, "q", 1, time.Hour)

	r := httptest.NewRequest(http.MethodPost, "/api/v1/agents/heartbeat", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("no token: status %d", w.Code)
	}

	r = httptest.NewRequest(http.MethodPost, "/api/v1/agents/heartbeat", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("valid token: status %d body %s", w.Code, w.Body.String())
	}
}

func TestSessionCookies(t *testing.T) {
	w := httptest.NewRecorder()
	SetSessionCookie(w, "tok", time.Now().Add(time.Hour), CookieOptions{Secure: true})
	c := w.Result().Cookies()[0]
	if c.Name != SessionCookieName || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.Path != "/" {
		t.Errorf("unexpected session cookie attributes: %+v", c)
	}

	w = httptest.NewRecorder()
	ClearSessionCookie(w, CookieOptions{})
	if w.Result().Cookies()[0].MaxAge != -1 {
		t.Error("clear should expire the cookie")
	}
}

// fakeSessions is a SessionStore with a revocation switch and a call counter
type fakeSessions struct {
	revoked map[string]bool
	calls   int
}

func (f *fakeSessions) TouchAdminSession(_ context.Context, id string) (bool, error) {
	f.calls++
	return id != "" && !f.revoked[id], nil
}

func TestSessionRevocation(t *testing.T) {
	tm := NewTokenManager("test-secret-key-must-be-very-long-123456")
	store := &fakeSessions{revoked: map[string]bool{}}
	a := NewAdminAuth(tm, nil, false)
	a.Sessions = NewSessionChecker(store, time.Minute)
	request := func(sid string) *http.Request {
		token, _, err := tm.CreateSession(&Identity{Subject: "s", Email: "a@example.com"}, sid, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodGet, "/api/v1/jobs", nil)
		r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: token})
		return r
	}

	p, err := a.Authenticate(request("s1"))
	if err != nil || p.SessionID != "s1" {
		t.Fatalf("valid session: %v %+v", err, p)
	}
	// Cached: a second request inside the TTL does not hit the store
	_, _ = a.Authenticate(request("s1"))
	if store.calls != 1 {
		t.Errorf("store called %d times, want 1 (cache)", store.calls)
	}
	// Revoked elsewhere: still cached here until Forget (or the TTL) ...
	store.revoked["s1"] = true
	a.Sessions.Forget("s1")
	if _, err := a.Authenticate(request("s1")); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("revoked session: %v, want ErrInvalidToken", err)
	}
	// A session cookie from before server-side tracking (no id) must sign in again
	if _, err := a.Authenticate(request("")); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("session without id: %v, want ErrInvalidToken", err)
	}
	// Without a store (tests, no database) the cookie alone counts, as before
	a.Sessions = nil
	if _, err := a.Authenticate(request("")); err != nil {
		t.Errorf("no session store: %v", err)
	}
}
