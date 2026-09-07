package auth

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

// CSRFHeader must be present on cookie-authenticated state-changing requests.
// Browsers cannot add custom headers cross-site, so its presence proves same-origin JS.
const (
	CSRFHeader      = "X-Requested-With"
	CSRFHeaderValue = "fallbck"
)

// PrincipalKind distinguishes how an admin request was authenticated
type PrincipalKind string

const (
	PrincipalSession  PrincipalKind = "session"
	PrincipalAPIKey   PrincipalKind = "apikey"
	PrincipalInsecure PrincipalKind = "insecure"
)

// Principal is the authenticated admin identity attached to the request context
type Principal struct {
	Kind    PrincipalKind
	Subject string
	Email   string
	Name    string
}

// Display returns a human-readable identifier for audit logs and the UI
func (p *Principal) Display() string {
	if p == nil {
		return ""
	}
	if p.Email != "" {
		return p.Email
	}
	if p.Name != "" {
		return p.Name
	}
	return p.Subject
}

type ctxKey int

const (
	ctxKeyPrincipal ctxKey = iota
	ctxKeyAgent
)

// PrincipalFrom returns the admin principal on the context, if any
func PrincipalFrom(ctx context.Context) *Principal {
	p, _ := ctx.Value(ctxKeyPrincipal).(*Principal)
	return p
}

// AgentFrom returns the authenticated agent on the context, if any
func AgentFrom(ctx context.Context) *AgentClaims {
	c, _ := ctx.Value(ctxKeyAgent).(*AgentClaims)
	return c
}

// WithPrincipal attaches a principal to a context (exported for tests and dev mode)
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, ctxKeyPrincipal, p)
}

// WithAgent attaches agent claims to a context
func WithAgent(ctx context.Context, c *AgentClaims) context.Context {
	return context.WithValue(ctx, ctxKeyAgent, c)
}

// AdminAuth authenticates admin requests via session cookie or API key
type AdminAuth struct {
	TM   *TokenManager
	Keys APIKeyStore
	// Insecure disables authentication entirely (development only)
	Insecure bool
	// LoginPath is where unauthenticated browser requests are redirected
	LoginPath string
}

// NewAdminAuth constructs the admin middleware
func NewAdminAuth(tm *TokenManager, keys APIKeyStore, insecure bool) *AdminAuth {
	return &AdminAuth{TM: tm, Keys: keys, Insecure: insecure, LoginPath: "/auth/login"}
}

// Authenticate resolves the principal for a request without enforcing anything
func (a *AdminAuth) Authenticate(r *http.Request) (*Principal, error) {
	if a.Insecure {
		return &Principal{Kind: PrincipalInsecure, Subject: "dev", Name: "Development admin"}, nil
	}

	if header := r.Header.Get("Authorization"); header != "" {
		raw := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(header, "Bearer "), "bearer "))
		if !IsAPIKey(raw) {
			return nil, ErrInvalidAPIKey
		}
		if a.Keys == nil {
			return nil, ErrInvalidAPIKey
		}
		key, err := LookupAPIKey(r.Context(), a.Keys, raw)
		if err != nil {
			return nil, err
		}
		_ = a.Keys.TouchAPIKey(r.Context(), key.ID)
		return &Principal{Kind: PrincipalAPIKey, Subject: key.ID.String(), Name: key.Name}, nil
	}

	cookie, err := r.Cookie(SessionCookieName)
	if err != nil || cookie.Value == "" {
		return nil, ErrInvalidToken
	}
	claims, err := a.TM.ValidateSession(cookie.Value)
	if err != nil {
		return nil, err
	}
	return &Principal{Kind: PrincipalSession, Subject: claims.Subject, Email: claims.Email, Name: claims.Name}, nil
}

// RequireAdmin enforces admin authentication and CSRF protection for cookie sessions.
// API-style paths get a JSON 401; browser navigations are redirected to the login page.
func (a *AdminAuth) RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, err := a.Authenticate(r)
		if err != nil {
			a.reject(w, r, err)
			return
		}
		if principal.Kind == PrincipalSession && !safeMethod(r.Method) && r.Header.Get(CSRFHeader) != CSRFHeaderValue {
			writeJSONError(w, http.StatusForbidden, "missing CSRF header")
			return
		}
		next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), principal)))
	})
}

func (a *AdminAuth) reject(w http.ResponseWriter, r *http.Request, err error) {
	if r.Header.Get("HX-Request") == "true" && !strings.HasPrefix(r.URL.Path, "/api/") && (errors.Is(err, ErrInvalidAPIKey) || errors.Is(err, ErrInvalidToken)) {
		next := "/dashboard"
		if current, parseErr := url.Parse(r.Header.Get("HX-Current-URL")); parseErr == nil && current.Host == r.Host {
			next = current.RequestURI()
		}
		w.Header().Set("HX-Redirect", a.LoginPath+"?next="+url.QueryEscape(next))
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if !wantsHTML(r) {
		if errors.Is(err, ErrInvalidAPIKey) || errors.Is(err, ErrInvalidToken) {
			writeJSONError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		slog.Error("Admin authentication failed", "error", err)
		writeJSONError(w, http.StatusInternalServerError, "authentication error")
		return
	}
	next := r.URL.RequestURI()
	http.Redirect(w, r, a.LoginPath+"?next="+url.QueryEscape(next), http.StatusFound)
}

// AgentAuth authenticates agent requests with the agent bearer token
type AgentAuth struct {
	Verifier *AgentVerifier
}

// RequireAgent enforces a valid, unrevoked agent token and attaches the claims
func (a *AgentAuth) RequireAgent(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		if header == "" {
			writeJSONError(w, http.StatusUnauthorized, "agent token required")
			return
		}
		claims, err := a.Verifier.Verify(r.Context(), header)
		if err != nil {
			if errors.Is(err, ErrInvalidToken) || errors.Is(err, ErrAgentRevoked) {
				writeJSONError(w, http.StatusUnauthorized, "invalid or revoked agent token")
				return
			}
			slog.Error("Agent authentication failed", "error", err)
			writeJSONError(w, http.StatusInternalServerError, "authentication error")
			return
		}
		next.ServeHTTP(w, r.WithContext(WithAgent(r.Context(), claims)))
	})
}

func safeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	return false
}

// wantsHTML decides between a login redirect and a JSON 401
func wantsHTML(r *http.Request) bool {
	if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/temporal/api/") {
		return false
	}
	if r.Header.Get(CSRFHeader) == CSRFHeaderValue || r.Header.Get("Authorization") != "" {
		return false
	}
	return safeMethod(r.Method) && strings.Contains(r.Header.Get("Accept"), "text/html")
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
