package auth

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	// SessionCookieName carries the admin browser session JWT
	SessionCookieName = "fallbck_session"
	// LoginStateCookieName carries the OIDC state/nonce between login redirect and callback
	LoginStateCookieName = "fallbck_login"

	DefaultSessionTTL = 12 * time.Hour
	loginStateTTL     = 10 * time.Minute
)

// SessionClaims is the payload of an admin browser session. `sub` is the OIDC subject.
type SessionClaims struct {
	Email  string   `json:"email,omitempty"`
	Name   string   `json:"name,omitempty"`
	Groups []string `json:"groups,omitempty"`
	// EmailUnverified: the IdP said email_verified=false, so user bindings on the
	// email never match
	EmailUnverified bool `json:"email_unverified,omitempty"`
	// BindingClaims are the identity's "<claim>=<value>" pairs for claim bindings
	BindingClaims []string `json:"binding_claims,omitempty"`
	jwt.RegisteredClaims
}

// CreateSession mints a session token for an authenticated admin identity. sessionID
// (the jti) names the server-side session row; "" only where no session store checks
// it (tests, development).
func (tm *TokenManager) CreateSession(id *Identity, sessionID string, ttl time.Duration) (string, time.Time, error) {
	if ttl <= 0 {
		ttl = DefaultSessionTTL
	}
	claims := SessionClaims{
		Email:            id.Email,
		Name:             id.Name,
		Groups:           id.Groups,
		EmailUnverified:  id.EmailUnverified,
		BindingClaims:    id.Claims,
		RegisteredClaims: registered(id.Subject, AudienceSession, ttl),
	}
	claims.ID = sessionID
	signed, err := tm.sign(claims)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to sign session: %w", err)
	}
	return signed, claims.ExpiresAt.Time, nil
}

// ValidateSession verifies a session token
func (tm *TokenManager) ValidateSession(tokenString string) (*SessionClaims, error) {
	claims := &SessionClaims{}
	if err := tm.parse(tokenString, AudienceSession, claims); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	return claims, nil
}

// LoginStateClaims protects the OIDC round trip: state must match the callback query,
// nonce must match the ID token, next is where to send the user afterwards.
type LoginStateClaims struct {
	State string `json:"state"`
	Nonce string `json:"nonce"`
	Next  string `json:"next,omitempty"`
	jwt.RegisteredClaims
}

// CreateLoginState signs the OIDC state cookie payload
func (tm *TokenManager) CreateLoginState(state, nonce, next string) (string, error) {
	claims := LoginStateClaims{
		State:            state,
		Nonce:            nonce,
		Next:             next,
		RegisteredClaims: registered("login", AudienceLoginState, loginStateTTL),
	}
	signed, err := tm.sign(claims)
	if err != nil {
		return "", fmt.Errorf("failed to sign login state: %w", err)
	}
	return signed, nil
}

// ValidateLoginState verifies the OIDC state cookie payload
func (tm *TokenManager) ValidateLoginState(tokenString string) (*LoginStateClaims, error) {
	claims := &LoginStateClaims{}
	if err := tm.parse(tokenString, AudienceLoginState, claims); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	return claims, nil
}

// CookieOptions controls the attributes of cookies set by the server
type CookieOptions struct {
	// Secure marks cookies as HTTPS-only; enable whenever PublicURL is https
	Secure bool
}

// SetSessionCookie writes the session cookie
func SetSessionCookie(w http.ResponseWriter, token string, expires time.Time, opts CookieOptions) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   opts.Secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearSessionCookie expires the session cookie
func ClearSessionCookie(w http.ResponseWriter, opts CookieOptions) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   opts.Secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// SetLoginStateCookie writes the short-lived OIDC state cookie
func SetLoginStateCookie(w http.ResponseWriter, token string, opts CookieOptions) {
	http.SetCookie(w, &http.Cookie{
		Name:     LoginStateCookieName,
		Value:    token,
		Path:     "/auth/",
		MaxAge:   int(loginStateTTL.Seconds()),
		HttpOnly: true,
		Secure:   opts.Secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearLoginStateCookie removes the OIDC state cookie
func ClearLoginStateCookie(w http.ResponseWriter, opts CookieOptions) {
	http.SetCookie(w, &http.Cookie{
		Name:     LoginStateCookieName,
		Value:    "",
		Path:     "/auth/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   opts.Secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// SessionStore validates server-side sessions (implemented by *db.DB)
type SessionStore interface {
	// TouchAdminSession reports whether the session exists, is not revoked and has
	// not expired, and records the activity
	TouchAdminSession(ctx context.Context, id string) (bool, error)
}

// SessionChecker caches positive answers of a SessionStore for a short TTL, so a
// session revoked on another server stops working within that window; Forget and
// Flush end it at once on this one
type SessionChecker struct {
	store SessionStore
	ttl   time.Duration

	mu    sync.Mutex
	valid map[string]time.Time // session id → checked at
}

// NewSessionChecker wraps store with a cache of ttl
func NewSessionChecker(store SessionStore, ttl time.Duration) *SessionChecker {
	return &SessionChecker{store: store, ttl: ttl, valid: map[string]time.Time{}}
}

// Active reports whether the session may still be used
func (c *SessionChecker) Active(ctx context.Context, id string) (bool, error) {
	if id == "" {
		return false, nil
	}
	c.mu.Lock()
	at, ok := c.valid[id]
	c.mu.Unlock()
	if ok && time.Since(at) < c.ttl {
		return true, nil
	}
	active, err := c.store.TouchAdminSession(ctx, id)
	if err != nil {
		return false, err
	}
	c.mu.Lock()
	if active {
		c.valid[id] = time.Now()
	} else {
		delete(c.valid, id)
	}
	c.mu.Unlock()
	return active, nil
}

// Forget drops one session from the cache (after revoking it here)
func (c *SessionChecker) Forget(id string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	delete(c.valid, id)
	c.mu.Unlock()
}

// Flush drops the whole cache (after revoking sessions by user)
func (c *SessionChecker) Flush() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.valid = map[string]time.Time{}
	c.mu.Unlock()
}
