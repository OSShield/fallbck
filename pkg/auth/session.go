package auth

import (
	"fmt"
	"net/http"
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
	jwt.RegisteredClaims
}

// CreateSession mints a session token for an authenticated admin identity
func (tm *TokenManager) CreateSession(id *Identity, ttl time.Duration) (string, time.Time, error) {
	if ttl <= 0 {
		ttl = DefaultSessionTTL
	}
	claims := SessionClaims{
		Email:            id.Email,
		Name:             id.Name,
		Groups:           id.Groups,
		EmailUnverified:  id.EmailUnverified,
		RegisteredClaims: registered(id.Subject, AudienceSession, ttl),
	}
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
