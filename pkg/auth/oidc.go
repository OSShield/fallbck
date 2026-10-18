package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/osshield/fallbck/pkg/config"
	"golang.org/x/oauth2"
)

// OIDCConfig is the OpenID Connect configuration (defined in pkg/config)
type OIDCConfig = config.OIDCConfig

// Identity is an authenticated admin resolved from an OIDC ID token
type Identity struct {
	Subject string
	Email   string
	Name    string
	Groups  []string
	// EmailUnverified is set when the IdP says email_verified=false; allowed_emails
	// never matches such an identity (a missing claim is taken as verified)
	EmailUnverified bool
	// Claims are the values of the configured binding claims as "<claim>=<value>",
	// which "claim" role bindings match
	Claims []string
}

// ErrNotAuthorized is returned when an authenticated identity is not permitted to administer
var ErrNotAuthorized = errors.New("identity is not authorized to access this server")

// OIDC performs the authorization-code login flow against the configured provider
type OIDC struct {
	cfg      OIDCConfig
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	oauth    oauth2.Config
}

// NewOIDC discovers the provider and prepares the OAuth2 client. redirectURL must be
// PublicURL + "/auth/callback" and registered with the provider.
func NewOIDC(ctx context.Context, cfg OIDCConfig, redirectURL string) (*OIDC, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery failed for %s: %w", cfg.Issuer, err)
	}

	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}
	if !slices.Contains(scopes, oidc.ScopeOpenID) {
		scopes = append([]string{oidc.ScopeOpenID}, scopes...)
	}
	if cfg.GroupsClaim == "" {
		cfg.GroupsClaim = "groups"
	}

	return &OIDC{
		cfg:      cfg,
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		oauth: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  redirectURL,
			Scopes:       scopes,
		},
	}, nil
}

// NewRandomToken returns a URL-safe random string for OIDC state and nonce values
func NewRandomToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// AuthCodeURL builds the provider login URL for a state/nonce pair
func (o *OIDC) AuthCodeURL(state, nonce string) string {
	return o.oauth.AuthCodeURL(state, oidc.Nonce(nonce))
}

// Exchange redeems the authorization code, verifies the ID token and its nonce, and
// applies the allow-lists. Returns ErrNotAuthorized when the identity is valid but not permitted.
func (o *OIDC) Exchange(ctx context.Context, code, nonce string) (*Identity, error) {
	token, err := o.oauth.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("OIDC code exchange failed: %w", err)
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, errors.New("OIDC provider did not return an id_token")
	}
	idToken, err := o.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("OIDC id_token verification failed: %w", err)
	}
	if idToken.Nonce != nonce {
		return nil, errors.New("OIDC nonce mismatch")
	}

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to decode id_token claims: %w", err)
	}

	id := &Identity{
		Subject: idToken.Subject,
		Email:   stringClaim(claims, "email"),
		Name:    stringClaim(claims, "name"),
		Groups:  stringSliceClaim(claims, o.cfg.GroupsClaim),
		Claims:  bindingClaimValues(claims, o.cfg.EffectiveBindingClaims()),
	}
	if id.Name == "" {
		id.Name = stringClaim(claims, "preferred_username")
	}
	if v, ok := claims["email_verified"].(bool); ok && !v {
		id.EmailUnverified = true
	}
	if err := o.Authorize(id); err != nil {
		return nil, err
	}
	return id, nil
}

// Authorize applies allowed_groups / allowed_emails to an identity
func (o *OIDC) Authorize(id *Identity) error {
	return AuthorizeIdentity(o.cfg, id)
}

// AuthorizeIdentity applies the allow-lists of cfg to id
func AuthorizeIdentity(cfg OIDCConfig, id *Identity) error {
	if len(cfg.AllowedEmails) == 0 && len(cfg.AllowedGroups) == 0 {
		return nil
	}
	for _, email := range cfg.AllowedEmails {
		if strings.EqualFold(email, id.Email) && id.Email != "" && !id.EmailUnverified {
			return nil
		}
	}
	for _, group := range cfg.AllowedGroups {
		if slices.Contains(id.Groups, group) {
			return nil
		}
	}
	return ErrNotAuthorized
}

func stringClaim(claims map[string]any, key string) string {
	if v, ok := claims[key].(string); ok {
		return v
	}
	return ""
}

// bindingClaimValues collects "<claim>=<value>" for each configured claim; a claim
// may be a single string or a list of strings
func bindingClaimValues(claims map[string]any, names []string) []string {
	var out []string
	for _, name := range names {
		if v, ok := claims[name].(string); ok && v != "" {
			out = append(out, name+"="+v)
		}
		for _, v := range stringSliceClaim(claims, name) {
			out = append(out, name+"="+v)
		}
	}
	return out
}

func stringSliceClaim(claims map[string]any, key string) []string {
	raw, ok := claims[key].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
