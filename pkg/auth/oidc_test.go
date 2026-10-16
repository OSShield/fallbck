package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// fakeIssuer is a minimal OIDC provider: discovery, JWKS and a token endpoint that
// returns an RS256 id_token for whatever code it receives.
type fakeIssuer struct {
	srv      *httptest.Server
	key      *rsa.PrivateKey
	clientID string
	claims   map[string]any // extra claims on the id_token
	lastCode string
	nonce    string
}

func newFakeIssuer(t *testing.T, clientID string) *fakeIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIssuer{key: key, clientID: clientID, claims: map[string]any{}}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                f.srv.URL,
			"authorization_endpoint":                f.srv.URL + "/authorize",
			"token_endpoint":                        f.srv.URL + "/token",
			"jwks_uri":                              f.srv.URL + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "test",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.lastCode = r.Form.Get("code")
		now := time.Now()
		claims := jwt.MapClaims{
			"iss": f.srv.URL, "sub": "user-123", "aud": clientID,
			"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "nonce": f.nonce,
		}
		for k, v := range f.claims {
			claims[k] = v
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = "test"
		signed, err := tok.SignedString(key)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at", "token_type": "Bearer", "expires_in": 3600, "id_token": signed,
		})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func TestOIDCLoginFlow(t *testing.T) {
	issuer := newFakeIssuer(t, "fallbck")
	issuer.claims["email"] = "alice@example.com"
	issuer.claims["name"] = "Alice"
	issuer.claims["groups"] = []string{"backup-admins", "devs"}

	cfg := OIDCConfig{Issuer: issuer.srv.URL, ClientID: "fallbck", ClientSecret: "s3cret", AllowedGroups: []string{"backup-admins"}}
	o, err := NewOIDC(context.Background(), cfg, "https://backup.example.com/auth/callback")
	if err != nil {
		t.Fatalf("NewOIDC: %v", err)
	}

	state, _ := NewRandomToken()
	nonce, _ := NewRandomToken()
	issuer.nonce = nonce

	loginURL, err := url.Parse(o.AuthCodeURL(state, nonce))
	if err != nil {
		t.Fatal(err)
	}
	q := loginURL.Query()
	if q.Get("state") != state || q.Get("nonce") != nonce || q.Get("client_id") != "fallbck" || q.Get("redirect_uri") != "https://backup.example.com/auth/callback" {
		t.Errorf("unexpected auth URL %s", loginURL)
	}
	if q.Get("scope") != "openid profile email" {
		t.Errorf("unexpected default scopes %q", q.Get("scope"))
	}

	id, err := o.Exchange(context.Background(), "code-abc", nonce)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if issuer.lastCode != "code-abc" {
		t.Errorf("token endpoint received code %q", issuer.lastCode)
	}
	if id.Subject != "user-123" || id.Email != "alice@example.com" || id.Name != "Alice" || len(id.Groups) != 2 {
		t.Errorf("unexpected identity %+v", id)
	}

	// nonce mismatch is rejected
	if _, err := o.Exchange(context.Background(), "code-abc", "other-nonce"); err == nil {
		t.Error("expected nonce mismatch error")
	}

	// group allow-list is enforced
	issuer.claims["groups"] = []string{"devs"}
	if _, err := o.Exchange(context.Background(), "code-abc", nonce); !errors.Is(err, ErrNotAuthorized) {
		t.Errorf("expected ErrNotAuthorized, got %v", err)
	}
}

func TestAuthorizeIdentity(t *testing.T) {
	id := &Identity{Email: "Bob@Example.com", Groups: []string{"ops"}}
	if err := AuthorizeIdentity(OIDCConfig{}, id); err != nil {
		t.Errorf("no allow-lists should admit everyone: %v", err)
	}
	if err := AuthorizeIdentity(OIDCConfig{AllowedEmails: []string{"bob@example.com"}}, id); err != nil {
		t.Errorf("email match should be case-insensitive: %v", err)
	}
	if err := AuthorizeIdentity(OIDCConfig{AllowedGroups: []string{"ops"}}, id); err != nil {
		t.Errorf("group match: %v", err)
	}
	if err := AuthorizeIdentity(OIDCConfig{AllowedGroups: []string{"admins"}, AllowedEmails: []string{"x@y"}}, id); !errors.Is(err, ErrNotAuthorized) {
		t.Errorf("expected ErrNotAuthorized, got %v", err)
	}
	if err := AuthorizeIdentity(OIDCConfig{AllowedEmails: []string{"bob@example.com"}}, &Identity{Email: "bob@example.com", EmailUnverified: true}); !errors.Is(err, ErrNotAuthorized) {
		t.Errorf("unverified email must not match allowed_emails: %v", err)
	}
	if err := AuthorizeIdentity(OIDCConfig{AllowedEmails: []string{""}}, &Identity{}); !errors.Is(err, ErrNotAuthorized) {
		t.Error("empty email must never match an allow-list entry")
	}
}

func TestLoginStateRoundTrip(t *testing.T) {
	tm := NewTokenManager("test-secret-key-must-be-very-long-123456")
	tok, err := tm.CreateLoginState("st", "nn", "/jobs")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := tm.ValidateLoginState(tok)
	if err != nil {
		t.Fatal(err)
	}
	if claims.State != "st" || claims.Nonce != "nn" || claims.Next != "/jobs" {
		t.Errorf("unexpected claims %+v", claims)
	}
	if _, err := tm.ValidateSession(tok); err == nil {
		t.Error("login state must not validate as a session")
	}
}
