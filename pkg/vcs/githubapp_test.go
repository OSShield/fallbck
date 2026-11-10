package vcs

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testAppKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
}

// verifyAppJWT checks an App JWT's signature and claims as GitHub would
func verifyAppJWT(t *testing.T, jwt string, pub *rsa.PublicKey, appID string) {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", jwt)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
		t.Fatalf("JWT signature: %v", err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var c struct {
		Iat, Exp int64
		Iss      string
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	if c.Iss != appID || c.Iat > now || c.Exp <= now || c.Exp-c.Iat > 600 {
		t.Errorf("JWT claims %+v (now %d)", c, now)
	}
}

func TestGitHubAppToken(t *testing.T) {
	key, pemKey := testAppKey(t)
	var body map[string]map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		verifyAppJWT(t, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), &key.PublicKey, "42")
		if r.Method != http.MethodPost || r.URL.Path != "/app/installations/7/access_tokens" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		_, _ = w.Write([]byte(`{"token":"ghs_minted","expires_at":"2099-01-01T00:00:00Z"}`))
	}))
	defer srv.Close()
	app := GitHubApp{AppID: 42, InstallationID: 7, PrivateKey: pemKey}
	token, exp, err := app.InstallationToken(context.Background(), srv.URL, srv.Client(), GitHubAppPermissions(&Spec{Workloads: Workloads{Metadata: true}}))
	if err != nil || token != "ghs_minted" || exp.Year() != 2099 {
		t.Fatalf("token %q %v %v", token, exp, err)
	}
	if p := body["permissions"]; p["contents"] != "read" || p["issues"] != "read" || p["pull_requests"] != "read" || len(p) != 4 {
		t.Errorf("the token must be limited to what the job reads: %v", body)
	}
	if p := GitHubAppPermissions(&Spec{}); p["issues"] != "" || len(p) != 2 {
		t.Errorf("without metadata only contents and metadata: %v", p)
	}

	// A wrong installation reads as such, not as a generic failure
	app.InstallationID = 8
	if _, _, err := app.InstallationToken(context.Background(), srv.URL, srv.Client(), nil); err == nil || !strings.Contains(err.Error(), "installation id") {
		t.Errorf("unknown installation: %v", err)
	}
}

func TestParseGitHubAppKey(t *testing.T) {
	key, pkcs1 := testAppKey(t)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	pkcs8 := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	for name, k := range map[string]string{"pkcs1": pkcs1, "pkcs8": pkcs8} {
		if _, err := ParseGitHubAppKey(k); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, bad := range []string{"", "not a key", "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----"} {
		if _, err := ParseGitHubAppKey(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestRefreshingToken(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	fetches := 0
	r := &RefreshingToken{Now: func() time.Time { return now }, Fetch: func(context.Context) (string, time.Time, error) {
		fetches++
		return "t" + string(rune('0'+fetches)), now.Add(time.Hour), nil
	}}
	r.Seed("t0", now.Add(time.Hour))
	if tok, _ := r.Token(context.Background()); tok != "t0" || fetches != 0 {
		t.Fatalf("a fresh seed must be used as is: %q, %d fetches", tok, fetches)
	}
	now = now.Add(55 * time.Minute) // inside the renewal margin
	if tok, _ := r.Token(context.Background()); tok != "t1" || fetches != 1 {
		t.Fatalf("not renewed before expiry: %q, %d fetches", tok, fetches)
	}
	if tok, _ := r.Token(context.Background()); tok != "t1" || fetches != 1 {
		t.Errorf("renewed again although the new token is fresh: %q, %d fetches", tok, fetches)
	}
}

func TestGitHubAppConnectionValidate(t *testing.T) {
	_, pemKey := testAppKey(t)
	exp := time.Now().Add(time.Hour)
	c := &Connection{Name: "gh", Provider: ProviderGitHub, BaseURL: "https://github.com", AuthType: "GitHub_App",
		AppID: 1, InstallationID: 2, AppKey: pemKey, TokenExpires: &exp}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.AuthType != AuthGitHubApp || c.TokenExpires != nil || !c.Sanitize().HasToken {
		t.Errorf("not normalised: %+v", c)
	}
	bad := map[string]Connection{
		"gitlab":     {Name: "gl", Provider: ProviderGitLab, BaseURL: "https://gitlab.com", AuthType: AuthGitHubApp, AppID: 1, InstallationID: 2, AppKey: pemKey},
		"with token": {Name: "gh", Provider: ProviderGitHub, BaseURL: "https://github.com", AuthType: AuthGitHubApp, AppID: 1, InstallationID: 2, AppKey: pemKey, Token: "ghp_x"},
		"no ids":     {Name: "gh", Provider: ProviderGitHub, BaseURL: "https://github.com", AuthType: AuthGitHubApp, AppKey: pemKey},
		"bad key":    {Name: "gh", Provider: ProviderGitHub, BaseURL: "https://github.com", AuthType: AuthGitHubApp, AppID: 1, InstallationID: 2, AppKey: "nope"},
		"bad type":   {Name: "gh", Provider: ProviderGitHub, BaseURL: "https://github.com", AuthType: "oauth"},
	}
	for name, c := range bad {
		if err := c.Validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// Switching back to a token drops the App and its key
	tok := &Connection{Name: "gh", Provider: ProviderGitHub, BaseURL: "https://github.com", Token: "ghp_x", AppID: 1, InstallationID: 2, AppKey: pemKey}
	if err := tok.Validate(); err != nil || tok.AuthType != AuthToken || tok.AppKey != "" || tok.AppID != 0 {
		t.Errorf("token connection keeps App fields: %+v %v", tok, err)
	}

	// Stars and gists belong to a user
	for _, s := range []*Spec{{ConnectionID: c.ID, Starred: true}, {ConnectionID: c.ID, Groups: []string{"acme"}, Gists: &Gists{IDs: []string{"1234567"}}}} {
		if err := s.ValidateFor(c); err == nil || !strings.Contains(err.Error(), "GitHub App") {
			t.Errorf("%+v on an App connection: %v", s, err)
		}
	}
	if err := (&Spec{ConnectionID: c.ID, Groups: []string{"acme"}}).ValidateFor(c); err != nil {
		t.Errorf("owners on an App connection: %v", err)
	}
}

func TestGitHubAppProfileValidate(t *testing.T) {
	_, pemKey := testAppKey(t)
	p := &Profile{URL: "https://github.com/", AuthType: AuthGitHubApp, AppID: 1, InstallationID: 2, AppKey: pemKey}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if app, err := p.App(); err != nil || app.AppID != 1 || app.InstallationID != 2 {
		t.Errorf("App(): %+v %v", app, err)
	}
	bad := map[string]Profile{
		"token too":    {URL: "https://github.com", AuthType: AuthGitHubApp, AppID: 1, InstallationID: 2, AppKey: pemKey, Token: "x"},
		"username":     {URL: "https://github.com", AuthType: AuthGitHubApp, AppID: 1, InstallationID: 2, AppKey: pemKey, Username: "u"},
		"two keys":     {URL: "https://github.com", AuthType: AuthGitHubApp, AppID: 1, InstallationID: 2, AppKey: pemKey, AppKeyFile: "/k.pem"},
		"no key":       {URL: "https://github.com", AuthType: AuthGitHubApp, AppID: 1, InstallationID: 2},
		"app on token": {URL: "https://github.com", Token: "x", AppID: 1},
	}
	for name, p := range bad {
		if err := p.Validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
