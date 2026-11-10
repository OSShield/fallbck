package vcs

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Authentication types of a connection or agent profile
const (
	// AuthToken is a static token (personal, group or project access token)
	AuthToken = "token"
	// AuthGitHubApp is a GitHub App installation: short-lived tokens minted with the
	// App's private key, not tied to a user
	AuthGitHubApp = "github_app"
	// GitHubAppUsername is the basic auth user name for installation tokens
	GitHubAppUsername = "x-access-token"
)

// normalizeAuthType returns the stored form ("" = token)
func normalizeAuthType(t string) (string, error) {
	switch t = strings.ToLower(strings.TrimSpace(t)); t {
	case "", AuthToken:
		return AuthToken, nil
	case AuthGitHubApp:
		return t, nil
	}
	return "", fmt.Errorf("auth_type must be %s or %s", AuthToken, AuthGitHubApp)
}

// TokenSource returns a token that is valid now
type TokenSource func(ctx context.Context) (string, error)

// GitHubApp identifies a GitHub App installation and holds the App's private key
type GitHubApp struct {
	AppID          int64
	InstallationID int64
	// PrivateKey is the PEM key GitHub generated for the App (PKCS#1 or PKCS#8)
	PrivateKey string
}

// ParseGitHubAppKey parses an App private key
func ParseGitHubAppKey(pemKey string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(pemKey)))
	if block == nil {
		return nil, errors.New("the private key is not PEM (-----BEGIN RSA PRIVATE KEY-----)")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("the private key is neither a PKCS#1 nor a PKCS#8 RSA key")
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("the private key is not an RSA key")
	}
	return rk, nil
}

// validate checks the ids and the key
func (a GitHubApp) validate() error {
	if a.AppID <= 0 || a.InstallationID <= 0 {
		return errors.New("a GitHub App needs its app id and installation id")
	}
	_, err := ParseGitHubAppKey(a.PrivateKey)
	return err
}

// jwt is the App's own credential: RS256, issued a minute back for clock drift and
// valid for 9 minutes (GitHub allows 10)
func (a GitHubApp) jwt(now time.Time) (string, error) {
	key, err := ParseGitHubAppKey(a.PrivateKey)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	header := enc.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, _ := json.Marshal(map[string]any{
		"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(9 * time.Minute).Unix(), "iss": strconv.FormatInt(a.AppID, 10),
	})
	signed := header + "." + enc.EncodeToString(claims)
	sum := sha256.Sum256([]byte(signed))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signed + "." + enc.EncodeToString(sig), nil
}

// appRequest sends one request authenticated as the App (JWT)
func (a GitHubApp) appRequest(ctx context.Context, client *http.Client, method, url string, body any, out any) error {
	jwt, err := a.jwt(time.Now())
	if err != nil {
		return err
	}
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "fallbck")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request to GitHub failed (this host needs outbound HTTPS to it): %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return fmt.Errorf("GitHub rejected the App's credentials (%s): check the app id and private key, and this host's clock", githubErrorText(data))
	case resp.StatusCode == http.StatusNotFound:
		return fmt.Errorf("GitHub does not know installation %d of app %d: check the installation id", a.InstallationID, a.AppID)
	case resp.StatusCode/100 != 2:
		return fmt.Errorf("GitHub answered %d: %s", resp.StatusCode, githubErrorText(data))
	}
	if out != nil && json.Unmarshal(data, out) != nil {
		return errors.New("unexpected answer from the GitHub API")
	}
	return nil
}

// InstallationToken mints a token for the installation (valid for an hour), limited
// to perms when set
func (a GitHubApp) InstallationToken(ctx context.Context, apiURL string, client *http.Client, perms map[string]string) (string, time.Time, error) {
	var body any
	if len(perms) > 0 {
		body = map[string]any{"permissions": perms}
	}
	var out struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	url := strings.TrimRight(apiURL, "/") + "/app/installations/" + strconv.FormatInt(a.InstallationID, 10) + "/access_tokens"
	if err := a.appRequest(ctx, client, http.MethodPost, url, body, &out); err != nil {
		return "", time.Time{}, err
	}
	if out.Token == "" || checkToken(out.Token) != nil {
		return "", time.Time{}, errors.New("GitHub returned no usable installation token")
	}
	if out.ExpiresAt.IsZero() {
		out.ExpiresAt = time.Now().Add(time.Hour)
	}
	return out.Token, out.ExpiresAt.UTC(), nil
}

// GitHubAppPermissions are the read permissions a job's installation token is
// limited to; the App itself may have more
func GitHubAppPermissions(s *Spec) map[string]string {
	p := map[string]string{"contents": "read", "metadata": "read"}
	if s != nil && s.Workloads.Metadata {
		p["issues"], p["pull_requests"] = "read", "read"
	}
	return p
}

// TestGitHubApp checks an App connection: the App (GET /app with its JWT), a token for
// the installation, and how many repositories the installation can read
func TestGitHubApp(ctx context.Context, baseURL string, app GitHubApp, client *http.Client) (*Instance, error) {
	api := GitHubAPIURL(baseURL)
	var info struct {
		Slug string `json:"slug"`
		Name string `json:"name"`
	}
	if err := app.appRequest(ctx, client, http.MethodGet, api+"/app", nil, &info); err != nil {
		return nil, err
	}
	token, _, err := app.InstallationToken(ctx, api, client, nil)
	if err != nil {
		return nil, err
	}
	var repos struct {
		TotalCount int `json:"total_count"`
	}
	gh := &GitHubClient{APIURL: api, Token: token, HTTP: client}
	if _, err := gh.getJSON(ctx, "/installation/repositories?per_page=1", &repos); err != nil {
		return nil, fmt.Errorf("listing the installation's repositories: %w", err)
	}
	inst := &Instance{Username: "app " + info.Slug}
	if repos.TotalCount == 0 {
		inst.Warnings = append(inst.Warnings, "the installation can read no repositories: add them in the App's installation settings")
	}
	return inst, nil
}

// RefreshingToken hands out a short-lived token and fetches the next one shortly
// before it expires; safe for concurrent use
type RefreshingToken struct {
	// Fetch returns a new token and its expiry
	Fetch func(ctx context.Context) (string, time.Time, error)
	// Now is replaced in tests
	Now func() time.Time

	mu      sync.Mutex
	token   string
	expires time.Time
}

// tokenRefreshMargin renews a token this long before it expires, so a git process
// started with it has time to finish
const tokenRefreshMargin = 10 * time.Minute

// Seed sets the current token (the one the run started with)
func (r *RefreshingToken) Seed(token string, expires time.Time) {
	r.mu.Lock()
	r.token, r.expires = token, expires
	r.mu.Unlock()
}

// Token returns the current token, fetching a new one when it is about to expire
func (r *RefreshingToken) Token(ctx context.Context) (string, error) {
	now := time.Now
	if r.Now != nil {
		now = r.Now
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.token != "" && now().Add(tokenRefreshMargin).Before(r.expires) {
		return r.token, nil
	}
	token, expires, err := r.Fetch(ctx)
	if err != nil {
		return "", fmt.Errorf("renewing the GitHub App token: %w", err)
	}
	r.token, r.expires = token, expires
	return token, nil
}
