package vcs

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// GitLab token scopes the backup needs: read_api lists groups and projects,
// read_repository fetches over HTTPS. api and write_repository also cover them but
// grant more than a backup should hold.
const (
	ScopeReadAPI        = "read_api"
	ScopeReadRepository = "read_repository"
)

// broaderScopes are the scopes that work but grant write or administrative access
var broaderScopes = []string{"api", "write_repository", "sudo", "admin_mode", "write_registry"}

// Instance is what TestConnection learns about a GitLab instance and its token
type Instance struct {
	Version  string `json:"version"`
	Username string `json:"username"`
	// IsAdmin: the token's user is an instance administrator. Without it a job with
	// no groups only sees the projects the user is a member of.
	IsAdmin      bool       `json:"is_admin"`
	TokenName    string     `json:"token_name,omitempty"`
	Scopes       []string   `json:"scopes,omitempty"`
	TokenExpires *time.Time `json:"token_expires,omitempty"`
	Warnings     []string   `json:"warnings,omitempty"`
}

// TestConnection checks a GitLab connection: the token is accepted (/version), whose
// it is (/user), and its scopes and expiry (/personal_access_tokens/self, which
// also answers for group and project access tokens). The error names the step that
// failed so an administrator can tell a wrong token from a blocked egress or a
// missing scope; problems that do not stop a backup come back as warnings.
func TestConnection(ctx context.Context, c Credentials, client *http.Client) (*Instance, error) {
	if c.Provider != ProviderGitLab {
		return nil, fmt.Errorf("connection test is only available for GitLab connections")
	}
	inst, err := Identify(ctx, c, client)
	if err != nil {
		return nil, err
	}

	var tok struct {
		Name      string   `json:"name"`
		Scopes    []string `json:"scopes"`
		ExpiresAt string   `json:"expires_at"`
		Active    bool     `json:"active"`
	}
	switch err := gitlabGet(ctx, client, c, "/personal_access_tokens/self", &tok); {
	case err == nil:
		inst.TokenName, inst.Scopes = tok.Name, tok.Scopes
		if tok.ExpiresAt != "" {
			if t, err := time.Parse(time.DateOnly, tok.ExpiresAt); err == nil {
				inst.TokenExpires = &t
			}
		}
		if err := checkScopes(tok.Scopes); err != nil {
			return inst, err
		}
		if broad := broaderThanNeeded(tok.Scopes); len(broad) > 0 {
			inst.Warnings = append(inst.Warnings, fmt.Sprintf("the token has broader scopes than a backup needs (%s); %s and %s are enough",
				strings.Join(broad, ", "), ScopeReadAPI, ScopeReadRepository))
		}
	case isStatus(err, http.StatusNotFound):
		inst.Warnings = append(inst.Warnings, "GitLab did not report the token's scopes and expiry (older than 15.5?); check that it has read_api and read_repository")
	default:
		return inst, err
	}
	if inst.TokenExpires != nil && time.Until(*inst.TokenExpires) < ExpiryWarning {
		inst.Warnings = append(inst.Warnings, "the token expires "+inst.TokenExpires.Format(time.DateOnly))
	}
	if !inst.IsAdmin && !IsGitLabCom(c.BaseURL) {
		inst.Warnings = append(inst.Warnings, "the token's user is not an administrator: jobs without groups only see the projects "+inst.Username+" is a member of")
	}
	return inst, nil
}

// Identify reads the GitLab version (/version) and the token's user (/user)
func Identify(ctx context.Context, c Credentials, client *http.Client) (*Instance, error) {
	inst := &Instance{}
	var version struct {
		Version string `json:"version"`
	}
	if err := gitlabGet(ctx, client, c, "/version", &version); err != nil {
		return nil, err
	}
	inst.Version = version.Version

	var user struct {
		Username string `json:"username"`
		IsAdmin  bool   `json:"is_admin"`
	}
	if err := gitlabGet(ctx, client, c, "/user", &user); err != nil {
		return nil, err
	}
	inst.Username, inst.IsAdmin = user.Username, user.IsAdmin
	return inst, nil
}

// checkScopes fails when the token can list projects or fetch repositories but not
// both
func checkScopes(scopes []string) error {
	has := func(s ...string) bool {
		return slices.ContainsFunc(scopes, func(x string) bool { return slices.Contains(s, x) })
	}
	var missing []string
	if !has(ScopeReadAPI, "api") {
		missing = append(missing, ScopeReadAPI)
	}
	if !has(ScopeReadRepository, "write_repository", "api") {
		missing = append(missing, ScopeReadRepository)
	}
	if len(missing) > 0 {
		return fmt.Errorf("the token lacks the %s scope (it has %s)", strings.Join(missing, " and "), strings.Join(scopes, ", "))
	}
	return nil
}

func broaderThanNeeded(scopes []string) []string {
	var out []string
	for _, s := range scopes {
		if slices.Contains(broaderScopes, s) {
			out = append(out, s)
		}
	}
	return out
}

// statusError is a non-2xx answer from GitLab
type statusError struct {
	path   string
	status int
	text   string
}

func (e *statusError) Error() string {
	switch e.status {
	case http.StatusUnauthorized:
		return fmt.Sprintf("GitLab rejected the token on %s (expired, revoked or mistyped)", e.path)
	case http.StatusForbidden:
		return fmt.Sprintf("GitLab refused %s with the token (missing scope, or the user is blocked): %s", e.path, e.text)
	}
	return fmt.Sprintf("GitLab answered %d to %s: %s", e.status, e.path, e.text)
}

func isStatus(err error, status int) bool {
	se, ok := err.(*statusError)
	return ok && se.status == status
}

// gitlabGet reads one /api/v4 resource into out
func gitlabGet(ctx context.Context, client *http.Client, c Credentials, path string, out any) error {
	body, _, err := gitlabDo(ctx, client, c, path, nil, 1<<20)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("unexpected answer to %s (is %s a GitLab instance?)", path, c.BaseURL)
	}
	return nil
}

// gitlabDo sends one GET to /api/v4 below the connection URL and returns the body
// (at most limit bytes) and the response headers. A non-200 answer is a
// *statusError.
func gitlabDo(ctx context.Context, client *http.Client, c Credentials, path string, query url.Values, limit int64) ([]byte, http.Header, error) {
	u := strings.TrimRight(c.BaseURL, "/") + "/api/v4" + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("PRIVATE-TOKEN", c.Token)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("request to %s failed (the caller needs outbound HTTPS to it; check the URL and CA bundle): %w", c.BaseURL, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if resp.StatusCode != http.StatusOK {
		return nil, nil, &statusError{path: path, status: resp.StatusCode, text: gitlabErrorText(body)}
	}
	if err != nil {
		return nil, nil, fmt.Errorf("reading the answer to %s: %w", path, err)
	}
	return body, resp.Header, nil
}

// gitlabErrorText extracts message / error from a GitLab error body
func gitlabErrorText(body []byte) string {
	var e struct {
		Message any    `json:"message"`
		Error   string `json:"error"`
	}
	if json.Unmarshal(body, &e) == nil {
		if e.Message != nil {
			return fmt.Sprint(e.Message)
		}
		if e.Error != "" {
			return e.Error
		}
	}
	s := strings.TrimSpace(string(body))
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}
