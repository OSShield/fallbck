// Package github is the GitHub job spec, account model, REST client and manifest, shared
// by server and agent; it must not exec processes (git mirroring is in pkg/agent/github).
package github

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

// DefaultAPIURL is github.com's REST endpoint; GitHub Enterprise Server uses
// https://<host>/api/v3
const DefaultAPIURL = "https://api.github.com"

// Account is a GitHub token (github_accounts). Token is clear in memory only; the
// repository seals it with the server master key.
type Account struct {
	ID uuid.UUID `json:"id"`
	// Name is the administrator's label; SafeName(Name) is the default group prefix
	Name string `json:"name"`
	// APIURL is the REST endpoint (github.com or a GitHub Enterprise Server)
	APIURL string `json:"api_url"`
	Token  string `json:"-"`
	// TokenExpires is when the token stops working (the list warns 30 days before)
	TokenExpires *time.Time `json:"token_expires,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`

	// Derived, API-safe
	HasToken bool `json:"has_token"`
	// Jobs is the number of jobs referencing the account (filled by the list API)
	Jobs int `json:"jobs"`
	// Labels place the account in access scopes (db.Labels; a plain map here because
	// pkg/db imports this package)
	Labels map[string]string `json:"labels"`
}

// ErrInvalidAccount wraps every validation failure
var ErrInvalidAccount = errors.New("invalid GitHub account")

func accountErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidAccount, fmt.Sprintf(format, args...))
}

// Validate normalises the API URL and checks the required fields
func (a *Account) Validate() error {
	a.Name = strings.TrimSpace(a.Name)
	a.Token = strings.TrimSpace(a.Token)
	if a.Name == "" {
		return accountErr("name is required")
	}
	if a.Token == "" {
		return accountErr("a token is required")
	}
	api, err := NormalizeAPIURL(a.APIURL)
	if err != nil {
		return accountErr("%v", err)
	}
	a.APIURL = api
	return nil
}

// NormalizeAPIURL defaults to github.com and requires an absolute http(s) URL
func NormalizeAPIURL(raw string) (string, error) {
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	if raw == "" {
		return DefaultAPIURL, nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return "", fmt.Errorf("api_url must be an absolute https URL (https://api.github.com or https://<ghes host>/api/v3)")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("api_url must not carry credentials, a query or a fragment")
	}
	return raw, nil
}

// Sanitize fills the derived fields
func (a *Account) Sanitize() *Account {
	a.HasToken = a.Token != ""
	if a.APIURL == "" {
		a.APIURL = DefaultAPIURL
	}
	return a
}

// Credentials is what an agent fetches for a run (GET /api/v1/agents/github-credentials)
type Credentials struct {
	APIURL string `json:"api_url"`
	Token  string `json:"token"`
}

// Credentials extracts the agent's view of the account
func (a *Account) Credentials() Credentials {
	return Credentials{APIURL: a.APIURL, Token: a.Token}
}

// ExpiryWarning is how long before the expiry the UI warns
const ExpiryWarning = 30 * 24 * time.Hour

// Expired / ExpiringSoon drive the expiry badge
func (a *Account) Expired() bool { return a.TokenExpires != nil && time.Until(*a.TokenExpires) < 0 }
func (a *Account) ExpiringSoon() bool {
	return a.TokenExpires != nil && time.Until(*a.TokenExpires) < ExpiryWarning
}
