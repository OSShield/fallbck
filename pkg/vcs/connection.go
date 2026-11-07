package vcs

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Connection is a VCS endpoint with the token FallBCK reads it with
// (vcs_connections). Token is in clear in memory only; the repository seals it with the server master key.
type Connection struct {
	ID uuid.UUID `json:"id"`
	// Name is the administrator's label; SafeName(Name) is the default group
	Name     string `json:"name"`
	Provider string `json:"provider"`
	// BaseURL is the GitLab instance (https://gitlab.com, https://git.example.com,
	// or with a relative URL root) or, for the git provider, the URL every
	// repository of its jobs must be below. Git sends the token to this URL only.
	BaseURL string `json:"base_url"`
	// Token is optional: without it, every job of the connection names an agent
	// credential profile (Spec.Profile)
	Token string `json:"-"`
	// TokenExpires is when the token stops working (the health page warns 30 days
	// before). Read from GitLab by the connection test, or entered by the
	// administrator.
	TokenExpires *time.Time `json:"token_expires,omitempty"`
	// CAPEM is an optional CA bundle for instances with a private CA
	CAPEM     string    `json:"ca_pem,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// To check for token presence without including the token in the API response
	HasToken bool `json:"has_token"`
	Jobs     int  `json:"jobs"`
	// Labels place the connection in access scopes (db.Labels; a plain map here
	// because pkg/db imports this package)
	Labels map[string]string `json:"labels"`
}

// ErrInvalidConnection wraps every validation failure
var ErrInvalidConnection = errors.New("invalid VCS connection")

func connErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidConnection, fmt.Sprintf(format, args...))
}

// Validate normalises the provider and URL and checks the token and CA bundle. The
// token is optional for both providers: jobs will try to use a agent credential profile
// (or for git connections & public repositories)
func (c *Connection) Validate() error {
	c.Name = strings.TrimSpace(c.Name)
	c.Provider = strings.ToLower(strings.TrimSpace(c.Provider))
	c.Token = strings.TrimSpace(c.Token)
	c.CAPEM = strings.TrimSpace(c.CAPEM)
	if c.Name == "" {
		return connErr("name is required")
	}
	switch c.Provider {
	case ProviderGitLab, ProviderGit, ProviderGitHub:
	default:
		return connErr("provider must be %s, %s or %s", ProviderGitLab, ProviderGitHub, ProviderGit)
	}
	base, err := NormalizeBaseURL(c.BaseURL)
	if err != nil {
		return connErr("base_url: %v", err)
	}
	c.BaseURL = base
	// The token travels in an HTTP header; anything but printable ASCII would let it
	// smuggle in another header
	if err := checkToken(c.Token); err != nil {
		return connErr("%v", err)
	}
	if c.CAPEM != "" {
		if _, err := CertPool(c.CAPEM); err != nil {
			return connErr("ca_pem: %v", err)
		}
	}
	return nil
}

// NormalizeBaseURL checks an https:// URL without credentials, query or fragment
// and returns it lower-cased (scheme and host) without a trailing slash
func NormalizeBaseURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("%q is not a URL", raw)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return "", errors.New("only https:// URLs are supported")
	}
	if u.User != nil {
		return "", errors.New("the URL must not carry credentials")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("the URL takes no query or fragment")
	}
	if hasDotSegment(u.Path) {
		return "", errors.New("the URL path must not contain . or .. segments")
	}
	u.Scheme, u.Host = "https", strings.ToLower(u.Host)
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return u.String(), nil
}

// UnderBaseURL reports whether repoURL is the base URL itself or below it (same
// host and port, path prefix on a segment boundary). Both must be normalised.
func UnderBaseURL(repoURL, baseURL string) bool {
	return repoURL == baseURL || strings.HasPrefix(repoURL, strings.TrimRight(baseURL, "/")+"/")
}

// IsGitLabCom reports whether the URL is gitlab.com, which cannot be enumerated as
// a whole
func IsGitLabCom(baseURL string) bool {
	u, err := url.Parse(baseURL)
	if err != nil {
		return false
	}
	h := strings.ToLower(u.Hostname())
	return h == "gitlab.com" || h == "www.gitlab.com"
}

// CertPool returns the system pool plus the PEM certificates (at least one)
func CertPool(caPEM string) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	rest, n := []byte(caPEM), 0
	for {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("certificate %d: %w", n+1, err)
		}
		pool.AddCert(cert)
		n++
	}
	if n == 0 {
		return nil, errors.New("no PEM CERTIFICATE block found")
	}
	return pool, nil
}

// Sanitize fills the derived fields
func (c *Connection) Sanitize() *Connection {
	c.HasToken = c.Token != ""
	return c
}

// Credentials is what an agent fetches for a run (GET /api/v1/agents/vcs-credentials)
type Credentials struct {
	Provider string `json:"provider"`
	BaseURL  string `json:"base_url"`
	Token    string `json:"token,omitempty"`
	CAPEM    string `json:"ca_pem,omitempty"`
}

// Credentials extracts the agent's view of the connection
func (c *Connection) Credentials() Credentials {
	return Credentials{Provider: c.Provider, BaseURL: c.BaseURL, Token: c.Token, CAPEM: c.CAPEM}
}

// HTTPClient is a client for the connection's API: the CA bundle on top of the
// system roots, proxies from the environment, and a timeout per request
func (c Credentials) HTTPClient(timeout time.Duration) (*http.Client, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if c.CAPEM != "" {
		pool, err := CertPool(c.CAPEM)
		if err != nil {
			return nil, err
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &http.Client{Transport: tr, Timeout: timeout}, nil
}

// ExpiresWithin reports whether the token expires before now+d (or has expired)
func (c *Connection) ExpiresWithin(d time.Duration) bool {
	return c.TokenExpires != nil && time.Until(*c.TokenExpires) < d
}

// ExpiryWarning is how long before the expiry the UI warns
const ExpiryWarning = 30 * 24 * time.Hour

// Expired / ExpiringSoon are the template-friendly forms of ExpiresWithin
func (c *Connection) Expired() bool      { return c.ExpiresWithin(0) }
func (c *Connection) ExpiringSoon() bool { return c.ExpiresWithin(ExpiryWarning) }
