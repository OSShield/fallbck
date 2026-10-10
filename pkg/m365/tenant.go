package m365

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Microsoft global cloud endpoints (the only cloud supported: the mailbox export
// API exists nowhere else)
const (
	AuthorityURL = "https://login.microsoftonline.com"
	GraphURL     = "https://graph.microsoft.com"
	// GraphScope is the client-credentials scope for application permissions
	GraphScope = GraphURL + "/.default"
)

// App authentication methods
const (
	AuthSecret      = "secret"
	AuthCertificate = "certificate"
)

// Tenant is a Microsoft 365 tenant with the Entra app registration FallBCK uses to
// read it (m365_tenants). Secret and KeyPEM are in clear in memory only; the
// repository seals them with the server master key.
type Tenant struct {
	ID uuid.UUID `json:"id"`
	// Name is the administrator's label; SafeName(Name) is the default group prefix
	Name string `json:"name"`
	// TenantID is the directory (tenant) id GUID or a verified domain
	TenantID string `json:"tenant_id"`
	// ClientID is the application (client) id of the app registration
	ClientID   string `json:"client_id"`
	AuthMethod string `json:"auth_method"`
	Secret     string `json:"-"`
	// CertificatePEM is the public certificate uploaded to the app registration;
	// KeyPEM its private key (RSA)
	CertificatePEM string `json:"-"`
	KeyPEM         string `json:"-"`
	// SecretExpires is when the secret or certificate stops working (the health page
	// warns 30 days before). Entered by the administrator for secrets, taken from the
	// certificate otherwise.
	SecretExpires *time.Time `json:"secret_expires,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`

	// Derived, API-safe
	HasSecret      bool `json:"has_secret"`
	HasCertificate bool `json:"has_certificate"`
	// Jobs is the number of jobs referencing the tenant (filled by the list API)
	Jobs int `json:"jobs"`
}

// ErrInvalidTenant wraps every validation failure
var ErrInvalidTenant = errors.New("invalid Microsoft 365 tenant")

func tenantErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidTenant, fmt.Sprintf(format, args...))
}

var (
	guidRe   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	domainRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
)

// Validate checks the identifiers and the credential of the chosen method. With the
// certificate method the PEM pair is parsed, the key must be RSA and match the
// certificate, and SecretExpires is set from the certificate.
func (t *Tenant) Validate() error {
	t.Name = strings.TrimSpace(t.Name)
	t.TenantID = strings.ToLower(strings.TrimSpace(t.TenantID))
	t.ClientID = strings.ToLower(strings.TrimSpace(t.ClientID))
	t.AuthMethod = strings.ToLower(strings.TrimSpace(t.AuthMethod))
	if t.Name == "" {
		return tenantErr("name is required")
	}
	if !guidRe.MatchString(t.TenantID) && !domainRe.MatchString(t.TenantID) {
		return tenantErr("tenant_id must be the directory id (GUID) or a verified domain")
	}
	if !guidRe.MatchString(t.ClientID) {
		return tenantErr("client_id must be the application (client) id GUID")
	}
	switch t.AuthMethod {
	case "", AuthSecret:
		t.AuthMethod = AuthSecret
		if strings.TrimSpace(t.Secret) == "" {
			return tenantErr("a client secret is required")
		}
		t.Secret = strings.TrimSpace(t.Secret)
	case AuthCertificate:
		cert, _, err := ParseCertificate(t.CertificatePEM, t.KeyPEM)
		if err != nil {
			return tenantErr("%v", err)
		}
		exp := cert.NotAfter
		t.SecretExpires = &exp
		t.Secret = ""
	default:
		return tenantErr("auth_method must be %s or %s", AuthSecret, AuthCertificate)
	}
	return nil
}

// ParseCertificate parses the PEM certificate and its RSA private key (PKCS#1 or
// PKCS#8) and checks they belong together
func ParseCertificate(certPEM, keyPEM string) (*x509.Certificate, *rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, errors.New("certificate must be a PEM CERTIFICATE block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("certificate: %w", err)
	}
	kb, _ := pem.Decode([]byte(keyPEM))
	if kb == nil {
		return nil, nil, errors.New("private key must be a PEM block")
	}
	var key *rsa.PrivateKey
	switch kb.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(kb.Bytes)
	case "PRIVATE KEY":
		var k any
		k, err = x509.ParsePKCS8PrivateKey(kb.Bytes)
		if err == nil {
			var ok bool
			if key, ok = k.(*rsa.PrivateKey); !ok {
				err = errors.New("not an RSA key (Entra client assertions are signed with RS256)")
			}
		}
	default:
		err = fmt.Errorf("unsupported key block %q (encrypted keys are not supported)", kb.Type)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("private key: %w", err)
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return nil, nil, errors.New("private key does not match the certificate")
	}
	if time.Now().After(cert.NotAfter) {
		return nil, nil, fmt.Errorf("certificate expired %s", cert.NotAfter.Format(time.RFC3339))
	}
	return cert, key, nil
}

// Sanitize fills the derived fields
func (t *Tenant) Sanitize() *Tenant {
	t.HasSecret = t.Secret != ""
	t.HasCertificate = t.CertificatePEM != "" && t.KeyPEM != ""
	if t.AuthMethod == "" {
		t.AuthMethod = AuthSecret
	}
	return t
}

// Credentials is what an agent fetches for a run (GET /api/v1/agents/m365-credentials)
type Credentials struct {
	TenantID       string `json:"tenant_id"`
	ClientID       string `json:"client_id"`
	AuthMethod     string `json:"auth_method"`
	Secret         string `json:"secret,omitempty"`
	CertificatePEM string `json:"certificate_pem,omitempty"`
	KeyPEM         string `json:"key_pem,omitempty"`
}

// Credentials extracts the agent's view of the tenant
func (t *Tenant) Credentials() Credentials {
	return Credentials{TenantID: t.TenantID, ClientID: t.ClientID, AuthMethod: t.AuthMethod,
		Secret: t.Secret, CertificatePEM: t.CertificatePEM, KeyPEM: t.KeyPEM}
}

// ExpiresWithin reports whether the credential expires before now+d (or has expired)
func (t *Tenant) ExpiresWithin(d time.Duration) bool {
	return t.SecretExpires != nil && time.Until(*t.SecretExpires) < d
}

// ExpiryWarning is how long before the expiry the UI warns
const ExpiryWarning = 30 * 24 * time.Hour

// Expired / ExpiringSoon are the template-friendly forms of ExpiresWithin
func (t *Tenant) Expired() bool      { return t.ExpiresWithin(0) }
func (t *Tenant) ExpiringSoon() bool { return t.ExpiresWithin(ExpiryWarning) }
