package m365

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// Profile is an agent credential profile for Microsoft 365 jobs: the app registration's
// secret or certificate, kept only in the agent's encrypted store. A job names it
// (Spec.Profile); the agent uses it only when its tenant and client ids equal the
// job's tenant, so a changed tenant can't make the agent use it for another one.
type Profile struct {
	TenantID   string `json:"tenant_id"`
	ClientID   string `json:"client_id"`
	AuthMethod string `json:"auth_method"`
	// Secret and KeyPEM are in clear in memory only; the credential store encrypts
	// them and they are never reported
	Secret         string `json:"-"`
	CertificatePEM string `json:"certificate_pem,omitempty"`
	KeyPEM         string `json:"-"`
	// SecretFile, CertFile and KeyFile are read at run time instead (files a secret
	// manager or certificate tooling keeps current)
	SecretFile string `json:"secret_file,omitempty"`
	CertFile   string `json:"cert_file,omitempty"`
	KeyFile    string `json:"key_file,omitempty"`
	// Expires is when the credential stops working: entered for secrets, from the
	// certificate otherwise (reported, so the server can warn)
	Expires *time.Time `json:"expires,omitempty"`
}

// ProfileSummary is what the agent reports about a profile: never the credential
type ProfileSummary struct {
	Name       string     `json:"name"`
	TenantID   string     `json:"tenant_id"`
	ClientID   string     `json:"client_id"`
	AuthMethod string     `json:"auth_method"`
	Files      bool       `json:"files,omitempty"`
	Expires    *time.Time `json:"expires,omitempty"`
}

// Validate normalises the ids and checks that the method's credential comes from
// exactly one source; the credential itself is read and checked too (files included)
func (p *Profile) Validate() error {
	p.TenantID = strings.ToLower(strings.TrimSpace(p.TenantID))
	p.ClientID = strings.ToLower(strings.TrimSpace(p.ClientID))
	p.AuthMethod = strings.ToLower(strings.TrimSpace(p.AuthMethod))
	p.Secret = strings.TrimSpace(p.Secret)
	p.SecretFile = strings.TrimSpace(p.SecretFile)
	p.CertFile = strings.TrimSpace(p.CertFile)
	p.KeyFile = strings.TrimSpace(p.KeyFile)
	if err := checkIDs(p.TenantID, p.ClientID); err != nil {
		return err
	}
	inlineCert := p.CertificatePEM != "" || p.KeyPEM != ""
	fileCert := p.CertFile != "" || p.KeyFile != ""
	switch p.AuthMethod {
	case "", AuthSecret:
		p.AuthMethod = AuthSecret
		switch {
		case inlineCert || fileCert:
			return errors.New("a secret profile takes no certificate or key")
		case (p.Secret == "") == (p.SecretFile == ""):
			return errors.New("set either a client secret or a secret file")
		}
	case AuthCertificate:
		switch {
		case p.Secret != "" || p.SecretFile != "":
			return errors.New("a certificate profile takes no client secret")
		case inlineCert == fileCert:
			return errors.New("set either the certificate and key, or the certificate and key files")
		}
	default:
		return fmt.Errorf("auth method must be %s or %s", AuthSecret, AuthCertificate)
	}
	c, err := p.Credentials()
	if err != nil {
		return err
	}
	if p.AuthMethod == AuthCertificate {
		cert, _, _ := ParseCertificate(c.CertificatePEM, c.KeyPEM)
		exp := cert.NotAfter
		p.Expires = &exp
	}
	return nil
}

// Credentials returns what the Graph client needs, reading the files when set
func (p *Profile) Credentials() (Credentials, error) {
	c := Credentials{TenantID: p.TenantID, ClientID: p.ClientID, AuthMethod: p.AuthMethod,
		Secret: p.Secret, CertificatePEM: p.CertificatePEM, KeyPEM: p.KeyPEM}
	read := func(path, what string, dst *string) error {
		if path == "" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading the %s file: %w", what, err)
		}
		if *dst = strings.TrimSpace(string(data)); *dst == "" {
			return fmt.Errorf("the %s file %s is empty", what, path)
		}
		return nil
	}
	if err := read(p.SecretFile, "secret", &c.Secret); err != nil {
		return c, err
	}
	if err := read(p.CertFile, "certificate", &c.CertificatePEM); err != nil {
		return c, err
	}
	if err := read(p.KeyFile, "key", &c.KeyPEM); err != nil {
		return c, err
	}
	if c.AuthMethod == AuthCertificate {
		if _, _, err := ParseCertificate(c.CertificatePEM, c.KeyPEM); err != nil {
			return c, err
		}
	}
	return c, nil
}

// Summary describes the profile without its credential. A certificate file is read
// again, so a renewed certificate reports its new expiry.
func (p *Profile) Summary(name string) ProfileSummary {
	s := ProfileSummary{Name: name, TenantID: p.TenantID, ClientID: p.ClientID, AuthMethod: p.AuthMethod,
		Files: p.SecretFile != "" || p.CertFile != "", Expires: p.Expires}
	if p.CertFile != "" {
		if c, err := p.Credentials(); err == nil {
			if cert, _, err := ParseCertificate(c.CertificatePEM, c.KeyPEM); err == nil {
				exp := cert.NotAfter
				s.Expires = &exp
			}
		}
	}
	return s
}

// Matches refuses a profile made for another tenant or app than the job's
func (p *Profile) Matches(tenantID, clientID string) error {
	tenantID, clientID = strings.ToLower(strings.TrimSpace(tenantID)), strings.ToLower(strings.TrimSpace(clientID))
	if p.TenantID != tenantID || p.ClientID != clientID {
		return fmt.Errorf("the profile is for tenant %s, app %s, but the job's tenant is %s, app %s (write the tenant id the same way in both)",
			p.TenantID, p.ClientID, tenantID, clientID)
	}
	return nil
}
