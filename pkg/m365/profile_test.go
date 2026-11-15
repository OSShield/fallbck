package m365

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestProfileValidate(t *testing.T) {
	notAfter := time.Now().Add(90 * 24 * time.Hour).Truncate(time.Second)
	certPEM, keyPEM, _ := testCertificate(t, notAfter)
	dir := t.TempDir()
	write := func(name, data string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	certFile, keyFile, secretFile := write("cert.pem", certPEM), write("key.pem", keyPEM), write("secret", "s3cret\n")

	ok := map[string]Profile{
		"secret":       {TenantID: " Contoso.onmicrosoft.com ", ClientID: testClientGUID, Secret: "s3cret"},
		"secret file":  {TenantID: testTenantGUID, ClientID: testClientGUID, SecretFile: secretFile},
		"inline cert":  {TenantID: testTenantGUID, ClientID: testClientGUID, AuthMethod: "Certificate", CertificatePEM: certPEM, KeyPEM: keyPEM},
		"cert in file": {TenantID: testTenantGUID, ClientID: testClientGUID, AuthMethod: AuthCertificate, CertFile: certFile, KeyFile: keyFile},
	}
	for name, p := range ok {
		if err := p.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		c, err := p.Credentials()
		if err != nil || c.TenantID != p.TenantID || c.ClientID != testClientGUID {
			t.Errorf("%s: credentials %+v %v", name, c, err)
		}
		if p.AuthMethod == AuthCertificate && (p.Expires == nil || !p.Expires.Equal(notAfter) || c.KeyPEM == "") {
			t.Errorf("%s: expiry %v, key set %v", name, p.Expires, c.KeyPEM != "")
		}
		if p.AuthMethod == AuthSecret && c.Secret != "s3cret" {
			t.Errorf("%s: secret %q", name, c.Secret)
		}
	}
	if p := ok["secret"]; p.Validate() != nil || p.TenantID != "contoso.onmicrosoft.com" {
		t.Errorf("tenant id not normalised: %q", p.TenantID)
	}

	bad := map[string]Profile{
		"no credential":    {TenantID: testTenantGUID, ClientID: testClientGUID},
		"secret twice":     {TenantID: testTenantGUID, ClientID: testClientGUID, Secret: "x", SecretFile: secretFile},
		"secret with cert": {TenantID: testTenantGUID, ClientID: testClientGUID, Secret: "x", CertFile: certFile},
		"cert both ways":   {TenantID: testTenantGUID, ClientID: testClientGUID, AuthMethod: AuthCertificate, CertificatePEM: certPEM, KeyPEM: keyPEM, CertFile: certFile, KeyFile: keyFile},
		"cert with secret": {TenantID: testTenantGUID, ClientID: testClientGUID, AuthMethod: AuthCertificate, Secret: "x", CertFile: certFile, KeyFile: keyFile},
		"missing file":     {TenantID: testTenantGUID, ClientID: testClientGUID, SecretFile: filepath.Join(dir, "nope")},
		"key mismatch":     {TenantID: testTenantGUID, ClientID: testClientGUID, AuthMethod: AuthCertificate, CertFile: certFile, KeyFile: secretFile},
		"bad client id":    {TenantID: testTenantGUID, ClientID: "app", Secret: "x"},
		"agent method":     {TenantID: testTenantGUID, ClientID: testClientGUID, AuthMethod: AuthAgent, Secret: "x"},
	}
	for name, p := range bad {
		if err := p.Validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}

	// A renewed certificate file reports its new expiry without touching the profile
	p := ok["cert in file"]
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	renewed := time.Now().Add(400 * 24 * time.Hour).Truncate(time.Second)
	c2, k2, _ := testCertificate(t, renewed)
	write("cert.pem", c2)
	write("key.pem", k2)
	if s := p.Summary("x"); s.Expires == nil || !s.Expires.Equal(renewed) || !s.Files {
		t.Errorf("summary after renewal %+v", s)
	}
}

func TestProfileMatches(t *testing.T) {
	p := Profile{TenantID: testTenantGUID, ClientID: testClientGUID, Secret: "x"}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := p.Matches(strings.ToUpper(testTenantGUID), testClientGUID); err != nil {
		t.Errorf("same ids: %v", err)
	}
	if err := p.Matches("contoso.onmicrosoft.com", testClientGUID); err == nil {
		t.Error("another tenant accepted")
	}
	if err := p.Matches(testTenantGUID, "99999999-2222-3333-4444-555555555555"); err == nil {
		t.Error("another app accepted")
	}
}

// A tenant whose credentials live on the agents keeps none on the server, and a job
// names its profile in canonical form
func TestAgentTenantAndSpecProfile(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	tn := Tenant{Name: "Contoso", TenantID: testTenantGUID, ClientID: testClientGUID, AuthMethod: " Agent ", Secret: "left over", KeyPEM: "x", SecretExpires: &exp}
	if err := tn.Validate(); err != nil {
		t.Fatal(err)
	}
	if tn.AuthMethod != AuthAgent || tn.Secret != "" || tn.KeyPEM != "" || tn.SecretExpires != nil {
		t.Errorf("agent tenant kept server credentials: %+v", tn)
	}
	s := Spec{TenantID: uuid.New(), Profile: " Contoso-Prod "}
	if err := s.Validate(); err != nil || s.Profile != "contoso-prod" {
		t.Errorf("profile %q: %v", s.Profile, err)
	}
	s.Profile = "no spaces allowed"
	if err := s.Validate(); err == nil {
		t.Error("bad profile name accepted")
	}
}
