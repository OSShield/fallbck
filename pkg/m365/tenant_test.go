package m365

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// testCertificate returns a self-signed RSA certificate and key as PEM, plus the key
func testCertificate(t *testing.T, notAfter time.Time) (certPEM, keyPEM string, key *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fallbck-test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})), key
}

const (
	testTenantGUID = "72f988bf-86f1-41af-91ab-2d7cd011db47"
	testClientGUID = "11111111-2222-3333-4444-555555555555"
)

func TestTenantValidateSecret(t *testing.T) {
	good := Tenant{Name: " Contoso ", TenantID: "Contoso.OnMicrosoft.com", ClientID: testClientGUID, Secret: " s3cret "}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	if good.Name != "Contoso" || good.TenantID != "contoso.onmicrosoft.com" || good.AuthMethod != AuthSecret || good.Secret != "s3cret" {
		t.Errorf("not normalised: %+v", good)
	}
	bad := map[string]Tenant{
		"no name":      {TenantID: testTenantGUID, ClientID: testClientGUID, Secret: "x"},
		"bad tenant":   {Name: "n", TenantID: "not a tenant", ClientID: testClientGUID, Secret: "x"},
		"bad client":   {Name: "n", TenantID: testTenantGUID, ClientID: "abc", Secret: "x"},
		"no secret":    {Name: "n", TenantID: testTenantGUID, ClientID: testClientGUID},
		"bad method":   {Name: "n", TenantID: testTenantGUID, ClientID: testClientGUID, AuthMethod: "password", Secret: "x"},
		"cert missing": {Name: "n", TenantID: testTenantGUID, ClientID: testClientGUID, AuthMethod: AuthCertificate},
	}
	for name, tn := range bad {
		if err := tn.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestTenantValidateCertificate(t *testing.T) {
	exp := time.Now().Add(400 * 24 * time.Hour).Truncate(time.Second)
	certPEM, keyPEM, _ := testCertificate(t, exp)
	tn := Tenant{Name: "n", TenantID: testTenantGUID, ClientID: testClientGUID, AuthMethod: AuthCertificate, CertificatePEM: certPEM, KeyPEM: keyPEM, Secret: "leftover"}
	if err := tn.Validate(); err != nil {
		t.Fatal(err)
	}
	if tn.SecretExpires == nil || !tn.SecretExpires.Equal(exp) {
		t.Errorf("expiry not taken from the certificate: %v", tn.SecretExpires)
	}
	if tn.Secret != "" {
		t.Error("secret must be dropped with the certificate method")
	}
	if tn.ExpiresWithin(30*24*time.Hour) || !tn.ExpiresWithin(500*24*time.Hour) {
		t.Error("ExpiresWithin")
	}
	s := tn.Sanitize()
	if !s.HasCertificate || s.HasSecret {
		t.Errorf("sanitize: %+v", s)
	}
	c := tn.Credentials()
	if c.AuthMethod != AuthCertificate || c.KeyPEM != keyPEM || c.TenantID != testTenantGUID {
		t.Errorf("credentials: %+v", c)
	}

	// Key of another certificate
	_, otherKey, _ := testCertificate(t, exp)
	if _, _, err := ParseCertificate(certPEM, otherKey); err == nil {
		t.Error("mismatched key accepted")
	}
	// Expired certificate
	expCert, expKey, _ := testCertificate(t, time.Now().Add(-time.Hour))
	if _, _, err := ParseCertificate(expCert, expKey); err == nil {
		t.Error("expired certificate accepted")
	}
	if _, _, err := ParseCertificate("garbage", keyPEM); err == nil {
		t.Error("garbage certificate accepted")
	}
}
