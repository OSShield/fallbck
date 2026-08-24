package certs

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrCreateCAAndIssueClientCert(t *testing.T) {
	tempDir := t.TempDir()
	caCertPath := filepath.Join(tempDir, "ca.crt")
	caKeyPath := filepath.Join(tempDir, "ca.key")

	// 1. Generate new CA
	ca, err := LoadOrCreateCA(caCertPath, caKeyPath)
	if err != nil {
		t.Fatalf("LoadOrCreateCA failed: %v", err)
	}

	if ca.CACert == nil || ca.CAKey == nil {
		t.Fatal("CA cert or key is nil")
	}

	// Verify files written to disk
	if _, err := os.Stat(caCertPath); err != nil {
		t.Fatalf("CA cert file missing: %v", err)
	}
	if _, err := os.Stat(caKeyPath); err != nil {
		t.Fatalf("CA key file missing: %v", err)
	}

	// 2. Reload CA from disk
	reloadedCA, err := LoadOrCreateCA(caCertPath, caKeyPath)
	if err != nil {
		t.Fatalf("Failed to reload CA from disk: %v", err)
	}
	if reloadedCA.CACert.SerialNumber.Cmp(ca.CACert.SerialNumber) != 0 {
		t.Errorf("Reloaded CA serial number mismatch")
	}

	// 3. Issue client certificate
	clientKP, err := ca.IssueClientCert("agent-test-uuid", 30)
	if err != nil {
		t.Fatalf("IssueClientCert failed: %v", err)
	}

	block, _ := pem.Decode(clientKP.CertPEM)
	if block == nil {
		t.Fatal("Failed to decode issued client cert PEM")
	}

	clientCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse issued client cert: %v", err)
	}

	if clientCert.Subject.CommonName != "agent-test-uuid" {
		t.Errorf("Expected Subject CommonName 'agent-test-uuid', got '%s'", clientCert.Subject.CommonName)
	}

	// Verify client cert against CA
	roots := x509.NewCertPool()
	roots.AddCert(ca.CACert)

	opts := x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	if _, err := clientCert.Verify(opts); err != nil {
		t.Errorf("Client cert failed verification against CA: %v", err)
	}
}
