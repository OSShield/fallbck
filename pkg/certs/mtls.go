package certs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// CertificateAuthority manages the internal PKI for FallBCK server and agent mTLS
type CertificateAuthority struct {
	CACert    *x509.Certificate
	CAKey     *rsa.PrivateKey
	CACertPEM []byte
	CAKeyPEM  []byte
}

// KeyPair holds PEM-encoded certificate and private key
type KeyPair struct {
	CertPEM []byte
	KeyPEM  []byte
}

// LoadOrCreateCA loads a CA from disk or generates a new self-signed root CA
func LoadOrCreateCA(certPath, keyPath string) (*CertificateAuthority, error) {
	if certPath != "" && keyPath != "" {
		certBytes, errCert := os.ReadFile(certPath)
		keyBytes, errKey := os.ReadFile(keyPath)
		if errCert == nil && errKey == nil {
			block, _ := pem.Decode(certBytes)
			if block == nil {
				return nil, fmt.Errorf("failed to decode CA cert PEM")
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
			}

			keyBlock, _ := pem.Decode(keyBytes)
			if keyBlock == nil {
				return nil, fmt.Errorf("failed to decode CA key PEM")
			}
			key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
			if err != nil {
				// try PKCS8
				k, err8 := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
				if err8 != nil {
					return nil, fmt.Errorf("failed to parse CA private key: %w", err)
				}
				rsaKey, ok := k.(*rsa.PrivateKey)
				if !ok {
					return nil, fmt.Errorf("CA key is not RSA")
				}
				key = rsaKey
			}

			return &CertificateAuthority{
				CACert:    cert,
				CAKey:     key,
				CACertPEM: certBytes,
				CAKeyPEM:  keyBytes,
			}, nil
		}
	}

	// Generate new CA
	caKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA private key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"FallBCK Internal PKI"},
			CommonName:   "FallBCK Root CA",
			Country:      []string{"US"},
		},
		NotBefore:             time.Now().Add(-10 * time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created CA cert: %w", err)
	}

	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})
	caKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caKey)})

	// Save if paths were provided
	if certPath != "" && keyPath != "" {
		_ = os.MkdirAll(filepath.Dir(certPath), 0700)
		_ = os.MkdirAll(filepath.Dir(keyPath), 0700)
		_ = os.WriteFile(certPath, caCertPEM, 0644)
		_ = os.WriteFile(keyPath, caKeyPEM, 0600)
	}

	return &CertificateAuthority{
		CACert:    caCert,
		CAKey:     caKey,
		CACertPEM: caCertPEM,
		CAKeyPEM:  caKeyPEM,
	}, nil
}

// IssueClientCert generates a client mTLS keypair signed by this CA for an agent or server
func (ca *CertificateAuthority) IssueClientCert(commonName string, validityDays int) (*KeyPair, error) {
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate client key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"FallBCK Agents"},
			CommonName:   commonName,
		},
		NotBefore:   time.Now().Add(-10 * time.Minute),
		NotAfter:    time.Now().Add(time.Duration(validityDays) * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{commonName, "localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.CACert, &clientKey.PublicKey, ca.CAKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create client certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientKey)})

	return &KeyPair{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	}, nil
}

// WriteKeyPair writes PEM cert and key to destination files
func (kp *KeyPair) WriteKeyPair(certPath, keyPath string) error {
	if err := os.MkdirAll(filepath.Dir(certPath), 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		return err
	}
	if err := os.WriteFile(certPath, kp.CertPEM, 0644); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, kp.KeyPEM, 0600); err != nil {
		return err
	}
	return nil
}
