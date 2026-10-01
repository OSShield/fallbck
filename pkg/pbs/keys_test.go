package pbs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

func TestKeyRoundTrip(t *testing.T) {
	key, fp, err := GenerateKey()
	if err != nil || key == [32]byte{} || len(strings.Split(fp, ":")) != 32 {
		t.Fatalf("generate: %v fp=%q", err, fp)
	}
	if _, err := ExportKeyFile(key, "abc", ""); err == nil {
		t.Error("short passphrase must fail")
	}
	data, err := ExportKeyFile(key, "correct horse", "the usual")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"kdf": null`) || !strings.Contains(strings.ToLower(string(data)), "scrypt") {
		t.Errorf("export is not passphrase protected: %s", data)
	}
	imp, err := ImportKeyFile(data, "correct horse")
	if err != nil || imp.Key != key || imp.Fingerprint != fp {
		t.Errorf("import: %v fp=%q", err, imp.Fingerprint)
	}
	if _, err := ImportKeyFile(data, "wrong"); err == nil {
		t.Error("wrong passphrase must fail")
	}
}

func TestValidateMasterPublicKey(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pemText := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	if out, err := ValidateMasterPublicKey(" \n" + pemText); err != nil || !strings.HasPrefix(out, "-----BEGIN PUBLIC KEY-----") {
		t.Errorf("pkix: %v", err)
	}
	pkcs1 := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&priv.PublicKey)}))
	if _, err := ValidateMasterPublicKey(pkcs1); err != nil {
		t.Errorf("pkcs1: %v", err)
	}
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	derSmall, _ := x509.MarshalPKIXPublicKey(&small.PublicKey)
	if _, err := ValidateMasterPublicKey(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: derSmall}))); err == nil {
		t.Error("1024-bit key must fail")
	}
	if _, err := ValidateMasterPublicKey("garbage"); err == nil {
		t.Error("garbage must fail")
	}
}
