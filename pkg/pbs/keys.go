package pbs

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	gopbs "github.com/osshield/gopbs/pbs"
)

// Backup encryption keys (per target). The cryptography itself lives in gopbs; these
// helpers wrap it for the server: generate, fingerprint, export and import in the
// proxmox-backup-client key-file format, and validate an RSA master public key.

// GenerateKey returns a fresh 32-byte key and its fingerprint
func GenerateKey() ([32]byte, string, error) {
	key, err := gopbs.GenerateEncryptionKey()
	if err != nil {
		return key, "", err
	}
	fp, err := KeyFingerprint(key)
	return key, fp, err
}

// KeyFingerprint is the colon-separated fingerprint proxmox-backup shows for a key
func KeyFingerprint(key [32]byte) (string, error) {
	// gopbs computes it when loading a key file; a plain (KDFNone) round trip is the
	// public way to get it
	data, err := gopbs.CreateKeyFile(key, nil, gopbs.KDFNone, "")
	if err != nil {
		return "", err
	}
	info, err := gopbs.LoadKeyFile(data, nil)
	if err != nil {
		return "", err
	}
	return info.Fingerprint, nil
}

// MinPassphrase is the shortest passphrase an exported key file may have. The file
// is the only way to decrypt the backups without the server, so it gets kept for
// years, often next to the backups; scrypt slows guessing, length does the rest.
// Importing an existing file takes whatever passphrase it was made with.
const MinPassphrase = 12

// ExportKeyFile renders the key as a passphrase-protected (scrypt) key file that
// proxmox-backup-client restores with (--keyfile)
func ExportKeyFile(key [32]byte, passphrase, hint string) ([]byte, error) {
	if len(passphrase) < MinPassphrase {
		return nil, fmt.Errorf("the passphrase must be at least %d characters", MinPassphrase)
	}
	return gopbs.CreateKeyFile(key, []byte(passphrase), gopbs.KDFScrypt, hint)
}

// ImportedKey is a key read from a proxmox-backup-client key file
type ImportedKey struct {
	Key         [32]byte
	Fingerprint string
	Created     time.Time
}

// ImportKeyFile reads a key file (passphrase-protected or plain)
func ImportKeyFile(data []byte, passphrase string) (ImportedKey, error) {
	var pass []byte
	if passphrase != "" {
		pass = []byte(passphrase)
	}
	info, err := gopbs.LoadKeyFile(data, pass)
	if err != nil {
		return ImportedKey{}, err
	}
	if info.Key == [32]byte{} {
		return ImportedKey{}, errors.New("key file holds an all-zero key")
	}
	return ImportedKey{Key: info.Key, Fingerprint: info.Fingerprint, Created: info.Created}, nil
}

// ValidateMasterPublicKey checks an RSA public key in PEM form ("PUBLIC KEY" or
// "RSA PUBLIC KEY"), at least 2048 bits, and returns it normalised
func ValidateMasterPublicKey(pemText string) (string, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return "", errors.New("not a PEM block")
	}
	var pub *rsa.PublicKey
	switch block.Type {
	case "PUBLIC KEY":
		k, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("parsing public key: %w", err)
		}
		var ok bool
		if pub, ok = k.(*rsa.PublicKey); !ok {
			return "", errors.New("the master key must be an RSA key")
		}
	case "RSA PUBLIC KEY":
		k, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("parsing RSA public key: %w", err)
		}
		pub = k
	default:
		return "", fmt.Errorf("unexpected PEM block %q (expected PUBLIC KEY)", block.Type)
	}
	if pub.N.BitLen() < 2048 {
		return "", fmt.Errorf("RSA key is %d bits; at least 2048 are required", pub.N.BitLen())
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: block.Bytes})), nil
}
