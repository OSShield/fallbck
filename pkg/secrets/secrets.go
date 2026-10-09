// Package secrets seals the server's stored secrets (PBS API tokens, backup encryption
// keys) with a master key held outside the database, so a database dump alone does
// not expose them. AES-256-GCM, one random nonce per value; the sealed form is
// "v1:" + base64(nonce || ciphertext), which lets reads tell sealed values from
// legacy plaintext while those are migrated.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	prefix  = "v1:"
	keySize = 32
)

// Sealer seals and opens values with one master key
type Sealer struct {
	aead cipher.AEAD
}

// New returns a Sealer for a 32-byte key
func New(key []byte) (*Sealer, error) {
	if len(key) != keySize {
		return nil, fmt.Errorf("master key must be %d bytes, got %d", keySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Sealer{aead: aead}, nil
}

// Seal encrypts plain; an empty value stays empty (nothing stored, nothing to protect)
func (s *Sealer) Seal(plain []byte) string {
	if len(plain) == 0 {
		return ""
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic("secrets: crypto/rand failed: " + err.Error())
	}
	out := s.aead.Seal(nonce, nonce, plain, nil)
	return prefix + base64.StdEncoding.EncodeToString(out)
}

// SealString is Seal for strings
func (s *Sealer) SealString(plain string) string { return s.Seal([]byte(plain)) }

// Open decrypts a value produced by Seal
func (s *Sealer) Open(sealed string) ([]byte, error) {
	if sealed == "" {
		return nil, nil
	}
	if !IsSealed(sealed) {
		return nil, errors.New("value is not sealed")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(sealed, prefix))
	if err != nil {
		return nil, fmt.Errorf("sealed value is not valid base64: %w", err)
	}
	n := s.aead.NonceSize()
	if len(raw) < n+s.aead.Overhead() {
		return nil, errors.New("sealed value is too short")
	}
	plain, err := s.aead.Open(nil, raw[:n], raw[n:], nil)
	if err != nil {
		return nil, errors.New("sealed value cannot be opened with this master key")
	}
	return plain, nil
}

// OpenString is Open for strings
func (s *Sealer) OpenString(sealed string) (string, error) {
	b, err := s.Open(sealed)
	return string(b), err
}

// IsSealed reports whether v carries the sealed-value prefix
func IsSealed(v string) bool { return strings.HasPrefix(v, prefix) }

// ParseKey decodes a master key given as 64 hex characters (the key file content or
// the FALLBCK_MASTER_KEY variable)
func ParseKey(text string) ([]byte, error) {
	key, err := hex.DecodeString(strings.TrimSpace(text))
	if err != nil {
		return nil, fmt.Errorf("master key is not hex: %w", err)
	}
	if len(key) != keySize {
		return nil, fmt.Errorf("master key must be %d hex characters, got %d", keySize*2, len(strings.TrimSpace(text)))
	}
	return key, nil
}

// LoadOrCreateKeyFile reads the master key from path, creating a random one (mode
// 0600) when the file does not exist. created reports whether it was generated.
func LoadOrCreateKeyFile(path string) (key []byte, created bool, err error) {
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		key, err = ParseKey(string(data))
		if err != nil {
			return nil, false, fmt.Errorf("%s: %w", path, err)
		}
		return key, false, nil
	case !errors.Is(err, os.ErrNotExist):
		return nil, false, err
	}
	key = make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return nil, false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, false, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, false, fmt.Errorf("creating master key file: %w", err)
	}
	if _, err := f.WriteString(hex.EncodeToString(key) + "\n"); err != nil {
		f.Close()
		return nil, false, err
	}
	if err := f.Close(); err != nil {
		return nil, false, err
	}
	return key, true, nil
}
