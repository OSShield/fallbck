package backup

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/osshield/gopbs/pbs"
)

// Encryption is the per-run client-side encryption: the target's key as a gopbs
// configuration plus its fingerprint for logs and the run record. The key lives in
// memory for the run only; Wipe zeroes it afterwards.
type Encryption struct {
	Config      *pbs.CryptConfig
	Fingerprint string
}

// NewEncryption builds the run's encryption from what the server hands the agent
// (GET /api/v1/agents/encryption-key): the base64 key, its fingerprint and creation
// time, and the optional RSA master public key (PEM)
func NewEncryption(keyB64, fingerprint string, created time.Time, masterPublicKey string) (*Encryption, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(keyB64))
	if err != nil {
		return nil, fmt.Errorf("encryption key is not valid base64: %w", err)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes, got %d", len(raw))
	}
	cfg := &pbs.CryptConfig{Mode: pbs.CryptModeEncrypt, KeyCreated: created}
	copy(cfg.Key[:], raw)
	clear(raw)
	if cfg.Key == [32]byte{} {
		return nil, errors.New("encryption key is all zero")
	}
	if masterPublicKey != "" {
		cfg.MasterPublicKey = []byte(masterPublicKey)
	}
	if fingerprint == "" {
		return nil, errors.New("encryption key has no fingerprint")
	}
	return &Encryption{Config: cfg, Fingerprint: fingerprint}, nil
}

// Wipe zeroes the key material once the run is over
func (e *Encryption) Wipe() {
	if e != nil && e.Config != nil {
		clear(e.Config.Key[:])
	}
}

// shortFingerprint is the first 16 hex characters of a colon-separated fingerprint,
// safe for a directory name
func shortFingerprint(fp string) string {
	s := strings.ReplaceAll(fp, ":", "")
	if len(s) > 16 {
		s = s[:16]
	}
	if s == "" {
		return "unknown"
	}
	return s
}
