package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/db"
)

// APIKeyPrefix makes keys recognisable in logs and secret scanners
const APIKeyPrefix = "fbk_"

// ErrInvalidAPIKey is returned for unknown, expired or revoked API keys
var ErrInvalidAPIKey = errors.New("invalid, expired or revoked API key")

// APIKeyStore provides API key persistence (implemented by *db.DB)
type APIKeyStore interface {
	CreateAPIKey(ctx context.Context, key *db.APIKey) error
	GetAPIKeyByHash(ctx context.Context, hash string) (*db.APIKey, error)
	TouchAPIKey(ctx context.Context, id uuid.UUID) error
}

// IsAPIKey reports whether a bearer value looks like an admin API key
func IsAPIKey(value string) bool {
	return strings.HasPrefix(value, APIKeyPrefix)
}

// NewAPIKey generates a new raw key and its persisted record. The raw key is returned
// exactly once; only its hash is stored.
func NewAPIKey(name, createdBy string, expiresAt *time.Time) (raw string, key *db.APIKey, err error) {
	rawSecret, _, err := GenerateSecureToken(32)
	if err != nil {
		return "", nil, err
	}
	raw = APIKeyPrefix + rawSecret
	key = &db.APIKey{
		ID:        uuid.New(),
		Name:      name,
		KeyHash:   HashToken(raw),
		CreatedBy: createdBy,
		ExpiresAt: expiresAt,
	}
	return raw, key, nil
}

// LookupAPIKey resolves a raw key to its record, enforcing expiry and revocation
func LookupAPIKey(ctx context.Context, store APIKeyStore, raw string) (*db.APIKey, error) {
	if !IsAPIKey(raw) {
		return nil, ErrInvalidAPIKey
	}
	key, err := store.GetAPIKeyByHash(ctx, HashToken(raw))
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return nil, ErrInvalidAPIKey
		}
		return nil, fmt.Errorf("failed to look up API key: %w", err)
	}
	now := time.Now()
	if key.RevokedAt != nil || (key.ExpiresAt != nil && now.After(*key.ExpiresAt)) {
		return nil, ErrInvalidAPIKey
	}
	return key, nil
}
