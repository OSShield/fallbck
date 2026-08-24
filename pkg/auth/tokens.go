package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var (
	ErrInvalidTicket = errors.New("invalid or expired backup ticket")
)

// GenerateSecureToken creates a cryptographically secure random token string and its SHA256 hash
func GenerateSecureToken(length int) (rawToken string, tokenHash string, err error) {
	if length <= 0 {
		length = 32
	}
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	rawToken = hex.EncodeToString(bytes)
	tokenHash = HashToken(rawToken)
	return rawToken, tokenHash, nil
}

// HashToken returns the hex SHA-256 hash of a raw token string
func HashToken(rawToken string) string {
	h := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(h[:])
}

// BackupTicketClaims defines the claims embedded in a short-lived backup session ticket
type BackupTicketClaims struct {
	JobID       uuid.UUID `json:"job_id"`
	AgentID     uuid.UUID `json:"agent_id"`
	TargetID    uuid.UUID `json:"target_id"`
	Datastore   string    `json:"datastore"`
	Namespace   string    `json:"namespace"`
	BackupType  string    `json:"backup_type"` // e.g. "host"
	BackupID    string    `json:"backup_id"`   // e.g. "agent-123"
	BackupTime  int64     `json:"backup_time"` // unix timestamp
	jwt.RegisteredClaims
}

// TokenManager signs and validates short-lived backup session tickets
type TokenManager struct {
	secretKey []byte
}

// NewTokenManager creates a new TokenManager with a shared signing secret
func NewTokenManager(secret string) *TokenManager {
	return &TokenManager{
		secretKey: []byte(secret),
	}
}

// CreateBackupTicket generates a signed JWT ticket valid for the specified duration (e.g. 2 hours)
func (tm *TokenManager) CreateBackupTicket(claims BackupTicketClaims, ttl time.Duration) (string, error) {
	now := time.Now().UTC()
	claims.RegisteredClaims = jwt.RegisteredClaims{
		Issuer:    "fallbck-server",
		Subject:   claims.AgentID.String(),
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		NotBefore: jwt.NewNumericDate(now.Add(-1 * time.Minute)),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(tm.secretKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign backup ticket: %w", err)
	}
	return signed, nil
}

// ValidateBackupTicket parses and verifies a short-lived backup ticket
func (tm *TokenManager) ValidateBackupTicket(ticketString string) (*BackupTicketClaims, error) {
	token, err := jwt.ParseWithClaims(ticketString, &BackupTicketClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return tm.secretKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidTicket, err)
	}

	claims, ok := token.Claims.(*BackupTicketClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidTicket
	}

	return claims, nil
}
