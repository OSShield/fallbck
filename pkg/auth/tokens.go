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
	ErrInvalidToken  = errors.New("invalid or expired token")
)

// Issuer is the `iss` claim on every JWT minted by the server
const Issuer = "fallbck-server"

// Audiences separate the JWT types that share the server signing secret so that a
// token of one kind can never be presented as another.
const (
	AudienceBackupTicket = "fallbck-ticket"
	AudienceAgent        = "fallbck-agent"
	AudienceSession      = "fallbck-session"
	AudienceLoginState   = "fallbck-login"
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
	JobID      uuid.UUID `json:"job_id"`
	AgentID    uuid.UUID `json:"agent_id"`
	TargetID   uuid.UUID `json:"target_id"`
	Datastore  string    `json:"datastore"`
	Namespace  string    `json:"namespace"`
	BackupType string    `json:"backup_type"` // e.g. "host"
	BackupID   string    `json:"backup_id"`   // e.g. "agent-123"
	BackupTime int64     `json:"backup_time"` // unix timestamp
	// Issued is when the run's first ticket was minted; refreshes and sub-tickets carry
	// it over so a run cannot keep itself alive forever
	Issued int64 `json:"issued,omitempty"`
	jwt.RegisteredClaims
}

// TokenManager signs and validates every JWT the server issues (backup tickets, agent
// tokens, admin sessions, login state) with a single HS256 secret, separated by audience.
type TokenManager struct {
	secretKey []byte
}

// NewTokenManager creates a new TokenManager with a shared signing secret
func NewTokenManager(secret string) *TokenManager {
	return &TokenManager{
		secretKey: []byte(secret),
	}
}

// registered builds the standard claims for a token of the given audience and lifetime
func registered(subject, audience string, ttl time.Duration) jwt.RegisteredClaims {
	now := time.Now().UTC()
	return jwt.RegisteredClaims{
		Issuer:    Issuer,
		Subject:   subject,
		Audience:  jwt.ClaimStrings{audience},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		NotBefore: jwt.NewNumericDate(now.Add(-1 * time.Minute)),
	}
}

// sign signs claims with the shared secret
func (tm *TokenManager) sign(claims jwt.Claims) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(tm.secretKey)
}

// parse verifies signature, algorithm, issuer, audience and time claims into claims
func (tm *TokenManager) parse(tokenString, audience string, claims jwt.Claims) error {
	token, err := jwt.ParseWithClaims(tokenString, claims,
		func(token *jwt.Token) (interface{}, error) { return tm.secretKey, nil },
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(Issuer),
		jwt.WithAudience(audience),
	)
	if err != nil {
		return err
	}
	if !token.Valid {
		return errors.New("token is not valid")
	}
	return nil
}

// CreateBackupTicket generates a signed JWT ticket valid for the specified duration (e.g. 2 hours)
func (tm *TokenManager) CreateBackupTicket(claims BackupTicketClaims, ttl time.Duration) (string, error) {
	if claims.Issued == 0 {
		claims.Issued = time.Now().Unix()
	}
	claims.RegisteredClaims = registered(claims.AgentID.String(), AudienceBackupTicket, ttl)
	signed, err := tm.sign(claims)
	if err != nil {
		return "", fmt.Errorf("failed to sign backup ticket: %w", err)
	}
	return signed, nil
}

// ValidateBackupTicket parses and verifies a short-lived backup ticket
func (tm *TokenManager) ValidateBackupTicket(ticketString string) (*BackupTicketClaims, error) {
	claims := &BackupTicketClaims{}
	if err := tm.parse(ticketString, AudienceBackupTicket, claims); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidTicket, err)
	}
	return claims, nil
}
