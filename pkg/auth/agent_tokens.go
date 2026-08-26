package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/db"
)

// DefaultAgentTokenTTL is the lifetime of an agent bearer token unless configured otherwise
const DefaultAgentTokenTTL = 365 * 24 * time.Hour

// AgentTokenClaims is the JWT payload of an agent bearer token. `sub` is the agent ID.
type AgentTokenClaims struct {
	TaskQueue string `json:"tq"`
	Version   int    `json:"ver"`
	jwt.RegisteredClaims
}

// AgentID returns the agent UUID from the subject claim
func (c *AgentTokenClaims) AgentID() (uuid.UUID, error) {
	return uuid.Parse(c.Subject)
}

// CreateAgentToken mints a long-lived bearer token for an enrolled agent
func (tm *TokenManager) CreateAgentToken(agentID uuid.UUID, taskQueue string, version int, ttl time.Duration) (string, time.Time, error) {
	if ttl <= 0 {
		ttl = DefaultAgentTokenTTL
	}
	claims := AgentTokenClaims{
		TaskQueue:        taskQueue,
		Version:          version,
		RegisteredClaims: registered(agentID.String(), AudienceAgent, ttl),
	}
	signed, err := tm.sign(claims)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to sign agent token: %w", err)
	}
	return signed, claims.ExpiresAt.Time, nil
}

// ValidateAgentToken verifies the signature and claims of an agent token. It does NOT
// consult revocation state; use AgentVerifier for that.
func (tm *TokenManager) ValidateAgentToken(tokenString string) (*AgentTokenClaims, error) {
	claims := &AgentTokenClaims{}
	if err := tm.parse(tokenString, AudienceAgent, claims); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if _, err := claims.AgentID(); err != nil {
		return nil, fmt.Errorf("%w: subject is not an agent id", ErrInvalidToken)
	}
	if claims.TaskQueue == "" {
		return nil, fmt.Errorf("%w: missing task queue", ErrInvalidToken)
	}
	return claims, nil
}

// AgentClaims is the authenticated identity of an agent, attached to request contexts
type AgentClaims struct {
	AgentID   uuid.UUID
	TaskQueue string
	Version   int
	ExpiresAt time.Time
}

// AgentStateStore provides the persisted revocation state of agents (implemented by *db.DB)
type AgentStateStore interface {
	GetAgentAuthState(ctx context.Context, id uuid.UUID) (*db.AgentAuthState, error)
}

// ErrAgentRevoked is returned when an agent has been deleted or revoked
var ErrAgentRevoked = errors.New("agent has been revoked")

// AgentVerifier validates agent bearer tokens against both the signature and the
// database state (agent exists, not revoked, token version current). Database lookups
// are cached per agent for a short time so every RPC does not hit Postgres.
type AgentVerifier struct {
	tm       *TokenManager
	store    AgentStateStore
	cacheTTL time.Duration

	mu    sync.Mutex
	cache map[uuid.UUID]cachedAgentState
}

type cachedAgentState struct {
	state   *db.AgentAuthState
	err     error
	expires time.Time
}

// NewAgentVerifier creates a verifier. cacheTTL bounds how long a revocation takes to propagate.
func NewAgentVerifier(tm *TokenManager, store AgentStateStore, cacheTTL time.Duration) *AgentVerifier {
	if cacheTTL <= 0 {
		cacheTTL = 30 * time.Second
	}
	return &AgentVerifier{tm: tm, store: store, cacheTTL: cacheTTL, cache: map[uuid.UUID]cachedAgentState{}}
}

// Verify validates a bearer token value (with or without the "Bearer " prefix)
func (v *AgentVerifier) Verify(ctx context.Context, bearer string) (*AgentClaims, error) {
	token := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(bearer, "Bearer "), "bearer "))
	if token == "" {
		return nil, fmt.Errorf("%w: missing token", ErrInvalidToken)
	}
	claims, err := v.tm.ValidateAgentToken(token)
	if err != nil {
		return nil, err
	}
	agentID, _ := claims.AgentID()

	state, err := v.lookup(ctx, agentID)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return nil, ErrAgentRevoked
		}
		return nil, fmt.Errorf("failed to load agent state: %w", err)
	}
	if state.Revoked {
		return nil, ErrAgentRevoked
	}
	if state.TokenVersion != claims.Version {
		return nil, fmt.Errorf("%w: token has been superseded", ErrInvalidToken)
	}
	if state.TaskQueue != claims.TaskQueue {
		return nil, fmt.Errorf("%w: task queue mismatch", ErrInvalidToken)
	}

	return &AgentClaims{
		AgentID:   agentID,
		TaskQueue: claims.TaskQueue,
		Version:   claims.Version,
		ExpiresAt: claims.ExpiresAt.Time,
	}, nil
}

// Invalidate drops the cached state for an agent (call after revocation for immediate effect)
func (v *AgentVerifier) Invalidate(agentID uuid.UUID) {
	v.mu.Lock()
	delete(v.cache, agentID)
	v.mu.Unlock()
}

func (v *AgentVerifier) lookup(ctx context.Context, agentID uuid.UUID) (*db.AgentAuthState, error) {
	now := time.Now()
	v.mu.Lock()
	if c, ok := v.cache[agentID]; ok && now.Before(c.expires) {
		v.mu.Unlock()
		return c.state, c.err
	}
	v.mu.Unlock()

	state, err := v.store.GetAgentAuthState(ctx, agentID)
	// Cache definitive answers (found / not found) but not transient DB errors.
	if err == nil || errors.Is(err, db.ErrNotFound) {
		v.mu.Lock()
		v.cache[agentID] = cachedAgentState{state: state, err: err, expires: now.Add(v.cacheTTL)}
		v.mu.Unlock()
	}
	return state, err
}
