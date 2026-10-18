package db

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ==========================================
// Agent authentication state
// ==========================================

// AgentAuthState is the subset of agent state needed to validate an agent bearer token
type AgentAuthState struct {
	ID           uuid.UUID
	TaskQueue    string
	TokenVersion int
	Revoked      bool
}

// GetAgentAuthState returns the token version and revocation state of an agent.
// Returns ErrNotFound if the agent does not exist (e.g. it was deleted).
func (d *DB) GetAgentAuthState(ctx context.Context, id uuid.UUID) (*AgentAuthState, error) {
	var (
		st        AgentAuthState
		revokedAt *time.Time
	)
	err := d.Pool.QueryRow(ctx,
		`SELECT id, task_queue, token_version, revoked_at FROM agents WHERE id = $1`, id,
	).Scan(&st.ID, &st.TaskQueue, &st.TokenVersion, &revokedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	st.Revoked = revokedAt != nil
	return &st, nil
}

// BumpAgentTokenVersion invalidates every previously issued token for the agent and
// returns the new version that must be embedded in freshly issued tokens.
func (d *DB) BumpAgentTokenVersion(ctx context.Context, id uuid.UUID) (int, error) {
	var version int
	err := d.Pool.QueryRow(ctx,
		`UPDATE agents SET token_version = token_version + 1, updated_at = NOW() WHERE id = $1 RETURNING token_version`, id,
	).Scan(&version)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, ErrNotFound
		}
		return 0, err
	}
	return version, nil
}

// RevokeAgent marks the agent as revoked; its tokens stop validating immediately
func (d *DB) RevokeAgent(ctx context.Context, id uuid.UUID) error {
	tag, err := d.Pool.Exec(ctx,
		`UPDATE agents SET revoked_at = NOW(), status = $2, updated_at = NOW() WHERE id = $1 AND revoked_at IS NULL`,
		id, AgentStatusOffline)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ==========================================
// Admin API keys
// ==========================================

// APIKey is an admin credential for fallbck-ctl and scripts. The raw key is never stored.
type APIKey struct {
	ID         uuid.UUID  `json:"id"`
	Name       string     `json:"name"`
	KeyHash    string     `json:"-"`
	CreatedBy  string     `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	ExpiresAt  *time.Time `json:"expires_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
	// Role and Selector are the key's single access binding
	Role     string   `json:"role"`
	Selector Selector `json:"selector"`
}

const apiKeyColumns = `id, name, key_hash, created_by, created_at, last_used_at, expires_at, revoked_at, role, selector`

func scanAPIKey(row pgx.Row) (*APIKey, error) {
	var k APIKey
	if err := row.Scan(&k.ID, &k.Name, &k.KeyHash, &k.CreatedBy, &k.CreatedAt, &k.LastUsedAt, &k.ExpiresAt, &k.RevokedAt, &k.Role, &k.Selector); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &k, nil
}

func (d *DB) CreateAPIKey(ctx context.Context, key *APIKey) error {
	if key.ID == uuid.Nil {
		key.ID = uuid.New()
	}
	key.CreatedAt = time.Now().UTC()
	if key.Role == "" {
		key.Role = "admin"
	}
	_, err := d.Pool.Exec(ctx,
		`INSERT INTO api_keys (id, name, key_hash, created_by, created_at, expires_at, role, selector) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		key.ID, key.Name, key.KeyHash, key.CreatedBy, key.CreatedAt, key.ExpiresAt, key.Role, key.Selector.String())
	return err
}

func (d *DB) GetAPIKeyByHash(ctx context.Context, hash string) (*APIKey, error) {
	return scanAPIKey(d.Pool.QueryRow(ctx, `SELECT `+apiKeyColumns+` FROM api_keys WHERE key_hash = $1`, hash))
}

func (d *DB) ListAPIKeys(ctx context.Context) ([]*APIKey, error) {
	rows, err := d.Pool.Query(ctx, `SELECT `+apiKeyColumns+` FROM api_keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []*APIKey
	for rows.Next() {
		k, err := scanAPIKey(rows)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

func (d *DB) RevokeAPIKey(ctx context.Context, id uuid.UUID) error {
	tag, err := d.Pool.Exec(ctx, `UPDATE api_keys SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// TouchAPIKey records the last use of a key (best-effort, called on successful auth)
func (d *DB) TouchAPIKey(ctx context.Context, id uuid.UUID) error {
	_, err := d.Pool.Exec(ctx, `UPDATE api_keys SET last_used_at = NOW() WHERE id = $1`, id)
	return err
}
