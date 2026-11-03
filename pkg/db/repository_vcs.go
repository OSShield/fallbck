package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/osshield/fallbck/pkg/vcs"
)

// ErrConnectionInUse is returned when a VCS connection still has jobs
var ErrConnectionInUse = errors.New("connection is referenced by backup jobs")

const connectionSelect = `
	SELECT c.id, c.name, c.provider, c.base_url, c.token_sealed, c.token_expires, c.ca_pem,
	       c.created_at, c.updated_at,
	       (SELECT count(*) FROM backup_jobs j WHERE j.vcs_connection_id = c.id), c.labels
	FROM vcs_connections c`

func (d *DB) scanConnection(row pgx.Row) (*vcs.Connection, error) {
	var c vcs.Connection
	if err := row.Scan(&c.ID, &c.Name, &c.Provider, &c.BaseURL, &c.Token, &c.TokenExpires, &c.CAPEM,
		&c.CreatedAt, &c.UpdatedAt, &c.Jobs, &c.Labels); err != nil {
		return nil, err
	}
	var err error
	if c.Token, err = d.open(c.Token); err != nil {
		return nil, fmt.Errorf("connection %s token: %w", c.Name, err)
	}
	return c.Sanitize(), nil
}

// CreateConnection stores a VCS connection; the token is sealed
func (d *DB) CreateConnection(ctx context.Context, c *vcs.Connection) error {
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	now := time.Now().UTC()
	c.CreatedAt, c.UpdatedAt = now, now
	_, err := d.Pool.Exec(ctx, `
		INSERT INTO vcs_connections (id, name, provider, base_url, token_sealed, token_expires, ca_pem, labels, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		c.ID, c.Name, c.Provider, c.BaseURL, d.seal(c.Token), c.TokenExpires, c.CAPEM, Labels(c.Labels).JSON(), c.CreatedAt, c.UpdatedAt)
	return err
}

// UpdateConnection replaces every editable field (the caller keeps the stored token
// when the request carries none)
func (d *DB) UpdateConnection(ctx context.Context, c *vcs.Connection) error {
	c.UpdatedAt = time.Now().UTC()
	tag, err := d.Pool.Exec(ctx, `
		UPDATE vcs_connections
		SET name = $2, provider = $3, base_url = $4, token_sealed = $5, token_expires = $6, ca_pem = $7,
		    labels = $8, updated_at = $9
		WHERE id = $1`,
		c.ID, c.Name, c.Provider, c.BaseURL, d.seal(c.Token), c.TokenExpires, c.CAPEM, Labels(c.Labels).JSON(), c.UpdatedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetConnectionTokenExpiry records the token expiry a connection test read from the
// provider
func (d *DB) SetConnectionTokenExpiry(ctx context.Context, id uuid.UUID, expires *time.Time) error {
	tag, err := d.Pool.Exec(ctx, `UPDATE vcs_connections SET token_expires = $2, updated_at = $3 WHERE id = $1`, id, expires, time.Now().UTC())
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// GetConnectionByID returns the connection within scope with its token opened
func (d *DB) GetConnectionByID(ctx context.Context, id uuid.UUID, scope Scope) (*vcs.Connection, error) {
	where, args := scope.SQL("c.labels", []any{id})
	c, err := d.scanConnection(d.Pool.QueryRow(ctx, connectionSelect+` WHERE c.id = $1 AND `+where, args...))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return c, err
}

// ListConnections returns the connections within scope ordered by name
func (d *DB) ListConnections(ctx context.Context, scope Scope) ([]*vcs.Connection, error) {
	where, args := scope.SQL("c.labels", nil)
	rows, err := d.Pool.Query(ctx, connectionSelect+` WHERE `+where+` ORDER BY c.name ASC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*vcs.Connection
	for rows.Next() {
		c, err := d.scanConnection(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// DeleteConnection removes a connection that no job references (ErrConnectionInUse
// otherwise)
func (d *DB) DeleteConnection(ctx context.Context, id uuid.UUID) error {
	var jobs int
	if err := d.Pool.QueryRow(ctx, `SELECT count(*) FROM backup_jobs WHERE vcs_connection_id = $1`, id).Scan(&jobs); err != nil {
		return err
	}
	if jobs > 0 {
		return ErrConnectionInUse
	}
	tag, err := d.Pool.Exec(ctx, `DELETE FROM vcs_connections WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
