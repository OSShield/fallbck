package db

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// AdminSession is one signed-in browser session
type AdminSession struct {
	ID         uuid.UUID  `json:"id"`
	Subject    string     `json:"subject"`
	Email      string     `json:"email"`
	Name       string     `json:"name"`
	SourceIP   string     `json:"source_ip"`
	UserAgent  string     `json:"user_agent"`
	CreatedAt  time.Time  `json:"created_at"`
	LastSeenAt time.Time  `json:"last_seen_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	RevokedBy  string     `json:"revoked_by,omitempty"`
}

// CreateAdminSession records a new session, and drops rows that expired over a week
// ago (they only matter while someone might still present the cookie)
func (d *DB) CreateAdminSession(ctx context.Context, s *AdminSession) error {
	if _, err := d.Pool.Exec(ctx, `DELETE FROM admin_sessions WHERE expires_at < NOW() - interval '7 days'`); err != nil {
		return err
	}
	return d.Pool.QueryRow(ctx, `INSERT INTO admin_sessions (id, subject, email, name, source_ip, user_agent, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING created_at, last_seen_at`,
		s.ID, s.Subject, s.Email, s.Name, s.SourceIP, s.UserAgent, s.ExpiresAt).Scan(&s.CreatedAt, &s.LastSeenAt)
}

// TouchAdminSession reports whether the session is still valid (exists, not revoked,
// not expired) and records the activity
func (d *DB) TouchAdminSession(ctx context.Context, id string) (bool, error) {
	sid, err := uuid.Parse(id)
	if err != nil {
		return false, nil
	}
	tag, err := d.Pool.Exec(ctx, `UPDATE admin_sessions SET last_seen_at = NOW()
		WHERE id = $1 AND revoked_at IS NULL AND expires_at > NOW()`, sid)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// ListActiveAdminSessions returns the sessions still valid, most recently active first
func (d *DB) ListActiveAdminSessions(ctx context.Context) ([]*AdminSession, error) {
	rows, err := d.Pool.Query(ctx, `SELECT id, subject, email, name, source_ip, user_agent, created_at, last_seen_at, expires_at
		FROM admin_sessions WHERE revoked_at IS NULL AND expires_at > NOW() ORDER BY last_seen_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*AdminSession{}
	for rows.Next() {
		var s AdminSession
		if err := rows.Scan(&s.ID, &s.Subject, &s.Email, &s.Name, &s.SourceIP, &s.UserAgent, &s.CreatedAt, &s.LastSeenAt, &s.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, &s)
	}
	return out, rows.Err()
}

// RevokeAdminSession ends one valid session (ErrNotFound when none)
func (d *DB) RevokeAdminSession(ctx context.Context, id uuid.UUID, by string) (*AdminSession, error) {
	var s AdminSession
	err := d.Pool.QueryRow(ctx, `UPDATE admin_sessions SET revoked_at = NOW(), revoked_by = $2
		WHERE id = $1 AND revoked_at IS NULL AND expires_at > NOW() RETURNING id, subject, email, name`, id, by).
		Scan(&s.ID, &s.Subject, &s.Email, &s.Name)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &s, nil
}

// RevokeUserAdminSessions ends every valid session of an email (case-insensitive) and
// returns how many
func (d *DB) RevokeUserAdminSessions(ctx context.Context, email, by string) (int, error) {
	tag, err := d.Pool.Exec(ctx, `UPDATE admin_sessions SET revoked_at = NOW(), revoked_by = $2
		WHERE lower(email) = lower($1) AND revoked_at IS NULL AND expires_at > NOW()`, email, by)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}
