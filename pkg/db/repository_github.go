package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/osshield/fallbck/pkg/github"
)

// ErrAccountInUse is returned when a GitHub account still has jobs
var ErrAccountInUse = errors.New("account is referenced by backup jobs")

const accountSelect = `
	SELECT a.id, a.name, a.api_url, a.token_sealed, a.token_expires, a.created_at, a.updated_at,
	       (SELECT count(*) FROM backup_jobs j WHERE j.github_account_id = a.id), a.labels
	FROM github_accounts a`

func (d *DB) scanAccount(row pgx.Row) (*github.Account, error) {
	var a github.Account
	if err := row.Scan(&a.ID, &a.Name, &a.APIURL, &a.Token, &a.TokenExpires, &a.CreatedAt, &a.UpdatedAt, &a.Jobs, &a.Labels); err != nil {
		return nil, err
	}
	var err error
	if a.Token, err = d.open(a.Token); err != nil {
		return nil, fmt.Errorf("GitHub account %s token: %w", a.Name, err)
	}
	return a.Sanitize(), nil
}

// CreateGitHubAccount stores an account; the token is sealed
func (d *DB) CreateGitHubAccount(ctx context.Context, a *github.Account) error {
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}
	now := time.Now().UTC()
	a.CreatedAt, a.UpdatedAt = now, now
	_, err := d.Pool.Exec(ctx, `
		INSERT INTO github_accounts (id, name, api_url, token_sealed, token_expires, labels, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		a.ID, a.Name, a.APIURL, d.seal(a.Token), a.TokenExpires, Labels(a.Labels).JSON(), a.CreatedAt, a.UpdatedAt)
	return err
}

// UpdateGitHubAccount replaces every editable field (the caller keeps the stored
// token when the request carries none)
func (d *DB) UpdateGitHubAccount(ctx context.Context, a *github.Account) error {
	a.UpdatedAt = time.Now().UTC()
	tag, err := d.Pool.Exec(ctx, `
		UPDATE github_accounts
		SET name = $2, api_url = $3, token_sealed = $4, token_expires = $5, labels = $6, updated_at = $7
		WHERE id = $1`,
		a.ID, a.Name, a.APIURL, d.seal(a.Token), a.TokenExpires, Labels(a.Labels).JSON(), a.UpdatedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// GetGitHubAccountByID returns the account within scope with its token opened
func (d *DB) GetGitHubAccountByID(ctx context.Context, id uuid.UUID, scope Scope) (*github.Account, error) {
	where, args := scope.SQL("a.labels", []any{id})
	a, err := d.scanAccount(d.Pool.QueryRow(ctx, accountSelect+` WHERE a.id = $1 AND `+where, args...))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return a, err
}

// ListGitHubAccounts returns the accounts within scope ordered by name
func (d *DB) ListGitHubAccounts(ctx context.Context, scope Scope) ([]*github.Account, error) {
	where, args := scope.SQL("a.labels", nil)
	rows, err := d.Pool.Query(ctx, accountSelect+` WHERE `+where+` ORDER BY a.name ASC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*github.Account
	for rows.Next() {
		a, err := d.scanAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// DeleteGitHubAccount removes an account no job references (ErrAccountInUse otherwise)
func (d *DB) DeleteGitHubAccount(ctx context.Context, id uuid.UUID) error {
	var jobs int
	if err := d.Pool.QueryRow(ctx, `SELECT count(*) FROM backup_jobs WHERE github_account_id = $1`, id).Scan(&jobs); err != nil {
		return err
	}
	if jobs > 0 {
		return ErrAccountInUse
	}
	tag, err := d.Pool.Exec(ctx, `DELETE FROM github_accounts WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
