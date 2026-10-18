package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/osshield/fallbck/pkg/m365"
)

// ErrTenantInUse is returned when a tenant still has jobs
var ErrTenantInUse = errors.New("tenant is referenced by backup jobs")

const tenantSelect = `
	SELECT t.id, t.name, t.tenant_id, t.client_id, t.auth_method, t.secret_sealed, t.certificate_pem, t.key_sealed,
	       t.secret_expires, t.created_at, t.updated_at,
	       (SELECT count(*) FROM backup_jobs j WHERE j.m365_tenant_id = t.id), t.labels
	FROM m365_tenants t`

func (d *DB) scanTenant(row pgx.Row) (*m365.Tenant, error) {
	var t m365.Tenant
	if err := row.Scan(&t.ID, &t.Name, &t.TenantID, &t.ClientID, &t.AuthMethod, &t.Secret, &t.CertificatePEM, &t.KeyPEM,
		&t.SecretExpires, &t.CreatedAt, &t.UpdatedAt, &t.Jobs, &t.Labels); err != nil {
		return nil, err
	}
	var err error
	if t.Secret, err = d.open(t.Secret); err != nil {
		return nil, fmt.Errorf("tenant %s secret: %w", t.Name, err)
	}
	if t.KeyPEM, err = d.open(t.KeyPEM); err != nil {
		return nil, fmt.Errorf("tenant %s key: %w", t.Name, err)
	}
	return t.Sanitize(), nil
}

// CreateTenant stores a tenant; the secret and private key are sealed
func (d *DB) CreateTenant(ctx context.Context, t *m365.Tenant) error {
	if t.ID == uuid.Nil {
		t.ID = uuid.New()
	}
	now := time.Now().UTC()
	t.CreatedAt, t.UpdatedAt = now, now
	_, err := d.Pool.Exec(ctx, `
		INSERT INTO m365_tenants (id, name, tenant_id, client_id, auth_method, secret_sealed, certificate_pem, key_sealed, secret_expires, created_at, updated_at, labels)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		t.ID, t.Name, t.TenantID, t.ClientID, t.AuthMethod, d.seal(t.Secret), t.CertificatePEM, d.seal(t.KeyPEM), t.SecretExpires, t.CreatedAt, t.UpdatedAt, Labels(t.Labels).JSON())
	return err
}

// UpdateTenant replaces every editable field (the caller keeps the stored credential
// when the request carries none)
func (d *DB) UpdateTenant(ctx context.Context, t *m365.Tenant) error {
	t.UpdatedAt = time.Now().UTC()
	tag, err := d.Pool.Exec(ctx, `
		UPDATE m365_tenants
		SET name = $2, tenant_id = $3, client_id = $4, auth_method = $5, secret_sealed = $6, certificate_pem = $7,
		    key_sealed = $8, secret_expires = $9, updated_at = $10, labels = $11
		WHERE id = $1`,
		t.ID, t.Name, t.TenantID, t.ClientID, t.AuthMethod, d.seal(t.Secret), t.CertificatePEM, d.seal(t.KeyPEM), t.SecretExpires, t.UpdatedAt, Labels(t.Labels).JSON())
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// GetTenantByID returns the tenant within scope with its credentials opened
func (d *DB) GetTenantByID(ctx context.Context, id uuid.UUID, scope Scope) (*m365.Tenant, error) {
	where, args := scope.SQL("t.labels", []any{id})
	t, err := d.scanTenant(d.Pool.QueryRow(ctx, tenantSelect+` WHERE t.id = $1 AND `+where, args...))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return t, err
}

// ListTenants returns the tenants within scope ordered by name
func (d *DB) ListTenants(ctx context.Context, scope Scope) ([]*m365.Tenant, error) {
	where, args := scope.SQL("t.labels", nil)
	rows, err := d.Pool.Query(ctx, tenantSelect+` WHERE `+where+` ORDER BY t.name ASC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*m365.Tenant
	for rows.Next() {
		t, err := d.scanTenant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// DeleteTenant removes a tenant that no job references (ErrTenantInUse otherwise)
func (d *DB) DeleteTenant(ctx context.Context, id uuid.UUID) error {
	var jobs int
	if err := d.Pool.QueryRow(ctx, `SELECT count(*) FROM backup_jobs WHERE m365_tenant_id = $1`, id).Scan(&jobs); err != nil {
		return err
	}
	if jobs > 0 {
		return ErrTenantInUse
	}
	tag, err := d.Pool.Exec(ctx, `DELETE FROM m365_tenants WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
