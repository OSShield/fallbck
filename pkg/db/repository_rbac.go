package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Role is a named set of permissions. Built-in roles are defined in code and
// rewritten at every start; they cannot be edited, only cloned.
type Role struct {
	Name        string    `json:"name"`
	Builtin     bool      `json:"builtin"`
	Description string    `json:"description"`
	Permissions []string  `json:"permissions"`
	Bindings    int       `json:"bindings"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Binding kinds
const (
	BindingUser  = "user"
	BindingGroup = "group"
)

// RoleBinding grants a role to a user (verified OIDC email) or a group (groups claim
// value) on the objects whose labels contain the selector (empty: everything)
type RoleBinding struct {
	ID        uuid.UUID `json:"id"`
	Kind      string    `json:"kind"`
	Subject   string    `json:"subject"`
	Role      string    `json:"role"`
	Selector  Labels    `json:"selector"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
	// Permissions of the role (joined)
	Permissions []string `json:"permissions,omitempty"`
}

// ErrLastAdmin refuses removing the last binding that can manage access
var ErrLastAdmin = errors.New("this is the last binding that grants rbac:manage on everything")

// SyncBuiltinRoles writes the built-in roles' permissions (called at every start, so
// a new permission reaches the built-ins without a migration)
func (d *DB) SyncBuiltinRoles(ctx context.Context, roles map[string][]string, descriptions map[string]string) error {
	for name, perms := range roles {
		if _, err := d.Pool.Exec(ctx, `
			INSERT INTO roles (name, builtin, description, permissions) VALUES ($1, TRUE, $2, $3)
			ON CONFLICT (name) DO UPDATE SET builtin = TRUE, description = EXCLUDED.description, permissions = EXCLUDED.permissions, updated_at = NOW()`,
			name, descriptions[name], perms); err != nil {
			return fmt.Errorf("built-in role %s: %w", name, err)
		}
	}
	return nil
}

const roleSelect = `SELECT r.name, r.builtin, r.description, r.permissions, r.created_at, r.updated_at,
	(SELECT count(*) FROM role_bindings b WHERE b.role = r.name) + (SELECT count(*) FROM api_keys k WHERE k.role = r.name AND k.revoked_at IS NULL)
	FROM roles r`

func scanRole(row pgx.Row) (*Role, error) {
	var r Role
	err := row.Scan(&r.Name, &r.Builtin, &r.Description, &r.Permissions, &r.CreatedAt, &r.UpdatedAt, &r.Bindings)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (d *DB) ListRoles(ctx context.Context) ([]*Role, error) {
	rows, err := d.Pool.Query(ctx, roleSelect+` ORDER BY r.builtin DESC, r.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Role{}
	for rows.Next() {
		r, err := scanRole(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (d *DB) GetRole(ctx context.Context, name string) (*Role, error) {
	return scanRole(d.Pool.QueryRow(ctx, roleSelect+` WHERE r.name = $1`, name))
}

// CreateRole stores a custom role
func (d *DB) CreateRole(ctx context.Context, r *Role) error {
	_, err := d.Pool.Exec(ctx, `INSERT INTO roles (name, builtin, description, permissions) VALUES ($1, FALSE, $2, $3)`, r.Name, r.Description, r.Permissions)
	return err
}

// UpdateRole replaces a custom role's description and permissions (built-ins: ErrNotFound)
func (d *DB) UpdateRole(ctx context.Context, r *Role) error {
	tag, err := d.Pool.Exec(ctx, `UPDATE roles SET description = $2, permissions = $3, updated_at = NOW() WHERE name = $1 AND NOT builtin`, r.Name, r.Description, r.Permissions)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteRole removes a custom role nothing is bound to (ErrInUse otherwise)
func (d *DB) DeleteRole(ctx context.Context, name string) error {
	tag, err := d.Pool.Exec(ctx, `DELETE FROM roles WHERE name = $1 AND NOT builtin`, name)
	if err != nil {
		if strings.Contains(err.Error(), "foreign key") {
			return ErrInUse
		}
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ScopedBindingsOfRole counts bindings and live API keys of a role with a non-empty
// selector (a role that gains a global-only permission must have none)
func (d *DB) ScopedBindingsOfRole(ctx context.Context, role string) (int, error) {
	var n int
	err := d.Pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM role_bindings WHERE role = $1 AND selector <> '{}'::jsonb) +
		(SELECT count(*) FROM api_keys WHERE role = $1 AND selector <> '{}'::jsonb AND revoked_at IS NULL)`, role).Scan(&n)
	return n, err
}

const bindingSelect = `SELECT b.id, b.kind, b.subject, b.role, b.selector, b.created_by, b.created_at, r.permissions
	FROM role_bindings b JOIN roles r ON r.name = b.role`

func scanBinding(row pgx.Row) (*RoleBinding, error) {
	var b RoleBinding
	err := row.Scan(&b.ID, &b.Kind, &b.Subject, &b.Role, &b.Selector, &b.CreatedBy, &b.CreatedAt, &b.Permissions)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &b, nil
}

func (d *DB) queryBindings(ctx context.Context, sql string, args ...any) ([]*RoleBinding, error) {
	rows, err := d.Pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*RoleBinding{}
	for rows.Next() {
		b, err := scanBinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (d *DB) ListBindings(ctx context.Context) ([]*RoleBinding, error) {
	return d.queryBindings(ctx, bindingSelect+` ORDER BY b.kind, lower(b.subject), b.role`)
}

// BindingsFor returns the bindings of a user (email, case-insensitive; "" matches
// none) and of the groups it belongs to, with their roles' permissions
func (d *DB) BindingsFor(ctx context.Context, email string, groups []string) ([]*RoleBinding, error) {
	if groups == nil {
		groups = []string{}
	}
	return d.queryBindings(ctx, bindingSelect+`
		WHERE (b.kind = 'user' AND $1 <> '' AND lower(b.subject) = lower($1)) OR (b.kind = 'group' AND b.subject = ANY($2))`, email, groups)
}

func (d *DB) GetBinding(ctx context.Context, id uuid.UUID) (*RoleBinding, error) {
	return scanBinding(d.Pool.QueryRow(ctx, bindingSelect+` WHERE b.id = $1`, id))
}

func (d *DB) CreateBinding(ctx context.Context, b *RoleBinding) error {
	if b.ID == uuid.Nil {
		b.ID = uuid.New()
	}
	b.CreatedAt = time.Now().UTC()
	b.Selector = b.Selector.OrEmpty()
	_, err := d.Pool.Exec(ctx, `INSERT INTO role_bindings (id, kind, subject, role, selector, created_by, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		b.ID, b.Kind, b.Subject, b.Role, b.Selector.JSON(), b.CreatedBy, b.CreatedAt)
	return err
}

// DeleteBinding removes a binding, refusing (ErrLastAdmin) to remove the last one
// that grants rbac:manage with an empty selector, which would lock everyone out
func (d *DB) DeleteBinding(ctx context.Context, id uuid.UUID) error {
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `LOCK TABLE role_bindings IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `DELETE FROM role_bindings WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	var admins int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM role_bindings b JOIN roles r ON r.name = b.role
		WHERE 'rbac:manage' = ANY(r.permissions) AND b.selector = '{}'::jsonb`).Scan(&admins); err != nil {
		return err
	}
	if admins == 0 {
		return ErrLastAdmin
	}
	return tx.Commit(ctx)
}

// BootstrapAdmin binds the built-in admin role globally to email when no binding
// exists yet (the first sign-in on a fresh instance). Reports whether it did.
func (d *DB) BootstrapAdmin(ctx context.Context, email, role string) (bool, error) {
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `LOCK TABLE role_bindings IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		return false, err
	}
	tag, err := tx.Exec(ctx, `INSERT INTO role_bindings (id, kind, subject, role, selector, created_by)
		SELECT $1, 'user', $2, $3, '{}'::jsonb, 'bootstrap' WHERE NOT EXISTS (SELECT 1 FROM role_bindings)`, uuid.New(), email, role)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, tx.Commit(ctx)
}

// ---- audit log ---------------------------------------------------------------------

// AuditEntry is one row of the append-only audit log
type AuditEntry struct {
	ID           int64           `json:"id"`
	At           time.Time       `json:"at"`
	ActorKind    string          `json:"actor_kind"`
	Actor        string          `json:"actor"`
	Action       string          `json:"action"`
	ResourceKind string          `json:"resource_kind"`
	ResourceID   string          `json:"resource_id"`
	ResourceName string          `json:"resource_name"`
	Labels       Labels          `json:"labels"`
	SourceIP     string          `json:"source_ip"`
	Details      json.RawMessage `json:"details,omitempty"`
}

func (d *DB) WriteAudit(ctx context.Context, e *AuditEntry) error {
	details := e.Details
	if len(details) == 0 {
		details = json.RawMessage("{}")
	}
	return d.Pool.QueryRow(ctx, `INSERT INTO audit_log (actor_kind, actor, action, resource_kind, resource_id, resource_name, labels, source_ip, details)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id, at`,
		e.ActorKind, e.Actor, e.Action, e.ResourceKind, e.ResourceID, e.ResourceName, e.Labels.JSON(), e.SourceIP, string(details)).Scan(&e.ID, &e.At)
}

// AuditFilter narrows ListAudit; empty fields match everything
type AuditFilter struct {
	Actor        string
	Action       string // prefix match: "job" matches job.create, job.delete...
	ResourceKind string
	From, To     *time.Time
	Limit        int
}

// ListAudit returns the newest entries within scope (on the labels the object had
// at the time) matching the filter
func (d *DB) ListAudit(ctx context.Context, f AuditFilter, scope Scope) ([]*AuditEntry, error) {
	if f.Limit <= 0 || f.Limit > 5000 {
		f.Limit = 500
	}
	conds := []string{}
	args := []any{f.Limit}
	add := func(cond string, v any) {
		args = append(args, v)
		conds = append(conds, fmt.Sprintf(cond, len(args)))
	}
	if f.Actor != "" {
		add("actor ILIKE '%%' || $%d || '%%'", f.Actor)
	}
	if f.Action != "" {
		add("action LIKE $%d || '%%'", f.Action)
	}
	if f.ResourceKind != "" {
		add("resource_kind = $%d", f.ResourceKind)
	}
	if f.From != nil {
		add("at >= $%d", *f.From)
	}
	if f.To != nil {
		add("at < $%d", *f.To)
	}
	where, args := scope.SQL("labels", args)
	conds = append(conds, where)
	rows, err := d.Pool.Query(ctx, `SELECT id, at, actor_kind, actor, action, resource_kind, resource_id, resource_name, labels, source_ip, details
		FROM audit_log WHERE `+strings.Join(conds, " AND ")+` ORDER BY at DESC, id DESC LIMIT $1`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		var details []byte
		if err := rows.Scan(&e.ID, &e.At, &e.ActorKind, &e.Actor, &e.Action, &e.ResourceKind, &e.ResourceID, &e.ResourceName, &e.Labels, &e.SourceIP, &details); err != nil {
			return nil, err
		}
		if len(details) > 0 && string(details) != "{}" {
			e.Details = details
		}
		out = append(out, &e)
	}
	return out, rows.Err()
}
