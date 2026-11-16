package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/osshield/fallbck/pkg/remote"
)

// ErrRemoteInUse is returned when a remote still has jobs
var ErrRemoteInUse = errors.New("remote is referenced by backup jobs")

// remoteConfig is the remotes.config column: the backend settings of remote.Remote
type remoteConfig struct {
	Provider   string   `json:"provider,omitempty"`
	Region     string   `json:"region,omitempty"`
	Endpoint   string   `json:"endpoint,omitempty"`
	PathStyle  bool     `json:"path_style,omitempty"`
	Account    string   `json:"account,omitempty"`
	Host       string   `json:"host,omitempty"`
	Port       int      `json:"port,omitempty"`
	User       string   `json:"user,omitempty"`
	Domain     string   `json:"domain,omitempty"`
	KnownHosts []string `json:"known_hosts,omitempty"`
	URL        string   `json:"url,omitempty"`
	Vendor     string   `json:"vendor,omitempty"`
}

func configOf(r *remote.Remote) remoteConfig {
	return remoteConfig{Provider: r.Provider, Region: r.Region, Endpoint: r.Endpoint, PathStyle: r.PathStyle,
		Account: r.Account, Host: r.Host, Port: r.Port, User: r.User, Domain: r.Domain,
		KnownHosts: r.KnownHosts, URL: r.URL, Vendor: r.Vendor}
}

func (c remoteConfig) apply(r *remote.Remote) {
	r.Provider, r.Region, r.Endpoint, r.PathStyle = c.Provider, c.Region, c.Endpoint, c.PathStyle
	r.Account, r.Host, r.Port, r.User, r.Domain = c.Account, c.Host, c.Port, c.User, c.Domain
	r.KnownHosts, r.URL, r.Vendor = c.KnownHosts, c.URL, c.Vendor
}

// sealSecrets stores the credential as one sealed JSON document ("" when unset)
func (d *DB) sealSecrets(s remote.Secrets) (string, error) {
	if s.IsZero() {
		return "", nil
	}
	data, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	return d.seal(string(data)), nil
}

const remoteSelect = `
	SELECT r.id, r.name, r.backend, r.auth_method, r.config, r.secrets_sealed, r.created_at, r.updated_at,
	       (SELECT count(*) FROM backup_jobs j WHERE j.remote_id = r.id), r.labels
	FROM remotes r`

func (d *DB) scanRemote(row pgx.Row) (*remote.Remote, error) {
	var (
		r        remote.Remote
		cfg      []byte
		sealed   string
		settings remoteConfig
	)
	if err := row.Scan(&r.ID, &r.Name, &r.Backend, &r.AuthMethod, &cfg, &sealed, &r.CreatedAt, &r.UpdatedAt, &r.Jobs, &r.Labels); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(cfg, &settings); err != nil {
		return nil, fmt.Errorf("remote %s config: %w", r.Name, err)
	}
	settings.apply(&r)
	plain, err := d.open(sealed)
	if err != nil {
		return nil, fmt.Errorf("remote %s credential: %w", r.Name, err)
	}
	if plain != "" {
		if err := json.Unmarshal([]byte(plain), &r.Secrets); err != nil {
			return nil, fmt.Errorf("remote %s credential: %w", r.Name, err)
		}
	}
	return r.Sanitize(), nil
}

// CreateRemote stores a validated remote; the credential is sealed
func (d *DB) CreateRemote(ctx context.Context, r *remote.Remote) error {
	if r.ID == uuid.Nil {
		r.ID = uuid.New()
	}
	sealed, err := d.sealSecrets(r.Secrets)
	if err != nil {
		return err
	}
	cfg, err := json.Marshal(configOf(r))
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	r.CreatedAt, r.UpdatedAt = now, now
	_, err = d.Pool.Exec(ctx, `
		INSERT INTO remotes (id, name, backend, auth_method, config, secrets_sealed, labels, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)`,
		r.ID, r.Name, r.Backend, r.AuthMethod, cfg, sealed, Labels(r.Labels).JSON(), now)
	r.Sanitize()
	return err
}

// UpdateRemote replaces every editable field (the caller keeps the stored
// credential when the request carries none)
func (d *DB) UpdateRemote(ctx context.Context, r *remote.Remote) error {
	sealed, err := d.sealSecrets(r.Secrets)
	if err != nil {
		return err
	}
	cfg, err := json.Marshal(configOf(r))
	if err != nil {
		return err
	}
	r.UpdatedAt = time.Now().UTC()
	tag, err := d.Pool.Exec(ctx, `
		UPDATE remotes SET name = $2, backend = $3, auth_method = $4, config = $5, secrets_sealed = $6,
		       labels = $7, updated_at = $8
		WHERE id = $1`,
		r.ID, r.Name, r.Backend, r.AuthMethod, cfg, sealed, Labels(r.Labels).JSON(), r.UpdatedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	r.Sanitize()
	return nil
}

// GetRemoteByID returns the remote within scope with its credential opened
func (d *DB) GetRemoteByID(ctx context.Context, id uuid.UUID, scope Scope) (*remote.Remote, error) {
	where, args := scope.SQL("r.labels", []any{id})
	r, err := d.scanRemote(d.Pool.QueryRow(ctx, remoteSelect+` WHERE r.id = $1 AND `+where, args...))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return r, err
}

// ListRemotes returns the remotes within scope ordered by name
func (d *DB) ListRemotes(ctx context.Context, scope Scope) ([]*remote.Remote, error) {
	where, args := scope.SQL("r.labels", nil)
	rows, err := d.Pool.Query(ctx, remoteSelect+` WHERE `+where+` ORDER BY r.name ASC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*remote.Remote{}
	for rows.Next() {
		r, err := d.scanRemote(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeleteRemote removes a remote that no job references (ErrRemoteInUse otherwise)
func (d *DB) DeleteRemote(ctx context.Context, id uuid.UUID) error {
	var jobs int
	if err := d.Pool.QueryRow(ctx, `SELECT count(*) FROM backup_jobs WHERE remote_id = $1`, id).Scan(&jobs); err != nil {
		return err
	}
	if jobs > 0 {
		return ErrRemoteInUse
	}
	tag, err := d.Pool.Exec(ctx, `DELETE FROM remotes WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// RemoteJobsWithoutProfile names the jobs of a remote that rely on its stored
// credential (they name no agent profile)
func (d *DB) RemoteJobsWithoutProfile(ctx context.Context, id uuid.UUID) ([]string, error) {
	rows, err := d.Pool.Query(ctx, `SELECT name FROM backup_jobs WHERE remote_id = $1 AND COALESCE(remote_config->>'profile', '') = '' ORDER BY name`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		names = append(names, n)
	}
	return names, rows.Err()
}
