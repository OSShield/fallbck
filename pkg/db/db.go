package db

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/osshield/fallbck/pkg/config"
	"github.com/osshield/fallbck/pkg/secrets"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// DB wraps the pgx connection pool and exposes repository operations
type DB struct {
	Pool *pgxpool.Pool
	// Sealer protects stored secrets (target API tokens, encryption keys) at rest.
	// nil (tests) stores them in clear.
	Sealer *secrets.Sealer
}

// seal / open apply the Sealer when one is configured. open accepts legacy plaintext
// values (rows written before the master key existed) until SealLegacySecrets has
// rewritten them.
func (d *DB) seal(plain string) string {
	if d.Sealer == nil || plain == "" {
		return plain
	}
	return d.Sealer.SealString(plain)
}

func (d *DB) open(stored string) (string, error) {
	if d.Sealer == nil || !secrets.IsSealed(stored) {
		return stored, nil
	}
	return d.Sealer.OpenString(stored)
}

// HasSealedSecrets reports whether any stored secret is already sealed, i.e. a master
// key existed before. A freshly generated key then means the key file was lost.
func (d *DB) HasSealedSecrets(ctx context.Context) (bool, error) {
	var n int
	err := d.Pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM backup_targets WHERE auth_token_encrypted LIKE 'v1:%') +
		(SELECT count(*) FROM target_keys WHERE key_sealed LIKE 'v1:%') +
		(SELECT count(*) FROM m365_tenants WHERE secret_sealed LIKE 'v1:%') +
		(SELECT count(*) FROM backup_jobs WHERE db_config->>'password' LIKE 'v1:%')`).Scan(&n)
	return n > 0, err
}

// SealLegacySecrets rewrites secrets stored in clear before the master key existed.
// It returns how many rows were sealed. Safe to run at every start.
func (d *DB) SealLegacySecrets(ctx context.Context) (int, error) {
	if d.Sealer == nil {
		return 0, nil
	}
	rows, err := d.Pool.Query(ctx, `SELECT id, auth_token_encrypted FROM backup_targets WHERE auth_token_encrypted <> '' AND auth_token_encrypted NOT LIKE 'v1:%'`)
	if err != nil {
		return 0, err
	}
	type row struct {
		id    uuid.UUID
		token string
	}
	var pending []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.token); err != nil {
			rows.Close()
			return 0, err
		}
		pending = append(pending, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for _, r := range pending {
		if _, err := d.Pool.Exec(ctx, `UPDATE backup_targets SET auth_token_encrypted = $2 WHERE id = $1`, r.id, d.seal(r.token)); err != nil {
			return 0, err
		}
	}
	// Database job passwords lived in clear inside db_config before 0.15
	rows, err = d.Pool.Query(ctx, `SELECT id, db_config->>'password' FROM backup_jobs WHERE job_type = 'database' AND COALESCE(db_config->>'password', '') <> '' AND db_config->>'password' NOT LIKE 'v1:%'`)
	if err != nil {
		return 0, err
	}
	var jobs []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.token); err != nil {
			rows.Close()
			return 0, err
		}
		jobs = append(jobs, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for _, r := range jobs {
		if _, err := d.Pool.Exec(ctx, `UPDATE backup_jobs SET db_config = jsonb_set(db_config, '{password}', to_jsonb($2::text)) WHERE id = $1`, r.id, d.seal(r.token)); err != nil {
			return 0, err
		}
	}
	return len(pending) + len(jobs), nil
}

// New creates a new database connection pool and applies migrations if enabled
func New(ctx context.Context, cfg config.DatabaseConfig) (*DB, error) {
	poolConfig, err := pgxpool.ParseConfig(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse postgres connection url: %w", err)
	}

	if cfg.MaxOpenConns > 0 {
		poolConfig.MaxConns = int32(cfg.MaxOpenConns)
	}
	if cfg.MaxIdleConns > 0 {
		poolConfig.MinConns = int32(cfg.MaxIdleConns)
	}
	if cfg.ConnMaxLifetime > 0 {
		poolConfig.MaxConnLifetime = cfg.ConnMaxLifetime
	}

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to postgres: %w", err)
	}

	// Verify connection
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping postgres: %w", err)
	}

	db := &DB{Pool: pool}

	if cfg.AutoMigrate {
		if err := db.Migrate(ctx); err != nil {
			pool.Close()
			return nil, fmt.Errorf("failed to execute database migrations: %w", err)
		}
	}

	return db, nil
}

// Close closes the underlying pool
func (d *DB) Close() {
	if d.Pool != nil {
		d.Pool.Close()
	}
}

// Migration is a single embedded SQL migration file
type Migration struct {
	Version int
	Name    string
	SQL     string
}

// LoadMigrations returns the embedded migrations ordered by version.
// Files are named NNN_description.sql; the numeric prefix is the version.
func LoadMigrations() ([]Migration, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("failed to read embedded migrations: %w", err)
	}

	var migrations []Migration
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".sql") {
			continue
		}
		prefix, _, ok := strings.Cut(name, "_")
		if !ok {
			return nil, fmt.Errorf("migration %q is not named NNN_description.sql", name)
		}
		version, err := strconv.Atoi(prefix)
		if err != nil {
			return nil, fmt.Errorf("migration %q has a non-numeric version prefix: %w", name, err)
		}
		content, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			return nil, fmt.Errorf("failed to read migration %q: %w", name, err)
		}
		migrations = append(migrations, Migration{Version: version, Name: name, SQL: string(content)})
	}

	sort.Slice(migrations, func(i, j int) bool { return migrations[i].Version < migrations[j].Version })
	for i := 1; i < len(migrations); i++ {
		if migrations[i].Version == migrations[i-1].Version {
			return nil, fmt.Errorf("duplicate migration version %d (%s, %s)", migrations[i].Version, migrations[i-1].Name, migrations[i].Name)
		}
	}
	return migrations, nil
}

// Migrate applies all pending schema migrations to PostgreSQL. Each migration runs in
// its own transaction and is recorded in schema_migrations so it is applied exactly once.
func (d *DB) Migrate(ctx context.Context) error {
	migrations, err := LoadMigrations()
	if err != nil {
		return err
	}

	if _, err := d.Pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    INTEGER PRIMARY KEY,
			name       TEXT NOT NULL,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`); err != nil {
		return fmt.Errorf("failed to create schema_migrations table: %w", err)
	}

	applied := map[int]bool{}
	rows, err := d.Pool.Query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return fmt.Errorf("failed to read schema_migrations: %w", err)
	}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return err
		}
		applied[v] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	pending := 0
	for _, m := range migrations {
		if applied[m.Version] {
			continue
		}
		pending++
		slog.Info("Applying database migration", "version", m.Version, "name", m.Name)

		tx, err := d.Pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("failed to begin transaction for migration %s: %w", m.Name, err)
		}
		if _, err := tx.Exec(ctx, m.SQL); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("migration %s failed: %w", m.Name, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version, name) VALUES ($1, $2)`, m.Version, m.Name); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("failed to record migration %s: %w", m.Name, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("failed to commit migration %s: %w", m.Name, err)
		}
	}

	if pending == 0 {
		slog.Info("Database schema is up to date", "version", migrations[len(migrations)-1].Version)
	} else {
		slog.Info("Database migrations applied successfully", "applied", pending)
	}
	return nil
}
