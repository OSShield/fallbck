package db

import (
	"context"
	_ "embed"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/osshield/fallbck/pkg/config"
)

//go:embed migrations/001_initial_schema.sql
var initialSchemaSQL string

// DB wraps the pgx connection pool and exposes repository operations
type DB struct {
	Pool *pgxpool.Pool
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

// Migrate applies the schema migrations to PostgreSQL
func (d *DB) Migrate(ctx context.Context) error {
	slog.Info("Running PostgreSQL database migrations...")
	_, err := d.Pool.Exec(ctx, initialSchemaSQL)
	if err != nil {
		return fmt.Errorf("migration error: %w", err)
	}
	slog.Info("Database migrations applied successfully")
	return nil
}
