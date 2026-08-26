package embedded

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"go.temporal.io/server/common/config"
	"go.temporal.io/server/tools/common/schema"
	toolsql "go.temporal.io/server/tools/sql"

	// Registers the postgres12 / postgres12_pgx persistence plugins
	_ "go.temporal.io/server/common/persistence/sql/sqlplugin/postgresql"
)

// Embedded schema names inside go.temporal.io/server/schema
const (
	postgresTemporalSchema   = "postgresql/v12/temporal"
	postgresVisibilitySchema = "postgresql/v12/visibility"
)

// BootstrapSchema creates the Temporal databases if missing and applies the embedded,
// versioned schema up to the version shipped with the linked server. It is idempotent
// and safe to run on every start. Creating databases requires the CREATEDB privilege;
// if that is not available, pre-create the databases and this only applies the schema.
func BootstrapSchema(ctx context.Context, cfg Config, logger *slog.Logger) error {
	cfg = cfg.withDefaults()
	if cfg.Persistence != PersistencePostgres {
		return nil
	}
	if logger == nil {
		logger = slog.Default()
	}
	tlogger := NewLogger(logger)

	targets := []struct{ database, schemaName string }{
		{cfg.TemporalDatabase, postgresTemporalSchema},
		{cfg.VisibilityDatabase, postgresVisibilitySchema},
	}
	for _, t := range targets {
		if err := ctx.Err(); err != nil {
			return err
		}
		sqlCfg, err := cfg.postgresSQLConfig(t.database)
		if err != nil {
			return err
		}

		// 1. CREATE DATABASE (DoCreateDatabase mutates DatabaseName → pass a copy)
		createCfg := *sqlCfg
		if err := toolsql.DoCreateDatabase(&createCfg, "postgres", tlogger); err != nil {
			if !isAlreadyExists(err) {
				return fmt.Errorf("failed to create temporal database %q (needs CREATEDB, or pre-create it): %w", t.database, err)
			}
		} else {
			logger.Info("Created Temporal database", "database", t.database)
		}

		// 2. Initial schema when the version table is absent, then roll forward
		if err := applySchema(sqlCfg, t.database, t.schemaName, logger); err != nil {
			return err
		}
	}
	return nil
}

func applySchema(sqlCfg *config.SQL, database, schemaName string, logger *slog.Logger) error {
	conn, err := toolsql.NewConnection(sqlCfg, NewLogger(logger))
	if err != nil {
		return fmt.Errorf("failed to connect to temporal database %q: %w", database, err)
	}
	defer conn.Close()

	current, err := conn.ReadSchemaVersion()
	if err != nil || current == "" {
		// Like `temporal-sql-tool setup-schema -v 0.0`: create only the schema version
		// tables at 0.0; the versioned migrations below build the actual schema. (Passing
		// SchemaName here would apply the full current schema AND stamp 0.0, after which
		// the update task would replay every migration on top of it.)
		logger.Info("Initialising Temporal schema", "database", database, "schema", schemaName)
		setup := schema.NewSetupSchemaTask(conn, &schema.SetupConfig{
			InitialVersion: "0.0",
		}, NewLogger(logger))
		if err := setup.Run(); err != nil {
			return fmt.Errorf("failed to set up temporal schema in %q: %w", database, err)
		}
		current = "0.0"
	}

	update := schema.NewUpdateSchemaTask(conn, &schema.UpdateConfig{
		DBName:     database,
		SchemaName: schemaName,
	}, NewLogger(logger))
	if err := update.Run(); err != nil {
		return fmt.Errorf("failed to update temporal schema in %q: %w", database, err)
	}

	final, err := conn.ReadSchemaVersion()
	if err != nil {
		return fmt.Errorf("failed to read temporal schema version in %q: %w", database, err)
	}
	if final != current {
		logger.Info("Temporal schema updated", "database", database, "from", current, "to", final)
	} else {
		logger.Info("Temporal schema is up to date", "database", database, "version", final)
	}
	return nil
}

func isAlreadyExists(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "already exists") || strings.Contains(msg, "42p04")
}
