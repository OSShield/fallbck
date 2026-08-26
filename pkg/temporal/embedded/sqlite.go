//go:build sqlite

package embedded

import (
	"fmt"
	"os"

	"github.com/google/uuid"
	"go.temporal.io/server/common/config"
	sqliteplugin "go.temporal.io/server/common/persistence/sql/sqlplugin/sqlite"
	sqliteschema "go.temporal.io/server/schema/sqlite"
)

// setupSQLite builds an in-memory (or file) SQLite datastore and pre-creates the schema
// and namespace. Only compiled with the `sqlite` build tag (tests); the production binary
// does not carry the SQLite driver.
func setupSQLite(cfg Config) (*config.SQL, error) {
	sqlCfg := &config.SQL{PluginName: sqliteplugin.PluginName}
	if cfg.SQLiteFile == "" {
		sqlCfg.ConnectAttributes = map[string]string{"mode": "memory", "cache": "shared"}
		sqlCfg.DatabaseName = uuid.NewString()
	} else {
		sqlCfg.ConnectAttributes = map[string]string{"mode": "rwc"}
		sqlCfg.DatabaseName = cfg.SQLiteFile
	}

	// In-memory databases are initialised by the plugin itself on connect; a file
	// database needs the schema applied once when it does not exist yet.
	needSetup := false
	if cfg.SQLiteFile != "" {
		if _, err := os.Stat(cfg.SQLiteFile); os.IsNotExist(err) {
			needSetup = true
		}
	}
	if needSetup {
		if err := sqliteschema.SetupSchema(sqlCfg); err != nil {
			return nil, fmt.Errorf("failed to set up sqlite schema: %w", err)
		}
	}

	ns, err := sqliteschema.NewNamespaceConfig(cfg.ClusterName, cfg.Namespace, false, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build sqlite namespace config: %w", err)
	}
	if err := sqliteschema.CreateNamespaces(sqlCfg, ns); err != nil {
		return nil, fmt.Errorf("failed to create sqlite namespace: %w", err)
	}
	return sqlCfg, nil
}
