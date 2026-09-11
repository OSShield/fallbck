package dbbackup

import (
	"context"
	"fmt"
	"strings"

	dbspec "github.com/osshield/fallbck/pkg/dbbackup"
)

// ServerVersion is the minimum a caller needs to pick matching client tools before a
// run: the kubernetes agent uses it to choose the dump pod's image tag.
type ServerVersion struct {
	Major   int
	Flavor  string // postgres, mysql, mariadb
	Version string
}

// ProbeServerVersion connects with the run's credentials and reads the server version.
// MongoDB is not supported (the agent carries no driver): the caller falls back to its
// default image.
func ProbeServerVersion(ctx context.Context, spec *dbspec.Spec, creds dbspec.Credentials) (ServerVersion, error) {
	switch spec.Engine {
	case dbspec.EnginePostgres:
		q, err := pgConnect(ctx, creds)
		if err != nil {
			return ServerVersion{}, fmt.Errorf("connecting to PostgreSQL at %s:%d: %w", creds.Host, creds.Port, err)
		}
		defer q.close()
		var vnum int
		var vstr string
		if err := q.queryRow(ctx, "SELECT current_setting('server_version_num')::int, current_setting('server_version')", &vnum, &vstr); err != nil {
			return ServerVersion{}, fmt.Errorf("reading server version: %w", err)
		}
		return ServerVersion{Major: vnum / 10000, Flavor: "postgres", Version: strings.Fields(vstr + " ")[0]}, nil
	case dbspec.EngineMySQL:
		q, err := mysqlConnect(ctx, creds)
		if err != nil {
			return ServerVersion{}, fmt.Errorf("connecting to MySQL at %s:%d: %w", creds.Host, creds.Port, err)
		}
		defer q.close()
		var ver string
		if err := q.queryRow(ctx, "SELECT VERSION()", &ver); err != nil {
			return ServerVersion{}, fmt.Errorf("reading server version: %w", err)
		}
		maj, _, _ := parseServerVersion(ver)
		flavor := "mysql"
		if strings.Contains(strings.ToLower(ver), "mariadb") {
			flavor = "mariadb"
		}
		return ServerVersion{Major: maj, Flavor: flavor, Version: ver}, nil
	}
	return ServerVersion{}, fmt.Errorf("version probe not supported for engine %q", spec.Engine)
}
