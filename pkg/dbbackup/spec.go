// Package dbbackup holds the database backup job specification, agent-side credential
// profiles and the run manifest. It is shared by the server (validation, redaction),
// the agent (execution) and the configuration loader, so it must stay free of
// process-execution and platform dependencies.
package dbbackup

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Supported engines
const (
	EnginePostgres = "postgres"
	EngineMySQL    = "mysql"
	EngineMongoDB  = "mongodb"
)

// Engines lists the supported engines in display order
var Engines = []string{EnginePostgres, EngineMySQL, EngineMongoDB}

var engineAliases = map[string]string{
	"postgres":   EnginePostgres,
	"postgresql": EnginePostgres,
	"pg":         EnginePostgres,
	"mysql":      EngineMySQL,
	"mariadb":    EngineMySQL,
	"mongodb":    EngineMongoDB,
	"mongo":      EngineMongoDB,
}

// NormalizeEngine maps aliases (postgresql, mariadb, mongo) to the canonical engine name
func NormalizeEngine(name string) (string, bool) {
	e, ok := engineAliases[strings.ToLower(strings.TrimSpace(name))]
	return e, ok
}

// DefaultPort returns the engine's default TCP port
func DefaultPort(engine string) int {
	switch engine {
	case EnginePostgres:
		return 5432
	case EngineMySQL:
		return 3306
	case EngineMongoDB:
		return 27017
	}
	return 0
}

// TLS modes (libpq spelling; mapped per engine by the agent)
const (
	TLSDisable    = "disable"
	TLSPrefer     = "prefer"
	TLSRequire    = "require"
	TLSVerifyCA   = "verify-ca"
	TLSVerifyFull = "verify-full"
)

// TLSSpec describes how the agent connects to the database server. File paths refer to
// the agent host.
type TLSSpec struct {
	Mode     string `json:"mode,omitempty" yaml:"mode,omitempty"`
	CAFile   string `json:"ca_file,omitempty" yaml:"ca_file,omitempty"`
	CertFile string `json:"cert_file,omitempty" yaml:"cert_file,omitempty"`
	KeyFile  string `json:"key_file,omitempty" yaml:"key_file,omitempty"`
}

// Compression settings for the spooled dumps. PBS deduplicates and compresses chunks
// itself, so the default is uncompressed dumps.
const (
	CompressionNone = "none"
	CompressionGzip = "gzip"
)

// PostgreSQL backup modes
const (
	PostgresModeDump       = "dump"       // pg_dumpall --globals-only + pg_dump per database
	PostgresModeBasebackup = "basebackup" // pg_basebackup with streamed WAL
	PostgresModeBoth       = "both"
)

// PostgresOptions are the PostgreSQL-specific job settings
type PostgresOptions struct {
	Mode string `json:"mode,omitempty"`
	// Format is "custom" (default, pg_restore) or "plain" (psql)
	Format string `json:"format,omitempty"`
	// Globals dumps roles and tablespaces with pg_dumpall --globals-only (default true)
	Globals *bool `json:"globals,omitempty"`
	// RolePasswords: "auto" (include when superuser), "include", "omit"
	RolePasswords string   `json:"role_passwords,omitempty"`
	ExtraDumpArgs []string `json:"extra_dump_args,omitempty"`
}

// MySQLOptions are the MySQL/MariaDB-specific job settings
type MySQLOptions struct {
	SingleTransaction *bool `json:"single_transaction,omitempty"` // default true
	// IncludeBinlogs fetches the binary logs written since the previous successful run
	IncludeBinlogs bool  `json:"include_binlogs,omitempty"`
	FlushLogs      *bool `json:"flush_logs,omitempty"` // default = IncludeBinlogs
	// IncludeSystemSchemas also dumps the mysql schema when an explicit list is given
	IncludeSystemSchemas bool     `json:"include_system_schemas,omitempty"`
	Routines             *bool    `json:"routines,omitempty"` // default true
	Triggers             *bool    `json:"triggers,omitempty"` // default true
	Events               *bool    `json:"events,omitempty"`   // default true
	ExtraDumpArgs        []string `json:"extra_dump_args,omitempty"`
}

// MongoOptions are the MongoDB-specific job settings
type MongoOptions struct {
	// Oplog captures the oplog during the dump (point-in-time, requires a replica set and
	// dumping all databases); default true when no database list is given
	Oplog                  *bool    `json:"oplog,omitempty"`
	ReadPreference         string   `json:"read_preference,omitempty"`
	AuthSource             string   `json:"auth_source,omitempty"` // default admin
	ReplicaSet             string   `json:"replica_set,omitempty"`
	NumParallelCollections int      `json:"num_parallel_collections,omitempty"`
	ExtraArgs              []string `json:"extra_args,omitempty"`
}

// Spec is the database job configuration stored server-side (backup_jobs.db_config)
// and handed to the agent (with the password redacted) for every run.
type Spec struct {
	Engine string `json:"engine"`
	// Host is a hostname/IP, or a path (leading "/") for a local unix socket
	Host string `json:"host"`
	Port int    `json:"port,omitempty"`
	User string `json:"user,omitempty"`
	// Password is stored server-side; blank means the agent resolves it from Profile
	Password string `json:"password,omitempty"`
	// HasPassword is set on API responses instead of the password itself
	HasPassword bool `json:"has_password,omitempty"`
	// ClearPassword (request only) removes a stored password on update
	ClearPassword bool `json:"clear_password,omitempty"`
	// Profile names the agent-side credential profile (default: the engine name)
	Profile          string   `json:"profile,omitempty"`
	TLS              TLSSpec  `json:"tls"`
	Databases        []string `json:"databases,omitempty"`
	ExcludeDatabases []string `json:"exclude_databases,omitempty"`
	Compression      string   `json:"compression,omitempty"`
	// BackupID overrides the PBS backup group id (default db-<engine>-<host>)
	BackupID string `json:"backup_id,omitempty"`

	Postgres *PostgresOptions `json:"postgres,omitempty"`
	MySQL    *MySQLOptions    `json:"mysql,omitempty"`
	MongoDB  *MongoOptions    `json:"mongodb,omitempty"`
}

// ErrInvalidSpec wraps every validation failure
var ErrInvalidSpec = errors.New("invalid database job configuration")

func specErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidSpec, fmt.Sprintf(format, args...))
}

// Options the agent controls itself; never accepted from job extra args
var deniedExtraArgs = []string{
	"--file", "-f", "--result-file", "-r", "--out", "-o", "--config", "--uri",
	"--password", "-p", "--pgdata", "-D", "--username", "-U", "--host", "-h", "--port",
}

var backupIDRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]*$`)

// Validate normalises the engine name, applies defaults where they are unambiguous and
// rejects inconsistent settings. It is used by the server (job create/update) and by
// the agent before a run.
func (s *Spec) Validate() error {
	if s == nil {
		return specErr("configuration is missing")
	}
	engine, ok := NormalizeEngine(s.Engine)
	if !ok {
		return specErr("unsupported engine %q (postgres, mysql, mongodb)", s.Engine)
	}
	s.Engine = engine
	s.Host = strings.TrimSpace(s.Host)
	if s.Host == "" {
		return specErr("host is required")
	}
	if s.Port < 0 || s.Port > 65535 {
		return specErr("port %d is out of range", s.Port)
	}
	switch s.TLS.Mode {
	case "", TLSDisable, TLSPrefer, TLSRequire, TLSVerifyCA, TLSVerifyFull:
	default:
		return specErr("tls.mode %q is not one of disable, prefer, require, verify-ca, verify-full", s.TLS.Mode)
	}
	switch s.Compression {
	case "":
		s.Compression = CompressionNone
	case CompressionNone, CompressionGzip:
	default:
		return specErr("compression %q is not one of none, gzip", s.Compression)
	}
	if s.BackupID != "" && !backupIDRe.MatchString(s.BackupID) {
		return specErr("backup_id %q may only contain letters, digits, '.', '_' and '-'", s.BackupID)
	}
	for _, list := range [][]string{s.Databases, s.ExcludeDatabases} {
		for i, name := range list {
			name = strings.TrimSpace(name)
			list[i] = name
			if name == "" {
				return specErr("database names must not be empty")
			}
			if strings.HasPrefix(name, "-") {
				return specErr("database name %q must not start with '-'", name)
			}
		}
	}
	s.Databases = dropEmpty(s.Databases)
	s.ExcludeDatabases = dropEmpty(s.ExcludeDatabases)

	switch s.Engine {
	case EnginePostgres:
		if s.MySQL != nil || s.MongoDB != nil {
			return specErr("mysql/mongodb options given for a postgres job")
		}
		if s.Postgres == nil {
			s.Postgres = &PostgresOptions{}
		}
		p := s.Postgres
		switch p.Mode {
		case "":
			p.Mode = PostgresModeDump
		case PostgresModeDump, PostgresModeBasebackup, PostgresModeBoth:
		default:
			return specErr("postgres.mode %q is not one of dump, basebackup, both", p.Mode)
		}
		switch p.Format {
		case "":
			p.Format = "custom"
		case "custom", "plain":
		default:
			return specErr("postgres.format %q is not one of custom, plain", p.Format)
		}
		switch p.RolePasswords {
		case "":
			p.RolePasswords = "auto"
		case "auto", "include", "omit":
		default:
			return specErr("postgres.role_passwords %q is not one of auto, include, omit", p.RolePasswords)
		}
		if err := validateExtraArgs(p.ExtraDumpArgs); err != nil {
			return err
		}
	case EngineMySQL:
		if s.Postgres != nil || s.MongoDB != nil {
			return specErr("postgres/mongodb options given for a mysql job")
		}
		if s.MySQL == nil {
			s.MySQL = &MySQLOptions{}
		}
		if err := validateExtraArgs(s.MySQL.ExtraDumpArgs); err != nil {
			return err
		}
	case EngineMongoDB:
		if s.Postgres != nil || s.MySQL != nil {
			return specErr("postgres/mysql options given for a mongodb job")
		}
		if s.MongoDB == nil {
			s.MongoDB = &MongoOptions{}
		}
		m := s.MongoDB
		if m.Oplog != nil && *m.Oplog && len(s.Databases) > 0 {
			return specErr("mongodb.oplog requires dumping all databases (remove the database list)")
		}
		if m.NumParallelCollections < 0 {
			return specErr("mongodb.num_parallel_collections must not be negative")
		}
		switch m.ReadPreference {
		case "", "primary", "primaryPreferred", "secondary", "secondaryPreferred", "nearest":
		default:
			return specErr("mongodb.read_preference %q is not a valid read preference", m.ReadPreference)
		}
		if err := validateExtraArgs(m.ExtraArgs); err != nil {
			return err
		}
	}
	return nil
}

func validateExtraArgs(args []string) error {
	for _, a := range args {
		if !strings.HasPrefix(a, "--") {
			return specErr("extra argument %q must be a long option (--name[=value])", a)
		}
		name := a
		if i := strings.IndexByte(a, '='); i >= 0 {
			name = a[:i]
		}
		for _, denied := range deniedExtraArgs {
			if name == denied {
				return specErr("extra argument %q is managed by the agent and cannot be overridden", name)
			}
		}
	}
	return nil
}

func dropEmpty(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := in[:0]
	for _, s := range in {
		if s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// Redacted returns a copy without the password (HasPassword tells whether one is stored)
func (s *Spec) Redacted() *Spec {
	if s == nil {
		return nil
	}
	c := *s
	c.HasPassword = s.Password != ""
	c.Password = ""
	c.ClearPassword = false
	if s.Postgres != nil {
		p := *s.Postgres
		c.Postgres = &p
	}
	if s.MySQL != nil {
		m := *s.MySQL
		c.MySQL = &m
	}
	if s.MongoDB != nil {
		m := *s.MongoDB
		c.MongoDB = &m
	}
	return &c
}

// Clone returns a deep copy of the spec
func (s *Spec) Clone() *Spec {
	if s == nil {
		return nil
	}
	c := s.Redacted()
	c.Password = s.Password
	c.HasPassword = s.HasPassword
	c.ClearPassword = s.ClearPassword
	return c
}

var backupIDClean = regexp.MustCompile(`[^a-z0-9._-]+`)

// DefaultBackupID is the PBS backup group id for a database job: db-<engine>-<host>,
// keeping database snapshots apart from the host's filesystem backups.
func DefaultBackupID(s *Spec) string {
	if s == nil {
		return ""
	}
	if s.BackupID != "" {
		return s.BackupID
	}
	host := strings.ToLower(strings.TrimSpace(s.Host))
	if strings.HasPrefix(host, "/") || host == "" {
		host = "local"
	}
	host = backupIDClean.ReplaceAllString(host, "-")
	host = strings.Trim(host, ".-_")
	if host == "" {
		host = "local"
	}
	return fmt.Sprintf("db-%s-%s", s.Engine, host)
}

// Summary is a short human-readable description (UI tables, logs)
func (s *Spec) Summary() string {
	if s == nil {
		return ""
	}
	target := s.Host
	if s.Port != 0 {
		target = fmt.Sprintf("%s:%d", s.Host, s.Port)
	}
	if len(s.Databases) > 0 {
		return fmt.Sprintf("%s @ %s (%s)", s.Engine, target, strings.Join(s.Databases, ", "))
	}
	return fmt.Sprintf("%s @ %s (all databases)", s.Engine, target)
}

// EffectivePort returns the configured port or the engine default
func (s *Spec) EffectivePort() int {
	if s.Port != 0 {
		return s.Port
	}
	return DefaultPort(s.Engine)
}

// IsSocket reports whether Host is a local unix socket path
func (s *Spec) IsSocket() bool {
	return strings.HasPrefix(s.Host, "/")
}

// Bool returns the value of an optional boolean with a default
func Bool(v *bool, def bool) bool {
	if v == nil {
		return def
	}
	return *v
}
