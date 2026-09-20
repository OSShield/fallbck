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
	EngineMSSQL    = "mssql"
)

// Engines lists the supported engines in display order
var Engines = []string{EnginePostgres, EngineMySQL, EngineMongoDB, EngineMSSQL}

var engineAliases = map[string]string{
	"postgres":   EnginePostgres,
	"postgresql": EnginePostgres,
	"pg":         EnginePostgres,
	"mysql":      EngineMySQL,
	"mariadb":    EngineMySQL,
	"mongodb":    EngineMongoDB,
	"mongo":      EngineMongoDB,
	"mssql":      EngineMSSQL,
	"sqlserver":  EngineMSSQL,
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
	case EngineMSSQL:
		return 1433
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
	IncludeSystemSchemas bool `json:"include_system_schemas,omitempty"`
	// PerDatabase dumps every database to its own file instead of one --all-databases
	// file (the mysql schema included), so a single database can be restored on its
	// own; the dumps are taken one after another and are not mutually consistent.
	// An explicit database or exclude list always dumps per database.
	PerDatabase   bool     `json:"per_database,omitempty"`
	Routines      *bool    `json:"routines,omitempty"` // default true
	Triggers      *bool    `json:"triggers,omitempty"` // default true
	Events        *bool    `json:"events,omitempty"`   // default true
	ExtraDumpArgs []string `json:"extra_dump_args,omitempty"`
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

// K8sTarget places the database inside a Kubernetes cluster. Such a job is assigned to
// a kubernetes agent, which dumps the database from a short-lived pod in Namespace that
// runs the engine's own client image.
type K8sTarget struct {
	Namespace string `json:"namespace"`
	// Service is the Service the dump pod connects to (<service>.<namespace>.svc);
	// Spec.Host, when set, is used verbatim instead
	Service string `json:"service,omitempty"`
	// SecretName names a Secret in Namespace holding the credentials: PasswordKey
	// (default "password") and optionally UserKey. A password stored on the job wins.
	SecretName  string `json:"secret_name,omitempty"`
	PasswordKey string `json:"password_key,omitempty"`
	UserKey     string `json:"user_key,omitempty"`
	// ToolsImage overrides the client-tools image of the dump pod (default: the agent's
	// per-engine image template with the tag taken from the detected server version)
	ToolsImage string `json:"tools_image,omitempty"`
}

// SQL Server backup modes
const (
	// MSSQLModeAuto takes a full backup when none exists, the chain was broken or the
	// last one is older than FullEveryDays, and a differential otherwise
	MSSQLModeAuto         = "auto"
	MSSQLModeFull         = "full"
	MSSQLModeDifferential = "differential"
	// MSSQLModeLog backs up the transaction log of databases in the FULL or
	// BULK_LOGGED recovery model (a job of its own on a short schedule)
	MSSQLModeLog = "log"
)

// MSSQLOptions configure SQL Server jobs. Backups are native BACKUP DATABASE / BACKUP
// LOG ... TO DISK files: SQL Server writes them on its own host, the agent picks them
// up, uploads them and deletes them.
type MSSQLOptions struct {
	// Mode is auto (default), full, differential or log
	Mode string `json:"mode,omitempty"`
	// FullEveryDays is the age after which auto mode takes a new full backup (default 7)
	FullEveryDays int `json:"full_every_days,omitempty"`
	// IncludeLog also backs up the transaction log of FULL/BULK_LOGGED databases right
	// after their full or differential backup (not used in log mode)
	IncludeLog bool `json:"include_log,omitempty"`
	// Compression uses SQL Server's native backup compression. Off by default: PBS
	// deduplicates uncompressed backups far better, and Express cannot compress.
	Compression bool `json:"compression,omitempty"`
	// Checksum adds WITH CHECKSUM (default true)
	Checksum *bool `json:"checksum,omitempty"`
	// CopyOnly takes copy-only backups that do not disturb another tool's chain;
	// differentials cannot be based on them, so it requires mode full or log
	CopyOnly bool `json:"copy_only,omitempty"`
	// BackupDir is the directory as SQL Server sees it (default: the instance's
	// default backup path). The SQL Server service account must be able to write it.
	BackupDir string `json:"backup_dir,omitempty"`
	// AgentDir is the same directory as the agent sees it (a UNC share or a bind
	// mount when SQL Server runs elsewhere or in a container); default BackupDir
	AgentDir string `json:"agent_dir,omitempty"`
	// StripeCount splits each backup over this many files (1..16, default 1)
	StripeCount int `json:"stripe_count,omitempty"`
	// MaxTransferSize is WITH MAXTRANSFERSIZE in bytes (a multiple of 64 KiB up to
	// 4 MiB; 0 = server default)
	MaxTransferSize int `json:"max_transfer_size,omitempty"`
}

// EffChecksum / EffFullEveryDays / EffStripeCount apply the defaults
func (o *MSSQLOptions) EffChecksum() bool { return o == nil || o.Checksum == nil || *o.Checksum }
func (o *MSSQLOptions) EffFullEveryDays() int {
	if o == nil || o.FullEveryDays <= 0 {
		return 7
	}
	return o.FullEveryDays
}
func (o *MSSQLOptions) EffStripeCount() int {
	if o == nil || o.StripeCount <= 0 {
		return 1
	}
	return o.StripeCount
}

// Spec is the database job configuration stored server-side (backup_jobs.db_config)
// and handed to the agent (with the password redacted) for every run.
type Spec struct {
	Engine string `json:"engine"`
	// Host is a hostname/IP, or a path (leading "/") for a local unix socket; optional
	// for kubernetes targets that name a Service
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
	MSSQL    *MSSQLOptions    `json:"mssql,omitempty"`

	// Kubernetes is set when the job runs on a kubernetes agent
	Kubernetes *K8sTarget `json:"kubernetes,omitempty"`
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

// dnsLabelRe matches Kubernetes namespace and Service names
var dnsLabelRe = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// Validate normalises the engine name, applies defaults where they are unambiguous and
// rejects inconsistent settings. It is used by the server (job create/update) and by
// the agent before a run.
func (s *Spec) Validate() error {
	if s == nil {
		return specErr("configuration is missing")
	}
	engine, ok := NormalizeEngine(s.Engine)
	if !ok {
		return specErr("unsupported engine %q (postgres, mysql, mongodb, mssql)", s.Engine)
	}
	s.Engine = engine
	s.Host = strings.TrimSpace(s.Host)
	if k := s.Kubernetes; k != nil {
		k.Namespace = strings.TrimSpace(k.Namespace)
		k.Service = strings.TrimSpace(k.Service)
		k.SecretName = strings.TrimSpace(k.SecretName)
		k.ToolsImage = strings.TrimSpace(k.ToolsImage)
		if !dnsLabelRe.MatchString(k.Namespace) {
			return specErr("kubernetes.namespace %q is not a valid namespace name", k.Namespace)
		}
		if k.Service != "" && !dnsLabelRe.MatchString(k.Service) {
			return specErr("kubernetes.service %q is not a valid Service name", k.Service)
		}
		if k.Service == "" && s.Host == "" {
			return specErr("kubernetes.service or host is required")
		}
		if k.SecretName != "" {
			if !dnsLabelRe.MatchString(strings.ReplaceAll(k.SecretName, ".", "-")) {
				return specErr("kubernetes.secret_name %q is not a valid Secret name", k.SecretName)
			}
			if k.PasswordKey == "" {
				k.PasswordKey = "password"
			}
		} else if k.PasswordKey != "" || k.UserKey != "" {
			return specErr("kubernetes.password_key / user_key need kubernetes.secret_name")
		}
		if s.Profile != "" {
			return specErr("credential profiles are not available for kubernetes targets (store the password on the job or in a Secret)")
		}
		if strings.HasPrefix(s.Host, "/") {
			return specErr("kubernetes targets cannot use a unix socket")
		}
		if s.TLS.CAFile != "" || s.TLS.CertFile != "" || s.TLS.KeyFile != "" {
			return specErr("tls certificate files are not available for kubernetes targets")
		}
	} else if s.Host == "" {
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
	case EngineMSSQL:
		if s.Postgres != nil || s.MySQL != nil || s.MongoDB != nil {
			return specErr("postgres/mysql/mongodb options given for a mssql job")
		}
		if s.Kubernetes != nil {
			return specErr("SQL Server jobs cannot run on a kubernetes agent: BACKUP ... TO DISK writes inside the SQL Server pod, where the dump pod cannot read it")
		}
		if s.Compression == CompressionGzip {
			return specErr("compression gzip does not apply to SQL Server backups; use mssql.compression for native backup compression")
		}
		if s.MSSQL == nil {
			s.MSSQL = &MSSQLOptions{}
		}
		m := s.MSSQL
		switch m.Mode {
		case "":
			m.Mode = MSSQLModeAuto
		case MSSQLModeAuto, MSSQLModeFull, MSSQLModeDifferential, MSSQLModeLog:
		default:
			return specErr("mssql.mode %q is not one of auto, full, differential, log", m.Mode)
		}
		if m.CopyOnly && (m.Mode == MSSQLModeAuto || m.Mode == MSSQLModeDifferential) {
			return specErr("mssql.copy_only needs mode full or log: a differential cannot be based on a copy-only backup")
		}
		if m.FullEveryDays < 0 {
			return specErr("mssql.full_every_days must not be negative")
		}
		if m.StripeCount < 0 || m.StripeCount > 16 {
			return specErr("mssql.stripe_count must be between 1 and 16")
		}
		if m.MaxTransferSize != 0 && (m.MaxTransferSize < 65536 || m.MaxTransferSize > 4194304 || m.MaxTransferSize%65536 != 0) {
			return specErr("mssql.max_transfer_size must be a multiple of 65536 between 65536 and 4194304")
		}
		m.BackupDir, m.AgentDir = strings.TrimSpace(m.BackupDir), strings.TrimSpace(m.AgentDir)
		if m.AgentDir != "" && m.BackupDir == "" {
			return specErr("mssql.agent_dir needs mssql.backup_dir (the same directory as SQL Server sees it)")
		}
	case EnginePostgres:
		if s.MySQL != nil || s.MongoDB != nil || s.MSSQL != nil {
			return specErr("mysql/mongodb/mssql options given for a postgres job")
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
		if s.Postgres != nil || s.MongoDB != nil || s.MSSQL != nil {
			return specErr("postgres/mongodb/mssql options given for a mysql job")
		}
		if s.MySQL == nil {
			s.MySQL = &MySQLOptions{}
		}
		if err := validateExtraArgs(s.MySQL.ExtraDumpArgs); err != nil {
			return err
		}
	case EngineMongoDB:
		if s.Postgres != nil || s.MySQL != nil || s.MSSQL != nil {
			return specErr("postgres/mysql/mssql options given for a mongodb job")
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
	if s.MSSQL != nil {
		m := *s.MSSQL
		if s.MSSQL.Checksum != nil {
			v := *s.MSSQL.Checksum
			m.Checksum = &v
		}
		c.MSSQL = &m
	}
	if s.Kubernetes != nil {
		k := *s.Kubernetes
		c.Kubernetes = &k
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
// keeping database snapshots apart from the host's filesystem backups. Kubernetes
// targets use db-<engine>-<namespace>-<service>.
func DefaultBackupID(s *Spec) string {
	if s == nil {
		return ""
	}
	if s.BackupID != "" {
		return s.BackupID
	}
	clean := func(v string) string {
		v = backupIDClean.ReplaceAllString(strings.ToLower(strings.TrimSpace(v)), "-")
		return strings.Trim(v, ".-_")
	}
	if k := s.Kubernetes; k != nil {
		name := k.Service
		if name == "" {
			name = s.Host
		}
		return fmt.Sprintf("db-%s-%s-%s", s.Engine, clean(k.Namespace), clean(name))
	}
	host := strings.ToLower(strings.TrimSpace(s.Host))
	if strings.HasPrefix(host, "/") || host == "" {
		host = "local"
	}
	host = clean(host)
	if host == "" {
		host = "local"
	}
	return fmt.Sprintf("db-%s-%s", s.Engine, host)
}

// EffectiveHost is the address the dump connects to: Host, or for a kubernetes target
// without an explicit host the Service's cluster DNS name
func (s *Spec) EffectiveHost() string {
	if s.Host == "" && s.Kubernetes != nil && s.Kubernetes.Service != "" {
		return s.Kubernetes.Service + "." + s.Kubernetes.Namespace + ".svc"
	}
	return s.Host
}

// Summary is a short human-readable description (UI tables, logs)
func (s *Spec) Summary() string {
	if s == nil {
		return ""
	}
	target := s.EffectiveHost()
	if k := s.Kubernetes; k != nil && s.Host == "" {
		target = k.Namespace + "/" + k.Service
	}
	if s.Port != 0 {
		target = fmt.Sprintf("%s:%d", target, s.Port)
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
