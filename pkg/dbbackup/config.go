package dbbackup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CredentialProfile is a named set of database credentials kept on the agent host
// (db_backup.profiles in the agent configuration). A job that leaves its password blank
// is resolved against the profile it names (default: the engine name).
type CredentialProfile struct {
	Engine   string `yaml:"engine" json:"engine"`
	User     string `yaml:"user,omitempty" json:"user,omitempty"`
	Password string `yaml:"password,omitempty" json:"-"`
	// PasswordFile is read at run time (trailing newline trimmed)
	PasswordFile string  `yaml:"password_file,omitempty" json:"password_file,omitempty"`
	Host         string  `yaml:"host,omitempty" json:"host,omitempty"`
	Port         int     `yaml:"port,omitempty" json:"port,omitempty"`
	TLS          TLSSpec `yaml:"tls,omitempty" json:"tls"`
}

// ProfileSummary is what an agent tells the server about a credential profile: the
// name to pick in the UI, the engine it is for, and the user and host it carries,
// never the password
type ProfileSummary struct {
	Name   string `json:"name"`
	Engine string `json:"engine"`
	User   string `json:"user,omitempty"`
	Host   string `json:"host,omitempty"`
}

// ToolConfig pins the client tool directories (default: PATH and well-known locations)
type ToolConfig struct {
	PostgresBinDir string `yaml:"postgres_bindir,omitempty" json:"postgres_bindir,omitempty"`
	MySQLBinDir    string `yaml:"mysql_bindir,omitempty" json:"mysql_bindir,omitempty"`
	MongoBinDir    string `yaml:"mongo_bindir,omitempty" json:"mongo_bindir,omitempty"`
}

// Config is the agent-side database backup configuration (db_backup: in agent.yaml)
type Config struct {
	// SpoolDir receives the dumps before upload (default <data_dir>/spool)
	SpoolDir string `yaml:"spool_dir,omitempty" json:"spool_dir,omitempty"`
	// StateDir keeps per-job state such as the last MySQL binlog position (default <data_dir>/state/db)
	StateDir string `yaml:"state_dir,omitempty" json:"state_dir,omitempty"`
	// MinFreeBytes must be free on the spool filesystem before and during a run (default 1 GiB)
	MinFreeBytes int64 `yaml:"min_free_bytes,omitempty" json:"min_free_bytes,omitempty"`
	// SizeSafetyFactor scales the server's size estimate for the disk check (default 1.2)
	SizeSafetyFactor float64 `yaml:"size_safety_factor,omitempty" json:"size_safety_factor,omitempty"`
	// KillGrace is the SIGTERM → SIGKILL grace period for client tools (default 20s)
	KillGrace time.Duration `yaml:"kill_grace,omitempty" json:"kill_grace,omitempty"`
	// KeepFailedSpool leaves the spool directory in place when a run fails (debugging)
	KeepFailedSpool bool `yaml:"keep_failed_spool,omitempty" json:"keep_failed_spool,omitempty"`
	// Checksums records a sha256 per spooled file in the manifest (default true)
	Checksums *bool                        `yaml:"checksums,omitempty" json:"checksums,omitempty"`
	Tools     ToolConfig                   `yaml:"tools,omitempty" json:"tools"`
	Profiles  map[string]CredentialProfile `yaml:"profiles,omitempty" json:"profiles,omitempty"`
}

// Defaults
const (
	DefaultMinFreeBytes     = int64(1 << 30)
	DefaultSizeSafetyFactor = 1.2
	DefaultKillGrace        = 20 * time.Second
)

// ApplyDefaults fills unset values; dataDir anchors the spool and state directories
func (c *Config) ApplyDefaults(dataDir string) {
	if c.SpoolDir == "" && dataDir != "" {
		c.SpoolDir = filepath.Join(dataDir, "spool")
	}
	if c.StateDir == "" && dataDir != "" {
		c.StateDir = filepath.Join(dataDir, "state", "db")
	}
	if c.MinFreeBytes <= 0 {
		c.MinFreeBytes = DefaultMinFreeBytes
	}
	if c.SizeSafetyFactor <= 0 {
		c.SizeSafetyFactor = DefaultSizeSafetyFactor
	}
	if c.KillGrace <= 0 {
		c.KillGrace = DefaultKillGrace
	}
}

// ChecksumsEnabled reports whether per-file checksums are recorded
func (c *Config) ChecksumsEnabled() bool { return Bool(c.Checksums, true) }

// Validate checks the profiles (engine names) and normalises them
func (c *Config) Validate() error {
	for name, p := range c.Profiles {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("db_backup.profiles: profile names must not be empty")
		}
		engine, ok := NormalizeEngine(p.Engine)
		if !ok {
			return fmt.Errorf("db_backup.profiles.%s: unsupported engine %q", name, p.Engine)
		}
		p.Engine = engine
		if p.Password != "" && p.PasswordFile != "" {
			return fmt.Errorf("db_backup.profiles.%s: set either password or password_file", name)
		}
		c.Profiles[name] = p
	}
	return nil
}

// Credentials are the resolved connection settings for one run
type Credentials struct {
	User     string
	Password string
	Host     string
	Port     int
	TLS      TLSSpec
	// Source records where the password came from ("job", "profile:<name>", "none",
	// or "local:<method>" for the agent's passwordless fallback on the database host)
	Source string
	// RunAs names the OS user the client tools run as, for peer / socket authentication
	// on the database host (PostgreSQL: postgres); "" is the agent's own user. Only the
	// agent's local fallback sets it, never a job or profile.
	RunAs string
}

// ErrNoCredentials marks a resolution failure that means "nothing configured" (no
// password on the job, no matching profile, no user) as opposed to a broken profile.
// The agent may then try passwordless local authentication on the database host.
var ErrNoCredentials = errors.New("no database credentials configured")

// ResolveCredentials merges the job spec with the agent profile. password is the
// server-stored password for this run ("" when the job has none). The profile is
// consulted only when the job carries no password; it may also fill in user, host,
// port and TLS settings the job left blank.
func ResolveCredentials(spec *Spec, password string, profiles map[string]CredentialProfile) (Credentials, error) {
	creds := Credentials{User: spec.User, Host: spec.EffectiveHost(), Port: spec.Port, TLS: spec.TLS, Source: "none"}
	if password != "" {
		creds.Password = password
		creds.Source = "job"
	} else {
		name := spec.Profile
		if name == "" {
			name = spec.Engine
		}
		p, ok := profiles[name]
		if !ok {
			// Without a profile only peer-authenticated sockets and MongoDB without a
			// password (no user, or a certificate / Kerberos / AWS mechanism) can proceed
			anonymousMongo := spec.Engine == EngineMongoDB && (spec.User == "" || spec.MongoDB.PasswordlessAuth())
			// SQL Server without a user means Windows integrated authentication
			integrated := spec.Engine == EngineMSSQL && spec.User == ""
			if spec.Profile != "" || (!spec.IsSocket() && !anonymousMongo && !integrated) {
				return creds, fmt.Errorf("%w: job stores no password and the agent has no credential profile %q (fallbck-agent database profile create --name %s ...)", ErrNoCredentials, name, name)
			}
		} else {
			if e, _ := NormalizeEngine(p.Engine); e != spec.Engine {
				return creds, fmt.Errorf("credential profile %q is for engine %q, job uses %q", name, p.Engine, spec.Engine)
			}
			pw := p.Password
			if p.PasswordFile != "" {
				data, err := os.ReadFile(p.PasswordFile)
				if err != nil {
					return creds, fmt.Errorf("credential profile %q: reading password_file: %w", name, err)
				}
				pw = strings.TrimRight(string(data), "\r\n")
			}
			creds.Password = pw
			creds.Source = "profile:" + name
			if creds.User == "" {
				creds.User = p.User
			}
			if p.Host != "" && (creds.Host == "" || creds.Host == spec.Host && spec.Host == "") {
				creds.Host = p.Host
			}
			if creds.Port == 0 {
				creds.Port = p.Port
			}
			if creds.TLS.Mode == "" {
				creds.TLS = p.TLS
			}
		}
	}
	if creds.Port == 0 {
		creds.Port = DefaultPort(spec.Engine)
	}
	if creds.User == "" {
		if spec.Engine != EngineMongoDB && spec.Engine != EngineMSSQL {
			return creds, fmt.Errorf("%w: no database user configured (set it on the job or in the credential profile)", ErrNoCredentials)
		}
	} else if creds.Password == "" && !strings.HasPrefix(creds.Host, "/") && (spec.Engine != EngineMongoDB || !spec.MongoDB.PasswordlessAuth()) {
		return creds, fmt.Errorf("%w: no password available for %s@%s (job password blank and profile provides none); only unix-socket connections may run without a password", ErrNoCredentials, creds.User, creds.Host)
	}
	return creds, nil
}
