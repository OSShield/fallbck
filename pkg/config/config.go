package config

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Temporal deployment modes
const (
	TemporalModeEmbedded = "embedded"
	TemporalModeExternal = "external"
)

// TemporalConfig is a Temporal *client* configuration (used for an external cluster)
type TemporalConfig struct {
	HostPort           string        `yaml:"host_port" json:"host_port"`
	Namespace          string        `yaml:"namespace" json:"namespace"`
	EnableTLS          bool          `yaml:"enable_tls" json:"enable_tls"`
	CACertPath         string        `yaml:"ca_cert_path" json:"ca_cert_path"`
	ClientCertPath     string        `yaml:"client_cert_path" json:"client_cert_path"`
	ClientKeyPath      string        `yaml:"client_key_path" json:"client_key_path"`
	ServerName         string        `yaml:"server_name" json:"server_name"`
	InsecureSkipVerify bool          `yaml:"insecure_skip_verify" json:"insecure_skip_verify"`
	ConnectTimeout     time.Duration `yaml:"connect_timeout" json:"connect_timeout"`
}

// EmbeddedTemporalConfig configures the in-process Temporal server
type EmbeddedTemporalConfig struct {
	BindIP string `yaml:"bind_ip" json:"bind_ip"`
	// PortBase is the loopback frontend port; the other services use PortBase+1..+6
	PortBase int `yaml:"port_base" json:"port_base"`
	// DatabaseURL defaults to the application database URL (database name is replaced)
	DatabaseURL string `yaml:"database_url" json:"database_url"`
	// HistoryShards is immutable after the first start
	HistoryShards int32         `yaml:"history_shards" json:"history_shards"`
	Retention     time.Duration `yaml:"retention" json:"retention"`
	// ClusterName is immutable after the first start (default "fallbck"); set it to the
	// existing cluster name when adopting databases created by another Temporal deployment
	ClusterName string `yaml:"cluster_name" json:"cluster_name"`
}

// TemporalUIConfig configures the embedded Temporal Web UI (served under /temporal/)
type TemporalUIConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Port is the loopback port the UI server listens on
	Port int `yaml:"port" json:"port"`
}

// TemporalServerConfig selects and configures the Temporal cluster the server uses
type TemporalServerConfig struct {
	Mode      string                 `yaml:"mode" json:"mode"`
	Namespace string                 `yaml:"namespace" json:"namespace"`
	Embedded  EmbeddedTemporalConfig `yaml:"embedded" json:"embedded"`
	External  TemporalConfig         `yaml:"external" json:"external"`
	UI        TemporalUIConfig       `yaml:"ui" json:"ui"`
}

// OIDCConfig configures admin login through an OpenID Connect provider
type OIDCConfig struct {
	Issuer       string   `yaml:"issuer" json:"issuer"`
	ClientID     string   `yaml:"client_id" json:"client_id"`
	ClientSecret string   `yaml:"client_secret" json:"-"`
	Scopes       []string `yaml:"scopes" json:"scopes"`
	// AllowedGroups restricts login to identities whose groups claim contains one of these (empty = any)
	AllowedGroups []string `yaml:"allowed_groups" json:"allowed_groups"`
	// AllowedEmails restricts login to these email addresses (empty = any)
	AllowedEmails []string `yaml:"allowed_emails" json:"allowed_emails"`
	// GroupsClaim is the ID token claim carrying group membership (default "groups")
	GroupsClaim string `yaml:"groups_claim" json:"groups_claim"`
}

// Enabled reports whether the OIDC configuration is populated
func (c OIDCConfig) Enabled() bool {
	return c.Issuer != "" && c.ClientID != ""
}

// Validate checks the configuration is usable
func (c OIDCConfig) Validate() error {
	if c.Issuer == "" {
		return errors.New("auth.oidc.issuer is required")
	}
	if c.ClientID == "" {
		return errors.New("auth.oidc.client_id is required")
	}
	return nil
}

// AuthConfig configures administrator authentication
type AuthConfig struct {
	OIDC       OIDCConfig    `yaml:"oidc" json:"oidc"`
	SessionTTL time.Duration `yaml:"session_ttl" json:"session_ttl"`
	// InsecureDisable turns admin authentication off. Development only; the server
	// refuses it unless started with --dev.
	InsecureDisable bool `yaml:"insecure_disable" json:"insecure_disable"`
}

// AgentTokensConfig configures agent bearer tokens
type AgentTokensConfig struct {
	TTL time.Duration `yaml:"ttl" json:"ttl"`
}

// DatabaseConfig configures the application PostgreSQL pool
type DatabaseConfig struct {
	URL             string        `yaml:"url" json:"url"`
	MaxOpenConns    int           `yaml:"max_open_conns" json:"max_open_conns"`
	MaxIdleConns    int           `yaml:"max_idle_conns" json:"max_idle_conns"`
	ConnMaxLifetime time.Duration `yaml:"conn_max_lifetime" json:"conn_max_lifetime"`
	AutoMigrate     bool          `yaml:"auto_migrate" json:"auto_migrate"`
}

// ServerConfig is the fallbck-server configuration
type ServerConfig struct {
	// HTTPPort / HTTPBind: the single plaintext h2c listener behind the reverse proxy
	HTTPPort int    `yaml:"http_port" json:"http_port"`
	HTTPBind string `yaml:"http_bind" json:"http_bind"`
	// PublicURL is the reverse proxy's externally reachable URL (OIDC redirect,
	// install script, enrollment response)
	PublicURL string `yaml:"public_url" json:"public_url"`
	JWTSecret string `yaml:"jwt_secret" json:"jwt_secret"`
	DataDir   string `yaml:"data_dir" json:"data_dir"`
	// AgentCABundlePath optionally points at a PEM bundle agents should trust for the
	// public URL (private CAs); it is handed out at enrollment
	AgentCABundlePath string `yaml:"agent_ca_bundle_path" json:"agent_ca_bundle_path"`

	Auth        AuthConfig           `yaml:"auth" json:"auth"`
	AgentTokens AgentTokensConfig    `yaml:"agent_tokens" json:"agent_tokens"`
	Database    DatabaseConfig       `yaml:"database" json:"database"`
	Temporal    TemporalServerConfig `yaml:"temporal" json:"temporal"`
}

// AgentConfig is the fallbck-agent configuration
type AgentConfig struct {
	AgentID  string `yaml:"agent_id" json:"agent_id"`
	Hostname string `yaml:"hostname" json:"hostname"`
	// ServerURL is the FallBCK server (reverse proxy) URL; HTTP API and Temporal gRPC
	// are both reached through it
	ServerURL string `yaml:"server_url" json:"server_url"`
	DataDir   string `yaml:"data_dir" json:"data_dir"`
	TaskQueue string `yaml:"task_queue" json:"task_queue"`
	Namespace string `yaml:"namespace" json:"namespace"`
	// AuthToken is the agent bearer token issued at enrollment
	AuthToken      string    `yaml:"auth_token" json:"-"`
	TokenExpiresAt time.Time `yaml:"token_expires_at" json:"token_expires_at"`
	// ServerCACertPath optionally trusts a private CA for ServerURL
	ServerCACertPath   string `yaml:"server_ca_cert_path" json:"server_ca_cert_path"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify" json:"insecure_skip_verify"`
	// EnrollmentKey triggers self-enrollment on first start
	EnrollmentKey string `yaml:"enrollment_key" json:"-"`
}

// DefaultServerConfig returns the defaults for fallbck-server
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		HTTPPort:  8080,
		HTTPBind:  "0.0.0.0",
		PublicURL: "http://localhost:8080",
		JWTSecret: "change-me-in-production-fallbck-secret-key-32bytes",
		DataDir:   "/var/lib/fallbck/server",
		Auth: AuthConfig{
			SessionTTL: 12 * time.Hour,
		},
		AgentTokens: AgentTokensConfig{
			TTL: 365 * 24 * time.Hour,
		},
		Database: DatabaseConfig{
			URL:             "postgres://fallbck:fallbck_password@localhost:5432/fallbck?sslmode=disable",
			MaxOpenConns:    25,
			MaxIdleConns:    5,
			ConnMaxLifetime: 5 * time.Minute,
			AutoMigrate:     true,
		},
		Temporal: TemporalServerConfig{
			Mode:      TemporalModeEmbedded,
			Namespace: "default",
			Embedded: EmbeddedTemporalConfig{
				BindIP:        "127.0.0.1",
				PortBase:      7233,
				HistoryShards: 4,
				Retention:     72 * time.Hour,
				ClusterName:   "fallbck",
			},
			External: TemporalConfig{
				HostPort:       "localhost:7233",
				ConnectTimeout: 10 * time.Second,
			},
			UI: TemporalUIConfig{
				Enabled: true,
				Port:    8233,
			},
		},
	}
}

// DefaultAgentConfig returns the defaults for fallbck-agent
func DefaultAgentConfig() *AgentConfig {
	hostname, _ := os.Hostname()
	return &AgentConfig{
		Hostname:  hostname,
		ServerURL: "http://localhost:8080",
		DataDir:   "/var/lib/fallbck/agent",
		Namespace: "default",
	}
}

// LoadServerConfig loads the YAML file (if any) and applies environment overrides
func LoadServerConfig(filePath string) (*ServerConfig, error) {
	cfg := DefaultServerConfig()

	if filePath != "" {
		data, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read server config file %s: %w", filePath, err)
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("failed to parse server config YAML: %w", err)
		}
	}

	envInt("FALLBCK_HTTP_PORT", &cfg.HTTPPort)
	envString("FALLBCK_HTTP_BIND", &cfg.HTTPBind)
	envString("FALLBCK_PUBLIC_URL", &cfg.PublicURL)
	envString("FALLBCK_JWT_SECRET", &cfg.JWTSecret)
	envString("FALLBCK_DATA_DIR", &cfg.DataDir)
	envString("FALLBCK_AGENT_CA_BUNDLE", &cfg.AgentCABundlePath)
	envString("FALLBCK_DB_URL", &cfg.Database.URL)

	envString("FALLBCK_OIDC_ISSUER", &cfg.Auth.OIDC.Issuer)
	envString("FALLBCK_OIDC_CLIENT_ID", &cfg.Auth.OIDC.ClientID)
	envString("FALLBCK_OIDC_CLIENT_SECRET", &cfg.Auth.OIDC.ClientSecret)
	envList("FALLBCK_OIDC_SCOPES", &cfg.Auth.OIDC.Scopes)
	envList("FALLBCK_OIDC_ALLOWED_GROUPS", &cfg.Auth.OIDC.AllowedGroups)
	envList("FALLBCK_OIDC_ALLOWED_EMAILS", &cfg.Auth.OIDC.AllowedEmails)
	envBool("FALLBCK_AUTH_INSECURE_DISABLE", &cfg.Auth.InsecureDisable)
	envDuration("FALLBCK_SESSION_TTL", &cfg.Auth.SessionTTL)
	envDuration("FALLBCK_AGENT_TOKEN_TTL", &cfg.AgentTokens.TTL)

	envString("FALLBCK_TEMPORAL_MODE", &cfg.Temporal.Mode)
	envString("FALLBCK_TEMPORAL_NAMESPACE", &cfg.Temporal.Namespace)
	envString("FALLBCK_TEMPORAL_DB_URL", &cfg.Temporal.Embedded.DatabaseURL)
	envInt("FALLBCK_TEMPORAL_PORT_BASE", &cfg.Temporal.Embedded.PortBase)
	envString("FALLBCK_TEMPORAL_CLUSTER_NAME", &cfg.Temporal.Embedded.ClusterName)
	envBool("FALLBCK_TEMPORAL_UI_ENABLED", &cfg.Temporal.UI.Enabled)
	envInt("FALLBCK_TEMPORAL_UI_PORT", &cfg.Temporal.UI.Port)
	// External cluster (temporal.mode: external)
	envString("FALLBCK_TEMPORAL_HOST", &cfg.Temporal.External.HostPort)
	envBool("FALLBCK_TEMPORAL_TLS", &cfg.Temporal.External.EnableTLS)
	envString("FALLBCK_TEMPORAL_CA_CERT", &cfg.Temporal.External.CACertPath)
	envString("FALLBCK_TEMPORAL_CLIENT_CERT", &cfg.Temporal.External.ClientCertPath)
	envString("FALLBCK_TEMPORAL_CLIENT_KEY", &cfg.Temporal.External.ClientKeyPath)

	cfg.Temporal.External.Namespace = cfg.Temporal.Namespace
	if cfg.Temporal.Embedded.DatabaseURL == "" {
		cfg.Temporal.Embedded.DatabaseURL = cfg.Database.URL
	}

	return cfg, nil
}

// Validate checks the server configuration for consistency. dev reports whether the
// server was started with --dev (relaxes the authentication requirement).
func (c *ServerConfig) Validate(dev bool) error {
	if c.PublicURL == "" {
		return errors.New("public_url is required")
	}
	if u, err := url.Parse(c.PublicURL); err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("public_url %q must be an absolute URL", c.PublicURL)
	}
	if len(c.JWTSecret) < 32 {
		return errors.New("jwt_secret must be at least 32 characters")
	}
	if c.Auth.InsecureDisable {
		if !dev {
			return errors.New("auth.insecure_disable is only permitted together with --dev")
		}
	} else if err := c.Auth.OIDC.Validate(); err != nil {
		return fmt.Errorf("admin authentication is not configured (%v); set auth.oidc.* or, for development only, auth.insecure_disable with --dev", err)
	}
	switch c.Temporal.Mode {
	case TemporalModeEmbedded, TemporalModeExternal:
	default:
		return fmt.Errorf("temporal.mode must be %q or %q, got %q", TemporalModeEmbedded, TemporalModeExternal, c.Temporal.Mode)
	}
	if c.Temporal.Namespace == "" {
		return errors.New("temporal.namespace is required")
	}
	if c.Temporal.Mode == TemporalModeExternal && c.Temporal.External.HostPort == "" {
		return errors.New("temporal.external.host_port is required in external mode")
	}
	return nil
}

// PublicURLIsHTTPS reports whether the public URL is served over TLS (cookie Secure flag)
func (c *ServerConfig) PublicURLIsHTTPS() bool {
	return strings.HasPrefix(strings.ToLower(c.PublicURL), "https://")
}

// ProxyURL returns the externally reachable base URL of the PBS proxy gateway.
// The proxy is served by the main HTTP listener, so it lives under PublicURL.
func (c *ServerConfig) ProxyURL() string {
	return strings.TrimRight(c.PublicURL, "/") + "/pbs-proxy"
}

// LoadAgentConfig loads the YAML file (if any) and applies environment overrides
func LoadAgentConfig(filePath string) (*AgentConfig, error) {
	cfg := DefaultAgentConfig()

	if filePath != "" {
		data, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read agent config file %s: %w", filePath, err)
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("failed to parse agent config YAML: %w", err)
		}
	}

	envString("FALLBCK_AGENT_ID", &cfg.AgentID)
	envString("FALLBCK_AGENT_HOSTNAME", &cfg.Hostname)
	envString("FALLBCK_AGENT_SERVER_URL", &cfg.ServerURL)
	envString("FALLBCK_AGENT_DATA_DIR", &cfg.DataDir)
	envString("FALLBCK_AGENT_TASK_QUEUE", &cfg.TaskQueue)
	envString("FALLBCK_AGENT_NAMESPACE", &cfg.Namespace)
	envString("FALLBCK_AGENT_AUTH_TOKEN", &cfg.AuthToken)
	envString("FALLBCK_AGENT_SERVER_CA", &cfg.ServerCACertPath)
	envBool("FALLBCK_AGENT_INSECURE_SKIP_VERIFY", &cfg.InsecureSkipVerify)
	envString("FALLBCK_AGENT_ENROLLMENT_KEY", &cfg.EnrollmentKey)

	return cfg, nil
}

// Save writes the agent configuration to path with owner-only permissions (it holds the token)
func (c *AgentConfig) Save(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to serialize agent config: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("failed to write agent config file %s: %w", path, err)
	}
	return nil
}

// BuildTLSConfig builds the client TLS configuration for an external Temporal cluster
func (tc *TemporalConfig) BuildTLSConfig() (*tls.Config, error) {
	if !tc.EnableTLS {
		return nil, nil
	}

	tlsConfig := &tls.Config{
		ServerName:         tc.ServerName,
		InsecureSkipVerify: tc.InsecureSkipVerify, //nolint:gosec // operator-controlled setting
	}

	if tc.CACertPath != "" {
		caCert, err := os.ReadFile(tc.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate from %s: %w", tc.CACertPath, err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to append CA certificate from %s", tc.CACertPath)
		}
		tlsConfig.RootCAs = caCertPool
	}

	if tc.ClientCertPath != "" && tc.ClientKeyPath != "" {
		cert, err := tls.LoadX509KeyPair(tc.ClientCertPath, tc.ClientKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load client keypair (%s, %s): %w", tc.ClientCertPath, tc.ClientKeyPath, err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	return tlsConfig, nil
}

// --- environment helpers ---

func envString(name string, dst *string) {
	if v := os.Getenv(name); v != "" {
		*dst = v
	}
}

func envInt(name string, dst *int) {
	if v := os.Getenv(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			*dst = n
		}
	}
}

func envBool(name string, dst *bool) {
	if v := os.Getenv(name); v != "" {
		switch strings.ToLower(v) {
		case "1", "true", "yes", "on":
			*dst = true
		case "0", "false", "no", "off":
			*dst = false
		}
	}
}

func envDuration(name string, dst *time.Duration) {
	if v := os.Getenv(name); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			*dst = d
		}
	}
}

func envList(name string, dst *[]string) {
	if v := os.Getenv(name); v != "" {
		var out []string
		for _, part := range strings.Split(v, ",") {
			if p := strings.TrimSpace(part); p != "" {
				out = append(out, p)
			}
		}
		*dst = out
	}
}
