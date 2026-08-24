package config

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

// TemporalConfig holds connection and mTLS settings for Temporal
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

// DatabaseConfig holds PostgreSQL database settings
type DatabaseConfig struct {
	URL             string        `yaml:"url" json:"url"`
	MaxOpenConns    int           `yaml:"max_open_conns" json:"max_open_conns"`
	MaxIdleConns    int           `yaml:"max_idle_conns" json:"max_idle_conns"`
	ConnMaxLifetime time.Duration `yaml:"conn_max_lifetime" json:"conn_max_lifetime"`
	AutoMigrate     bool          `yaml:"auto_migrate" json:"auto_migrate"`
}

// ServerConfig defines the central FallBCK server configuration
type ServerConfig struct {
	HTTPPort       int            `yaml:"http_port" json:"http_port"`
	HTTPBind       string         `yaml:"http_bind" json:"http_bind"`
	PublicURL      string         `yaml:"public_url" json:"public_url"`
	JWTSecret      string         `yaml:"jwt_secret" json:"jwt_secret"`
	DataDir        string         `yaml:"data_dir" json:"data_dir"`
	CACertPath     string         `yaml:"ca_cert_path" json:"ca_cert_path"`
	CAKeyPath      string         `yaml:"ca_key_path" json:"ca_key_path"`
	ProxyPort      int            `yaml:"proxy_port" json:"proxy_port"`
	Database       DatabaseConfig `yaml:"database" json:"database"`
	Temporal       TemporalConfig `yaml:"temporal" json:"temporal"`
}

// AgentConfig defines the client backup agent configuration
type AgentConfig struct {
	AgentID        string         `yaml:"agent_id" json:"agent_id"`
	Hostname       string         `yaml:"hostname" json:"hostname"`
	ServerURL      string         `yaml:"server_url" json:"server_url"`
	DataDir        string         `yaml:"data_dir" json:"data_dir"`
	TaskQueue      string         `yaml:"task_queue" json:"task_queue"`
	EnrollmentKey  string         `yaml:"enrollment_key" json:"enrollment_key"`
	Temporal       TemporalConfig `yaml:"temporal" json:"temporal"`
}

// DefaultServerConfig returns a ServerConfig with sensible defaults
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		HTTPPort:  8080,
		HTTPBind:  "0.0.0.0",
		PublicURL: "http://localhost:8080",
		JWTSecret: "change-me-in-production-fallbck-secret-key-32bytes",
		DataDir:   "/var/lib/fallbck/server",
		ProxyPort: 8443,
		Database: DatabaseConfig{
			URL:             "postgres://fallbck:fallbck_password@localhost:5432/fallbck?sslmode=disable",
			MaxOpenConns:    25,
			MaxIdleConns:    5,
			ConnMaxLifetime: 5 * time.Minute,
			AutoMigrate:     true,
		},
		Temporal: TemporalConfig{
			HostPort:       "localhost:7233",
			Namespace:      "default",
			EnableTLS:      false,
			ConnectTimeout: 10 * time.Second,
		},
	}
}

// DefaultAgentConfig returns an AgentConfig with sensible defaults
func DefaultAgentConfig() *AgentConfig {
	hostname, _ := os.Hostname()
	return &AgentConfig{
		Hostname:  hostname,
		ServerURL: "http://localhost:8080",
		DataDir:   "/var/lib/fallbck/agent",
		Temporal: TemporalConfig{
			HostPort:       "localhost:7233",
			Namespace:      "default",
			EnableTLS:      false,
			ConnectTimeout: 10 * time.Second,
		},
	}
}

// LoadServerConfig loads configuration from a YAML file and overrides with environment variables
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

	// Environment variable overrides
	if val := os.Getenv("FALLBCK_HTTP_PORT"); val != "" {
		if port, err := strconv.Atoi(val); err == nil {
			cfg.HTTPPort = port
		}
	}
	if val := os.Getenv("FALLBCK_HTTP_BIND"); val != "" {
		cfg.HTTPBind = val
	}
	if val := os.Getenv("FALLBCK_PUBLIC_URL"); val != "" {
		cfg.PublicURL = val
	}
	if val := os.Getenv("FALLBCK_JWT_SECRET"); val != "" {
		cfg.JWTSecret = val
	}
	if val := os.Getenv("FALLBCK_DATA_DIR"); val != "" {
		cfg.DataDir = val
	}
	if val := os.Getenv("FALLBCK_DB_URL"); val != "" {
		cfg.Database.URL = val
	}
	if val := os.Getenv("FALLBCK_TEMPORAL_HOST"); val != "" {
		cfg.Temporal.HostPort = val
	}
	if val := os.Getenv("FALLBCK_TEMPORAL_NAMESPACE"); val != "" {
		cfg.Temporal.Namespace = val
	}
	if val := os.Getenv("FALLBCK_TEMPORAL_TLS"); val == "true" || val == "1" {
		cfg.Temporal.EnableTLS = true
	}
	if val := os.Getenv("FALLBCK_TEMPORAL_CA_CERT"); val != "" {
		cfg.Temporal.CACertPath = val
	}
	if val := os.Getenv("FALLBCK_TEMPORAL_CLIENT_CERT"); val != "" {
		cfg.Temporal.ClientCertPath = val
	}
	if val := os.Getenv("FALLBCK_TEMPORAL_CLIENT_KEY"); val != "" {
		cfg.Temporal.ClientKeyPath = val
	}

	return cfg, nil
}

// LoadAgentConfig loads configuration for an agent
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

	if val := os.Getenv("FALLBCK_AGENT_ID"); val != "" {
		cfg.AgentID = val
	}
	if val := os.Getenv("FALLBCK_AGENT_HOSTNAME"); val != "" {
		cfg.Hostname = val
	}
	if val := os.Getenv("FALLBCK_AGENT_SERVER_URL"); val != "" {
		cfg.ServerURL = val
	}
	if val := os.Getenv("FALLBCK_AGENT_DATA_DIR"); val != "" {
		cfg.DataDir = val
	}
	if val := os.Getenv("FALLBCK_AGENT_TASK_QUEUE"); val != "" {
		cfg.TaskQueue = val
	}
	if val := os.Getenv("FALLBCK_AGENT_ENROLLMENT_KEY"); val != "" {
		cfg.EnrollmentKey = val
	}
	if val := os.Getenv("FALLBCK_TEMPORAL_HOST"); val != "" {
		cfg.Temporal.HostPort = val
	}
	if val := os.Getenv("FALLBCK_TEMPORAL_NAMESPACE"); val != "" {
		cfg.Temporal.Namespace = val
	}
	if val := os.Getenv("FALLBCK_TEMPORAL_TLS"); val == "true" || val == "1" {
		cfg.Temporal.EnableTLS = true
	}
	if val := os.Getenv("FALLBCK_TEMPORAL_CA_CERT"); val != "" {
		cfg.Temporal.CACertPath = val
	}
	if val := os.Getenv("FALLBCK_TEMPORAL_CLIENT_CERT"); val != "" {
		cfg.Temporal.ClientCertPath = val
	}
	if val := os.Getenv("FALLBCK_TEMPORAL_CLIENT_KEY"); val != "" {
		cfg.Temporal.ClientKeyPath = val
	}

	return cfg, nil
}

// BuildTLSConfig constructs a *tls.Config from TemporalConfig
func (tc *TemporalConfig) BuildTLSConfig() (*tls.Config, error) {
	if !tc.EnableTLS {
		return nil, nil
	}

	tlsConfig := &tls.Config{
		ServerName:         tc.ServerName,
		InsecureSkipVerify: tc.InsecureSkipVerify,
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
