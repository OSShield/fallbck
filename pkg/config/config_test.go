package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultAndEnvironmentOverrides(t *testing.T) {
	os.Setenv("FALLBCK_HTTP_PORT", "9090")
	os.Setenv("FALLBCK_DB_URL", "postgres://test:test@localhost:5432/testdb")
	defer func() {
		os.Unsetenv("FALLBCK_HTTP_PORT")
		os.Unsetenv("FALLBCK_DB_URL")
	}()

	cfg, err := LoadServerConfig("")
	if err != nil {
		t.Fatalf("LoadServerConfig failed: %v", err)
	}

	if cfg.HTTPPort != 9090 {
		t.Errorf("Expected HTTPPort 9090, got %d", cfg.HTTPPort)
	}
	if cfg.Database.URL != "postgres://test:test@localhost:5432/testdb" {
		t.Errorf("Expected overridden DB URL, got %s", cfg.Database.URL)
	}
}

func TestConfigFileLoading(t *testing.T) {
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "server.yaml")

	yamlData := `
http_port: 8888
public_url: "https://backup.example.com"
jwt_secret: "my-custom-secret"
temporal:
  host_port: "temporal.internal:7233"
  namespace: "production"
  enable_tls: true
`
	if err := os.WriteFile(configFile, []byte(yamlData), 0644); err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}

	cfg, err := LoadServerConfig(configFile)
	if err != nil {
		t.Fatalf("LoadServerConfig with file failed: %v", err)
	}

	if cfg.HTTPPort != 8888 {
		t.Errorf("Expected HTTPPort 8888, got %d", cfg.HTTPPort)
	}
	if cfg.PublicURL != "https://backup.example.com" {
		t.Errorf("Expected PublicURL https://backup.example.com, got %s", cfg.PublicURL)
	}
	if cfg.Temporal.HostPort != "temporal.internal:7233" {
		t.Errorf("Expected Temporal host temporal.internal:7233, got %s", cfg.Temporal.HostPort)
	}
	if !cfg.Temporal.EnableTLS {
		t.Errorf("Expected Temporal TLS enabled")
	}
}
