package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDefaultAndEnvironmentOverrides(t *testing.T) {
	t.Setenv("FALLBCK_HTTP_PORT", "9090")
	t.Setenv("FALLBCK_DB_URL", "postgres://test:test@localhost:5432/testdb")
	t.Setenv("FALLBCK_TEMPORAL_MODE", "external")
	t.Setenv("FALLBCK_TEMPORAL_HOST", "temporal.internal:7233")
	t.Setenv("FALLBCK_OIDC_ALLOWED_GROUPS", "admins, ops")
	t.Setenv("FALLBCK_AUTH_INSECURE_DISABLE", "true")

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
	if cfg.Temporal.Embedded.DatabaseURL != cfg.Database.URL {
		t.Errorf("embedded temporal DB URL should default to the app DB URL, got %s", cfg.Temporal.Embedded.DatabaseURL)
	}
	if cfg.Temporal.Mode != TemporalModeExternal || cfg.Temporal.External.HostPort != "temporal.internal:7233" {
		t.Errorf("unexpected temporal config %+v", cfg.Temporal)
	}
	if cfg.Temporal.External.Namespace != "default" {
		t.Errorf("external namespace should mirror temporal.namespace, got %q", cfg.Temporal.External.Namespace)
	}
	if len(cfg.Auth.OIDC.AllowedGroups) != 2 || cfg.Auth.OIDC.AllowedGroups[1] != "ops" {
		t.Errorf("unexpected allowed groups %v", cfg.Auth.OIDC.AllowedGroups)
	}
	if !cfg.Auth.InsecureDisable {
		t.Error("expected insecure_disable from env")
	}
	if !cfg.Temporal.UI.ReadOnly {
		t.Error("the Temporal UI must default to read-only")
	}
}

func TestTemporalUIReadOnlyOverrides(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "server.yaml")
	if err := os.WriteFile(file, []byte("temporal:\n  ui:\n    read_only: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadServerConfig(file)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Temporal.UI.ReadOnly {
		t.Error("read_only: false in the file should enable write actions")
	}

	t.Setenv("FALLBCK_TEMPORAL_UI_READ_ONLY", "false")
	if cfg, err = LoadServerConfig(""); err != nil {
		t.Fatal(err)
	}
	if cfg.Temporal.UI.ReadOnly {
		t.Error("FALLBCK_TEMPORAL_UI_READ_ONLY=false should enable write actions")
	}
}

func TestConfigFileLoading(t *testing.T) {
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "server.yaml")

	yamlData := `
http_port: 8888
public_url: "https://backup.example.com"
jwt_secret: "my-custom-secret-that-is-long-enough-123456"
auth:
  oidc:
    issuer: "https://idp.example.com"
    client_id: "fallbck"
    client_secret: "s3cret"
temporal:
  mode: embedded
  namespace: "production"
  embedded:
    port_base: 17233
    retention: 240h
  ui:
    enabled: false
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
	if cfg.PublicURL != "https://backup.example.com" || !cfg.PublicURLIsHTTPS() {
		t.Errorf("Expected https PublicURL, got %s", cfg.PublicURL)
	}
	if cfg.Temporal.Embedded.PortBase != 17233 || cfg.Temporal.Embedded.Retention.Hours() != 240 {
		t.Errorf("unexpected embedded config %+v", cfg.Temporal.Embedded)
	}
	if cfg.Temporal.UI.Enabled {
		t.Error("ui should be disabled by file")
	}
	if !cfg.Temporal.UI.ReadOnly {
		t.Error("a ui block without read_only must keep the read-only default")
	}
	if cfg.ProxyURL() != "https://backup.example.com/pbs-proxy" {
		t.Errorf("ProxyURL = %s", cfg.ProxyURL())
	}
	if err := cfg.Validate(false); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
}

func TestValidate(t *testing.T) {
	cfg := DefaultServerConfig()
	if err := cfg.Validate(false); err == nil {
		t.Error("defaults without OIDC must fail validation")
	}
	cfg.Auth.InsecureDisable = true
	if err := cfg.Validate(false); err == nil {
		t.Error("insecure_disable without --dev must fail")
	}
	if err := cfg.Validate(true); err != nil {
		t.Errorf("insecure_disable with --dev should pass: %v", err)
	}
	cfg.Temporal.Mode = "sidecar"
	if err := cfg.Validate(true); err == nil {
		t.Error("unknown temporal mode must fail")
	}
	cfg.Temporal.Mode = TemporalModeExternal
	cfg.Temporal.External.HostPort = ""
	if err := cfg.Validate(true); err == nil {
		t.Error("external mode without host_port must fail")
	}
}

func TestAgentConfigSaveLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.yaml")
	cfg := &AgentConfig{AgentID: "a", ServerURL: "https://backup.example.com", TaskQueue: "q", Namespace: "default", AuthToken: "secret"}
	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}
	// Windows has no POSIX permission bits; os.WriteFile's mode only toggles read-only there
	if info, _ := os.Stat(path); runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("agent.yaml should be 0600, got %v", info.Mode().Perm())
	}
	loaded, err := LoadAgentConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.AuthToken != "secret" || loaded.TaskQueue != "q" || loaded.ServerURL != "https://backup.example.com" {
		t.Errorf("round trip mismatch: %+v", loaded)
	}
}

func TestTimezoneConfig(t *testing.T) {
	t.Setenv("TZ", "Europe/Stockholm")
	if tz := DetectTimezone(); tz != "Europe/Stockholm" {
		t.Errorf("DetectTimezone with TZ set = %q", tz)
	}
	t.Setenv("TZ", "Not/AZone")
	if tz := DetectTimezone(); tz == "Not/AZone" {
		t.Errorf("invalid TZ accepted: %q", tz)
	}
	cfg := DefaultServerConfig()
	cfg.Auth.InsecureDisable = true
	cfg.Timezone = "Europe/Stockholm"
	if err := cfg.Validate(true); err != nil {
		t.Errorf("valid timezone rejected: %v", err)
	}
	cfg.Timezone = "Mars/Olympus"
	if err := cfg.Validate(true); err == nil {
		t.Error("invalid timezone accepted")
	}
	cfg.Timezone = "Europe/Stockholm"
	if cfg.ScheduleLocation().String() != "Europe/Stockholm" {
		t.Errorf("ScheduleLocation = %v", cfg.ScheduleLocation())
	}
}

func TestAgentServerTLSConfig(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		cfg := &AgentConfig{ServerURL: "https://backup.example.com:8443"}
		tlsCfg, err := cfg.ServerTLSConfig()
		if err != nil {
			t.Fatal(err)
		}
		if tlsCfg.ServerName != "backup.example.com" || tlsCfg.InsecureSkipVerify || tlsCfg.RootCAs != nil {
			t.Fatalf("unexpected config: %+v", tlsCfg)
		}
	})
	t.Run("insecure", func(t *testing.T) {
		tlsCfg, err := (&AgentConfig{ServerURL: "https://x", InsecureSkipVerify: true}).ServerTLSConfig()
		if err != nil || !tlsCfg.InsecureSkipVerify {
			t.Fatalf("insecure_skip_verify not applied (err=%v)", err)
		}
	})
	t.Run("missing CA file", func(t *testing.T) {
		_, err := (&AgentConfig{ServerURL: "https://x", ServerCACertPath: filepath.Join(t.TempDir(), "nope.crt")}).ServerTLSConfig()
		if err == nil {
			t.Fatal("expected an error for a missing CA bundle")
		}
	})
	t.Run("CA file without certificates", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "empty.crt")
		if err := os.WriteFile(path, []byte("not a pem"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := (&AgentConfig{ServerURL: "https://x", ServerCACertPath: path}).ServerTLSConfig()
		if err == nil || !strings.Contains(err.Error(), "contains no certificates") {
			t.Fatalf("expected a no-certificates error, got %v", err)
		}
	})
}

func TestTrustedProxiesDefaultLoopbackOnly(t *testing.T) {
	for _, p := range DefaultServerConfig().TrustedProxies {
		if p != "127.0.0.0/8" && p != "::1/128" {
			t.Errorf("default trusted proxy %s: only loopback may set X-Forwarded-For by default", p)
		}
	}
}

func TestAgentConcurrencyAndDockerSpaceDefaults(t *testing.T) {
	var c AgentConfig
	if c.EffMaxConcurrentActivities() != DefaultMaxConcurrentActivities || c.DockerBackup.EffMinFreeBytes() != 1<<30 {
		t.Errorf("defaults: %d %d", c.EffMaxConcurrentActivities(), c.DockerBackup.EffMinFreeBytes())
	}
	c.MaxConcurrentActivities, c.DockerBackup.MinFreeBytes = 4, 5<<30
	if c.EffMaxConcurrentActivities() != 4 || c.DockerBackup.EffMinFreeBytes() != 5<<30 {
		t.Error("configured values are not used")
	}
}
