package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultAgentDataDir(t *testing.T) {
	t.Setenv("FALLBCK_AGENT_DATA_DIR", "/srv/agent")
	if got := DefaultAgentDataDir(); got != "/srv/agent" {
		t.Errorf("env override: got %q", got)
	}

	t.Setenv("FALLBCK_AGENT_DATA_DIR", "")
	got := DefaultAgentDataDir()
	// Root on Unix, an elevated token on Windows (GitHub's Windows runners are elevated)
	if isPrivileged() {
		if want := SystemAgentDataDirFor(AgentTypeFilesystem); got != want {
			t.Errorf("privileged: got %q, want %q", got, want)
		}
		return
	}
	home, _ := os.UserHomeDir()
	if got != filepath.Join(home, ".fallbck", "agent") {
		t.Errorf("unprivileged: got %q", got)
	}
	if DefaultAgentConfig().DataDir != got {
		t.Error("DefaultAgentConfig must use DefaultAgentDataDir")
	}
}

func TestVCSStateDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.yaml")
	if err := os.WriteFile(path, []byte("server_url: https://fallbck.example.com\ndata_dir: "+dir+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FALLBCK_AGENT_VCS_STATE_DIR", "")
	cfg, err := LoadAgentConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.EffVCSStateDir(); got != filepath.Join(dir, "vcs-state") {
		t.Errorf("default: %q", got)
	}
	t.Setenv("FALLBCK_AGENT_VCS_STATE_DIR", "/mnt/big/vcs")
	if cfg, err = LoadAgentConfig(path); err != nil {
		t.Fatal(err)
	}
	if got := cfg.EffVCSStateDir(); got != "/mnt/big/vcs" {
		t.Errorf("env override: %q", got)
	}
}
