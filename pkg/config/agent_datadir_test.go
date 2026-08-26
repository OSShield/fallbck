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
	if os.Geteuid() == 0 {
		if got != SystemAgentDataDir {
			t.Errorf("as root: got %q, want %q", got, SystemAgentDataDir)
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
