package api

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/agentupdate"
	"github.com/osshield/fallbck/pkg/db"
)

func TestAgentUpdateDecision(t *testing.T) {
	dir := t.TempDir()
	cache := agentupdate.New("2.0.0", dir)
	// A binary mirrored earlier: Binary() reads it from disk
	_ = os.MkdirAll(filepath.Dir(cache.Path("linux", "amd64")), 0o755)
	_ = os.WriteFile(cache.Path("linux", "amd64"), []byte("bin"), 0o755)
	_ = os.WriteFile(cache.Path("linux", "amd64")+".sha256", []byte("abc\n"), 0o644)
	s := &ServerAPI{Updates: cache}
	linux := db.HeartbeatState{OS: "linux", Arch: "amd64"}

	cases := []struct {
		name    string
		version string
		st      db.HeartbeatState
		want    bool
	}{
		{"behind, auto on", "1.9.0", db.HeartbeatState{OS: "linux", Arch: "amd64", AutoUpdate: true}, true},
		{"behind, requested", "1.9.0", db.HeartbeatState{OS: "linux", Arch: "amd64", UpdateRequested: true}, true},
		{"behind, not opted in", "1.9.0", linux, false},
		{"up to date", "2.0.0", db.HeartbeatState{OS: "linux", Arch: "amd64", AutoUpdate: true}, false},
		{"dev agent", "dev", db.HeartbeatState{OS: "linux", Arch: "amd64", AutoUpdate: true}, false},
		{"not mirrored arch", "1.9.0", db.HeartbeatState{OS: "linux", Arch: "riscv64", AutoUpdate: true}, false},
	}
	for _, c := range cases {
		got := s.agentUpdate(context.Background(), uuid.New(), c.version, c.st)
		if (got != nil) != c.want {
			t.Errorf("%s: update=%v, want %v", c.name, got != nil, c.want)
		}
		if got != nil && (got.SHA256 != "abc" || got.URL != "/api/v1/agents/update/linux/amd64" || got.Version != "2.0.0") {
			t.Errorf("%s: bad instruction %+v", c.name, got)
		}
	}
	if (&ServerAPI{}).agentUpdate(context.Background(), uuid.New(), "1.0.0", linux) != nil {
		t.Error("nil cache must disable updates")
	}
}
