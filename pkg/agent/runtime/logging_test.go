package runtime

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/osshield/fallbck/pkg/config"
)

func TestLoggingRingAndRemoteToggle(t *testing.T) {
	t.Setenv("DEBUG", "")
	t.Setenv("FALLBCK_LOG_LEVEL", "")
	logging := SetupLogging()

	// Debug lines land in the ring even though stdout runs at info
	slog.Debug("ring only", "k", "v")
	slog.Info("visible line")
	tail := logging.Tail()
	if !strings.Contains(tail, "ring only") || !strings.Contains(tail, "visible line") {
		t.Errorf("ring did not capture all levels: %q", tail)
	}

	if !logging.Control.SetRemoteDebug(true) {
		t.Error("first enable must report a change")
	}
	if logging.Control.SetRemoteDebug(true) {
		t.Error("repeat enable must not report a change")
	}
	if logging.Control.Level() != slog.LevelDebug {
		t.Error("remote toggle did not raise the stdout level")
	}
	logging.Control.SetRemoteDebug(false)
	if logging.Control.Level() != slog.LevelInfo {
		t.Error("disable did not restore the base level")
	}

	// Config file level applies unless the environment chose one
	logging.ApplyConfigLogLevel(&config.AgentConfig{LogLevel: "warn"})
	if logging.Control.Level() != slog.LevelWarn {
		t.Error("config log_level warn not applied")
	}
	// ... and stays the base under a remote-debug cycle
	logging.Control.SetRemoteDebug(true)
	logging.Control.SetRemoteDebug(false)
	if logging.Control.Level() != slog.LevelWarn {
		t.Error("remote cycle lost the configured base level")
	}
	t.Setenv("DEBUG", "true")
	logging2 := SetupLogging()
	logging2.ApplyConfigLogLevel(&config.AgentConfig{LogLevel: "error"})
	if logging2.Control.Level() != slog.LevelDebug {
		t.Error("DEBUG env must outrank the config file")
	}
}

func TestLogRingCaps(t *testing.T) {
	r := &LogRing{}
	long := strings.Repeat("x", 1000)
	for i := 0; i < 200; i++ {
		_, _ = r.Write([]byte(long + "\n"))
	}
	tail := r.Tail()
	lines := strings.Split(tail, "\n")
	if len(lines) != tailLines {
		t.Errorf("ring holds %d lines, want %d", len(lines), tailLines)
	}
	if len(lines[0]) > tailLineMax+4 {
		t.Errorf("line not truncated: %d bytes", len(lines[0]))
	}
}
