package runtime

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"sync"

	"github.com/osshield/fallbck/pkg/config"
)

// tailLines / tailLineMax bound the in-memory log ring attached to failed runs
const (
	tailLines   = 60
	tailLineMax = 400
)

// LogRing keeps the most recent log lines (all levels, independent of the stdout
// level) so a failed backup can ship them to the server.
type LogRing struct {
	mu    sync.Mutex
	lines []string
	line  []byte
}

func (r *LogRing) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.line = append(r.line, p...)
	for {
		i := -1
		for j, b := range r.line {
			if b == '\n' {
				i = j
				break
			}
		}
		if i < 0 {
			break
		}
		line := string(r.line[:i])
		r.line = r.line[i+1:]
		if line == "" {
			continue
		}
		if len(line) > tailLineMax {
			line = line[:tailLineMax] + "…"
		}
		r.lines = append(r.lines, line)
		if len(r.lines) > tailLines {
			r.lines = r.lines[len(r.lines)-tailLines:]
		}
	}
	return len(p), nil
}

// Tail returns the buffered lines, oldest first
func (r *LogRing) Tail() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.Join(r.lines, "\n")
}

// teeHandler fans a record out to every handler that wants its level
type teeHandler struct{ handlers []slog.Handler }

func (t teeHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, h := range t.handlers {
		if h.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (t teeHandler) Handle(ctx context.Context, r slog.Record) error {
	var firstErr error
	for _, h := range t.handlers {
		if h.Enabled(ctx, r.Level) {
			if err := h.Handle(ctx, r.Clone()); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

func (t teeHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	hs := make([]slog.Handler, len(t.handlers))
	for i, h := range t.handlers {
		hs[i] = h.WithAttrs(attrs)
	}
	return teeHandler{handlers: hs}
}

func (t teeHandler) WithGroup(name string) slog.Handler {
	hs := make([]slog.Handler, len(t.handlers))
	for i, h := range t.handlers {
		hs[i] = h.WithGroup(name)
	}
	return teeHandler{handlers: hs}
}

// DebugControl owns the agent's stdout log level: a base level from environment and
// config, and a runtime override the server toggles per agent via heartbeats.
type DebugControl struct {
	mu     sync.Mutex
	level  *slog.LevelVar
	base   slog.Level
	remote bool
}

// SetBase installs the configured base level (unless a remote override is active)
func (d *DebugControl) SetBase(level slog.Level) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.base = level
	if !d.remote {
		d.level.Set(level)
	}
}

// Level reports the current stdout log level
func (d *DebugControl) Level() slog.Level {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.level.Level()
}

// SetRemoteDebug applies or clears the server-side debug toggle; it reports whether
// the state changed.
func (d *DebugControl) SetRemoteDebug(enabled bool) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if enabled == d.remote {
		return false
	}
	d.remote = enabled
	if enabled {
		d.level.Set(slog.LevelDebug)
	} else {
		d.level.Set(d.base)
	}
	return true
}

// Logging is the agent's logging setup: the stdout logger (level adjustable at
// runtime) plus the ring buffer that always captures debug-level lines.
type Logging struct {
	Control *DebugControl
	Ring    *LogRing
}

// Tail returns the recent log lines for failure reports
func (l *Logging) Tail() string {
	if l == nil || l.Ring == nil {
		return ""
	}
	return l.Ring.Tail()
}

// SetupLogging installs the process-wide logger: JSON on stdout at the environment's
// level (adjustable later), and a text copy of every record — including debug — into
// the ring buffer.
func SetupLogging() *Logging {
	lv := &slog.LevelVar{}
	lv.Set(config.LogLevel())
	ring := &LogRing{}
	handler := teeHandler{handlers: []slog.Handler{
		slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lv}),
		slog.NewTextHandler(ring, &slog.HandlerOptions{Level: slog.LevelDebug}),
	}}
	slog.SetDefault(slog.New(handler))
	return &Logging{Control: &DebugControl{level: lv, base: config.LogLevel()}, Ring: ring}
}

// ApplyConfigLogLevel applies agent.yaml's log_level as the base level unless the
// environment already chose one (DEBUG / FALLBCK_LOG_LEVEL win).
func (l *Logging) ApplyConfigLogLevel(cfg *config.AgentConfig) {
	if l == nil || cfg == nil || cfg.LogLevel == "" || config.EnvLogLevelSet() {
		return
	}
	if lvl, ok := config.ParseLogLevel(cfg.LogLevel); ok {
		l.Control.SetBase(lvl)
	} else {
		slog.Warn("Unknown log_level in agent configuration", "log_level", cfg.LogLevel)
	}
}
