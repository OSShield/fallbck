package embedded

import (
	"log/slog"
	"os"

	tlog "go.temporal.io/server/common/log"
	"go.temporal.io/server/common/log/tag"
)

// slogLogger adapts *slog.Logger to Temporal's log.Logger interface
type slogLogger struct {
	log *slog.Logger
}

// NewLogger wraps a slog logger for the Temporal server. Temporal is verbose at Info;
// callers typically pass a logger at Warn level for production.
func NewLogger(l *slog.Logger) tlog.Logger {
	if l == nil {
		l = slog.Default()
	}
	return &slogLogger{log: l.With("component", "temporal")}
}

func attrs(tags []tag.Tag) []any {
	out := make([]any, 0, len(tags))
	for _, t := range tags {
		out = append(out, slog.Any(t.Key(), t.Value()))
	}
	return out
}

func (s *slogLogger) Debug(msg string, tags ...tag.Tag)  { s.log.Debug(msg, attrs(tags)...) }
func (s *slogLogger) Info(msg string, tags ...tag.Tag)   { s.log.Info(msg, attrs(tags)...) }
func (s *slogLogger) Warn(msg string, tags ...tag.Tag)   { s.log.Warn(msg, attrs(tags)...) }
func (s *slogLogger) Error(msg string, tags ...tag.Tag)  { s.log.Error(msg, attrs(tags)...) }
func (s *slogLogger) DPanic(msg string, tags ...tag.Tag) { s.log.Error(msg, attrs(tags)...) }

func (s *slogLogger) Panic(msg string, tags ...tag.Tag) {
	s.log.Error(msg, attrs(tags)...)
	panic(msg)
}

// Fatal terminates the process: the Temporal server relies on Fatal never returning
func (s *slogLogger) Fatal(msg string, tags ...tag.Tag) {
	s.log.Error("FATAL: "+msg, attrs(tags)...)
	os.Exit(1)
}
