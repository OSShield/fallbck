// Package audit keeps the audit log bounded: a daily prune deletes entries older than
// the retention, after handing them to the configured export so they still exist
// somewhere.
package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/osshield/fallbck/pkg/db"
)

// Export delivers entries to a destination; an error keeps them in the database
type Export func(ctx context.Context, entries []*db.AuditEntry) error

// NewExport builds the export named by target (see config.AuditConfig.Export) and
// checks the destination is reachable now, so a typo fails at startup rather than at
// the first prune. Empty target: nil, no export.
func NewExport(target string, headers map[string]string) (Export, error) {
	switch {
	case target == "":
		return nil, nil
	case strings.HasPrefix(target, "/") || strings.HasPrefix(target, "file://"):
		return fileExport(strings.TrimPrefix(target, "file://"))
	case strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://"):
		if _, err := url.ParseRequestURI(target); err != nil {
			return nil, fmt.Errorf("audit.export: %w", err)
		}
		return httpExport(target, headers), nil
	case strings.HasPrefix(target, "udp://") || strings.HasPrefix(target, "tcp://") || target == "syslog:" || target == "syslog://":
		return syslogExport(target)
	}
	return nil, fmt.Errorf("audit.export %q: expected an absolute file path, http(s)://, udp://, tcp:// or syslog:", target)
}

func jsonLines(entries []*db.AuditEntry) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, e := range entries {
		if err := enc.Encode(e); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// fileExport appends JSON lines and fsyncs before the rows are deleted
func fileExport(path string) (Export, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("audit.export: %q is not an absolute path", path)
	}
	appendLines := func(data []byte) error {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		if _, err := f.Write(data); err != nil {
			_ = f.Close()
			return err
		}
		if err := f.Sync(); err != nil {
			_ = f.Close()
			return err
		}
		return f.Close()
	}
	if err := appendLines(nil); err != nil {
		return nil, fmt.Errorf("audit.export: %w", err)
	}
	return func(_ context.Context, entries []*db.AuditEntry) error {
		data, err := jsonLines(entries)
		if err != nil {
			return err
		}
		return appendLines(data)
	}, nil
}

// httpExport POSTs one batch as application/x-ndjson; any 2xx counts as delivered
func httpExport(target string, headers map[string]string) Export {
	client := &http.Client{Timeout: 60 * time.Second}
	return func(ctx context.Context, entries []*db.AuditEntry) error {
		data, err := jsonLines(entries)
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(data))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/x-ndjson")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return fmt.Errorf("audit export endpoint answered %s", resp.Status)
		}
		return nil
	}
}

// Prune deletes entries older than retention (export first) and records the prune
// in the audit log itself. It returns how many entries it deleted.
func Prune(ctx context.Context, d *db.DB, retention time.Duration, export Export, exportName string) (int, error) {
	before := time.Now().Add(-retention)
	var exp func([]*db.AuditEntry) error
	if export != nil {
		exp = func(entries []*db.AuditEntry) error { return export(ctx, entries) }
	}
	n, err := d.PruneAudit(ctx, before, exp)
	if n > 0 {
		details, _ := json.Marshal(map[string]any{"before": before.UTC(), "deleted": n, "exported_to": exportName, "complete": err == nil})
		if werr := d.WriteAudit(ctx, &db.AuditEntry{ActorKind: "system", Actor: "fallbck-server", Action: "audit.prune",
			ResourceKind: "audit", Details: details}); werr != nil {
			slog.Error("Writing the audit prune entry failed", "error", werr)
		}
	}
	return n, err
}

// RunPruner prunes a minute after start and then once a day until ctx ends.
// retention 0 disables it.
func RunPruner(ctx context.Context, d *db.DB, retention time.Duration, export Export, exportName string) {
	if retention <= 0 {
		slog.Info("Audit log retention is off: entries are kept forever")
		return
	}
	timer := time.NewTimer(time.Minute)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		n, err := Prune(ctx, d, retention, export, exportName)
		switch {
		case err != nil:
			slog.Error("Audit log prune failed; entries stay until the next try", "deleted", n, "export", exportName, "error", err)
		case n > 0:
			slog.Info("Audit log pruned", "deleted", n, "retention", retention, "export", exportName)
		}
		timer.Reset(24 * time.Hour)
	}
}

// Redact hides userinfo in an export URL before it is logged or audited
func Redact(target string) string {
	if u, err := url.Parse(target); err == nil && u.User != nil {
		u.User = url.User("redacted")
		return u.String()
	}
	return target
}
