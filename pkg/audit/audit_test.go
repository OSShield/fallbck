package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/osshield/fallbck/pkg/db"
)

func entries() []*db.AuditEntry {
	return []*db.AuditEntry{
		{ID: 1, Actor: "alice@example.com", Action: "job.create", Labels: db.Labels{"team": "a"}},
		{ID: 2, Actor: "bob@example.com", Action: "target.credentials"},
	}
}

func TestFileExportAppendsJSONLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	exp, err := NewExport(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := exp(context.Background(), entries()); err != nil {
			t.Fatal(err)
		}
	}
	f, _ := os.Open(path)
	defer f.Close()
	var lines []db.AuditEntry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e db.AuditEntry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("line %q: %v", sc.Text(), err)
		}
		lines = append(lines, e)
	}
	if len(lines) != 4 || lines[2].Action != "job.create" {
		t.Errorf("file holds %+v", lines)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, want 0600", st.Mode().Perm())
	}
	if _, err := NewExport(filepath.Join(t.TempDir(), "missing", "audit.jsonl"), nil); err == nil {
		t.Error("an unwritable path must fail at startup")
	}
}

func TestHTTPExport(t *testing.T) {
	var body, auth, ctype string
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body, auth, ctype = string(b), r.Header.Get("Authorization"), r.Header.Get("Content-Type")
		w.WriteHeader(status)
	}))
	defer srv.Close()
	exp, err := NewExport(srv.URL+"/collect", map[string]string{"Authorization": "Splunk abc"})
	if err != nil {
		t.Fatal(err)
	}
	if err := exp(context.Background(), entries()); err != nil {
		t.Fatal(err)
	}
	if strings.Count(body, "\n") != 2 || auth != "Splunk abc" || ctype != "application/x-ndjson" {
		t.Errorf("body %q auth %q type %q", body, auth, ctype)
	}
	status = http.StatusServiceUnavailable
	if err := exp(context.Background(), entries()); err == nil {
		t.Error("a non-2xx answer must fail the export, so nothing is pruned")
	}
}

func TestNewExportRejectsUnknown(t *testing.T) {
	for _, bad := range []string{"relative/path.jsonl", "ftp://x", "s3://bucket"} {
		if _, err := NewExport(bad, nil); err == nil {
			t.Errorf("%q: expected an error", bad)
		}
	}
	if exp, err := NewExport("", nil); exp != nil || err != nil {
		t.Error("no export configured must be nil, nil")
	}
	if got := Redact("https://user:secret@logs.example.com/in"); strings.Contains(got, "secret") {
		t.Errorf("Redact left the password: %s", got)
	}
}
