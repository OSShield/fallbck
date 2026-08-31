package dbbackup

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	dbspec "github.com/osshield/fallbck/pkg/dbbackup"
	"github.com/osshield/fallbck/pkg/temporal"
	"github.com/osshield/gopbs"
	"github.com/osshield/gopbs/pbs"
)

// fakeBin installs a shell script named name into dir (which the test puts on PATH).
// Scripts get LOG (argv log path) and NAME substituted.
func fakeBin(t *testing.T, dir, name, script string) string {
	t.Helper()
	log := filepath.Join(dir, name+".log")
	script = strings.ReplaceAll(script, "@LOG@", log)
	script = strings.ReplaceAll(script, "@NAME@", name)
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatal(err)
	}
	return log
}

// logArgs is the shell snippet that records every invocation (one arg per line,
// invocations separated by ---) and a few interesting environment variables
const logArgs = `
{
  echo "---"
  for a in "$@"; do echo "$a"; done
  echo "ENV PGPASSFILE=${PGPASSFILE:-}"
  echo "ENV PGPASSWORD=${PGPASSWORD:-}"
  echo "ENV MYSQL_PWD=${MYSQL_PWD:-}"
  echo "ENV FALLBCK_AGENT_AUTH_TOKEN=${FALLBCK_AGENT_AUTH_TOKEN:-}"
  [ -n "${PGPASSFILE:-}" ] && printf 'PGPASS %s\n' "$(cat "$PGPASSFILE")"
  for a in "$@"; do
    case "$a" in
      --defaults-extra-file=*) printf 'MYCNF %s\n' "$(cat "${a#--defaults-extra-file=}" | tr '\n' ' ')";;
      --config=*) printf 'MONGOCFG %s\n' "$(cat "${a#--config=}")";;
    esac
  done
} >> "@LOG@"
`

// invocations splits a log into per-call argument lists
func invocations(t *testing.T, log string) [][]string {
	t.Helper()
	data, err := os.ReadFile(log)
	if err != nil {
		return nil
	}
	var out [][]string
	for _, block := range strings.Split(string(data), "---\n") {
		block = strings.TrimSpace(block)
		if block == "" {
			continue
		}
		out = append(out, strings.Split(block, "\n"))
	}
	return out
}

func hasArg(args []string, want string) bool {
	for _, a := range args {
		if a == want || strings.HasPrefix(a, want+"=") {
			return true
		}
	}
	return false
}

func argValue(args []string, prefix string) string {
	for _, a := range args {
		if strings.HasPrefix(a, prefix) {
			return strings.TrimPrefix(a, prefix)
		}
	}
	return ""
}

// fakeQuerier answers queries by substring match, first match wins
type fakeQuerier struct {
	single [][2]any // {substring, []string values}
	rows   map[string][][]string
	closed bool
}

func (f *fakeQuerier) queryRow(_ context.Context, sql string, dest ...any) error {
	for _, e := range f.single {
		if strings.Contains(sql, e[0].(string)) {
			vals := e[1].([]string)
			for i, d := range dest {
				if i < len(vals) {
					if err := assign(d, vals[i]); err != nil {
						return err
					}
				}
			}
			return nil
		}
	}
	return fmt.Errorf("fake querier: no answer for %q", sql)
}

func (f *fakeQuerier) queryRows(_ context.Context, sql string) ([][]string, error) {
	for k, rows := range f.rows {
		if strings.Contains(sql, k) {
			return rows, nil
		}
	}
	return nil, fmt.Errorf("fake querier: no rows for %q", sql)
}

func (f *fakeQuerier) close() { f.closed = true }

func assign(dest any, val string) error {
	switch d := dest.(type) {
	case *string:
		*d = val
	case *int:
		_, err := fmt.Sscanf(val, "%d", d)
		return err
	case *int64:
		_, err := fmt.Sscanf(val, "%d", d)
		return err
	case *bool:
		*d = val == "t" || val == "true" || val == "1"
	default:
		return fmt.Errorf("unsupported dest %T", dest)
	}
	return nil
}

// captureUpload records what would be uploaded and returns a completed result
type captureUpload struct {
	spool string
	files []string
	blobs []gopbs.Blob
	err   error
	// copyTo receives a copy of the spool (integration restores)
	copyTo string
}

func (c *captureUpload) fn(_ context.Context, spoolDir string, blobs []gopbs.Blob, progress func(string, pbs.UploadStats, bool)) (*temporal.BackupExecutionResult, error) {
	c.spool = spoolDir
	c.blobs = blobs
	c.files = nil
	_ = filepath.WalkDir(spoolDir, func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(spoolDir, path)
			c.files = append(c.files, filepath.ToSlash(rel))
		}
		return nil
	})
	if c.err != nil {
		return nil, c.err
	}
	if c.copyTo != "" {
		if out, err := exec.Command("cp", "-a", spoolDir+"/.", c.copyTo).CombinedOutput(); err != nil {
			return nil, fmt.Errorf("copying spool: %v %s", err, out)
		}
	}
	progress("db.pxar.didx", pbs.UploadStats{Size: 10}, true)
	return &temporal.BackupExecutionResult{Status: "completed", SnapshotID: "host/db-x/2026-08-28T01:00:00Z", ChunkCount: 1}, nil
}

func (c *captureUpload) has(name string) bool {
	for _, f := range c.files {
		if f == name {
			return true
		}
	}
	return false
}

func (c *captureUpload) manifest(t *testing.T) *dbspec.Manifest {
	t.Helper()
	for _, b := range c.blobs {
		if b.Name == dbspec.ManifestBlobName {
			m, err := dbspec.ParseManifest(b.Data)
			if err != nil {
				t.Fatal(err)
			}
			return m
		}
	}
	t.Fatal("manifest blob not uploaded")
	return nil
}

func testSession(jobID uuid.UUID) *temporal.BackupSessionInfo {
	return &temporal.BackupSessionInfo{
		JobID: jobID, BackupRunID: uuid.New(), BackupType: "host", BackupID: "db-x", BackupTime: 1700000000,
		JobType: "database", JobName: "test job",
	}
}

func testConfig(t *testing.T) dbspec.Config {
	t.Helper()
	root := t.TempDir()
	cfg := dbspec.Config{MinFreeBytes: 1}
	cfg.ApplyDefaults(root)
	return cfg
}

func withPath(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}
