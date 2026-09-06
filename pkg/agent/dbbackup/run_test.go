package dbbackup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	dbspec "github.com/osshield/fallbck/pkg/dbbackup"
)

const pgDumpScript = `
case "$1" in --version) echo "pg_dump (PostgreSQL) @VER@ (Debian @VER@-1.pgdg120+1)"; exit 0;; esac
` + logArgs + `
echo "PGDMP fake dump"
exit ${FAKE_EXIT:-0}
`

func installPostgresTools(t *testing.T, dir, ver string) map[string]string {
	logs := map[string]string{}
	logs["pg_dump"] = fakeBin(t, dir, "pg_dump", strings.ReplaceAll(pgDumpScript, "@VER@", ver))
	logs["pg_dumpall"] = fakeBin(t, dir, "pg_dumpall", strings.ReplaceAll(strings.ReplaceAll(pgDumpScript, "@VER@", ver), "pg_dump (PostgreSQL)", "pg_dumpall (PostgreSQL)"))
	logs["pg_basebackup"] = fakeBin(t, dir, "pg_basebackup", `
case "$1" in --version) echo "pg_basebackup (PostgreSQL) `+ver+`"; exit 0;; esac
`+logArgs+`
for a in "$@"; do case "$a" in --pgdata=*) d=${a#--pgdata=};; esac; done
mkdir -p "$d" && echo base > "$d/base.tar" && echo wal > "$d/pg_wal.tar" && echo m > "$d/backup_manifest"
echo "pg_basebackup: initiating base backup, waiting for checkpoint to complete" >&2
echo "pg_basebackup: write-ahead log start point: 0/2000028 on timeline 1" >&2
echo "pg_basebackup: write-ahead log end point: 0/2000138" >&2
exit 0
`)
	return logs
}

func pgFake(superuser, replication bool) *fakeQuerier {
	b := func(v bool) string {
		if v {
			return "t"
		}
		return "f"
	}
	return &fakeQuerier{
		single: [][2]any{
			{"server_version_num", []string{"160004", "16.4 (Debian 16.4-1)"}},
			{"rolsuper", []string{b(superuser), b(replication)}},
			{"pg_is_in_recovery", []string{"f"}},
			{"wal_level", []string{"replica", "10"}},
			{"pg_database_size", []string{"4096"}},
			{"pg_current_wal_lsn", []string{"0/2000138"}},
			{"timeline_id", []string{"1"}},
			{"pg_walfile_name", []string{"000000010000000000000002"}},
		},
		rows: map[string][][]string{"pg_database": {{"app"}, {"postgres"}}},
	}
}

func TestPostgresDumpRun(t *testing.T) {
	bin := t.TempDir()
	logs := installPostgresTools(t, bin, "16.4")
	withPath(t, bin)
	pgSearchGlobs = nil
	fq := pgFake(false, false)
	pgConnect = func(context.Context, dbspec.Credentials) (querier, error) { return fq, nil }
	t.Cleanup(func() { pgConnect = nil })

	cfg := testConfig(t)
	up := &captureUpload{}
	jobID := uuid.New()
	spec := &dbspec.Spec{Engine: "postgresql", Host: "db01", User: "backup"}
	var phases []string
	result, err := Run(context.Background(), RunOptions{
		Session: testSession(jobID), Spec: spec, Password: "s3c:ret", Config: cfg, Upload: up.fn,
		Hostname: "agent01", AgentVersion: "test", PollInterval: 20 * time.Millisecond,
		Progress: func(p Progress) { phases = append(phases, p.Phase) },
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.SnapshotID == "" {
		t.Error("snapshot id missing")
	}
	for _, f := range []string{"postgres/globals.sql", "postgres/dumps/app.dump", "postgres/dumps/postgres.dump", "fallbck-db.json"} {
		if !up.has(f) {
			t.Errorf("spool is missing %s (have %v)", f, up.files)
		}
	}
	m := up.manifest(t)
	if m.Engine != "postgres" || len(m.Databases) != 2 || m.Postgres == nil || m.Postgres.Globals == nil || m.Postgres.Globals.RolePasswordsIncluded || m.Server.Version != "16.4" || m.Postgres.WALLSN != "0/2000138" {
		t.Errorf("manifest: %+v %+v", m, m.Postgres)
	}
	if m.Spec.Password != "" || !m.Spec.HasPassword {
		t.Errorf("manifest spec must be redacted: %+v", m.Spec)
	}
	if len(m.Restore.Commands) == 0 || !strings.Contains(m.Restore.Commands[1], "pg_restore --create") {
		t.Errorf("restore commands: %v", m.Restore.Commands)
	}

	dumpall := invocations(t, logs["pg_dumpall"])
	if len(dumpall) != 1 || !hasArg(dumpall[0], "--globals-only") || !hasArg(dumpall[0], "--no-role-passwords") {
		t.Errorf("pg_dumpall args: %v", dumpall)
	}
	dumps := invocations(t, logs["pg_dump"])
	if len(dumps) != 2 || !hasArg(dumps[0], "--format=custom") || !hasArg(dumps[0], "--compress=0") || !hasArg(dumps[0], "--dbname=app") || !hasArg(dumps[0], "--no-password") {
		t.Errorf("pg_dump args: %v", dumps)
	}
	joined := strings.Join(dumps[0], "\n")
	if strings.Contains(joined, "s3c:ret") && !strings.Contains(joined, `PGPASS *:*:*:backup:s3c\:ret`) {
		t.Errorf("password leaked into argv: %s", joined)
	}
	if !strings.Contains(joined, `PGPASS *:*:*:backup:s3c\:ret`) {
		t.Errorf("pgpass file not written or not escaped: %s", joined)
	}
	if !strings.Contains(joined, "ENV PGPASSWORD=\n") || !strings.Contains(joined, "ENV FALLBCK_AGENT_AUTH_TOKEN=\n") {
		t.Errorf("environment not scrubbed: %s", joined)
	}
	if _, err := os.Stat(up.spool); !os.IsNotExist(err) {
		t.Error("spool directory not removed after upload")
	}
	if entries, _ := os.ReadDir(cfg.SpoolDir); len(entries) != 0 {
		t.Errorf("secret dir left behind: %v", entries)
	}
	st, err := loadState(cfg.StateDir, jobID.String())
	if err != nil || st == nil || st.LastSuccess == nil || st.LastSuccess.Snapshot != result.SnapshotID {
		t.Errorf("state: %+v %v", st, err)
	}
	if !fq.closed {
		t.Error("querier not closed")
	}
	if !strings.Contains(strings.Join(phases, ","), "upload") {
		t.Errorf("phases: %v", phases)
	}
}

func TestPostgresBasebackupRun(t *testing.T) {
	bin := t.TempDir()
	logs := installPostgresTools(t, bin, "16.4")
	withPath(t, bin)
	pgSearchGlobs = nil
	fq := pgFake(false, true)
	pgConnect = func(context.Context, dbspec.Credentials) (querier, error) { return fq, nil }
	t.Cleanup(func() { pgConnect = nil })

	up := &captureUpload{}
	spec := &dbspec.Spec{Engine: "postgres", Host: "db01", User: "repl", Compression: "gzip", Postgres: &dbspec.PostgresOptions{Mode: "basebackup"}}
	if _, err := Run(context.Background(), RunOptions{Session: testSession(uuid.New()), Spec: spec, Password: "pw", Config: testConfig(t), Upload: up.fn}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	bb := invocations(t, logs["pg_basebackup"])
	if len(bb) != 1 || !hasArg(bb[0], "--format=tar") || !hasArg(bb[0], "--wal-method=stream") || !hasArg(bb[0], "--checkpoint=fast") || !hasArg(bb[0], "--gzip") || !hasArg(bb[0], "--manifest-checksums=sha256") {
		t.Errorf("pg_basebackup args: %v", bb)
	}
	if len(invocations(t, logs["pg_dump"])) != 0 {
		t.Error("pg_dump must not run in basebackup mode")
	}
	m := up.manifest(t)
	b := m.Postgres.Basebackup
	if b == nil || b.WALStartLSN != "0/2000028" || b.WALEndLSN != "0/2000138" || b.Timeline != 1 || b.WALStartFile == "" || len(b.Files) != 3 || b.Compression != "gzip" {
		t.Errorf("basebackup manifest: %+v", b)
	}
}

func TestPostgresPrechecks(t *testing.T) {
	bin := t.TempDir()
	installPostgresTools(t, bin, "15.6")
	withPath(t, bin)
	alt := filepath.Join(t.TempDir(), "postgresql", "16", "bin")
	if err := os.MkdirAll(alt, 0o755); err != nil {
		t.Fatal(err)
	}
	pgSearchGlobs = []string{filepath.Join(filepath.Dir(filepath.Dir(alt)), "*", "bin")}
	t.Cleanup(func() { pgSearchGlobs = nil })
	fq := pgFake(false, false)
	pgConnect = func(context.Context, dbspec.Credentials) (querier, error) { return fq, nil }
	t.Cleanup(func() { pgConnect = nil })

	run := func(spec *dbspec.Spec) error {
		_, err := Run(context.Background(), RunOptions{Session: testSession(uuid.New()), Spec: spec, Password: "pw", Config: testConfig(t), Upload: (&captureUpload{}).fn})
		return err
	}
	// pg_dump 15 on PATH cannot dump a 16 server and no alternative exists yet
	err := run(&dbspec.Spec{Engine: "postgres", Host: "h", User: "u"})
	if !IsPrecheck(err) || !strings.Contains(err.Error(), "cannot back up a PostgreSQL 16 server") {
		t.Errorf("version skew: %v", err)
	}
	// an installed 16 tool set in a well-known directory is picked up instead
	altLogs := installPostgresTools(t, alt, "16.4")
	if err := run(&dbspec.Spec{Engine: "postgres", Host: "h", User: "u"}); err != nil {
		t.Errorf("alternative tools: %v", err)
	}
	if len(invocations(t, altLogs["pg_dump"])) != 2 {
		t.Error("alternative pg_dump was not used")
	}
	// basebackup needs REPLICATION
	err = run(&dbspec.Spec{Engine: "postgres", Host: "h", User: "u", Postgres: &dbspec.PostgresOptions{Mode: "basebackup"}})
	if !IsPrecheck(err) || !strings.Contains(err.Error(), "REPLICATION") {
		t.Errorf("replication precheck: %v", err)
	}
	// unknown database
	err = run(&dbspec.Spec{Engine: "postgres", Host: "h", User: "u", Databases: []string{"nope"}})
	if !IsPrecheck(err) || !strings.Contains(err.Error(), `"nope" does not exist`) {
		t.Errorf("unknown database: %v", err)
	}
	// missing profile
	err = run(&dbspec.Spec{Engine: "postgres", Host: "h", User: "u", Password: ""})
	_, err2 := Run(context.Background(), RunOptions{Session: testSession(uuid.New()), Spec: &dbspec.Spec{Engine: "postgres", Host: "h", User: "u"}, Config: testConfig(t), Upload: (&captureUpload{}).fn})
	if err != nil || !IsPrecheck(err2) || !strings.Contains(err2.Error(), "credential profile") {
		t.Errorf("profile resolution: %v / %v", err, err2)
	}
}

func TestToolFailureAndDiskCheck(t *testing.T) {
	bin := t.TempDir()
	fakeBin(t, bin, "pg_dump", `
case "$1" in --version) echo "pg_dump (PostgreSQL) 16.4"; exit 0;; esac
echo "pg_dump: error: connection to server failed: FATAL:  password authentication failed for user \"u\"" >&2
exit 1
`)
	fakeBin(t, bin, "pg_dumpall", `case "$1" in --version) echo "pg_dumpall (PostgreSQL) 16.4"; exit 0;; esac; exit 0`)
	withPath(t, bin)
	pgSearchGlobs = nil
	pgConnect = func(context.Context, dbspec.Credentials) (querier, error) { return pgFake(true, false), nil }
	t.Cleanup(func() { pgConnect = nil })
	spec := &dbspec.Spec{Engine: "postgres", Host: "h", User: "u", Postgres: &dbspec.PostgresOptions{Globals: new(bool)}}
	_, err := Run(context.Background(), RunOptions{Session: testSession(uuid.New()), Spec: spec, Password: "pw", Config: testConfig(t), Upload: (&captureUpload{}).fn})
	var te *ToolError
	if !IsPrecheck(err) || !errors.As(err, &te) || te.ExitCode != 1 || !strings.Contains(err.Error(), "check the database user and password") {
		t.Errorf("tool failure: %v", err)
	}

	old := freeBytes
	freeBytes = func(string) (uint64, error) { return 100, nil }
	t.Cleanup(func() { freeBytes = old })
	cfg := testConfig(t)
	cfg.MinFreeBytes = 1 << 20
	_, err = Run(context.Background(), RunOptions{Session: testSession(uuid.New()), Spec: spec, Password: "pw", Config: cfg, Upload: (&captureUpload{}).fn})
	if !IsPrecheck(err) || !strings.Contains(err.Error(), "insufficient space") {
		t.Errorf("disk precheck: %v", err)
	}
}

func TestRunCancelKillsTool(t *testing.T) {
	bin := t.TempDir()
	fakeBin(t, bin, "pg_dump", `
case "$1" in --version) echo "pg_dump (PostgreSQL) 16.4"; exit 0;; esac
sleep 30
`)
	fakeBin(t, bin, "pg_dumpall", `case "$1" in --version) echo "pg_dumpall (PostgreSQL) 16.4"; exit 0;; esac; exit 0`)
	withPath(t, bin)
	pgSearchGlobs = nil
	pgConnect = func(context.Context, dbspec.Credentials) (querier, error) { return pgFake(true, false), nil }
	t.Cleanup(func() { pgConnect = nil })
	cfg := testConfig(t)
	cfg.KillGrace = time.Second
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(300 * time.Millisecond); cancel() }()
	start := time.Now()
	spec := &dbspec.Spec{Engine: "postgres", Host: "h", User: "u", Postgres: &dbspec.PostgresOptions{Globals: new(bool)}}
	_, err := Run(ctx, RunOptions{Session: testSession(uuid.New()), Spec: spec, Password: "pw", Config: cfg, Upload: (&captureUpload{}).fn})
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Errorf("expected a cancellation error, got %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("cancellation took %s; the tool was not killed", time.Since(start))
	}
	if entries, _ := os.ReadDir(cfg.SpoolDir); len(entries) != 0 {
		t.Errorf("spool not cleaned after cancel: %v", entries)
	}
}

func TestStateAndFailedUploadKeepsState(t *testing.T) {
	bin := t.TempDir()
	installPostgresTools(t, bin, "16.4")
	withPath(t, bin)
	pgSearchGlobs = nil
	pgConnect = func(context.Context, dbspec.Credentials) (querier, error) { return pgFake(true, false), nil }
	t.Cleanup(func() { pgConnect = nil })
	cfg := testConfig(t)
	cfg.KeepFailedSpool = true
	jobID := uuid.New()
	up := &captureUpload{err: errors.New("pbs down")}
	spec := &dbspec.Spec{Engine: "postgres", Host: "h", User: "u"}
	if _, err := Run(context.Background(), RunOptions{Session: testSession(jobID), Spec: spec, Password: "pw", Config: cfg, Upload: up.fn}); err == nil {
		t.Fatal("upload failure must fail the run")
	}
	if st, _ := loadState(cfg.StateDir, jobID.String()); st != nil {
		t.Error("state must not be written after a failed upload")
	}
	if _, err := os.Stat(up.spool); err != nil {
		t.Error("keep_failed_spool: spool should have been kept")
	}
}
