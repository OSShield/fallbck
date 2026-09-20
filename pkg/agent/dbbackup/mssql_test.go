package dbbackup

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	dbspec "github.com/osshield/fallbck/pkg/dbbackup"
)

func TestPlanMSSQLDatabase(t *testing.T) {
	now := time.Date(2026, 9, 20, 2, 0, 0, 0, time.UTC)
	held := func(uuid string, age time.Duration) *dbspec.MSSQLDBState {
		return &dbspec.MSSQLDBState{RecoveryModel: "FULL", LastFull: &dbspec.MSSQLBackupRef{BackupSetUUID: uuid, At: now.Add(-age)}}
	}
	app := mssqlDB{Name: "app", Recovery: "FULL", State: "ONLINE"}
	cases := []struct {
		name     string
		opts     dbspec.MSSQLOptions
		db       mssqlDB
		st       *dbspec.MSSQLDBState
		lastFull string
		want     string // kinds joined by "+", or "skip"
		reason   string // substring of the reason / skip text
	}{
		{"first run is a full", dbspec.MSSQLOptions{Mode: "auto"}, app, nil, "", "full", "no full backup"},
		{"auto within the window", dbspec.MSSQLOptions{Mode: "auto"}, app, held("u1", 48*time.Hour), "u1", "differential", ""},
		{"auto after the window", dbspec.MSSQLOptions{Mode: "auto", FullEveryDays: 3}, app, held("u1", 96*time.Hour), "u1", "full", "4 days old"},
		{"foreign full resets the chain", dbspec.MSSQLOptions{Mode: "differential"}, app, held("u1", time.Hour), "u2", "full", "chain reset"},
		{"purged history resets the chain", dbspec.MSSQLOptions{Mode: "differential"}, app, held("u1", time.Hour), "", "full", "chain reset"},
		{"recovery model change", dbspec.MSSQLOptions{Mode: "auto"}, mssqlDB{Name: "app", Recovery: "SIMPLE", State: "ONLINE"}, held("u1", time.Hour), "u1", "full", "recovery model changed"},
		{"master is always full", dbspec.MSSQLOptions{Mode: "differential"}, mssqlDB{Name: "master", Recovery: "SIMPLE", State: "ONLINE"}, held("u1", time.Hour), "u1", "full", "master"},
		{"full mode", dbspec.MSSQLOptions{Mode: "full"}, app, held("u1", time.Hour), "u1", "full", ""},
		{"include log after a differential", dbspec.MSSQLOptions{Mode: "auto", IncludeLog: true}, app, held("u1", time.Hour), "u1", "differential+log", ""},
		{"include log skips SIMPLE", dbspec.MSSQLOptions{Mode: "full", IncludeLog: true}, mssqlDB{Name: "tiny", Recovery: "SIMPLE", State: "ONLINE"}, nil, "", "full", ""},
		{"log mode", dbspec.MSSQLOptions{Mode: "log"}, app, held("u1", time.Hour), "u1", "log", ""},
		{"log mode without a held full", dbspec.MSSQLOptions{Mode: "log"}, app, nil, "u9", "log", "not held by this job"},
		{"log mode on SIMPLE", dbspec.MSSQLOptions{Mode: "log"}, mssqlDB{Name: "tiny", Recovery: "SIMPLE", State: "ONLINE"}, nil, "u1", "skip", "SIMPLE"},
		{"log mode before any full", dbspec.MSSQLOptions{Mode: "log"}, app, nil, "", "skip", "no full backup exists"},
		{"offline database", dbspec.MSSQLOptions{Mode: "auto"}, mssqlDB{Name: "old", Recovery: "FULL", State: "OFFLINE"}, nil, "", "skip", "OFFLINE"},
		{"database snapshot", dbspec.MSSQLOptions{Mode: "auto"}, mssqlDB{Name: "snap", Recovery: "FULL", State: "ONLINE", IsSnapshot: true}, nil, "", "skip", "snapshot"},
	}
	for _, c := range cases {
		tasks, skip := planMSSQLDatabase(&c.opts, c.db, c.st, c.lastFull, now)
		got, reason := "skip", skip
		if skip == "" {
			kinds := make([]string, len(tasks))
			for i, task := range tasks {
				kinds[i] = task.Kind
			}
			got, reason = strings.Join(kinds, "+"), tasks[0].Reason
		}
		if got != c.want || !strings.Contains(reason, c.reason) {
			t.Errorf("%s: got %s (%q), want %s (…%s…)", c.name, got, reason, c.want, c.reason)
		}
	}
}

func TestMSSQLStatementsAndNames(t *testing.T) {
	off := false
	opts := &dbspec.MSSQLOptions{Mode: "full", CopyOnly: true, Checksum: &off, MaxTransferSize: 1048576}
	sql := mssqlBackupSQL(opts, mssqlTask{DB: "we]ird", Kind: mssqlFull}, []string{`D:\Backup\a.bak`, `D:\Backup\b.bak`}, true, "fallbck it's")
	for _, want := range []string{"BACKUP DATABASE [we]]ird] TO DISK = N'D:\\Backup\\a.bak', DISK = N'D:\\Backup\\b.bak'", "COPY_ONLY", "COMPRESSION", "MAXTRANSFERSIZE = 1048576", "NAME = N'fallbck it''s'", "STATS = 10", "FORMAT, INIT"} {
		if !strings.Contains(sql, want) {
			t.Errorf("statement lacks %q:\n%s", want, sql)
		}
	}
	if strings.Contains(sql, "CHECKSUM") || strings.Contains(sql, "DIFFERENTIAL") {
		t.Errorf("unexpected options: %s", sql)
	}
	logSQL := mssqlBackupSQL(&dbspec.MSSQLOptions{}, mssqlTask{DB: "app", Kind: mssqlLog}, []string{"/var/opt/mssql/backup/x.trn"}, false, "l")
	if !strings.HasPrefix(logSQL, "BACKUP LOG [app] TO DISK = N'/var/opt/mssql/backup/x.trn' WITH CHECKSUM, NO_COMPRESSION") {
		t.Errorf("log statement: %s", logSQL)
	}
	if got := mssqlServerJoin(`D:\Backup\`, "f.bak"); got != `D:\Backup\f.bak` {
		t.Errorf("windows join %q", got)
	}
	if got := mssqlServerJoin(`\\nas\sql`, "f.bak"); got != `\\nas\sql\f.bak` {
		t.Errorf("unc join %q", got)
	}
	if got := mssqlServerJoin("/var/opt/mssql/backup", "f.bak"); got != "/var/opt/mssql/backup/f.bak" {
		t.Errorf("linux join %q", got)
	}
	names := mssqlFileNames("0a1b2c3d-0000-0000-0000-000000000000", mssqlTask{DB: "my db/x", Kind: mssqlDiff}, 2)
	if len(names) != 2 || names[0] != "fallbck-0a1b2c3d-my_db_x-differential-1of2.bak" {
		t.Errorf("stripe names %v", names)
	}
	if n := mssqlFileNames("0a1b2c3d-1", mssqlTask{DB: "app", Kind: mssqlLog}, 1); n[0] != "fallbck-0a1b2c3d-app-log.trn" {
		t.Errorf("log name %v", n)
	}
	if dsn := mssqlDSN(dbspec.Credentials{Host: `sql01\INST`, Port: 1433, User: "backup", Password: "p@ss"}); !strings.HasPrefix(dsn, "sqlserver://backup:p%40ss@sql01/INST?") || strings.Contains(dsn, ":1433") {
		t.Errorf("named instance dsn %s", dsn)
	}
	// Default TLS mode: the driver still runs TLS for the login and would reject SQL
	// Server's self-signed certificate unless told to trust it (found against a real server)
	if dsn := mssqlDSN(dbspec.Credentials{Host: "sql01", Port: 1433, User: "u", Password: "p"}); !strings.Contains(dsn, "TrustServerCertificate=true") || !strings.Contains(dsn, "encrypt=false") {
		t.Errorf("default tls dsn %s", dsn)
	}
	if dsn := mssqlDSN(dbspec.Credentials{Host: "sql01", Port: 1433, User: "u", Password: "p", TLS: dbspec.TLSSpec{Mode: dbspec.TLSVerifyFull, CAFile: "/etc/ssl/ca.pem"}}); !strings.Contains(dsn, "TrustServerCertificate=false") || !strings.Contains(dsn, "certificate=%2Fetc%2Fssl%2Fca.pem") {
		t.Errorf("verify dsn %s", dsn)
	}
	if dsn := mssqlDSN(dbspec.Credentials{Host: "sql01", Port: 1444, TLS: dbspec.TLSSpec{Mode: dbspec.TLSRequire}}); !strings.HasPrefix(dsn, "sqlserver://sql01:1444?") || !strings.Contains(dsn, "TrustServerCertificate=true") || strings.Contains(dsn, "@") {
		t.Errorf("integrated dsn %s", dsn)
	}
}

// fakeMSSQL is a tiny SQL Server: it answers the engine's queries, "writes" the files
// of every BACKUP statement into dir and keeps a backupset history like msdb
type fakeMSSQL struct {
	dir        string
	dbs        [][]string // name, recovery, state, is_snapshot
	edition    string
	engineEd   string
	lastFull   map[string]string // database -> uuid of the newest real full
	sets       map[string][]string
	lsn        int
	statements []string
	failOn     string
}

var diskRe = regexp.MustCompile(`DISK = N'([^']+)'`)

func (f *fakeMSSQL) exec(_ context.Context, sql string, onMessage func(string)) error {
	f.statements = append(f.statements, sql)
	if f.failOn != "" && strings.Contains(sql, f.failOn) {
		return fmt.Errorf("mssql: Cannot open backup device; BACKUP DATABASE is terminating abnormally")
	}
	db := regexp.MustCompile(`BACKUP (?:DATABASE|LOG) \[([^\]]+)\]`).FindStringSubmatch(sql)[1]
	for _, m := range diskRe.FindAllStringSubmatch(sql, -1) {
		if err := os.WriteFile(filepath.Join(f.dir, filepath.Base(m[1])), []byte("TAPE "+sql), 0o640); err != nil {
			return err
		}
	}
	if onMessage != nil {
		onMessage("50 percent processed.")
		onMessage("Processed 392 pages for database.")
	}
	f.lsn++
	id := fmt.Sprintf("set-%d", f.lsn)
	if strings.HasPrefix(sql, "BACKUP DATABASE") && !strings.Contains(sql, "DIFFERENTIAL") && !strings.Contains(sql, "COPY_ONLY") {
		f.lastFull[db] = id
	}
	first := diskRe.FindStringSubmatch(sql)[1]
	f.sets[db+"|"+first] = []string{id, fmt.Sprintf("%d000", f.lsn), fmt.Sprintf("%d000", f.lsn+1), "0", "0", f.lastFull[db], "4096.00", "4096.00", "2026-09-20T02:00:00", "2026-09-20T02:00:05"}
	return nil
}

func (f *fakeMSSQL) queryRow(context.Context, string, ...any) error { return fmt.Errorf("not used") }

func (f *fakeMSSQL) queryRows(_ context.Context, sql string) ([][]string, error) {
	switch {
	case strings.Contains(sql, "SERVERPROPERTY('ProductVersion')"):
		return [][]string{{"16.0.4135.4", f.edition, f.engineEd, f.dir}}, nil
	case strings.Contains(sql, "FROM sys.databases"):
		return f.dbs, nil
	case strings.Contains(sql, "MAX(backup_set_id)"):
		var rows [][]string
		for db, id := range f.lastFull {
			rows = append(rows, []string{db, id})
		}
		return rows, nil
	case strings.Contains(sql, "HAS_PERMS_BY_NAME"):
		return [][]string{{"1"}}, nil
	case strings.Contains(sql, "xp_fileexist"):
		name := regexp.MustCompile(`N'([^']+)'`).FindStringSubmatch(sql)[1]
		if _, err := os.Stat(filepath.Join(f.dir, filepath.Base(name))); err != nil {
			return [][]string{{"0", "0", "1"}}, nil
		}
		return [][]string{{"1", "0", "1"}}, nil
	case strings.Contains(sql, "sys.master_files"):
		return [][]string{{"8388608"}}, nil
	case strings.Contains(sql, "backupmediafamily"):
		m := regexp.MustCompile(`database_name = N'([^']+)' AND mf.physical_device_name = N'([^']+)'`).FindStringSubmatch(sql)
		if set, ok := f.sets[m[1]+"|"+m[2]]; ok {
			return [][]string{set}, nil
		}
		return nil, nil
	}
	return nil, fmt.Errorf("fake mssql: no answer for %q", sql)
}

func (f *fakeMSSQL) close() {}

func TestRunMSSQLChain(t *testing.T) {
	srv := &fakeMSSQL{dir: t.TempDir(), edition: "Express Edition (64-bit)", engineEd: "4", lastFull: map[string]string{}, sets: map[string][]string{},
		dbs: [][]string{{"app", "FULL", "ONLINE", "0"}, {"master", "SIMPLE", "ONLINE", "0"}, {"tempdb", "SIMPLE", "ONLINE", "0"}, {"old", "FULL", "OFFLINE", "0"}}}
	orig := mssqlConnect
	mssqlConnect = func(context.Context, dbspec.Credentials) (mssqlConn, error) { return srv, nil }
	t.Cleanup(func() { mssqlConnect = orig })

	cfg := testConfig(t)
	jobID := uuid.New()
	spec := &dbspec.Spec{Engine: dbspec.EngineMSSQL, Host: "sql01", User: "backup", MSSQL: &dbspec.MSSQLOptions{Mode: dbspec.MSSQLModeAuto, IncludeLog: true, Compression: true}}
	run := func() (*captureUpload, *dbspec.Manifest) {
		t.Helper()
		up := &captureUpload{}
		srv.statements = nil
		if _, err := Run(context.Background(), RunOptions{Session: testSession(jobID), Spec: spec, Password: "pw", Config: cfg, Upload: up.fn}); err != nil {
			t.Fatalf("Run: %v", err)
		}
		return up, up.manifest(t)
	}
	kinds := func(m *dbspec.Manifest) string {
		var out []string
		for _, s := range m.MSSQL.BackupSets {
			out = append(out, s.Database+":"+s.Type)
		}
		return strings.Join(out, " ")
	}

	// Run 1: nothing held yet, so fulls; app is in FULL recovery and gets a log backup too
	up, m := run()
	if got := kinds(m); got != "app:full app:log master:full" {
		t.Fatalf("run 1 sets: %s", got)
	}
	if m.MSSQL.Compression {
		t.Error("compression must be switched off on Express")
	}
	if len(m.MSSQL.Skipped) != 1 || m.MSSQL.Skipped[0].Database != "old" {
		t.Errorf("skipped %+v", m.MSSQL.Skipped)
	}
	for _, s := range srv.statements {
		if strings.Contains(s, "tempdb") || strings.Contains(s, " COMPRESSION") && !strings.Contains(s, "NO_COMPRESSION") {
			t.Errorf("unexpected statement %s", s)
		}
	}
	short := strings.ReplaceAll(m.Job.BackupRunID, "-", "")[:8]
	for _, f := range []string{"mssql/fallbck-" + short + "-app-full.bak", "mssql/fallbck-" + short + "-app-log.trn", "mssql/fallbck-" + short + "-master-full.bak", dbspec.ManifestFileName} {
		if !up.has(f) {
			t.Errorf("upload lacks %s (has %v)", f, up.files)
		}
	}
	if left, _ := os.ReadDir(srv.dir); len(left) != 0 {
		t.Errorf("backup directory not emptied: %v", left)
	}
	if len(m.Databases) != 3 || m.Databases[0].SizeBytes == 0 || m.Databases[0].Format != "mssql-full" {
		t.Errorf("database entries %+v", m.Databases)
	}

	// Run 2: the held full is still the server's newest: differential + log; master stays full
	_, m = run()
	if got := kinds(m); got != "app:differential app:log master:full" {
		t.Fatalf("run 2 sets: %s", got)
	}
	restore := strings.Join(m.Restore.Commands, "\n")
	for _, want := range []string{"RESTORE DATABASE [app] FROM DISK = N'", "-app-full.bak' WITH REPLACE, NORECOVERY;", "-app-differential.bak' WITH NORECOVERY;", "RESTORE LOG [app] FROM", "RESTORE DATABASE [app] WITH RECOVERY;", "proxmox-backup-client restore host/db-x/"} {
		if !strings.Contains(restore, want) {
			t.Errorf("restore commands lack %q:\n%s", want, restore)
		}
	}
	if strings.Index(restore, "-app-full.bak") > strings.Index(restore, "-app-differential.bak") || strings.Index(restore, "-app-differential.bak") > strings.Index(restore, "RESTORE LOG [app]") {
		t.Errorf("restore order wrong:\n%s", restore)
	}

	// Another tool takes a full: the next run must not build a differential on it
	srv.lastFull["app"] = "foreign-full"
	_, m = run()
	if got := kinds(m); got != "app:full app:log master:full" {
		t.Fatalf("run 3 sets: %s", got)
	}
	if !strings.Contains(strings.Join(m.Notes, " "), "chain reset") {
		t.Errorf("chain reset not noted: %v", m.Notes)
	}

	// A failing BACKUP fails the run and leaves nothing behind in the backup directory
	srv.failOn = "BACKUP DATABASE [master]"
	up = &captureUpload{}
	if _, err := Run(context.Background(), RunOptions{Session: testSession(jobID), Spec: spec, Password: "pw", Config: cfg, Upload: up.fn}); err == nil || !strings.Contains(err.Error(), "Cannot open backup device") {
		t.Fatalf("expected the BACKUP error, got %v", err)
	}
	if left, _ := os.ReadDir(srv.dir); len(left) != 0 {
		t.Errorf("failed run left files behind: %v", left)
	}
}

func TestMSSQLPrecheckDirectoryMismatch(t *testing.T) {
	srv := &fakeMSSQL{dir: t.TempDir(), edition: "Developer Edition", engineEd: "3", lastFull: map[string]string{}, sets: map[string][]string{},
		dbs: [][]string{{"app", "FULL", "ONLINE", "0"}}}
	orig := mssqlConnect
	mssqlConnect = func(context.Context, dbspec.Credentials) (mssqlConn, error) { return srv, nil }
	t.Cleanup(func() { mssqlConnect = orig })

	// The agent writes its probe into another directory than the one the server checks
	spec := &dbspec.Spec{Engine: dbspec.EngineMSSQL, Host: "sql01", User: "backup", MSSQL: &dbspec.MSSQLOptions{Mode: "full", BackupDir: "/var/opt/mssql/backup", AgentDir: t.TempDir()}}
	_, err := Run(context.Background(), RunOptions{Session: testSession(uuid.New()), Spec: spec, Password: "pw", Config: testConfig(t), Upload: (&captureUpload{}).fn})
	if err == nil || !IsPrecheck(err) || !strings.Contains(err.Error(), "not the same directory") {
		t.Fatalf("expected a directory mismatch precheck error, got %v", err)
	}
	if len(srv.statements) != 0 {
		t.Errorf("no BACKUP may run after a failed precheck: %v", srv.statements)
	}
}

func TestMSSQLLogChainGap(t *testing.T) {
	st := &dbspec.MSSQLState{Databases: map[string]*dbspec.MSSQLDBState{"app": {Logs: []dbspec.MSSQLBackupRef{{LastLSN: "100"}}}}}
	if w := applyMSSQLSet(st, dbspec.MSSQLBackupSet{Database: "app", Type: mssqlLog, FirstLSN: "100", LastLSN: "140"}, "r", "s"); w != "" || len(st.Databases["app"].Logs) != 2 {
		t.Errorf("contiguous log must extend the chain: %q %+v", w, st.Databases["app"].Logs)
	}
	if w := applyMSSQLSet(st, dbspec.MSSQLBackupSet{Database: "app", Type: mssqlLog, FirstLSN: "200", LastLSN: "240"}, "r", "s"); !strings.Contains(w, "log chain gap") || len(st.Databases["app"].Logs) != 1 {
		t.Errorf("gap must warn and restart the held log list: %q %+v", w, st.Databases["app"].Logs)
	}
}
