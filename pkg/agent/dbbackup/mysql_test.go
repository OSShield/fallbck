package dbbackup

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	dbspec "github.com/osshield/fallbck/pkg/dbbackup"
)

func installMySQLTools(t *testing.T, dir, dumpName, verLine string) map[string]string {
	logs := map[string]string{}
	logs["dump"] = fakeBin(t, dir, dumpName, `
case "$1" in --version) echo "`+verLine+`"; exit 0;; esac
`+logArgs+`
for a in "$@"; do case "$a" in --result-file=*) f=${a#--result-file=};; esac; done
{
  echo "-- MySQL dump"
  echo "-- CHANGE MASTER TO MASTER_LOG_FILE='binlog.000012', MASTER_LOG_POS=157;"
  echo "-- SET GLOBAL gtid_slave_pos='0-1-2345';"
  echo "CREATE DATABASE app;"
} > "$f"
exit 0
`)
	binlogName := "mysqlbinlog"
	if dumpName == "mariadb-dump" {
		binlogName = "mariadb-binlog"
	}
	logs["binlog"] = fakeBin(t, dir, binlogName, `
case "$1" in --version) echo "`+strings.Replace(verLine, dumpName, binlogName, 1)+`"; exit 0;; esac
`+logArgs+`
for a in "$@"; do case "$a" in --result-file=*) d=${a#--result-file=};; esac; done
last=""; for a in "$@"; do last="$a"; done
mkdir -p "$d" && printf 'binlogdata' > "$d$last"
exit 0
`)
	return logs
}

func mysqlFake(version string) *fakeQuerier {
	return &fakeQuerier{
		single: [][2]any{
			{"VERSION()", []string{version}},
			{"@@log_bin", []string{"1"}},
			{"@@server_id", []string{"7"}},
			{"@@server_uuid", []string{"abc-uuid"}},
			{"@@gtid_mode", []string{"ON"}},
			{"@@gtid_current_pos", []string{"0-7-99"}},
			{"COUNT(*)", []string{"1"}},
			{"information_schema.TABLES", []string{"123456"}},
		},
		rows: map[string][][]string{
			"SHOW DATABASES":   {{"information_schema"}, {"app"}, {"mysql"}, {"shop"}},
			"SHOW BINARY LOGS": {{"binlog.000009", "10"}, {"binlog.000010", "10"}, {"binlog.000011", "10"}, {"binlog.000012", "10"}},
		},
	}
}

func TestMySQLRunMariaDBWithBinlogs(t *testing.T) {
	bin := t.TempDir()
	logs := installMySQLTools(t, bin, "mariadb-dump", "mariadb-dump  Ver 10.19 Distrib 10.11.6-MariaDB, for debian-linux-gnu (x86_64)")
	withPath(t, bin)
	mysqlConnect = func(context.Context, dbspec.Credentials) (querier, error) {
		return mysqlFake("10.11.6-MariaDB-ubu2404"), nil
	}
	t.Cleanup(func() { mysqlConnect = nil })

	cfg := testConfig(t)
	jobID := uuid.New()
	// previous run ended at binlog.000010:157 on the same server
	if err := saveState(cfg.StateDir, jobID.String(), &dbspec.JobState{JobID: jobID.String(), Engine: "mysql", LastSuccess: &dbspec.JobStateRecord{RunID: "prev", Snapshot: "host/db-x/prev", MySQL: &dbspec.MySQLState{BinlogFile: "binlog.000010", BinlogPos: 157, ServerID: 7}}}); err != nil {
		t.Fatal(err)
	}
	up := &captureUpload{}
	spec := &dbspec.Spec{Engine: "mariadb", Host: "db02", User: "backup", MySQL: &dbspec.MySQLOptions{IncludeBinlogs: true}}
	if _, err := Run(context.Background(), RunOptions{Session: testSession(jobID), Spec: spec, Password: `p"w\x`, Config: cfg, Upload: up.fn}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	dumps := invocations(t, logs["dump"])
	if len(dumps) != 1 {
		t.Fatalf("dump invocations: %v", dumps)
	}
	args := dumps[0]
	if !strings.HasPrefix(args[0], "--defaults-extra-file=") {
		t.Errorf("--defaults-extra-file must be the first argument: %v", args)
	}
	for _, want := range []string{"--host=db02", "--port=3306", "--protocol=TCP", "--single-transaction", "--quick", "--master-data=2", "--gtid", "--flush-logs", "--all-databases", "--routines", "--events"} {
		if !hasArg(args, want) {
			t.Errorf("missing %s in %v", want, args)
		}
	}
	for _, unwanted := range []string{"--set-gtid-purged", "--source-data", "--no-tablespaces", "--password"} {
		if hasArg(args, unwanted) {
			t.Errorf("unexpected %s in %v", unwanted, args)
		}
	}
	joined := strings.Join(args, "\n")
	if !strings.Contains(joined, `MYCNF [client] user=backup password="p\"w\\x"`) {
		t.Errorf("credentials file: %s", joined)
	}
	if strings.Count(joined, `p"w\x`) != 0 {
		t.Errorf("raw password leaked into argv: %s", joined)
	}
	fetched := invocations(t, logs["binlog"])
	if len(fetched) != 3 {
		t.Errorf("expected 3 binlog fetches, got %d", len(fetched))
	}
	for _, f := range fetched {
		if !hasArg(f, "--read-from-remote-server") || !hasArg(f, "--raw") || !strings.HasPrefix(f[0], "--defaults-extra-file=") {
			t.Errorf("binlog args: %v", f)
		}
	}
	m := up.manifest(t)
	bl := m.MySQL.Binlog
	if bl == nil || bl.File != "binlog.000012" || bl.Position != 157 || bl.GTID != "0-1-2345" || bl.PositionSource != "dump-header" {
		t.Fatalf("binlog position: %+v", bl)
	}
	if len(bl.Files) != 3 || bl.Files[0].Path != "mysql/binlog/binlog.000010" || bl.Files[2].Path != "mysql/binlog/binlog.000012" || bl.ChainGap || bl.ChainReset {
		t.Errorf("binlog files: %+v", bl)
	}
	if bl.CoversFrom == nil || bl.CoversFrom.File != "binlog.000010" || bl.CoversFrom.Position != 157 || bl.Previous == nil || bl.Previous.RunID != "prev" {
		t.Errorf("covers: %+v %+v", bl.CoversFrom, bl.Previous)
	}
	for _, f := range []string{"mysql/all-databases.sql", "mysql/binlog/binlog.000011"} {
		if !up.has(f) {
			t.Errorf("missing %s in %v", f, up.files)
		}
	}
	if m.MySQL.NonTransactionalTables != 1 || m.MySQL.Flavor != "mariadb" {
		t.Errorf("mysql manifest: %+v", m.MySQL)
	}
	st, _ := loadState(cfg.StateDir, jobID.String())
	if st == nil || st.LastSuccess.MySQL == nil || st.LastSuccess.MySQL.BinlogFile != "binlog.000012" || st.LastSuccess.MySQL.BinlogPos != 157 {
		t.Errorf("state: %+v", st)
	}
	_ = os.RemoveAll(filepath.Join(cfg.StateDir))
}

func TestMySQLDumpArgsMySQL8(t *testing.T) {
	req := &DumpRequest{
		Spec:   &dbspec.Spec{Engine: "mysql", Host: "h", MySQL: &dbspec.MySQLOptions{}},
		Tools:  ToolInfo{Binaries: map[string]Binary{"dump": {Path: "/usr/bin/mysqldump", Flavor: "mysql", Major: 8, Minor: 0, Patch: 36}}},
		Server: ServerInfo{Attrs: map[string]string{"log_bin": "1"}},
	}
	args := mysqlDumpArgs(req)
	for _, want := range []string{"--source-data=2", "--set-gtid-purged=AUTO", "--no-tablespaces", "--single-transaction"} {
		if !hasArg(args, want) {
			t.Errorf("missing %s in %v", want, args)
		}
	}
	for _, unwanted := range []string{"--master-data=2", "--gtid", "--flush-logs"} {
		if hasArg(args, unwanted) {
			t.Errorf("unexpected %s in %v", unwanted, args)
		}
	}
	req.Tools.Binaries["dump"] = Binary{Flavor: "mysql", Major: 8, Minor: 0, Patch: 20}
	if args := mysqlDumpArgs(req); !hasArg(args, "--master-data=2") {
		t.Errorf("old mysql must use --master-data: %v", args)
	}
	req.Server.Attrs["log_bin"] = "0"
	if args := mysqlDumpArgs(req); hasArg(args, "--master-data=2") || hasArg(args, "--source-data=2") {
		t.Errorf("no position flag without binlog: %v", args)
	}
}

func TestSelectBinlogRange(t *testing.T) {
	logs := []binlogFile{{"binlog.000012", 1}, {"binlog.000010", 1}, {"binlog.000011", 1}}
	names := func(f []binlogFile) string {
		var n []string
		for _, x := range f {
			n = append(n, x.Name)
		}
		return strings.Join(n, ",")
	}
	if f, gap := selectBinlogRange(logs, "binlog.000011", "binlog.000012"); names(f) != "binlog.000011,binlog.000012" || gap {
		t.Errorf("normal: %s %v", names(f), gap)
	}
	if f, gap := selectBinlogRange(logs, "", "binlog.000012"); names(f) != "binlog.000012" || gap {
		t.Errorf("first run: %s %v", names(f), gap)
	}
	if f, gap := selectBinlogRange(logs, "binlog.000003", "binlog.000012"); names(f) != "binlog.000010,binlog.000011,binlog.000012" || !gap {
		t.Errorf("purged: %s %v", names(f), gap)
	}
}

func TestParseDumpHeaderMySQL8(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.sql")
	if err := os.WriteFile(path, []byte("-- MySQL dump 10.13\n-- CHANGE REPLICATION SOURCE TO SOURCE_LOG_FILE='binlog.000042', SOURCE_LOG_POS=4;\nSET @@GLOBAL.GTID_PURGED=/*!80000 '+'*/ '3E11FA47-71CA-11E1-9E33-C80AA9429562:1-5';\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, pos, gtid := parseDumpHeader(path)
	if file != "binlog.000042" || pos != 4 || gtid != "3E11FA47-71CA-11E1-9E33-C80AA9429562:1-5" {
		t.Errorf("got %s %d %q", file, pos, gtid)
	}
}

func TestVersionParsing(t *testing.T) {
	if b, ok := parseMySQLVersion("mysqldump  Ver 8.0.36 for Linux on x86_64 (MySQL Community Server - GPL)"); !ok || b.Flavor != "mysql" || b.Version != "8.0.36" {
		t.Errorf("mysql: %+v %v", b, ok)
	}
	if b, ok := parseMySQLVersion("mariadb-dump  Ver 10.19 Distrib 10.11.6-MariaDB, for debian-linux-gnu (x86_64)"); !ok || b.Flavor != "mariadb" || b.Major != 10 || b.Minor != 11 {
		t.Errorf("mariadb: %+v %v", b, ok)
	}
	if b, ok := parseMySQLVersion("/usr/bin/mariadb-dump from 11.4.12-MariaDB, client 10.19 for Linux (x86_64)"); !ok || b.Flavor != "mariadb" || b.Version != "11.4.12" {
		t.Errorf("mariadb 11.4: %+v %v", b, ok)
	}
	if b, ok := parseMongoVersion("mongodump version: 100.9.4"); !ok || b.Major != 100 || b.Version != "100.9.4" {
		t.Errorf("mongo: %+v %v", b, ok)
	}
	if b, ok := parseMongoVersion("mongodump version: r4.2.24"); !ok || b.Major != 4 {
		t.Errorf("legacy mongo: %+v %v", b, ok)
	}
	if maj, min, ok := parsePGVersion("pg_dump (PostgreSQL) 16.4 (Debian 16.4-1.pgdg120+1)"); !ok || maj != 16 || min != 4 {
		t.Errorf("pg: %d %d %v", maj, min, ok)
	}
	if maj, _, _ := parseServerVersion("11.4.2-MariaDB-ubu2404"); maj != 11 {
		t.Errorf("server version: %d", maj)
	}
}

func TestMySQLRunPerDatabase(t *testing.T) {
	bin := t.TempDir()
	logs := installMySQLTools(t, bin, "mariadb-dump", "mariadb-dump  Ver 10.19 Distrib 10.11.6-MariaDB, for debian-linux-gnu (x86_64)")
	withPath(t, bin)
	mysqlConnect = func(context.Context, dbspec.Credentials) (querier, error) {
		return mysqlFake("10.11.6-MariaDB-ubu2404"), nil
	}
	t.Cleanup(func() { mysqlConnect = nil })

	cfg := testConfig(t)
	up := &captureUpload{}
	spec := &dbspec.Spec{Engine: "mariadb", Host: "db02", User: "backup", MySQL: &dbspec.MySQLOptions{PerDatabase: true}}
	if _, err := Run(context.Background(), RunOptions{Session: testSession(uuid.New()), Spec: spec, Password: "pw", Config: cfg, Upload: up.fn}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	dumps := invocations(t, logs["dump"])
	// user databases in SHOW DATABASES order, then the mysql schema; system schemas skipped
	if len(dumps) != 3 {
		t.Fatalf("expected one dump per database, got %d: %v", len(dumps), dumps)
	}
	for i, want := range []string{"app", "shop", "mysql"} {
		args := dumps[i]
		target := ""
		for j, a := range args {
			if a == "--databases" && j+1 < len(args) {
				target = args[j+1]
			}
		}
		if hasArg(args, "--all-databases") || target != want {
			t.Errorf("dump %d should target only %s: %v", i, want, args)
		}
		if !up.has("mysql/" + want + ".sql") {
			t.Errorf("missing mysql/%s.sql in %v", want, up.files)
		}
	}
	if up.has("mysql/all-databases.sql") {
		t.Errorf("no all-databases dump expected: %v", up.files)
	}
	m := up.manifest(t)
	if !m.MySQL.PerDatabase || m.MySQL.AllDatabases || len(m.MySQL.DumpFiles) != 3 || len(m.Databases) != 3 {
		t.Errorf("mysql manifest: %+v databases=%+v", m.MySQL, m.Databases)
	}
	if m.Spec == nil || m.Spec.MySQL == nil || !m.Spec.MySQL.PerDatabase {
		t.Errorf("per_database not recorded in the manifest spec")
	}
	found := false
	for _, n := range m.Notes {
		if strings.Contains(n, "not mutually consistent") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected the consistency note, got %v", m.Notes)
	}
	_ = os.RemoveAll(cfg.StateDir)
}
