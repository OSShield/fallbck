//go:build dbintegration

package dbbackup

// SQL Server against a real server: docker runs mcr.microsoft.com/mssql/server with a
// host directory bind-mounted as the backup directory, which is exactly the
// backup_dir / agent_dir split of a containerised or remote SQL Server. One job takes
// full+log, then differential+log, then a log-only run; the chain is restored into a
// second server and the rows are counted.
//
//   go test -tags dbintegration -run TestIntegrationMSSQL -v ./pkg/agent/dbbackup/
//
// FALLBCK_TEST_MSSQL_IMAGE overrides the image (default 2019-latest: newer images need
// AVX, which not every development host has).

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	dbspec "github.com/osshield/fallbck/pkg/dbbackup"
)

const mssqlTestPassword = "Fallbck-Test-1!"

// mssqlContainer starts SQL Server as the current user (group 0), so the backup files
// it writes into the bind mount are readable by the test the way they are readable by
// a root or LocalSystem agent in production
func mssqlContainer(t *testing.T, hostDir, mountAt string) container {
	t.Helper()
	image := os.Getenv("FALLBCK_TEST_MSSQL_IMAGE")
	if image == "" {
		image = "mcr.microsoft.com/mssql/server:2019-latest"
	}
	args := []string{"run", "-d", "--rm", "-p", "127.0.0.1:0:1433", "--user", fmt.Sprintf("%d:0", os.Getuid()),
		"-e", "ACCEPT_EULA=Y", "-e", "MSSQL_SA_PASSWORD=" + mssqlTestPassword, "-e", "MSSQL_PID=Developer",
		"-v", hostDir + ":" + mountAt, image}
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Skipf("cannot start %s: %v\n%s", image, err, out)
	}
	id := strings.TrimSpace(string(out))
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", id).Run() })
	pout, err := exec.Command("docker", "port", id, "1433").Output()
	if err != nil {
		t.Fatalf("docker port: %v", err)
	}
	first := strings.Split(strings.TrimSpace(string(pout)), "\n")[0]
	c := container{id: id, port: first[strings.LastIndex(first, ":")+1:]}
	waitFor(t, "sql server", 120*time.Second, func() error {
		_, err := mssqlQuery(c, "SELECT 1")
		return err
	})
	return c
}

// mssqlQuery runs a batch with the sqlcmd shipped in the image (its path moved
// between image generations)
func mssqlQuery(c container, query string) (string, error) {
	script := `S=$(ls /opt/mssql-tools18/bin/sqlcmd /opt/mssql-tools/bin/sqlcmd 2>/dev/null | head -1); "$S" -C -b -S localhost -U sa -P '` + mssqlTestPassword + `' -h -1 -W -Q "$1"`
	out, err := exec.Command("docker", "exec", c.id, "bash", "-c", script, "--", query).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%v: %s", err, out)
	}
	return string(out), nil
}

func mustMSSQL(t *testing.T, c container, query string) string {
	t.Helper()
	out, err := mssqlQuery(c, query)
	if err != nil {
		t.Fatalf("sqlcmd %q: %v", query, err)
	}
	return out
}

func TestIntegrationMSSQL(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed")
	}
	backupDir := t.TempDir()
	if err := os.Chmod(backupDir, 0o777); err != nil {
		t.Fatal(err)
	}
	src := mssqlContainer(t, backupDir, "/backup")
	mustMSSQL(t, src, "CREATE DATABASE app; ALTER DATABASE app SET RECOVERY FULL;")
	mustMSSQL(t, src, "CREATE TABLE app.dbo.t(id int identity primary key, v varchar(64)); INSERT INTO app.dbo.t(v) SELECT TOP 1000 CONVERT(varchar(64), NEWID()) FROM sys.all_objects a CROSS JOIN sys.all_objects b;")

	cfg := testConfig(t)
	jobID := uuid.New()
	restoreDir := t.TempDir()
	if err := os.Chmod(restoreDir, 0o777); err != nil {
		t.Fatal(err)
	}
	run := func(mode string, includeLog bool) *dbspec.Manifest {
		t.Helper()
		up := &captureUpload{copyTo: restoreDir}
		spec := &dbspec.Spec{Engine: dbspec.EngineMSSQL, Host: "127.0.0.1", Port: portInt(src.port), User: "sa", Databases: []string{"app"},
			MSSQL: &dbspec.MSSQLOptions{Mode: mode, IncludeLog: includeLog, BackupDir: "/backup", AgentDir: backupDir}}
		if _, err := Run(context.Background(), RunOptions{Session: testSession(jobID), Spec: spec, Password: mssqlTestPassword, Config: cfg, Upload: up.fn, Hostname: "ci"}); err != nil {
			t.Fatalf("Run (%s): %v", mode, err)
		}
		return up.manifest(t)
	}
	types := func(m *dbspec.Manifest) string {
		var out []string
		for _, s := range m.MSSQL.BackupSets {
			out = append(out, s.Type)
			if s.BackupSetUUID == "" || s.LastLSN == "" || len(s.Files) == 0 {
				t.Errorf("incomplete backup set %+v", s)
			}
		}
		return strings.Join(out, "+")
	}

	var chain []dbspec.MSSQLBackupSet
	m := run(dbspec.MSSQLModeAuto, true)
	if got := types(m); got != "full+log" {
		t.Fatalf("run 1: %s", got)
	}
	chain = append(chain, m.MSSQL.BackupSets...)
	if m.Server.Version == "" || m.MSSQL.Edition == "" {
		t.Errorf("server info %+v %+v", m.Server, m.MSSQL)
	}

	mustMSSQL(t, src, "INSERT INTO app.dbo.t(v) SELECT TOP 500 CONVERT(varchar(64), NEWID()) FROM sys.all_objects;")
	m = run(dbspec.MSSQLModeAuto, true)
	if got := types(m); got != "differential+log" {
		t.Fatalf("run 2: %s", got)
	}
	chain = append(chain, m.MSSQL.BackupSets...)

	mustMSSQL(t, src, "INSERT INTO app.dbo.t(v) SELECT TOP 250 CONVERT(varchar(64), NEWID()) FROM sys.all_objects;")
	m = run(dbspec.MSSQLModeLog, false)
	if got := types(m); got != "log" {
		t.Fatalf("run 3: %s", got)
	}
	if len(m.Warnings) != 0 {
		t.Errorf("a contiguous log chain must not warn: %v", m.Warnings)
	}
	chain = append(chain, m.MSSQL.BackupSets...)
	if !strings.Contains(strings.Join(m.Restore.Commands, "\n"), "RESTORE LOG [app]") {
		t.Errorf("restore commands: %v", m.Restore.Commands)
	}
	if left, _ := filepath.Glob(filepath.Join(backupDir, "fallbck-*")); len(left) != 0 {
		t.Errorf("backup directory not emptied: %v", left)
	}

	// A full taken behind the job's back must turn the next differential into a full
	mustMSSQL(t, src, "BACKUP DATABASE app TO DISK = N'/backup/foreign.bak' WITH INIT;")
	m = run(dbspec.MSSQLModeDifferential, false)
	if got := types(m); got != "full" || !strings.Contains(strings.Join(m.Notes, " "), "chain reset") {
		t.Fatalf("run 4 after a foreign full: %s, notes %v", got, m.Notes)
	}

	// Restore runs 1-3 into a second server: full, differential, then the logs after it
	rst := mssqlContainer(t, restoreDir, "/restore")
	disk := func(s dbspec.MSSQLBackupSet) string { return "DISK = N'/restore/" + s.Files[0] + "'" }
	full, diff := chain[0], chain[2]
	mustMSSQL(t, rst, "RESTORE DATABASE app FROM "+disk(full)+" WITH REPLACE, NORECOVERY;")
	mustMSSQL(t, rst, "RESTORE DATABASE app FROM "+disk(diff)+" WITH NORECOVERY;")
	for _, s := range chain[3:] {
		mustMSSQL(t, rst, "RESTORE LOG app FROM "+disk(s)+" WITH NORECOVERY;")
	}
	mustMSSQL(t, rst, "RESTORE DATABASE app WITH RECOVERY;")
	if out := strings.TrimSpace(mustMSSQL(t, rst, "SET NOCOUNT ON; SELECT COUNT(*) FROM app.dbo.t;")); !strings.HasPrefix(out, "1750") {
		t.Errorf("restored row count %q, want 1750", out)
	}
}
