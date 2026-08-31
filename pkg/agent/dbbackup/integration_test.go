//go:build dbintegration

package dbbackup

// Real-server tests: docker on the host runs postgres:16, mariadb:11 and mongo:7 while
// the engines use the client tools installed on the host (pg_dump, mariadb-dump,
// mysqlbinlog, mongodump, mongorestore, psql, mariadb). Each test dumps, then restores
// into a second container and compares the data.
//
//   go test -tags dbintegration -run TestIntegration -v ./pkg/agent/dbbackup/

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

type container struct {
	id   string
	port string
}

func dockerRun(t *testing.T, image string, port int, env []string, args ...string) container {
	t.Helper()
	dargs := []string{"run", "-d", "--rm", "-p", fmt.Sprintf("127.0.0.1:0:%d", port)}
	for _, e := range env {
		dargs = append(dargs, "-e", e)
	}
	dargs = append(dargs, image)
	dargs = append(dargs, args...)
	out, err := exec.Command("docker", dargs...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run %s: %v\n%s", image, err, out)
	}
	id := strings.TrimSpace(string(out))
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", id).Run() })
	pout, err := exec.Command("docker", "port", id, fmt.Sprint(port)).Output()
	if err != nil {
		t.Fatalf("docker port: %v", err)
	}
	first := strings.Split(strings.TrimSpace(string(pout)), "\n")[0]
	return container{id: id, port: first[strings.LastIndex(first, ":")+1:]}
}

func dockerExec(t *testing.T, c container, args ...string) string {
	t.Helper()
	out, err := exec.Command("docker", append([]string{"exec", c.id}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker exec %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func waitFor(t *testing.T, name string, timeout time.Duration, probe func() error) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var err error
	for time.Now().Before(deadline) {
		if err = probe(); err == nil {
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("%s not ready after %s: %v", name, timeout, err)
}

func needTools(t *testing.T, names ...string) {
	t.Helper()
	for _, n := range names {
		if _, err := exec.LookPath(n); err != nil {
			t.Skipf("%s not installed", n)
		}
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed")
	}
}

func portInt(p string) int {
	var n int
	fmt.Sscanf(p, "%d", &n)
	return n
}

func runIntegration(t *testing.T, spec *dbspec.Spec, password string) (*captureUpload, dbspec.Config) {
	t.Helper()
	cfg := testConfig(t)
	up := &captureUpload{}
	_, err := Run(context.Background(), RunOptions{Session: testSession(uuid.New()), Spec: spec, Password: password, Config: cfg, Upload: up.fn, Hostname: "ci"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// keep a copy of the spool for the restore (Run removes it)
	return up, cfg
}

// keepSpool makes the capture upload copy the spool aside so restores can use it
func keepSpool(t *testing.T, up *captureUpload) string {
	t.Helper()
	dst := t.TempDir()
	up.copyTo = dst
	return dst
}

func TestIntegrationPostgres(t *testing.T) {
	needTools(t, "pg_dump", "pg_dumpall", "pg_basebackup", "pg_restore", "psql")
	src := dockerRun(t, "postgres:16", 5432, []string{"POSTGRES_PASSWORD=pw"}, "-c", "wal_level=replica", "-c", "max_wal_senders=4")
	waitFor(t, "postgres", 60*time.Second, func() error {
		return exec.Command("docker", "exec", src.id, "pg_isready", "-U", "postgres").Run()
	})
	dockerExec(t, src, "psql", "-U", "postgres", "-c", "CREATE DATABASE app")
	dockerExec(t, src, "psql", "-U", "postgres", "-d", "app", "-c", "CREATE TABLE t(id int primary key, v text); INSERT INTO t SELECT g, md5(g::text) FROM generate_series(1,1000) g")
	dockerExec(t, src, "psql", "-U", "postgres", "-c", "CREATE ROLE backup LOGIN REPLICATION PASSWORD 'bpw'; GRANT pg_read_all_data TO backup")

	up := &captureUpload{}
	dst := keepSpool(t, up)
	cfg := testConfig(t)
	spec := &dbspec.Spec{Engine: "postgres", Host: "127.0.0.1", Port: portInt(src.port), User: "backup", Databases: []string{"app"}, Postgres: &dbspec.PostgresOptions{Mode: "both"}}
	if _, err := Run(context.Background(), RunOptions{Session: testSession(uuid.New()), Spec: spec, Password: "bpw", Config: cfg, Upload: up.fn, Hostname: "ci"}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	m := up.manifest(t)
	if m.Postgres == nil || m.Postgres.Basebackup == nil || m.Postgres.Basebackup.WALStartLSN == "" || len(m.Databases) != 1 {
		t.Fatalf("manifest: %+v", m.Postgres)
	}
	for _, f := range []string{"postgres/globals.sql", "postgres/dumps/app.dump", "postgres/base/base.tar", "postgres/base/pg_wal.tar"} {
		if _, err := os.Stat(filepath.Join(dst, f)); err != nil {
			t.Errorf("missing %s", f)
		}
	}

	// Logical restore into a fresh server
	rst := dockerRun(t, "postgres:16", 5432, []string{"POSTGRES_PASSWORD=pw"})
	waitFor(t, "restore postgres", 60*time.Second, func() error {
		return exec.Command("docker", "exec", rst.id, "pg_isready", "-U", "postgres").Run()
	})
	env := append(os.Environ(), "PGHOST=127.0.0.1", "PGPORT="+rst.port, "PGUSER=postgres", "PGPASSWORD=pw")
	cmd := exec.Command("pg_restore", "--create", "--dbname=postgres", filepath.Join(dst, "postgres/dumps/app.dump"))
	cmd.Env = env
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("pg_restore: %v\n%s", err, out)
	}
	if out := dockerExec(t, rst, "psql", "-U", "postgres", "-d", "app", "-Atc", "SELECT count(*) FROM t"); strings.TrimSpace(out) != "1000" {
		t.Errorf("restored row count %q", out)
	}
}

func TestIntegrationMariaDB(t *testing.T) {
	needTools(t, "mariadb-dump", "mariadb-binlog", "mariadb")
	src := dockerRun(t, "mariadb:11", 3306, []string{"MARIADB_ROOT_PASSWORD=pw"}, "--log-bin", "--server-id=1", "--binlog-format=ROW")
	waitFor(t, "mariadb", 90*time.Second, func() error {
		return exec.Command("docker", "exec", src.id, "mariadb", "-uroot", "-ppw", "-e", "SELECT 1").Run()
	})
	dockerExec(t, src, "mariadb", "-uroot", "-ppw", "-e", "CREATE DATABASE app; CREATE TABLE app.t(id int primary key, v text); INSERT INTO app.t VALUES (1,'a'),(2,'b'); CREATE USER backup@'%' IDENTIFIED BY 'bpw'; GRANT SELECT, SHOW VIEW, TRIGGER, EVENT, LOCK TABLES, RELOAD, PROCESS, REPLICATION SLAVE, BINLOG MONITOR ON *.* TO backup@'%'")

	cfg := testConfig(t)
	jobID := uuid.New()
	spec := &dbspec.Spec{Engine: "mysql", Host: "127.0.0.1", Port: portInt(src.port), User: "backup", MySQL: &dbspec.MySQLOptions{IncludeBinlogs: true}}
	up1 := &captureUpload{}
	if _, err := Run(context.Background(), RunOptions{Session: testSession(jobID), Spec: spec, Password: "bpw", Config: cfg, Upload: up1.fn}); err != nil {
		t.Fatalf("first run: %v", err)
	}
	m1 := up1.manifest(t)
	if m1.MySQL.Binlog == nil || m1.MySQL.Binlog.File == "" {
		t.Fatalf("first run binlog position missing: %+v", m1.MySQL)
	}

	dockerExec(t, src, "mariadb", "-uroot", "-ppw", "-e", "INSERT INTO app.t VALUES (3,'c')")
	up2 := &captureUpload{}
	dst := keepSpool(t, up2)
	if _, err := Run(context.Background(), RunOptions{Session: testSession(jobID), Spec: spec, Password: "bpw", Config: cfg, Upload: up2.fn}); err != nil {
		t.Fatalf("second run: %v", err)
	}
	m2 := up2.manifest(t)
	bl := m2.MySQL.Binlog
	if bl.Previous == nil || bl.Previous.File != m1.MySQL.Binlog.File || len(bl.Files) == 0 || bl.ChainGap {
		t.Fatalf("binlog chain: %+v", bl)
	}

	rst := dockerRun(t, "mariadb:11", 3306, []string{"MARIADB_ROOT_PASSWORD=pw"})
	waitFor(t, "restore mariadb", 90*time.Second, func() error {
		return exec.Command("docker", "exec", rst.id, "mariadb", "-uroot", "-ppw", "-e", "SELECT 1").Run()
	})
	dump, err := os.Open(filepath.Join(dst, "mysql/all-databases.sql"))
	if err != nil {
		t.Fatal(err)
	}
	defer dump.Close()
	cmd := exec.Command("mariadb", "-h127.0.0.1", "-P"+rst.port, "--protocol=TCP", "-uroot", "-ppw")
	cmd.Stdin = dump
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("restore: %v\n%s", err, out)
	}
	if out := dockerExec(t, rst, "mariadb", "-uroot", "-ppw", "-Nse", "SELECT count(*) FROM app.t"); strings.TrimSpace(out) != "3" {
		t.Errorf("restored row count %q", out)
	}
}

func TestIntegrationMongoDB(t *testing.T) {
	needTools(t, "mongodump", "mongorestore")
	src := dockerRun(t, "mongo:7", 27017, nil, "--replSet", "rs0", "--bind_ip_all")
	waitFor(t, "mongo", 60*time.Second, func() error {
		return exec.Command("docker", "exec", src.id, "mongosh", "--quiet", "--eval", "db.runCommand({ping:1}).ok").Run()
	})
	dockerExec(t, src, "mongosh", "--quiet", "--eval", "rs.initiate({_id:'rs0', members:[{_id:0, host:'127.0.0.1:27017'}]})")
	waitFor(t, "replica set primary", 60*time.Second, func() error {
		out, err := exec.Command("docker", "exec", src.id, "mongosh", "--quiet", "--eval", "rs.status().myState").Output()
		if err != nil || strings.TrimSpace(string(out)) != "1" {
			return fmt.Errorf("state %q %v", out, err)
		}
		return nil
	})
	dockerExec(t, src, "mongosh", "--quiet", "--eval", "db.getSiblingDB('app').t.insertMany([{a:1},{a:2},{a:3}])")

	up := &captureUpload{}
	dst := keepSpool(t, up)
	// The container advertises 127.0.0.1:27017 as the replica set member; connect
	// directly (no replicaSet option) through the mapped port.
	spec := &dbspec.Spec{Engine: "mongodb", Host: "127.0.0.1", Port: portInt(src.port), MongoDB: &dbspec.MongoOptions{ExtraArgs: []string{"--forceTableScan"}}}
	if _, err := Run(context.Background(), RunOptions{Session: testSession(uuid.New()), Spec: spec, Config: testConfig(t), Upload: up.fn}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	m := up.manifest(t)
	if m.MongoDB == nil || !m.MongoDB.Oplog || m.MongoDB.OplogFile == "" {
		t.Fatalf("manifest: %+v", m.MongoDB)
	}

	rst := dockerRun(t, "mongo:7", 27017, nil, "--replSet", "rs1", "--bind_ip_all")
	waitFor(t, "restore mongo", 60*time.Second, func() error {
		return exec.Command("docker", "exec", rst.id, "mongosh", "--quiet", "--eval", "db.runCommand({ping:1}).ok").Run()
	})
	dockerExec(t, rst, "mongosh", "--quiet", "--eval", "rs.initiate({_id:'rs1', members:[{_id:0, host:'127.0.0.1:27017'}]})")
	time.Sleep(3 * time.Second)
	cmd := exec.Command("mongorestore", "--host=127.0.0.1", "--port="+rst.port, "--oplogReplay", "--dir="+filepath.Join(dst, "mongodb"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("mongorestore: %v\n%s", err, out)
	}
	if out := dockerExec(t, rst, "mongosh", "--quiet", "--eval", "db.getSiblingDB('app').t.countDocuments()"); strings.TrimSpace(out) != "3" {
		t.Errorf("restored document count %q", out)
	}
}
