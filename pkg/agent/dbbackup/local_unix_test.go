//go:build !windows

package dbbackup

import (
	"bytes"
	"context"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	dbspec "github.com/osshield/fallbck/pkg/dbbackup"
)

// listenUnix creates a unix socket at path for the discovery tests
func listenUnix(t *testing.T, path string) string {
	t.Helper()
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	return path
}

// psqlScript answers the precheck queries the way psql -A -t -F '\x1f' -0 prints them
const psqlScript = `
case "$1" in --version) echo "psql (PostgreSQL) 16.4"; exit 0;; esac
` + logArgs + `
for a in "$@"; do case "$a" in --command=*) q=${a#--command=};; esac; done
case "$q" in
  *server_version_num*) printf '%s\037%s\000' 160004 "16.4 (Debian 16.4-1)";;
  *rolsuper*) printf '%s\037%s\000' t f;;
  *pg_is_in_recovery*) printf '%s\000' f;;
  *"SELECT datname"*) printf '%s\000%s\000' app postgres;;
  *pg_database_size*) printf '%s\000' 4096;;
  *pg_current_wal_lsn*) printf '%s\000' 0/2000138;;
  *) echo "ERROR: unexpected query: $q" >&2; exit 1;;
esac
`

func TestLocalCredentials(t *testing.T) {
	ctx := context.Background()
	if os.PathSeparator == '\\' {
		t.Skip("unix sockets and peer authentication")
	}
	dir := t.TempDir()
	listenUnix(t, dir+"/.s.PGSQL.5433")
	mySock := listenUnix(t, dir+"/mysqld.sock")
	pgSocketDirs, mysqlSocketPaths = []string{dir + "/nope", dir}, []string{dir + "/nope.sock", mySock}
	isRoot = func() bool { return true }
	osUserExists = func(name string) error {
		if name == "postgres" || name == "pgbackup" {
			return nil
		}
		return os.ErrNotExist
	}
	t.Cleanup(func() { isRoot = func() bool { return os.Geteuid() == 0 } })

	c, err := localCredentials(ctx, &dbspec.Spec{Engine: dbspec.EnginePostgres, Host: "localhost", Port: 5433, TLS: dbspec.TLSSpec{Mode: "require"}})
	if err != nil || c.User != "postgres" || c.RunAs != "postgres" || c.Host != dir || c.Port != 5433 || c.Password != "" || c.Source != "local:peer" || c.TLS.Mode != "" {
		t.Errorf("postgres: %+v %v", c, err)
	}
	c, err = localCredentials(ctx, &dbspec.Spec{Engine: dbspec.EnginePostgres, Host: "localhost", Port: 5433, User: "pgbackup"})
	if err != nil || c.User != "pgbackup" || c.RunAs != "pgbackup" {
		t.Errorf("postgres role = OS user: %+v %v", c, err)
	}
	if _, err := localCredentials(ctx, &dbspec.Spec{Engine: dbspec.EnginePostgres, Host: "localhost", Port: 5433, User: "app"}); err == nil {
		t.Error("role without an OS user must fail")
	}
	if _, err := localCredentials(ctx, &dbspec.Spec{Engine: dbspec.EnginePostgres, Host: "localhost", Port: 5432}); err == nil || !strings.Contains(err.Error(), ".s.PGSQL.5432") {
		t.Errorf("missing socket must name it: %v", err)
	}
	c, err = localCredentials(ctx, &dbspec.Spec{Engine: dbspec.EnginePostgres, Host: dir + "/explicit"})
	if err != nil || c.Host != dir+"/explicit" {
		t.Errorf("explicit socket dir is kept: %+v %v", c, err)
	}

	c, err = localCredentials(ctx, &dbspec.Spec{Engine: dbspec.EngineMySQL, Host: "127.0.0.1"})
	if err != nil || c.User != "root" || c.RunAs != "" || c.Host != mySock || c.Source != "local:socket" {
		t.Errorf("mysql: %+v %v", c, err)
	}
	if _, err := localCredentials(ctx, &dbspec.Spec{Engine: dbspec.EngineMySQL, Host: "127.0.0.1", User: "backup"}); err == nil {
		t.Error("mysql user other than root must fail")
	}

	c, err = localCredentials(ctx, &dbspec.Spec{Engine: dbspec.EngineMongoDB, Host: "localhost"})
	if err != nil || c.User != "" || c.Host != "localhost" || c.Port != 27017 || c.Source != "local:none" {
		t.Errorf("mongodb: %+v %v", c, err)
	}
	if _, err := localCredentials(ctx, &dbspec.Spec{Engine: dbspec.EngineMongoDB, Host: "localhost", User: "admin"}); err == nil {
		t.Error("mongodb user without password must fail")
	}
	if _, err := localCredentials(ctx, &dbspec.Spec{Engine: dbspec.EngineMSSQL, Host: "localhost"}); err == nil {
		t.Error("mssql on linux must fail")
	}

	if _, err := localCredentials(ctx, &dbspec.Spec{Engine: dbspec.EnginePostgres, Host: "db01.example.invalid"}); err == nil || !strings.Contains(err.Error(), "not this machine") {
		t.Errorf("remote host: %v", err)
	}
	if _, err := localCredentials(ctx, &dbspec.Spec{Engine: dbspec.EnginePostgres, Host: "pg", Kubernetes: &dbspec.K8sTarget{Namespace: "db"}}); err == nil {
		t.Error("kubernetes target must fail")
	}
	isRoot = func() bool { return false }
	if _, err := localCredentials(ctx, &dbspec.Spec{Engine: dbspec.EnginePostgres, Host: "localhost", Port: 5433}); err == nil || !strings.Contains(err.Error(), "root") {
		t.Errorf("not root: %v", err)
	}
	if _, err := localCredentials(ctx, &dbspec.Spec{Engine: dbspec.EngineMongoDB, Host: "localhost"}); err != nil {
		t.Errorf("mongodb needs no root: %v", err)
	}
}

func TestRunAsCurrentUser(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	bin := t.TempDir()
	fakeBin(t, bin, "whoami-env", `echo "HOME=$HOME"; id -u`)
	var out bytes.Buffer
	_, err = NewRunner(time.Second).Run(context.Background(), Command{Name: "x", Path: filepath.Join(bin, "whoami-env"), Env: []string{"HOME=/nowhere", "PATH=" + os.Getenv("PATH")}, Stdout: &out, RunAs: me.Username})
	if err != nil {
		t.Fatal(err)
	}
	if got := out.String(); !strings.Contains(got, "HOME="+me.HomeDir+"\n") || !strings.Contains(got, me.Uid+"\n") {
		t.Errorf("output %q: want HOME=%s and uid %s", got, me.HomeDir, me.Uid)
	}
	if _, err := NewRunner(time.Second).Run(context.Background(), Command{Name: "x", Path: filepath.Join(bin, "whoami-env"), RunAs: "no-such-user-fallbck"}); err == nil || !strings.Contains(err.Error(), "no-such-user-fallbck") {
		t.Errorf("unknown user: %v", err)
	}
}

func TestPsqlQuerier(t *testing.T) {
	bin := t.TempDir()
	log := fakeBin(t, bin, "psql", psqlScript)
	q := psqlQuerier{path: filepath.Join(bin, "psql"), env: []string{"PATH=" + os.Getenv("PATH"), "PGHOST=/tmp/x"}, runner: NewRunner(time.Second)}
	var vnum int
	var vstr string
	if err := q.queryRow(context.Background(), "SELECT current_setting('server_version_num')::int, current_setting('server_version')", &vnum, &vstr); err != nil || vnum != 160004 || vstr != "16.4 (Debian 16.4-1)" {
		t.Errorf("row: %d %q %v", vnum, vstr, err)
	}
	var super, repl bool
	if err := q.queryRow(context.Background(), "SELECT rolsuper, rolreplication FROM pg_roles", &super, &repl); err != nil || !super || repl {
		t.Errorf("bools: %v %v %v", super, repl, err)
	}
	rows, err := q.queryRows(context.Background(), "SELECT datname FROM pg_database")
	if err != nil || len(rows) != 2 || rows[0][0] != "app" || rows[1][0] != "postgres" {
		t.Errorf("rows: %v %v", rows, err)
	}
	if err := q.queryRow(context.Background(), "SELECT nonsense", &vnum); err == nil {
		t.Error("psql error must surface")
	}
	inv := invocations(t, log)
	if len(inv) == 0 || !hasArg(inv[0], "--tuples-only") || !hasArg(inv[0], "--no-align") || !hasArg(inv[0], "--record-separator-zero") || !hasArg(inv[0], "--no-password") || !hasArg(inv[0], "--dbname=postgres") {
		t.Errorf("psql args: %v", inv)
	}
}

// TestPostgresLocalPeerRun runs a job without any credentials through the local
// fallback: the current user stands in for postgres (setuid to oneself needs no
// privilege), the checks go through the fake psql, the dumps arrive through stdout
func TestPostgresLocalPeerRun(t *testing.T) {
	me, err := user.Current()
	if err != nil || me.Username == "" {
		t.Skip("no current user")
	}
	bin := t.TempDir()
	logs := installPostgresTools(t, bin, "16.4")
	logs["psql"] = fakeBin(t, bin, "psql", psqlScript)
	withPath(t, bin)
	pgSearchGlobs = nil
	pgConnect = func(context.Context, dbspec.Credentials) (querier, error) {
		t.Error("pgx must not be used when the tools run as another user")
		return nil, os.ErrInvalid
	}
	t.Cleanup(func() { pgConnect = nil })
	sockDir := t.TempDir()
	listenUnix(t, filepath.Join(sockDir, ".s.PGSQL.5432"))
	pgSocketDirs = []string{sockDir}
	isRoot = func() bool { return true }
	osUserExists = func(string) error { return nil }
	t.Cleanup(func() { isRoot = func() bool { return os.Geteuid() == 0 } })

	cfg := testConfig(t)
	up := &captureUpload{copyTo: t.TempDir()}
	spec := &dbspec.Spec{Engine: "postgres", Host: "localhost", User: me.Username}
	result, err := Run(context.Background(), RunOptions{
		Session: testSession(uuid.New()), Spec: spec, Config: cfg, Upload: up.fn,
		Hostname: "agent01", AgentVersion: "test", PollInterval: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "completed" || !up.has("postgres/globals.sql") || !up.has("postgres/dumps/app.dump") || !up.has("postgres/dumps/postgres.dump") {
		t.Errorf("result %+v files %v", result, up.files)
	}
	m := up.manifest(t)
	if m.Server.User != me.Username || m.Server.Host != sockDir || m.Server.Version != "16.4" || m.Spec.HasPassword {
		t.Errorf("manifest server %+v", m.Server)
	}
	dumps := invocations(t, logs["pg_dump"])
	if len(dumps) != 2 || hasArg(dumps[0], "--file") || !hasArg(dumps[0], "--dbname=app") {
		t.Errorf("pg_dump args: %v", dumps)
	}
	for _, line := range dumps[0] {
		if strings.HasPrefix(line, "ENV PGPASSFILE=") && line != "ENV PGPASSFILE=" {
			t.Errorf("no password file expected: %s", line)
		}
	}
	if psql := invocations(t, logs["psql"]); len(psql) < 4 {
		t.Errorf("psql invocations: %d", len(psql))
	}
	// pg_dumpall wrote through stdout into a file the agent opened
	if data, err := os.ReadFile(filepath.Join(up.copyTo, "postgres", "globals.sql")); err != nil || !strings.Contains(string(data), "PGDMP fake dump") {
		t.Errorf("globals content %q: %v", data, err)
	}
}

// TestPrepareDirFor checks the reachability walk for a directory handed to a user
func TestPrepareDirFor(t *testing.T) {
	me, err := user.Current()
	if err != nil || me.Uid == "0" {
		t.Skip("needs an unprivileged user")
	}
	root := t.TempDir()
	if err := prepareDirFor(filepath.Join(root, "a", "b"), me.Username); err != nil {
		t.Errorf("own directories are reachable: %v", err)
	}
	closed := filepath.Join(root, "closed")
	if err := os.Mkdir(closed, 0o700); err != nil {
		t.Fatal(err)
	}
	// As the owner 0700 is fine; a parent owned by someone else without x would not
	// be, which searchableBy decides
	st, _ := os.Stat(closed)
	if !searchableBy(st, atoi(me.Uid), map[int]bool{}) {
		t.Error("owner with 0700 can search")
	}
	if searchableBy(st, atoi(me.Uid)+1, map[int]bool{}) {
		t.Error("others cannot search 0700")
	}
	if err := os.Chmod(closed, 0o701); err == nil {
		st, _ = os.Stat(closed)
		if !searchableBy(st, atoi(me.Uid)+1, map[int]bool{}) {
			t.Error("others can search 0701")
		}
	}
}
