package dbbackup

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	dbspec "github.com/osshield/fallbck/pkg/dbbackup"
)

func installMongoTools(t *testing.T, dir, ver string) string {
	return fakeBin(t, dir, "mongodump", `
case "$1" in --version) echo "mongodump version: `+ver+`"; echo "git version: x"; exit 0;; esac
`+logArgs+`
for a in "$@"; do case "$a" in --out=*) o=${a#--out=};; --db=*) db=${a#--db=};; esac; done
if [ -n "$db" ]; then mkdir -p "$o/$db" && echo x > "$o/$db/coll.bson"; else
  mkdir -p "$o/admin" "$o/app" && echo x > "$o/app/coll.bson" && echo o > "$o/oplog.bson"; fi
exit 0
`)
}

func TestMongoRunOplog(t *testing.T) {
	bin := t.TempDir()
	log := installMongoTools(t, bin, "100.9.4")
	withPath(t, bin)
	up := &captureUpload{}
	spec := &dbspec.Spec{Engine: "mongo", Host: "mongo1", User: "backup", MongoDB: &dbspec.MongoOptions{ReadPreference: "secondary", ReplicaSet: "rs0"}}
	if _, err := Run(context.Background(), RunOptions{Session: testSession(uuid.New()), Spec: spec, Password: "p@ss/w", Config: testConfig(t), Upload: up.fn}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	calls := invocations(t, log)
	if len(calls) != 1 || !hasArg(calls[0], "--oplog") || !hasArg(calls[0], "--config") || hasArg(calls[0], "--uri") || hasArg(calls[0], "--password") {
		t.Errorf("mongodump args: %v", calls)
	}
	joined := strings.Join(calls[0], "\n")
	if !strings.Contains(joined, `MONGOCFG uri: "mongodb://backup:p%40ss%2Fw@mongo1:27017/?authSource=admin&connectTimeoutMS=15000&readPreference=secondary&replicaSet=rs0"`) {
		t.Errorf("config file content: %s", joined)
	}
	if strings.Contains(joined, "p@ss/w") {
		t.Errorf("password on argv: %s", joined)
	}
	m := up.manifest(t)
	if m.MongoDB == nil || !m.MongoDB.Oplog || m.MongoDB.OplogFile != "mongodb/oplog.bson" || strings.Join(m.MongoDB.Databases, ",") != "admin,app" || m.MongoDB.PerDatabase {
		t.Errorf("mongo manifest: %+v", m.MongoDB)
	}
	if len(m.Restore.Commands) == 0 || !strings.Contains(m.Restore.Commands[0], "--oplogReplay") {
		t.Errorf("restore: %v", m.Restore.Commands)
	}
}

func TestMongoRunPerDatabaseAndOldTools(t *testing.T) {
	bin := t.TempDir()
	log := installMongoTools(t, bin, "100.9.4")
	withPath(t, bin)
	up := &captureUpload{}
	spec := &dbspec.Spec{Engine: "mongodb", Host: "mongo1", Databases: []string{"app", "shop"}, Compression: "gzip"}
	if _, err := Run(context.Background(), RunOptions{Session: testSession(uuid.New()), Spec: spec, Config: testConfig(t), Upload: up.fn}); err != nil {
		t.Fatalf("Run (no auth): %v", err)
	}
	calls := invocations(t, log)
	if len(calls) != 2 || !hasArg(calls[0], "--db=app") || !hasArg(calls[0], "--dumpDbUsersAndRoles") || !hasArg(calls[0], "--gzip") || hasArg(calls[0], "--oplog") {
		t.Errorf("per-db args: %v", calls)
	}
	if !strings.Contains(strings.Join(calls[0], "\n"), `uri: "mongodb://mongo1:27017/?connectTimeoutMS=15000"`) {
		t.Errorf("unauthenticated uri: %v", calls[0])
	}
	if m := up.manifest(t); !m.MongoDB.PerDatabase || m.MongoDB.Oplog || !m.MongoDB.Gzip {
		t.Errorf("manifest: %+v", m.MongoDB)
	}

	old := t.TempDir()
	installMongoTools(t, old, "r4.2.24")
	t.Setenv("PATH", old)
	_, err := Run(context.Background(), RunOptions{Session: testSession(uuid.New()), Spec: spec, Config: testConfig(t), Upload: up.fn})
	if !IsPrecheck(err) || !strings.Contains(err.Error(), "too old") {
		t.Errorf("old tools: %v", err)
	}
}
