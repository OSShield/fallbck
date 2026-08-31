package dbbackup

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSpecValidateDefaults(t *testing.T) {
	s := &Spec{Engine: "PostgreSQL", Host: " db01 "}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	if s.Engine != EnginePostgres || s.Host != "db01" || s.Postgres == nil || s.Postgres.Mode != PostgresModeDump || s.Postgres.Format != "custom" || s.Compression != CompressionNone {
		t.Errorf("defaults not applied: %+v %+v", s, s.Postgres)
	}
	if DefaultBackupID(s) != "db-postgres-db01" || s.EffectivePort() != 5432 {
		t.Errorf("backup id %q port %d", DefaultBackupID(s), s.EffectivePort())
	}
	sock := &Spec{Engine: "mariadb", Host: "/var/run/mysqld/mysqld.sock"}
	if err := sock.Validate(); err != nil || DefaultBackupID(sock) != "db-mysql-local" || !sock.IsSocket() {
		t.Errorf("socket spec: %v %q", err, DefaultBackupID(sock))
	}
	if DefaultBackupID(&Spec{Engine: EngineMongoDB, Host: "Mongo.Example.COM", BackupID: "custom_id"}) != "custom_id" {
		t.Error("backup_id override ignored")
	}
}

func TestSpecValidateRejects(t *testing.T) {
	yes := true
	cases := map[string]*Spec{
		"engine":        {Engine: "oracle", Host: "h"},
		"host":          {Engine: "postgres"},
		"port":          {Engine: "postgres", Host: "h", Port: 70000},
		"tls":           {Engine: "postgres", Host: "h", TLS: TLSSpec{Mode: "maybe"}},
		"dash db":       {Engine: "postgres", Host: "h", Databases: []string{"-x"}},
		"extra short":   {Engine: "postgres", Host: "h", Postgres: &PostgresOptions{ExtraDumpArgs: []string{"-f"}}},
		"extra denied":  {Engine: "mysql", Host: "h", MySQL: &MySQLOptions{ExtraDumpArgs: []string{"--result-file=/x"}}},
		"oplog with db": {Engine: "mongodb", Host: "h", Databases: []string{"app"}, MongoDB: &MongoOptions{Oplog: &yes}},
		"wrong options": {Engine: "mysql", Host: "h", Postgres: &PostgresOptions{}},
		"backup id":     {Engine: "mysql", Host: "h", BackupID: "bad/id"},
		"pg mode":       {Engine: "postgres", Host: "h", Postgres: &PostgresOptions{Mode: "wal"}},
	}
	for name, s := range cases {
		if err := s.Validate(); err == nil {
			t.Errorf("%s: expected an error", name)
		} else if !strings.Contains(err.Error(), "invalid database job configuration") {
			t.Errorf("%s: error not wrapped: %v", name, err)
		}
	}
}

func TestRedactedAndClone(t *testing.T) {
	s := &Spec{Engine: EngineMySQL, Host: "h", Password: "pw", MySQL: &MySQLOptions{IncludeBinlogs: true}}
	r := s.Redacted()
	if r.Password != "" || !r.HasPassword || r.MySQL == s.MySQL || !r.MySQL.IncludeBinlogs {
		t.Errorf("redacted: %+v", r)
	}
	data, _ := json.Marshal(r)
	if strings.Contains(string(data), "pw") {
		t.Errorf("password leaked: %s", data)
	}
	c := s.Clone()
	if c.Password != "pw" || c.MySQL == s.MySQL {
		t.Errorf("clone: %+v", c)
	}
}

func TestResolveCredentials(t *testing.T) {
	dir := t.TempDir()
	pwFile := filepath.Join(dir, "pw")
	if err := os.WriteFile(pwFile, []byte("filepw\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	profiles := map[string]CredentialProfile{
		"postgres": {Engine: "postgresql", User: "backup", PasswordFile: pwFile, TLS: TLSSpec{Mode: TLSRequire}},
		"maria":    {Engine: "mysql", User: "root", Password: "rootpw", Port: 3307},
	}
	spec := &Spec{Engine: EnginePostgres, Host: "db01"}
	c, err := ResolveCredentials(spec, "", profiles)
	if err != nil || c.User != "backup" || c.Password != "filepw" || c.Port != 5432 || c.TLS.Mode != TLSRequire || c.Source != "profile:postgres" {
		t.Errorf("profile resolution: %+v %v", c, err)
	}
	c, err = ResolveCredentials(&Spec{Engine: EnginePostgres, Host: "db01", User: "app"}, "jobpw", profiles)
	if err != nil || c.User != "app" || c.Password != "jobpw" || c.Source != "job" {
		t.Errorf("job password: %+v %v", c, err)
	}
	c, err = ResolveCredentials(&Spec{Engine: EngineMySQL, Host: "db02", Profile: "maria"}, "", profiles)
	if err != nil || c.User != "root" || c.Port != 3307 {
		t.Errorf("named profile: %+v %v", c, err)
	}
	if _, err := ResolveCredentials(&Spec{Engine: EngineMySQL, Host: "db02"}, "", profiles); err == nil {
		t.Error("missing default profile must fail")
	}
	if _, err := ResolveCredentials(&Spec{Engine: EngineMySQL, Host: "db02", Profile: "postgres"}, "", profiles); err == nil {
		t.Error("engine mismatch must fail")
	}
	if _, err := ResolveCredentials(&Spec{Engine: EnginePostgres, Host: "/var/run/postgresql", User: "postgres"}, "", nil); err != nil {
		t.Errorf("socket without password should pass: %v", err)
	}
}

func TestConfigDefaults(t *testing.T) {
	var c Config
	c.ApplyDefaults("/var/lib/fallbck/db-agent")
	if c.SpoolDir != "/var/lib/fallbck/db-agent/spool" || c.StateDir != "/var/lib/fallbck/db-agent/state/db" || c.MinFreeBytes != DefaultMinFreeBytes || c.KillGrace != DefaultKillGrace || !c.ChecksumsEnabled() {
		t.Errorf("defaults: %+v", c)
	}
	c.Profiles = map[string]CredentialProfile{"x": {Engine: "nope"}}
	if err := c.Validate(); err == nil {
		t.Error("bad profile engine accepted")
	}
}

func TestManifestRoundTrip(t *testing.T) {
	m := &Manifest{SchemaVersion: ManifestSchemaVersion, Engine: EngineMySQL, MySQL: &MySQLManifest{Binlog: &MySQLBinlog{Enabled: true, File: "binlog.000012", Position: 157}}}
	data, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseManifest(data)
	if err != nil || back.MySQL.Binlog.Position != 157 {
		t.Errorf("round trip: %v %+v", err, back)
	}
}
