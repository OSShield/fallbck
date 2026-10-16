package dbbackup

import (
	"encoding/json"
	"errors"
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
		"extra prefix":  {Engine: "postgres", Host: "h", Postgres: &PostgresOptions{ExtraDumpArgs: []string{"--fil=/root/.ssh/authorized_keys"}}},
		"extra archive": {Engine: "mongodb", Host: "h", MongoDB: &MongoOptions{ExtraArgs: []string{"--archive=/etc/x"}}},
		"extra plugin":  {Engine: "mysql", Host: "h", MySQL: &MySQLOptions{ExtraDumpArgs: []string{"--plugin-dir=/tmp"}}},
		"extra control": {Engine: "postgres", Host: "h", Postgres: &PostgresOptions{ExtraDumpArgs: []string{"--schema=a\nb"}}},
		"user newline":  {Engine: "mysql", Host: "h", User: "root\npassword=x"},
		"secret host":   {Engine: "postgres", Host: "evil.example", Kubernetes: &K8sTarget{Namespace: "kube-system", SecretName: "admin"}},
		"host control":  {Engine: "postgres", Host: "h\x00"},
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
	if _, err := ResolveCredentials(&Spec{Engine: EngineMySQL, Host: "db02"}, "", profiles); !errors.Is(err, ErrNoCredentials) {
		t.Errorf("missing default profile must fail with ErrNoCredentials: %v", err)
	}
	if _, err := ResolveCredentials(&Spec{Engine: EngineMySQL, Host: "db02", Profile: "nope"}, "", profiles); !errors.Is(err, ErrNoCredentials) {
		t.Errorf("missing named profile must fail with ErrNoCredentials: %v", err)
	}
	if _, err := ResolveCredentials(&Spec{Engine: EnginePostgres, Host: "db02", Profile: "postgres"}, "", map[string]CredentialProfile{"postgres": {Engine: EnginePostgres}}); !errors.Is(err, ErrNoCredentials) {
		t.Errorf("profile without user must fail with ErrNoCredentials: %v", err)
	}
	if _, err := ResolveCredentials(&Spec{Engine: EnginePostgres, Host: "db02", User: "app", Profile: "postgres"}, "", map[string]CredentialProfile{"postgres": {Engine: EnginePostgres}}); !errors.Is(err, ErrNoCredentials) {
		t.Errorf("tcp without password must fail with ErrNoCredentials: %v", err)
	}
	if _, err := ResolveCredentials(&Spec{Engine: EngineMySQL, Host: "db02", Profile: "postgres"}, "", profiles); err == nil || errors.Is(err, ErrNoCredentials) {
		t.Errorf("engine mismatch must fail, and not as missing credentials: %v", err)
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

func TestKubernetesTarget(t *testing.T) {
	s := &Spec{Engine: "postgres", User: "backup", Kubernetes: &K8sTarget{Namespace: " clusterdb ", Service: "postgresql", SecretName: "pg-creds"}}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	if s.Kubernetes.PasswordKey != "password" {
		t.Errorf("password_key default not applied: %q", s.Kubernetes.PasswordKey)
	}
	if s.EffectiveHost() != "postgresql.clusterdb.svc" || s.Host != "" {
		t.Errorf("effective host %q host %q", s.EffectiveHost(), s.Host)
	}
	if id := DefaultBackupID(s); id != "db-postgres-clusterdb-postgresql" {
		t.Errorf("backup id %q", id)
	}
	if !strings.Contains(s.Summary(), "clusterdb/postgresql") {
		t.Errorf("summary %q", s.Summary())
	}
	creds, err := ResolveCredentials(s, "secret", nil)
	if err != nil || creds.Host != "postgresql.clusterdb.svc" || creds.Port != 5432 {
		t.Errorf("credentials %+v %v", creds, err)
	}
	c := s.Clone()
	c.Kubernetes.Namespace = "other"
	if s.Kubernetes.Namespace != "clusterdb" {
		t.Error("Clone shares the kubernetes target")
	}
	if s.Redacted().Kubernetes == nil {
		t.Error("Redacted dropped the kubernetes target")
	}

	explicit := &Spec{Engine: "mysql", Host: "db.example.com", Kubernetes: &K8sTarget{Namespace: "apps"}}
	if err := explicit.Validate(); err != nil || explicit.EffectiveHost() != "db.example.com" || DefaultBackupID(explicit) != "db-mysql-apps-db.example.com" {
		t.Errorf("explicit host: %v %q %q", err, explicit.EffectiveHost(), DefaultBackupID(explicit))
	}

	bad := []struct {
		name string
		spec *Spec
	}{
		{"no namespace", &Spec{Engine: "postgres", Kubernetes: &K8sTarget{Service: "pg"}}},
		{"bad namespace", &Spec{Engine: "postgres", Kubernetes: &K8sTarget{Namespace: "Bad_NS", Service: "pg"}}},
		{"no service or host", &Spec{Engine: "postgres", Kubernetes: &K8sTarget{Namespace: "ns"}}},
		{"keys without secret", &Spec{Engine: "postgres", Kubernetes: &K8sTarget{Namespace: "ns", Service: "pg", PasswordKey: "pw"}}},
		{"profile", &Spec{Engine: "postgres", Profile: "prod", Kubernetes: &K8sTarget{Namespace: "ns", Service: "pg"}}},
		{"socket", &Spec{Engine: "postgres", Host: "/var/run/pg.sock", Kubernetes: &K8sTarget{Namespace: "ns"}}},
		{"tls files", &Spec{Engine: "postgres", TLS: TLSSpec{CAFile: "/ca.pem"}, Kubernetes: &K8sTarget{Namespace: "ns", Service: "pg"}}},
	}
	for _, tc := range bad {
		if err := tc.spec.Validate(); err == nil {
			t.Errorf("%s: expected a validation error", tc.name)
		}
	}
}

func TestMSSQLSpecValidation(t *testing.T) {
	s := &Spec{Engine: "sqlserver", Host: "sql01"}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	if s.Engine != EngineMSSQL || s.MSSQL == nil || s.MSSQL.Mode != MSSQLModeAuto || s.EffectivePort() != 1433 {
		t.Errorf("defaults: %+v %+v port %d", s, s.MSSQL, s.EffectivePort())
	}
	if !s.MSSQL.EffChecksum() || s.MSSQL.EffFullEveryDays() != 7 || s.MSSQL.EffStripeCount() != 1 {
		t.Error("option defaults")
	}
	off := false
	c := (&Spec{Engine: EngineMSSQL, Host: "h", MSSQL: &MSSQLOptions{Checksum: &off}}).Clone()
	*c.MSSQL.Checksum = true
	if off {
		t.Error("clone shares the checksum pointer")
	}
	bad := map[string]*Spec{
		"mode":            {Engine: EngineMSSQL, Host: "h", MSSQL: &MSSQLOptions{Mode: "weekly"}},
		"copy-only diff":  {Engine: EngineMSSQL, Host: "h", MSSQL: &MSSQLOptions{Mode: MSSQLModeDifferential, CopyOnly: true}},
		"copy-only auto":  {Engine: EngineMSSQL, Host: "h", MSSQL: &MSSQLOptions{CopyOnly: true}},
		"gzip":            {Engine: EngineMSSQL, Host: "h", Compression: CompressionGzip},
		"kubernetes":      {Engine: EngineMSSQL, Host: "h", Kubernetes: &K8sTarget{Namespace: "db", Service: "mssql"}},
		"stripes":         {Engine: EngineMSSQL, Host: "h", MSSQL: &MSSQLOptions{StripeCount: 40}},
		"transfer size":   {Engine: EngineMSSQL, Host: "h", MSSQL: &MSSQLOptions{MaxTransferSize: 1000}},
		"agent dir alone": {Engine: EngineMSSQL, Host: "h", MSSQL: &MSSQLOptions{AgentDir: "/mnt/sqlbackup"}},
		"foreign options": {Engine: EnginePostgres, Host: "h", MSSQL: &MSSQLOptions{}},
	}
	for name, spec := range bad {
		if err := spec.Validate(); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
	ok := &Spec{Engine: EngineMSSQL, Host: "h", MSSQL: &MSSQLOptions{Mode: MSSQLModeFull, CopyOnly: true, StripeCount: 4, MaxTransferSize: 4194304, BackupDir: `\\nas\sql`, AgentDir: `Z:\sql`}}
	if err := ok.Validate(); err != nil {
		t.Errorf("valid spec rejected: %v", err)
	}
}

func TestMSSQLIntegratedAuthCredentials(t *testing.T) {
	s := &Spec{Engine: EngineMSSQL, Host: "sql01"}
	_ = s.Validate()
	creds, err := ResolveCredentials(s, "", nil)
	if err != nil || creds.User != "" || creds.Port != 1433 {
		t.Errorf("integrated auth must resolve without a user: %v %+v", err, creds)
	}
	withUser := &Spec{Engine: EngineMSSQL, Host: "sql01", User: "backup"}
	_ = withUser.Validate()
	if _, err := ResolveCredentials(withUser, "", nil); err == nil {
		t.Error("a SQL login without a password or profile must fail")
	}
}

func TestMongoAuthMechanism(t *testing.T) {
	s := &Spec{Engine: "mongo", Host: "m1", User: "svc", MongoDB: &MongoOptions{AuthMechanism: " scram-sha-256 "}}
	if err := s.Validate(); err != nil || s.MongoDB.AuthMechanism != MongoAuthScramSHA256 || s.MongoDB.EffAuthSource() != "admin" || s.MongoDB.PasswordlessAuth() {
		t.Errorf("normalised: %v %+v", err, s.MongoDB)
	}
	if err := (&Spec{Engine: "mongo", Host: "m1", MongoDB: &MongoOptions{AuthMechanism: "SCRAM-SHA-512"}}).Validate(); err == nil {
		t.Error("unknown mechanism must fail")
	}
	x := &Spec{Engine: "mongo", Host: "m1", MongoDB: &MongoOptions{AuthMechanism: "MONGODB-X509"}, TLS: TLSSpec{Mode: TLSVerifyFull, CertFile: "/c.pem"}}
	if err := x.Validate(); err != nil || x.MongoDB.EffAuthSource() != "$external" || !x.MongoDB.PasswordlessAuth() {
		t.Errorf("x509: %v %+v", err, x.MongoDB)
	}
	creds, err := ResolveCredentials(x, "", nil)
	if err != nil || creds.Password != "" {
		t.Errorf("x509 needs no password or profile: %v %+v", err, creds)
	}
	if _, err := ResolveCredentials(&Spec{Engine: "mongo", Host: "m1", User: "svc", MongoDB: &MongoOptions{AuthMechanism: "PLAIN"}}, "", nil); !errors.Is(err, ErrNoCredentials) {
		t.Errorf("PLAIN still needs a password: %v", err)
	}
	k := &Spec{Engine: "mongo", Host: "m1", Kubernetes: &K8sTarget{Namespace: "db"}, MongoDB: &MongoOptions{AuthMechanism: "MONGODB-X509"}}
	if err := k.Validate(); err == nil {
		t.Error("x509 on a kubernetes target must fail")
	}
}
