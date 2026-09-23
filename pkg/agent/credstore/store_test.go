package credstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	dbspec "github.com/osshield/fallbck/pkg/dbbackup"
)

func TestStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s := Open(dir)
	if s.Exists() {
		t.Fatal("fresh store must not exist")
	}
	if names, err := s.Names(); err != nil || len(names) != 0 {
		t.Fatalf("empty store: %v %v", err, names)
	}
	if err := s.Put("PG-Main", dbspec.CredentialProfile{Engine: "postgresql", User: "backup", Password: "s3cret", Host: "db01"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Put("mysql", dbspec.CredentialProfile{Engine: "mariadb", User: "root", PasswordFile: "/etc/x"}); err != nil {
		t.Fatal(err)
	}
	profiles, err := Open(dir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if p := profiles["pg-main"]; p.Engine != "postgres" || p.Password != "s3cret" || p.User != "backup" {
		t.Errorf("profile %+v", p)
	}
	names, _ := Open(dir).Names()
	if len(names) != 2 || names[0].Name != "mysql" || names[0].Engine != "mysql" || names[1].Name != "pg-main" {
		t.Errorf("names %+v", names)
	}

	// Nothing readable on disk, and the file modes are private
	raw, _ := os.ReadFile(filepath.Join(dir, StoreFile))
	if strings.Contains(string(raw), "s3cret") || strings.Contains(string(raw), "backup") {
		t.Error("store file leaks plain text")
	}
	for _, f := range []string{StoreFile, KeyFile} {
		if st, err := os.Stat(filepath.Join(dir, f)); err != nil || st.Mode().Perm() != 0o600 {
			t.Errorf("%s mode: %v %v", f, err, st)
		}
	}

	if err := s.Delete("pg-main"); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete("pg-main"); err != ErrNotFound {
		t.Errorf("second delete: %v", err)
	}
	if err := s.Put("bad", dbspec.CredentialProfile{Engine: "oracle"}); err == nil {
		t.Error("unknown engine accepted")
	}
	if err := s.Put("both", dbspec.CredentialProfile{Engine: "postgres", Password: "a", PasswordFile: "b"}); err == nil {
		t.Error("password and password file together accepted")
	}
}

func TestStoreWrongKey(t *testing.T) {
	dir := t.TempDir()
	if err := Open(dir).Put("p", dbspec.CredentialProfile{Engine: "postgres", Password: "x"}); err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	if err := Open(other).Put("q", dbspec.CredentialProfile{Engine: "mysql", Password: "y"}); err != nil {
		t.Fatal(err)
	}
	// Swap the key: the store must refuse rather than return garbage
	otherKey, _ := os.ReadFile(filepath.Join(other, KeyFile))
	_ = os.WriteFile(filepath.Join(dir, KeyFile), otherKey, 0o600)
	if _, err := Open(dir).Load(); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Errorf("wrong key: %v", err)
	}
	_ = os.Remove(filepath.Join(dir, KeyFile))
	if _, err := Open(dir).Load(); err == nil || !strings.Contains(err.Error(), "key file") {
		t.Errorf("missing key: %v", err)
	}
}
