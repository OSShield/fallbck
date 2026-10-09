package secrets

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSealOpen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "master.key")
	key, created, err := LoadOrCreateKeyFile(path)
	if err != nil || !created || len(key) != 32 {
		t.Fatalf("create: %v created=%v len=%d", err, created, len(key))
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Errorf("key file mode %o", st.Mode().Perm())
	}
	again, created, err := LoadOrCreateKeyFile(path)
	if err != nil || created || string(again) != string(key) {
		t.Fatalf("reload: %v created=%v same=%v", err, created, string(again) == string(key))
	}
	s, err := New(key)
	if err != nil {
		t.Fatal(err)
	}
	sealed := s.SealString("user@pbs!tok:secret")
	if !IsSealed(sealed) || strings.Contains(sealed, "secret") {
		t.Errorf("sealed form: %q", sealed)
	}
	if sealed2 := s.SealString("user@pbs!tok:secret"); sealed2 == sealed {
		t.Error("nonce must differ per call")
	}
	plain, err := s.OpenString(sealed)
	if err != nil || plain != "user@pbs!tok:secret" {
		t.Errorf("open: %q %v", plain, err)
	}
	if s.SealString("") != "" {
		t.Error("empty stays empty")
	}
	if v, err := s.Open(""); err != nil || v != nil {
		t.Error("opening empty is a no-op")
	}
	if _, err := s.OpenString("plaintext-token"); err == nil {
		t.Error("unsealed input must be rejected")
	}
	other, _ := New(make([]byte, 32))
	if _, err := other.OpenString(sealed); err == nil {
		t.Error("another key must not open it")
	}
	if _, err := ParseKey("abc"); err == nil {
		t.Error("short hex must fail")
	}
	if _, err := New([]byte("short")); err == nil {
		t.Error("short key must fail")
	}
}
