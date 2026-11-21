package backends

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/osshield/fallbck/pkg/agent/remote"
	spec "github.com/osshield/fallbck/pkg/remote"
)

func hostKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestSFTPWithoutHostKeysIsRefused(t *testing.T) {
	_, err := newSession(&spec.Remote{Backend: spec.BackendSFTP, Host: "nas", User: "u"}, remote.Credentials{})
	if err == nil || !strings.Contains(err.Error(), "no host keys") {
		t.Fatalf("got %v", err)
	}
}

// The known_hosts file accepts the remote's key for its host and port, nothing else,
// and is gone once the session closes
func TestSFTPKnownHostsFile(t *testing.T) {
	key, other := hostKey(t), hostKey(t)
	r := &spec.Remote{Backend: spec.BackendSFTP, Host: "nas.example.com", Port: 2222, User: "u",
		KnownHosts: []string{key.Type() + " " + base64.StdEncoding.EncodeToString(key.Marshal())}}
	s, err := newSession(r, remote.Credentials{})
	if err != nil {
		t.Fatal(err)
	}
	path := s.knownHosts
	if st, err := os.Stat(path); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("known_hosts file: %v %v", st, err)
	}
	check, err := knownhosts.New(path)
	if err != nil {
		t.Fatal(err)
	}
	addr := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 2222}
	if err := check("nas.example.com:2222", addr, key); err != nil {
		t.Errorf("the remote's key is refused: %v", err)
	}
	if err := check("nas.example.com:2222", addr, other); err == nil {
		t.Error("another key is accepted")
	}
	if err := check("nas.example.com:22", addr, key); err == nil {
		t.Error("the key is accepted on another port")
	}

	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("known_hosts file still there: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("second close: %v", err)
	}
	if _, err := s.Open(context.Background(), "data"); err == nil {
		t.Error("open after close succeeded")
	}
}

// Other backends write nothing to disk
func TestNonSFTPSessionHasNoFiles(t *testing.T) {
	s, err := newSession(&spec.Remote{Backend: spec.BackendS3, Endpoint: "http://minio:9000"}, remote.Credentials{})
	if err != nil || s.knownHosts != "" {
		t.Fatalf("%v %q", err, s.knownHosts)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}
