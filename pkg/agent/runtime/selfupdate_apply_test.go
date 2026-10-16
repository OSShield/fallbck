package runtime

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/osshield/fallbck/pkg/agentupdate"
	"github.com/osshield/fallbck/pkg/api"
	"github.com/osshield/fallbck/pkg/config"
)

// fakeUpdateServer serves a release whose "binary" is a shell script, with the
// checksums "signed" by echoing them into the bundle
func fakeUpdateServer(t *testing.T, version string, tamperChecksums bool) (*httptest.Server, *api.AgentUpdate) {
	t.Helper()
	binary := []byte("#!/bin/sh\necho fallbck-agent " + version + "\n")
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	tw := tar.NewWriter(gz)
	_ = tw.WriteHeader(&tar.Header{Name: "fallbck-agent", Mode: 0o755, Size: int64(len(binary)), Typeflag: tar.TypeReg})
	_, _ = tw.Write(binary)
	tw.Close()
	gz.Close()
	name := agentupdate.ArchiveName("linux", "amd64")
	sum := sha256.Sum256(archive.Bytes())
	signed := hex.EncodeToString(sum[:]) + "  " + name + "\n"
	served := signed
	if tamperChecksums {
		served = "0000" + signed[4:]
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/archive", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(archive.Bytes()) })
	mux.HandleFunc("/checksums", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(served)) })
	mux.HandleFunc("/bundle", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("bundle-for:" + signed)) })
	srv := httptest.NewServer(mux)
	return srv, &api.AgentUpdate{Version: version, Archive: name, ArchiveURL: "/archive", ChecksumsURL: "/checksums", BundleURL: "/bundle"}
}

func newTestUpdater(t *testing.T, srv *httptest.Server) *selfUpdater {
	t.Helper()
	dir := t.TempDir()
	exe := filepath.Join(dir, "fallbck-agent")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\necho old\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := &config.AgentConfig{ServerURL: srv.URL, AuthToken: "t"}
	u := newSelfUpdater(cfg, NewTokenStore(cfg, ""), &inflight{})
	u.exe = exe
	u.verify = func(bundle, checksums []byte) error {
		if string(bundle) != "bundle-for:"+string(checksums) {
			return errors.New("release signature: bad")
		}
		return nil
	}
	return u
}

func TestApplyVerifiesSignedReleaseAndSwaps(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script binary")
	}
	srv, upd := fakeUpdateServer(t, "9.9.9", false)
	defer srv.Close()
	u := newTestUpdater(t, srv)
	if err := u.apply(context.Background(), upd); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if b, _ := os.ReadFile(u.exe); !strings.Contains(string(b), "9.9.9") {
		t.Fatalf("binary not swapped: %q", b)
	}
	if _, err := os.Stat(u.exe + ".old"); err != nil {
		t.Error("previous binary not kept")
	}
}

func TestApplyRejectsTamperedChecksums(t *testing.T) {
	srv, upd := fakeUpdateServer(t, "9.9.9", true)
	defer srv.Close()
	u := newTestUpdater(t, srv)
	err := u.apply(context.Background(), upd)
	if err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("tampered checksums: %v", err)
	}
	if b, _ := os.ReadFile(u.exe); !strings.Contains(string(b), "old") {
		t.Fatal("binary replaced despite failed verification")
	}
}

func TestApplyRefusesUnsignedServer(t *testing.T) {
	srv, _ := fakeUpdateServer(t, "9.9.9", false)
	defer srv.Close()
	u := newTestUpdater(t, srv)
	if err := u.apply(context.Background(), &api.AgentUpdate{Version: "9.9.9", URL: "/archive", SHA256: "x"}); err == nil {
		t.Fatal("legacy unsigned update accepted")
	}
}
