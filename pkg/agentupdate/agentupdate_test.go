package agentupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func fakeRelease(t *testing.T, binary []byte, corrupt bool) *httptest.Server {
	t.Helper()
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	tw := tar.NewWriter(gz)
	_ = tw.WriteHeader(&tar.Header{Name: "fallbck-agent", Mode: 0o755, Size: int64(len(binary)), Typeflag: tar.TypeReg})
	_, _ = tw.Write(binary)
	tw.Close()
	gz.Close()
	sum := sha256.Sum256(archive.Bytes())
	sums := hex.EncodeToString(sum[:]) + "  " + ArchiveName("linux", "amd64") + "\n"
	if corrupt {
		sums = "0000" + sums[4:]
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1.2.3/fallbck_1.2.3_checksums.txt", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(sums)) })
	mux.HandleFunc("/v1.2.3/"+ArchiveName("linux", "amd64"), func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(archive.Bytes()) })
	return httptest.NewServer(mux)
}

func wait(t *testing.T, c *Cache) (string, bool) {
	t.Helper()
	for range 100 {
		if sha, ok := c.Binary("linux", "amd64"); ok {
			return sha, true
		}
		if len(c.Errors()) > 0 {
			return "", false
		}
		time.Sleep(20 * time.Millisecond)
	}
	return "", false
}

func TestMirrorsVerifiedBinary(t *testing.T) {
	binary := []byte("#!/bin/sh\necho fallbck-agent v1.2.3\n")
	srv := fakeRelease(t, binary, false)
	defer srv.Close()
	c := New("v1.2.3", t.TempDir())
	c.BaseURL = srv.URL
	if _, ok := c.Binary("linux", "amd64"); ok {
		t.Fatal("ready before the fetch finished")
	}
	sha, ok := wait(t, c)
	if !ok {
		t.Fatalf("fetch failed: %v", c.Errors())
	}
	want := sha256.Sum256(binary)
	if sha != hex.EncodeToString(want[:]) {
		t.Fatalf("sha %s, want %x", sha, want)
	}
	got, err := os.ReadFile(c.Path("linux", "amd64"))
	if err != nil || !bytes.Equal(got, binary) {
		t.Fatalf("cached binary wrong: %v", err)
	}
	// A new cache over the same dir reuses the extracted file without fetching
	c2 := New("1.2.3", c.Dir[:len(c.Dir)-len("/agent-releases")])
	c2.BaseURL = "http://127.0.0.1:1"
	if sha2, ok := c2.Binary("linux", "amd64"); !ok || sha2 != sha {
		t.Fatalf("cache not reused: %q %v", sha2, ok)
	}
	if _, ok := c.Binary("windows", "amd64"); ok {
		t.Fatal("windows must not be served")
	}
}

func TestRejectsBadChecksum(t *testing.T) {
	srv := fakeRelease(t, []byte("x"), true)
	defer srv.Close()
	c := New("1.2.3", t.TempDir())
	c.BaseURL = srv.URL
	if _, ok := wait(t, c); ok {
		t.Fatal("corrupt archive accepted")
	}
	if _, err := os.Stat(c.Path("linux", "amd64")); err == nil {
		t.Fatal("binary written despite checksum mismatch")
	}
}

func TestDevBuildDisabled(t *testing.T) {
	if New("dev", t.TempDir()).Enabled() || New("0.1.0", t.TempDir()).Enabled() != true {
		t.Fatal("Enabled wrong")
	}
	if _, ok := New("dev", t.TempDir()).Binary("linux", "amd64"); ok {
		t.Fatal("dev build served an update")
	}
}
