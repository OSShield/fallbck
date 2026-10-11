// Package agentupdate mirrors the fallbck-agent binary of the server's own release
// for agents that update themselves. The goreleaser archive and checksum file are
// fetched from GitHub once per OS/arch, the archive is verified, the binary is
// extracted into <data dir>/agent-releases/<version>/ and served to agents from there.
package agentupdate

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/osshield/fallbck/pkg/agenthealth"
)

// ReleaseBase is where goreleaser publishes the archives
const ReleaseBase = "https://github.com/osshield/fallbck/releases/download"

// retryAfter is how long a failed fetch is remembered before it is tried again
const retryAfter = 10 * time.Minute

// Cache is the per-server mirror; Version is the server's release version
type Cache struct {
	Version string
	Dir     string
	// BaseURL is the release download base (ReleaseBase); tests point it elsewhere
	BaseURL string
	Client  *http.Client

	mu       sync.Mutex
	ready    map[string]string // os/arch -> sha256 of the extracted binary
	fetching map[string]bool
	failed   map[string]fetchError
}

type fetchError struct {
	at  time.Time
	err string
}

// New returns the cache for the server's version under dataDir
func New(version, dataDir string) *Cache {
	return &Cache{
		Version:  strings.TrimPrefix(version, "v"),
		Dir:      filepath.Join(dataDir, "agent-releases"),
		BaseURL:  ReleaseBase,
		Client:   &http.Client{Timeout: 10 * time.Minute},
		ready:    map[string]string{},
		fetching: map[string]bool{},
		failed:   map[string]fetchError{},
	}
}

// Enabled reports whether the server runs a release build (dev builds never update agents)
func (c *Cache) Enabled() bool {
	_, ok := agenthealth.VersionBehind("0.0.0", c.Version)
	return ok
}

// Binary returns the sha256 of the cached binary for os/arch when it is ready. When
// it is not, the fetch starts in the background and ok is false until it completes;
// the next heartbeat picks it up.
func (c *Cache) Binary(goos, goarch string) (sha string, ok bool) {
	if goos != "linux" || !c.Enabled() {
		return "", false
	}
	key := goos + "/" + goarch
	c.mu.Lock()
	defer c.mu.Unlock()
	if sha, ok := c.ready[key]; ok {
		return sha, true
	}
	// Extracted by an earlier server process
	if b, err := os.ReadFile(c.Path(goos, goarch) + ".sha256"); err == nil {
		if _, err := os.Stat(c.Path(goos, goarch)); err == nil {
			c.ready[key] = strings.TrimSpace(string(b))
			return c.ready[key], true
		}
	}
	if c.fetching[key] || time.Since(c.failed[key].at) < retryAfter {
		return "", false
	}
	c.fetching[key] = true
	go func() {
		sha, err := c.fetch(goos, goarch)
		c.mu.Lock()
		defer c.mu.Unlock()
		delete(c.fetching, key)
		if err != nil {
			slog.Error("Agent release could not be mirrored", "version", c.Version, "platform", key, "error", err)
			c.failed[key] = fetchError{at: time.Now(), err: err.Error()}
			return
		}
		delete(c.failed, key)
		c.ready[key] = sha
		slog.Info("Agent release mirrored for self-updating agents", "version", c.Version, "platform", key)
	}()
	return "", false
}

// Path is where the extracted binary for os/arch lives
func (c *Cache) Path(goos, goarch string) string {
	return filepath.Join(c.Dir, c.Version, "fallbck-agent_"+goos+"_"+goarch)
}

// Errors returns the last fetch error per os/arch, for the agents page
func (c *Cache) Errors() map[string]string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := map[string]string{}
	for k, f := range c.failed {
		out[k] = f.err
	}
	return out
}

// ArchiveName is the goreleaser archive for the agent on os/arch
func ArchiveName(goos, goarch string) string {
	arch := map[string]string{"amd64": "x86_64", "386": "i386"}[goarch]
	if arch == "" {
		arch = goarch
	}
	return "fallbck_agent_" + strings.ToUpper(goos[:1]) + goos[1:] + "_" + arch + ".tar.gz"
}

// fetch downloads and verifies the archive and extracts the binary
func (c *Cache) fetch(goos, goarch string) (string, error) {
	base := c.BaseURL + "/v" + c.Version + "/"
	sums, err := c.get(base + "fallbck_" + c.Version + "_checksums.txt")
	if err != nil {
		return "", err
	}
	defer sums.Close()
	want, err := checksumFor(sums, ArchiveName(goos, goarch))
	if err != nil {
		return "", err
	}

	archive, err := c.get(base + ArchiveName(goos, goarch))
	if err != nil {
		return "", err
	}
	defer archive.Close()
	tmp, err := os.CreateTemp("", "fallbck-agent-release-*.tar.gz")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, h), archive); err != nil {
		return "", fmt.Errorf("download %s: %w", ArchiveName(goos, goarch), err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return "", fmt.Errorf("%s: checksum mismatch (got %s, want %s)", ArchiveName(goos, goarch), got, want)
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return "", err
	}

	dst := c.Path(goos, goarch)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return "", err
	}
	sha, err := extractBinary(tmp, dst)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(dst+".sha256", []byte(sha+"\n"), 0o644); err != nil {
		return "", err
	}
	return sha, nil
}

func (c *Cache) get(url string) (io.ReadCloser, error) {
	resp, err := c.Client.Get(url)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return resp.Body, nil
}

// checksumFor finds name in a goreleaser checksums file ("<sha256>  <name>" lines)
func checksumFor(r io.Reader, name string) (string, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[1] == name {
			return f[0], nil
		}
	}
	return "", fmt.Errorf("%s is not in the checksums file", name)
}

// extractBinary writes the fallbck-agent entry of the tar.gz to dst (atomically) and
// returns its sha256
func extractBinary(r io.Reader, dst string) (string, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return "", err
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return "", errors.New("fallbck-agent is not in the archive")
		}
		if err != nil {
			return "", err
		}
		if hdr.Typeflag != tar.TypeReg || filepath.Base(hdr.Name) != "fallbck-agent" {
			continue
		}
		f, err := os.OpenFile(dst+".tmp", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
		if err != nil {
			return "", err
		}
		h := sha256.New()
		_, err = io.Copy(io.MultiWriter(f, h), tr)
		f.Close()
		if err != nil {
			return "", err
		}
		if err := os.Rename(dst+".tmp", dst); err != nil {
			return "", err
		}
		return hex.EncodeToString(h.Sum(nil)), nil
	}
}
