// Package agentupdate mirrors the fallbck-agent release of the server's own version
// for agents that update themselves. The goreleaser archive, the checksums file and
// its Sigstore bundle are fetched from GitHub once per OS/arch, the bundle is
// verified against the release workflow identity, the archive against the signed
// checksums, and everything is kept under <data dir>/agent-releases/<version>/.
// Agents fetch the archive plus the signed checksums and verify again themselves
// (the extracted binary is still served for agents from before release signing).
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
	"github.com/osshield/fallbck/pkg/releasesig"
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
	// Verify checks the checksums file against its Sigstore bundle (releasesig.Verify;
	// tests substitute it)
	Verify func(bundle, checksums []byte) error

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
		Verify:   releasesig.Verify,
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

// ArchivePath is where the verified release archive for os/arch lives
func (c *Cache) ArchivePath(goos, goarch string) string {
	return filepath.Join(c.Dir, c.Version, ArchiveName(goos, goarch))
}

// ChecksumsPath and BundlePath are the release's signed checksums file and its
// Sigstore bundle
func (c *Cache) ChecksumsPath() string { return filepath.Join(c.Dir, c.Version, "checksums.txt") }
func (c *Cache) BundlePath() string    { return c.ChecksumsPath() + ".sigstore.json" }

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

// fetch downloads the signed checksums, verifies the bundle, downloads and verifies
// the archive, keeps it, and extracts the binary
func (c *Cache) fetch(goos, goarch string) (string, error) {
	base := c.BaseURL + "/v" + c.Version + "/"
	sums, err := c.getBytes(base+"fallbck_"+c.Version+"_checksums.txt", 1<<20)
	if err != nil {
		return "", err
	}
	bundle, err := c.getBytes(base+"fallbck_"+c.Version+"_checksums.txt.sigstore.json", 1<<20)
	if err != nil {
		return "", err
	}
	if err := c.Verify(bundle, sums); err != nil {
		return "", err
	}
	want, err := releasesig.ChecksumFor(sums, ArchiveName(goos, goarch))
	if err != nil {
		return "", err
	}

	dst := c.Path(goos, goarch)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return "", err
	}
	archive, err := c.get(base + ArchiveName(goos, goarch))
	if err != nil {
		return "", err
	}
	defer archive.Close()
	archivePath := c.ArchivePath(goos, goarch)
	tmp, err := os.OpenFile(archivePath+".tmp", os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o644)
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
	sha, err := ExtractBinary(tmp, dst)
	if err != nil {
		return "", err
	}
	if err := os.Rename(tmp.Name(), archivePath); err != nil {
		return "", err
	}
	for path, data := range map[string][]byte{c.ChecksumsPath(): sums, c.BundlePath(): bundle, dst + ".sha256": []byte(sha + "\n")} {
		if err := os.WriteFile(path, data, 0o644); err != nil {
			return "", err
		}
	}
	return sha, nil
}

func (c *Cache) getBytes(url string, limit int64) ([]byte, error) {
	r, err := c.get(url)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	b, err := releasesig.ReadAll(r, limit)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	return b, nil
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

// ExtractBinary writes the fallbck-agent entry of the tar.gz to dst (atomically) and
// returns its sha256
func ExtractBinary(r io.Reader, dst string) (string, error) {
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
