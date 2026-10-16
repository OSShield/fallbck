package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/osshield/fallbck/pkg/agentupdate"
	"github.com/osshield/fallbck/pkg/api"
	"github.com/osshield/fallbck/pkg/config"
	"github.com/osshield/fallbck/pkg/releasesig"
	"go.temporal.io/sdk/interceptor"
)

// ErrRestart is returned by RunUntil when the binary was replaced and the process
// should re-execute itself
var ErrRestart = errors.New("agent binary updated; restart required")

// updateRetryAfter is how long a failed update is left alone before auto-update tries again
const updateRetryAfter = time.Hour

// inflight counts the activities currently executing so an update never kills a run
type inflight struct {
	interceptor.WorkerInterceptorBase
	n atomic.Int32
}

func (i *inflight) InterceptActivity(ctx context.Context, next interceptor.ActivityInboundInterceptor) interceptor.ActivityInboundInterceptor {
	return &inflightActivity{ActivityInboundInterceptorBase: interceptor.ActivityInboundInterceptorBase{Next: next}, n: &i.n}
}

type inflightActivity struct {
	interceptor.ActivityInboundInterceptorBase
	n *atomic.Int32
}

func (a *inflightActivity) ExecuteActivity(ctx context.Context, in *interceptor.ExecuteActivityInput) (any, error) {
	a.n.Add(1)
	defer a.n.Add(-1)
	return a.Next.ExecuteActivity(ctx, in)
}

// selfUpdater applies an update instruction from a heartbeat: download the binary
// from the server, verify it, swap it in and ask RunUntil to re-exec
type selfUpdater struct {
	exe      string // the binary's path at startup (os.Executable changes once it is renamed)
	client   *http.Client
	base     string
	store    *TokenStore
	inflight *inflight
	restart  chan struct{}
	// verify checks the release checksums against their Sigstore bundle
	// (releasesig.Verify; tests substitute it)
	verify func(bundle, checksums []byte) error

	lastErr string
	nextTry time.Time
	done    bool
}

func newSelfUpdater(cfg *config.AgentConfig, store *TokenStore, inflight *inflight) *selfUpdater {
	exe, _ := os.Executable()
	client := ServerHTTPClient(cfg)
	client.Timeout = 10 * time.Minute
	return &selfUpdater{exe: exe, client: client, base: strings.TrimRight(cfg.ServerURL, "/"), store: store, inflight: inflight, restart: make(chan struct{}), verify: releasesig.Verify}
}

// canSelfUpdate reports whether this process can replace its own binary: Linux, not
// a container (the image owns the binary) and the binary's directory is writable
func (u *selfUpdater) canSelfUpdate() bool {
	if goruntime.GOOS != "linux" || u.exe == "" || os.Getenv("FALLBCK_IN_CONTAINER") != "" {
		return false
	}
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return false
	}
	f, err := os.CreateTemp(filepath.Dir(u.exe), ".fallbck-agent-w-*")
	if err != nil {
		return false
	}
	f.Close()
	os.Remove(f.Name()) //nolint:errcheck
	return true
}

// handle acts on an update instruction; it is called from the heartbeat loop
func (u *selfUpdater) handle(ctx context.Context, upd *api.AgentUpdate) {
	if u.done || time.Now().Before(u.nextTry) {
		return
	}
	if n := u.inflight.n.Load(); n > 0 {
		slog.Info("Agent update deferred: activities in flight", "version", upd.Version, "activities", n)
		return
	}
	slog.Info("Updating agent binary", "to", upd.Version, "path", u.exe)
	if err := u.apply(ctx, upd); err != nil {
		slog.Error("Agent update failed", "version", upd.Version, "error", err)
		u.lastErr = fmt.Sprintf("update to %s failed: %v", upd.Version, err)
		u.nextTry = time.Now().Add(updateRetryAfter)
		return
	}
	u.done = true
	close(u.restart)
}

// apply downloads the release archive next to the current binary, verifies the
// release's Sigstore bundle and the archive against the signed checksums (so a
// compromised server cannot hand out a binary GitHub never built), extracts the
// binary, smoke-tests it and renames it into place (the previous binary stays as
// <name>.old)
func (u *selfUpdater) apply(ctx context.Context, upd *api.AgentUpdate) error {
	if upd.ArchiveURL == "" || upd.ChecksumsURL == "" || upd.BundleURL == "" || upd.Archive == "" {
		return errors.New("server offers no signed release (older server); update by hand")
	}
	archive := u.exe + ".new.tar.gz"
	defer os.Remove(archive) //nolint:errcheck
	gotSHA, err := u.download(ctx, upd.ArchiveURL, archive)
	if err != nil {
		return err
	}
	sums, err := u.fetch(ctx, upd.ChecksumsURL)
	if err != nil {
		return err
	}
	bundle, err := u.fetch(ctx, upd.BundleURL)
	if err != nil {
		return err
	}
	if err := u.verify(bundle, sums); err != nil {
		return err
	}
	want, err := releasesig.ChecksumFor(sums, upd.Archive)
	if err != nil {
		return err
	}
	if gotSHA != want {
		return fmt.Errorf("%s: checksum mismatch against the signed release (got %s, want %s)", upd.Archive, gotSHA, want)
	}
	tmp := u.exe + ".new"
	defer os.Remove(tmp)
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	_, err = agentupdate.ExtractBinary(f, tmp)
	f.Close()
	if err != nil {
		return err
	}
	smoke, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(smoke, tmp, "version").Output()
	if err != nil {
		return fmt.Errorf("new binary does not run: %w", err)
	}
	if !strings.Contains(string(out), upd.Version) {
		return fmt.Errorf("new binary reports %q, expected %s", strings.TrimSpace(string(out)), upd.Version)
	}
	return swapBinary(u.exe, tmp)
}

// get performs an authenticated GET against the server
func (u *selfUpdater) get(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.base+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+u.store.Token())
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s: %s", path, resp.Status)
	}
	return resp, nil
}

// download saves path to dst and returns the file's sha256
func (u *selfUpdater) download(ctx context.Context, path, dst string) (string, error) {
	resp, err := u.get(ctx, path)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(f, h), resp.Body)
	f.Close()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// fetch reads a small file (checksums, bundle) from the server
func (u *selfUpdater) fetch(ctx context.Context, path string) ([]byte, error) {
	resp, err := u.get(ctx, path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return releasesig.ReadAll(resp.Body, 1<<20)
}

// swapBinary moves exe to exe.old and tmp to exe, restoring exe when the second
// rename fails
func swapBinary(exe, tmp string) error {
	old := exe + ".old"
	os.Remove(old)
	if err := os.Rename(exe, old); err != nil {
		return err
	}
	if err := os.Rename(tmp, exe); err != nil {
		_ = os.Rename(old, exe)
		return err
	}
	return nil
}
