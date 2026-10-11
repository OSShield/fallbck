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

	"github.com/osshield/fallbck/pkg/api"
	"github.com/osshield/fallbck/pkg/config"
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

	lastErr string
	nextTry time.Time
	done    bool
}

func newSelfUpdater(cfg *config.AgentConfig, store *TokenStore, inflight *inflight) *selfUpdater {
	exe, _ := os.Executable()
	client := ServerHTTPClient(cfg)
	client.Timeout = 10 * time.Minute
	return &selfUpdater{exe: exe, client: client, base: strings.TrimRight(cfg.ServerURL, "/"), store: store, inflight: inflight, restart: make(chan struct{})}
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
	os.Remove(f.Name())
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

// apply downloads the binary next to the current one, checks its digest, smoke-tests
// it and renames it into place (the previous binary stays as <name>.old)
func (u *selfUpdater) apply(ctx context.Context, upd *api.AgentUpdate) error {
	tmp := u.exe + ".new"
	defer os.Remove(tmp)
	if err := u.download(ctx, upd, tmp); err != nil {
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

func (u *selfUpdater) download(ctx context.Context, upd *api.AgentUpdate, dst string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.base+upd.URL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+u.store.Token())
	resp, err := u.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download: %s", resp.Status)
	}
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(f, h), resp.Body)
	f.Close()
	if err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != upd.SHA256 {
		return fmt.Errorf("checksum mismatch (got %s, want %s)", got, upd.SHA256)
	}
	return nil
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
