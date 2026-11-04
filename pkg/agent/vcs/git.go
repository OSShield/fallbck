// Package vcs runs VCS (git) backups on the agent: git mirrors kept between runs,
// the virtual tree that archives them under their project paths, and (later) the
// run loop. The job specification lives in pkg/vcs.
package vcs

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Auth for the connection. The token is sent as a HTTP header scoped to
// BaseURL (http.<BaseURL>/.extraHeader), passed through the GIT_CONFIG_COUNT environment:
// never on the command line, never sent to another host
// LFS downloads redirected to object storage go without it
type Auth struct {
	// BaseURL is the connection URL the header is scoped to (normalised, no trailing slash)
	BaseURL string
	// Username for HTTP basic authentication; gitlab accepts any name with an access token ("oauth2" by convention)
	Username string
	Token    string
	// CAPEM is an optional CA bundle for the host (written to a private temp file for http.sslCAInfo)
	CAPEM string
}

// DefaultUsername is sent with the token when Auth.Username is empty
const DefaultUsername = "oauth2"

// Git runs the git binary for one run with the connection's credentials
type Git struct {
	// Path is the git binary
	Path string
	auth Auth
	// caFile is the CA bundle written for this run ("" when none)
	caFile  string
	secrets []string
	// KillGrace is how long a cancelled git gets before it is killed
	KillGrace time.Duration
}

// NewGit prepares git for a run. tempDir receives the CA bundle (removed by Close).
//  gitPath "" looks git up in PATH.
func NewGit(gitPath string, auth Auth, tempDir string) (*Git, error) {
	if gitPath == "" {
		p, err := exec.LookPath("git")
		if err != nil {
			return nil, fmt.Errorf("git is not installed: %w", err)
		}
		gitPath = p
	}
	if auth.Username == "" {
		auth.Username = DefaultUsername
	}
	auth.BaseURL = strings.TrimRight(auth.BaseURL, "/")
	g := &Git{Path: gitPath, auth: auth, KillGrace: 20 * time.Second}
	if auth.Token != "" {
		g.secrets = []string{auth.Token, basicCredentials(auth.Username, auth.Token)}
	}
	if auth.CAPEM != "" {
		f, err := os.CreateTemp(tempDir, "vcs-ca-*.pem")
		if err != nil {
			return nil, fmt.Errorf("writing the CA bundle: %w", err)
		}
		g.caFile = f.Name()
		_, werr := f.WriteString(auth.CAPEM)
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			_ = os.Remove(g.caFile)
			return nil, fmt.Errorf("writing the CA bundle: %w", werr)
		}
	}
	return g, nil
}

// Close removes the run's temporary files
func (g *Git) Close() error {
	if g.caFile == "" {
		return nil
	}
	return os.Remove(g.caFile)
}

func basicCredentials(user, token string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + token))
}

// env is the complete environment of every git process: nothing inherited from the
// agent but PATH, HOME, temp and proxy settings; no system or global git config, no
// credential helpers, no prompts; https only (no file::, ext:: or ssh); and the
// connection's header and CA bundle scoped to its URL
func (g *Git) env() []string {
	env := []string{"LANG=C", "LC_ALL=C", "TZ=UTC",
		"GIT_TERMINAL_PROMPT=0", "GCM_INTERACTIVE=never", "GIT_ASKPASS=", "SSH_ASKPASS=",
		"GIT_ALLOW_PROTOCOL=https",
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + os.DevNull,
		"GIT_LFS_SKIP_SMUDGE=1",
	}
	for _, k := range []string{"PATH", "HOME", "TMPDIR", "TEMP", "TMP", "SYSTEMROOT", "USERPROFILE",
		"HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy", "ALL_PROXY", "all_proxy"} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	cfg := [][2]string{
		// An empty value clears the list: tokens from fallbck only
		{"credential.helper", ""},
		{"lfs.locksverify", "false"},
	}
	if g.auth.Token != "" && g.auth.BaseURL != "" {
		cfg = append(cfg, [2]string{"http." + g.auth.BaseURL + "/.extraHeader", "Authorization: Basic " + basicCredentials(g.auth.Username, g.auth.Token)})
	}
	if g.caFile != "" && g.auth.BaseURL != "" {
		cfg = append(cfg, [2]string{"http." + g.auth.BaseURL + "/.sslCAInfo", g.caFile})
	}
	env = append(env, "GIT_CONFIG_COUNT="+strconv.Itoa(len(cfg)))
	for i, kv := range cfg {
		n := strconv.Itoa(i)
		env = append(env, "GIT_CONFIG_KEY_"+n+"="+kv[0], "GIT_CONFIG_VALUE_"+n+"="+kv[1])
	}
	return env
}

// GitError is a git command that exited with an error
type GitError struct {
	Command  string
	ExitCode int
	Stderr   string
	Hint     string
}

func (e *GitError) Error() string {
	msg := fmt.Sprintf("git %s exited with status %d", e.Command, e.ExitCode)
	if tail := lastLines(e.Stderr, 4); tail != "" {
		msg += ": " + tail
	}
	if e.Hint != "" {
		msg += " (" + e.Hint + ")"
	}
	return msg
}

var gitHints = []struct{ match, hint string }{
	{"authentication failed", "the host rejected the token: check that it is valid and has read_repository"},

	// After a 401 git asks for credentials, which the disabled prompt refuses
	{"terminal prompts disabled", "the host rejected the token or none is configured: check that it is valid and has read_repository"},
	{"returned error: 401", "the host rejected the token: check that it is valid and has read_repository"},
	{"returned error: 403", "the token may not read this repository"},
	{"returned error: 404", "the repository does not exist or the token cannot see it"},
	{"repository not found", "the repository does not exist or the token cannot see it"},
	{"ssl certificate problem", "the host's certificate is not trusted: add its CA bundle to the connection"},
	{"could not resolve host", "the agent cannot resolve the host name"},
	{"not allowed", "only https:// repositories are allowed"},
	{"'lfs' is not a git command", "git-lfs is not installed on the agent"},
}

func hintFor(stderr string) string {
	s := strings.ToLower(stderr)
	for _, h := range gitHints {
		if strings.Contains(s, h.match) {
			return h.hint
		}
	}
	return ""
}

// run executes one git command in dir. stdout receives standard output (nil discards)
// progress, when set, gets every stderr line (git's --progress outputends lines with \r).
// The returned error has the redacted stderr tail.
func (g *Git) run(ctx context.Context, dir string, stdout io.Writer, progress func(string), args ...string) error {
	cmd := exec.CommandContext(ctx, g.Path, args...)
	cmd.Dir = dir
	cmd.Env = g.env()
	cmd.Stdout = stdout
	stderr := &lineWriter{limit: 64 << 10, secrets: g.secrets, onLine: progress}
	cmd.Stderr = stderr
	configureKill(cmd)
	cmd.WaitDelay = g.KillGrace
	name := args[0]
	slog.Debug("Running git", "args", args, "dir", dir)
	err := cmd.Run()
	if ctx.Err() != nil {
		return fmt.Errorf("git %s interrupted: %w", name, context.Cause(ctx))
	}
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			out := stderr.String()
			return &GitError{Command: name, ExitCode: exitErr.ExitCode(), Stderr: out, Hint: hintFor(out)}
		}
		return fmt.Errorf("git %s: %w", name, err)
	}
	return nil
}

// runs a git command and returns its standard output
func (g *Git) output(ctx context.Context, dir string, args ...string) (string, error) {
	var out bytes.Buffer
	err := g.run(ctx, dir, &out, nil, args...)
	return out.String(), err
}

// "git --version" without the "git version" prefix ("2.43.0")
func (g *Git) Version(ctx context.Context) (string, error) {
	out, err := g.output(ctx, "", "--version")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(out), "git version")), nil
}

// LFSVersion is the first line of "git lfs version", or an error when git-lfs is
// not installed
func (g *Git) LFSVersion(ctx context.Context) (string, error) {
	out, err := g.output(ctx, "", "lfs", "version")
	if err != nil {
		return "", err
	}
	line, _, _ := strings.Cut(strings.TrimSpace(out), "\n")
	return line, nil
}

// RemoteRefs lists the refs the fetch refspecs select on the remote and their digest
// (comparable with Mirror.LocalRefs): equal digests mean a fetch would change
// nothing
func (g *Git) RemoteRefs(ctx context.Context, url string) (digest string, count int, err error) {
	out, err := g.output(ctx, "", "ls-remote", "--refs", url)
	if err != nil {
		return "", 0, err
	}
	var lines []string
	for l := range strings.SplitSeq(out, "\n") {
		oid, ref, ok := strings.Cut(strings.TrimSpace(l), "\t")
		if ok && selectedRef(ref) {
			lines = append(lines, oid+" "+ref)
		}
	}
	d, n := refsDigest(lines)
	return d, n, nil
}

// lineWriter keeps the last limit bytes of a stream (redacted) and reports every
// line, splitting on \n and \r
type lineWriter struct {
	mu      sync.Mutex
	limit   int
	buf     []byte
	partial []byte
	secrets []string
	onLine  func(string)
}

func (w *lineWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf = append(w.buf, p...)
	if over := len(w.buf) - w.limit; over > 0 {
		w.buf = w.buf[over:]
	}
	if w.onLine != nil {
		w.partial = append(w.partial, p...)
		for {
			i := bytes.IndexAny(w.partial, "\r\n")
			if i < 0 {
				break
			}
			if line := strings.TrimSpace(string(w.partial[:i])); line != "" {
				w.onLine(redact(line, w.secrets))
			}
			w.partial = w.partial[i+1:]
		}
		if len(w.partial) > 4096 {
			w.partial = w.partial[len(w.partial)-4096:]
		}
	}
	return len(p), nil
}

func (w *lineWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return redact(string(w.buf), w.secrets)
}

// redact masks every secret (longest first)
func redact(s string, secrets []string) string {
	if s == "" || len(secrets) == 0 {
		return s
	}
	sorted := append([]string(nil), secrets...)
	sort.Slice(sorted, func(i, j int) bool { return len(sorted[i]) > len(sorted[j]) })
	for _, sec := range sorted {
		if sec != "" {
			s = strings.ReplaceAll(s, sec, "***")
		}
	}
	return s
}

// lastLines returns the last n non-empty lines of s, joined with "; " (progress
// lines, which end in \r, count as lines)
func lastLines(s string, n int) string {
	var lines []string
	for _, l := range strings.FieldsFunc(s, func(r rune) bool { return r == '\n' || r == '\r' }) {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "; ")
}

// dirSize sums the sizes of the regular files below dir (0 when it does not exist)
func dirSize(dir string) int64 {
	var n int64
	_ = filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.Type().IsRegular() {
			if fi, err := d.Info(); err == nil {
				n += fi.Size()
			}
		}
		return nil
	})
	return n
}

// reports the git on PATH ("" if none) and if git-lfs is installed
// the capability a filesystem agent sends with enrollment and heartbeats
func Probe(ctx context.Context) (version string, lfs bool) {
	g, err := NewGit("", Auth{}, "")
	if err != nil {
		return "", false
	}
	if version, err = g.Version(ctx); err != nil {
		return "", false
	}
	_, err = g.LFSVersion(ctx)
	return version, err == nil
}
