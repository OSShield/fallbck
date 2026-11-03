package github

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Git ignores the host's git config (url rewrites, credential helpers) and passes the
// token as an env-borne HTTP header, so it never reaches argv or the mirror's config
type Git struct {
	Path    string
	Version string
	// Token authenticates HTTPS remotes (empty: anonymous)
	Token string
}

// minGitMajor/minGitMinor: GIT_CONFIG_COUNT needs 2.31
const minGitMajor, minGitMinor = 2, 31

var gitVersionRe = regexp.MustCompile(`git version (\d+)\.(\d+)`)

// FindGit locates git and checks its version
func FindGit(ctx context.Context, path string) (*Git, error) {
	if path == "" {
		var err error
		if path, err = exec.LookPath("git"); err != nil {
			return nil, errors.New("git is not installed on the agent host")
		}
	}
	out, err := exec.CommandContext(ctx, path, "version").Output()
	if err != nil {
		return nil, fmt.Errorf("running %s version: %w", path, err)
	}
	m := gitVersionRe.FindStringSubmatch(string(out))
	if m == nil {
		return nil, fmt.Errorf("unrecognised git version %q", strings.TrimSpace(string(out)))
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	if major < minGitMajor || (major == minGitMajor && minor < minGitMinor) {
		return nil, fmt.Errorf("git %s.%s is too old (need %d.%d or newer)", m[1], m[2], minGitMajor, minGitMinor)
	}
	return &Git{Path: path, Version: m[1] + "." + m[2]}, nil
}

// env builds the environment of one git invocation against remote
func (g *Git) env(remote string) []string {
	env := append(os.Environ(),
		"GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_ASKPASS=",
		"SSH_ASKPASS=",
	)
	cfg := [][2]string{{"credential.helper", ""}, {"core.askPass", ""}}
	if g.Token != "" {
		if u, err := url.Parse(remote); err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" {
			// Scoped to the remote's origin so the header never goes to another host
			basic := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + g.Token))
			cfg = append(cfg, [2]string{"http." + u.Scheme + "://" + u.Host + "/.extraHeader", "Authorization: Basic " + basic})
		}
	}
	env = append(env, "GIT_CONFIG_COUNT="+strconv.Itoa(len(cfg)))
	for i, kv := range cfg {
		env = append(env, fmt.Sprintf("GIT_CONFIG_KEY_%d=%s", i, kv[0]), fmt.Sprintf("GIT_CONFIG_VALUE_%d=%s", i, kv[1]))
	}
	return env
}

// GitError carries git's stderr
type GitError struct {
	Args   []string
	Stderr string
	Err    error
}

func (e *GitError) Error() string {
	msg := strings.TrimSpace(e.Stderr)
	if len(msg) > 2000 {
		msg = msg[len(msg)-2000:]
	}
	if msg == "" {
		msg = e.Err.Error()
	}
	return fmt.Sprintf("git %s: %s", strings.Join(e.Args, " "), msg)
}

func (e *GitError) Unwrap() error { return e.Err }

// IsRemoteNotFound reports a missing remote repository (a wiki that was never created)
func IsRemoteNotFound(err error) bool {
	var ge *GitError
	if !errors.As(err, &ge) {
		return false
	}
	s := strings.ToLower(ge.Stderr)
	return strings.Contains(s, "not found") || strings.Contains(s, "does not appear to be a git repository") || strings.Contains(s, "does not exist")
}

// run executes git in dir (empty: no -C) against remote (for the auth header)
func (g *Git) run(ctx context.Context, dir, remote string, args ...string) (string, error) {
	full := args
	if dir != "" {
		full = append([]string{"-C", dir}, args...)
	}
	cmd := exec.CommandContext(ctx, g.Path, full...)
	cmd.Env = g.env(remote)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", &GitError{Args: args, Stderr: redact(stderr.String(), g.Token), Err: err}
	}
	return stdout.String(), nil
}

func redact(s, token string) string {
	if token == "" {
		return s
	}
	return strings.ReplaceAll(s, token, "***")
}

// isMirror reports whether dir holds a bare repository
func isMirror(dir string) bool {
	st, err := os.Stat(filepath.Join(dir, "HEAD"))
	if err != nil || st.IsDir() {
		return false
	}
	st, err = os.Stat(filepath.Join(dir, "objects"))
	return err == nil && st.IsDir()
}

// Mirror fetches into an existing mirror, or clones afresh when there is none or the
// fetch finds it broken; cloned reports the latter
func (g *Git) Mirror(ctx context.Context, remote, dir string) (cloned bool, err error) {
	if isMirror(dir) {
		if _, err = g.run(ctx, dir, remote, "remote", "set-url", "origin", remote); err == nil {
			if _, err = g.run(ctx, dir, remote, "fetch", "--prune", "--prune-tags", "--force", "--quiet", "origin"); err == nil {
				return false, nil
			}
		}
		if ctx.Err() != nil || IsRemoteNotFound(err) {
			return false, err
		}
		// A corrupt or half-written mirror: start over
		if rmErr := os.RemoveAll(dir); rmErr != nil {
			return false, fmt.Errorf("%w (and removing the broken mirror failed: %v)", err, rmErr)
		}
	}
	tmp := dir + ".partial"
	_ = os.RemoveAll(tmp)
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return false, err
	}
	if _, err := g.run(ctx, "", remote, "clone", "--mirror", "--quiet", remote, tmp); err != nil {
		_ = os.RemoveAll(tmp)
		return false, err
	}
	_ = os.RemoveAll(dir)
	if err := os.Rename(tmp, dir); err != nil {
		_ = os.RemoveAll(tmp)
		return false, err
	}
	return true, nil
}

// LFSAvailable reports whether git-lfs is installed
func (g *Git) LFSAvailable(ctx context.Context) bool {
	_, err := g.run(ctx, "", "", "lfs", "version")
	return err == nil
}

// FetchLFS downloads every LFS object referenced by any ref into the mirror
func (g *Git) FetchLFS(ctx context.Context, remote, dir string) error {
	_, err := g.run(ctx, dir, remote, "lfs", "fetch", "--all", "origin")
	return err
}

// MirrorInfo describes a mirror for the manifest
type MirrorInfo struct {
	Refs int
	Head string
}

// Describe counts the refs and resolves HEAD (empty for an empty repository)
func (g *Git) Describe(ctx context.Context, dir string) (MirrorInfo, error) {
	var info MirrorInfo
	out, err := g.run(ctx, dir, "", "for-each-ref", "--format=%(refname)")
	if err != nil {
		return info, err
	}
	for _, l := range strings.Split(out, "\n") {
		if strings.TrimSpace(l) != "" {
			info.Refs++
		}
	}
	if head, err := g.run(ctx, dir, "", "rev-parse", "--verify", "--quiet", "HEAD"); err == nil {
		info.Head = strings.TrimSpace(head)
	}
	return info, nil
}

// WikiURL derives the wiki remote of a repository clone URL
func WikiURL(cloneURL string) string {
	return strings.TrimSuffix(cloneURL, ".git") + ".wiki.git"
}
