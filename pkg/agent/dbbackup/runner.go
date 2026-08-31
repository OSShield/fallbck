package dbbackup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Command describes a client tool invocation. Env is the complete environment (the
// agent's own environment, which carries its token, is never inherited).
type Command struct {
	// Name is the logical tool name for logs and errors
	Name   string
	Path   string
	Args   []string
	Env    []string
	Dir    string
	Stdout io.Writer
}

// Result describes a finished command
type Result struct {
	ExitCode int
	Stderr   string
	Duration time.Duration
}

// Runner executes client tools; tests substitute a fake
type Runner interface {
	Run(ctx context.Context, c Command) (Result, error)
	LookPath(name string) (string, error)
}

// ToolError is a non-zero exit of a client tool
type ToolError struct {
	Tool     string
	ExitCode int
	Stderr   string
	// Hint explains known failure messages; Config marks configuration problems
	Hint   string
	Config bool
}

func (e *ToolError) Error() string {
	msg := fmt.Sprintf("%s exited with status %d", e.Tool, e.ExitCode)
	if tail := lastLines(e.Stderr, 6); tail != "" {
		msg += ": " + tail
	}
	if e.Hint != "" {
		msg += " (" + e.Hint + ")"
	}
	return msg
}

// knownFailures maps tool messages to hints; config marks non-retryable problems
var knownFailures = []struct {
	match  string
	hint   string
	config bool
}{
	{"no pg_hba.conf entry for replication connection", "add a 'host replication <user> <address> scram-sha-256' line to pg_hba.conf", true},
	{"no pg_hba.conf entry", "allow the agent host and user in pg_hba.conf", true},
	{"password authentication failed", "check the database user and password (job or agent profile)", true},
	{"server version mismatch", "install a pg_dump at least as new as the server or set db_backup.tools.postgres_bindir", true},
	{"must be superuser or replication role", "grant the REPLICATION attribute to the backup role", true},
	{"permission denied for table pg_authid", "set postgres.role_passwords to omit or use a superuser", true},
	{"Access denied for user", "check the database user, password and grants", true},
	{"Binlogging on server not active", "enable log_bin on the server or disable include_binlogs", true},
	{"--oplog mode only supported on replica sets", "run mongod as a replica set or disable mongodb.oplog", true},
	{"Authentication failed", "check the MongoDB user, password and auth_source", true},
	{"auth error", "check the MongoDB user, password and auth_source", true},
	{"Unknown database", "the database does not exist on the server", true},
	{"does not exist", "", false},
	{"No space left on device", "the spool filesystem is full; lower the job size or move db_backup.spool_dir", false},
}

func classify(tool string, code int, stderr string) *ToolError {
	te := &ToolError{Tool: tool, ExitCode: code, Stderr: stderr}
	for _, k := range knownFailures {
		if strings.Contains(stderr, k.match) {
			te.Hint, te.Config = k.hint, k.config
			break
		}
	}
	return te
}

func lastLines(s string, n int) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}

// ringWriter keeps the last max bytes written and streams complete lines to slog
type ringWriter struct {
	mu   sync.Mutex
	buf  []byte
	max  int
	line []byte
	log  func(string)
}

func newRingWriter(max int, log func(string)) *ringWriter {
	return &ringWriter{max: max, log: log}
}

func (w *ringWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf = append(w.buf, p...)
	if len(w.buf) > w.max {
		w.buf = w.buf[len(w.buf)-w.max:]
	}
	if w.log != nil {
		w.line = append(w.line, p...)
		for {
			i := bytes.IndexByte(w.line, '\n')
			if i < 0 {
				break
			}
			if l := strings.TrimRight(string(w.line[:i]), "\r"); l != "" {
				w.log(l)
			}
			w.line = w.line[i+1:]
		}
	}
	return len(p), nil
}

func (w *ringWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return string(w.buf)
}

// execRunner runs real processes
type execRunner struct {
	KillGrace time.Duration
}

// NewRunner returns the process runner used by the agent
func NewRunner(killGrace time.Duration) Runner {
	if killGrace <= 0 {
		killGrace = 20 * time.Second
	}
	return &execRunner{KillGrace: killGrace}
}

func (r *execRunner) LookPath(name string) (string, error) { return exec.LookPath(name) }

func (r *execRunner) Run(ctx context.Context, c Command) (Result, error) {
	start := time.Now()
	cmd := exec.CommandContext(ctx, c.Path, c.Args...)
	cmd.Env = c.Env
	cmd.Dir = c.Dir
	cmd.Stdout = c.Stdout
	stderr := newRingWriter(64*1024, func(line string) { slog.Debug("tool output", "tool", c.Name, "stderr", line) })
	cmd.Stderr = stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		// Terminate the whole process group; WaitDelay escalates to SIGKILL
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	}
	cmd.WaitDelay = r.KillGrace
	slog.Debug("Running tool", "tool", c.Name, "path", c.Path, "args", c.Args)

	err := cmd.Run()
	res := Result{Duration: time.Since(start), Stderr: stderr.String()}
	if cmd.ProcessState != nil {
		res.ExitCode = cmd.ProcessState.ExitCode()
	}
	if ctx.Err() != nil {
		return res, fmt.Errorf("%s interrupted: %w", c.Name, context.Cause(ctx))
	}
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return res, classify(c.Name, res.ExitCode, res.Stderr)
		}
		return res, fmt.Errorf("%s: %w", c.Name, err)
	}
	return res, nil
}

// baseEnv is the environment given to every client tool: no agent secrets, C locale
// (stderr is parsed), UTC.
func baseEnv() []string {
	env := []string{"LANG=C", "LC_ALL=C", "TZ=UTC"}
	for _, k := range []string{"PATH", "HOME", "TMPDIR", "SYSTEMROOT"} {
		if v := os.Getenv(k); v != "" {
			env = append(env, k+"="+v)
		}
	}
	return env
}

// version runs "<tool> --version" and returns the first line of its output
func version(ctx context.Context, r Runner, name, path string) (string, error) {
	var out bytes.Buffer
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if _, err := r.Run(ctx, Command{Name: name, Path: path, Args: []string{"--version"}, Env: baseEnv(), Stdout: &out}); err != nil {
		return "", err
	}
	line, _, _ := strings.Cut(strings.TrimSpace(out.String()), "\n")
	return strings.TrimSpace(line), nil
}
