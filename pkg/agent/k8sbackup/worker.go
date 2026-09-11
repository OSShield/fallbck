package k8sbackup

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime/debug"
	"time"

	"github.com/osshield/fallbck/pkg/agent/backup"
	"github.com/osshield/fallbck/pkg/agent/runtime"
	"github.com/osshield/fallbck/pkg/config"
	spec "github.com/osshield/fallbck/pkg/k8sbackup"
	"github.com/osshield/fallbck/pkg/proxy"
	"github.com/osshield/fallbck/pkg/temporal"
	"github.com/osshield/gopbs/pbs"
)

// Environment of a worker pod (set by the agent when building the pod spec)
const (
	EnvWorkerServerURL  = "FALLBCK_WORKER_SERVER_URL"
	EnvWorkerToken      = "FALLBCK_WORKER_TOKEN"
	EnvWorkerTicket     = "FALLBCK_WORKER_TICKET"
	EnvWorkerSession    = "FALLBCK_WORKER_SESSION" // JSON temporal.BackupSessionInfo (identity fields)
	EnvWorkerPath       = "FALLBCK_WORKER_PATH"    // default /data
	EnvWorkerResult     = "FALLBCK_WORKER_RESULT"  // default /dev/termination-log
	EnvWorkerInsecure   = "FALLBCK_WORKER_INSECURE_SKIP_VERIFY"
	EnvWorkerServerCA   = "FALLBCK_WORKER_SERVER_CA" // inline PEM
	EnvWorkerPBSDirect  = "FALLBCK_WORKER_PBS"       // JSON backup.DirectOptions (direct mode)
	workerUploadTimeout = 6 * time.Hour

	// Database worker pods (db-worker mode)
	EnvWorkerDBPassword   = "FALLBCK_WORKER_DB_PASSWORD"
	EnvWorkerDBUser       = "FALLBCK_WORKER_DB_USER"  // overrides the spec's user (Secret user_key)
	EnvWorkerDBState      = "FALLBCK_WORKER_DB_STATE" // JSON dbbackup.JobState of the previous run
	EnvWorkerSpool        = "FALLBCK_WORKER_SPOOL"    // default /spool
	EnvWorkerHostname     = "FALLBCK_WORKER_HOSTNAME"
	EnvWorkerAgentVersion = "FALLBCK_WORKER_AGENT_VERSION"
)

// outcomeLogMarker prefixes the full outcome JSON in the pod log when it does not fit
// the termination message (Kubernetes caps it at 4 KiB); the agent reads it from there
const outcomeLogMarker = "FALLBCK-WORKER-OUTCOME "

// maxTerminationMessage keeps the message under the kubelet's 4096-byte cap
const maxTerminationMessage = 4000

// RunWorker is the worker-pod entrypoint: mount is at /data, credentials in the
// environment; the outcome is written to the termination-message file so the agent
// can read it from the pod status.
func RunWorker(ctx context.Context) error {
	return reportOutcome(runWorkerSafely(ctx, runWorkerFn))
}

// RunDBWorker is the database worker-pod entrypoint (db-worker mode): the dump runs
// in this pod with the engine's client tools, the spool is an emptyDir.
func RunDBWorker(ctx context.Context) error {
	return reportOutcome(runWorkerSafely(ctx, runDBWorker))
}

// reportOutcome logs the outcome (pod logs are the channel the agent can always read,
// even if the termination-message file is unwritable or the pod is killed) and writes
// the termination message. An outcome too large for the message is written slim, with
// the full JSON in the log for the agent to fetch.
func reportOutcome(outcome workerOutcome) error {
	resultPath := envDefault(EnvWorkerResult, "/dev/termination-log")
	if outcome.Error != "" {
		slog.Error("Worker failed", "phase", outcome.Phase, "error", outcome.Error)
	} else if outcome.Result != nil {
		slog.Info("Worker completed", "snapshot", outcome.Result.SnapshotID, "bytes_uploaded", outcome.Result.BytesUploaded)
	}
	data, err := json.Marshal(outcome)
	if err != nil {
		data = []byte(`{"error":"failed to encode worker outcome"}`)
	}
	if len(data) > maxTerminationMessage {
		fmt.Println(outcomeLogMarker + string(data))
		slim := outcome
		slim.DetailsInLog = true
		if slim.Result != nil {
			r := *slim.Result
			r.Details = nil
			slim.Result = &r
		}
		slim.State = nil
		if slimData, err := json.Marshal(slim); err == nil {
			data = slimData
		}
	}
	if err := os.WriteFile(resultPath, data, 0o644); err != nil {
		slog.Warn("Could not write the termination message; the agent will read the error from the pod logs", "path", resultPath, "error", err)
	}
	if outcome.Error != "" {
		return fmt.Errorf("%s", outcome.Error)
	}
	return nil
}

// runWorkerSafely turns a panic in the worker into a reported outcome. Without it a
// crash after the PBS snapshot was finalised leaves no termination message, and the
// agent can only guess from the exit code (and would retry a backup that succeeded).
func runWorkerSafely(ctx context.Context, body func(context.Context) workerOutcome) (outcome workerOutcome) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("Worker panicked", "panic", r, "stack", string(debug.Stack()))
			outcome = workerOutcome{Error: fmt.Sprintf("worker panic: %v", r), Phase: "panic"}
		}
	}()
	return body(ctx)
}

// runWorkerFn is the volume worker body; replaced in tests
var runWorkerFn = runWorker

func fail(phase string, err error) workerOutcome {
	return workerOutcome{Error: err.Error(), Phase: phase}
}

// workerSession reads the session and ticket every worker mode needs
func workerSession() (*temporal.BackupSessionInfo, string, error) {
	ticket := os.Getenv(EnvWorkerTicket)
	sessionJSON := os.Getenv(EnvWorkerSession)
	if sessionJSON == "" || ticket == "" {
		return nil, "", fmt.Errorf("worker environment is incomplete (session/ticket missing)")
	}
	var session temporal.BackupSessionInfo
	if err := json.Unmarshal([]byte(sessionJSON), &session); err != nil {
		return nil, "", fmt.Errorf("parsing %s: %w", EnvWorkerSession, err)
	}
	session.Ticket = ticket
	return &session, ticket, nil
}

// workerTransport resolves how the worker reaches PBS: directly (credentials in the
// environment) or through the server tunnel with the worker token. The returned close
// function releases the tunnel connection.
func workerTransport(ticket string) (dial func(ctx context.Context, ref pbs.SnapshotRef) (net.Conn, error), direct *backup.DirectOptions, closeFn func(), err error) {
	closeFn = func() {}
	if directJSON := os.Getenv(EnvWorkerPBSDirect); directJSON != "" {
		var d backup.DirectOptions
		if err := json.Unmarshal([]byte(directJSON), &d); err != nil {
			return nil, nil, closeFn, fmt.Errorf("parsing %s: %w", EnvWorkerPBSDirect, err)
		}
		return nil, &d, closeFn, nil
	}
	serverURL := os.Getenv(EnvWorkerServerURL)
	token := os.Getenv(EnvWorkerToken)
	if serverURL == "" || token == "" {
		return nil, nil, closeFn, fmt.Errorf("worker environment is incomplete (server URL/token missing)")
	}
	cfg := &config.AgentConfig{ServerURL: serverURL, AuthToken: token}
	if os.Getenv(EnvWorkerInsecure) == "true" {
		cfg.InsecureSkipVerify = true
	}
	if pem := os.Getenv(EnvWorkerServerCA); pem != "" {
		caPath := filepath.Join(os.TempDir(), "fallbck-server-ca.crt")
		if err := os.WriteFile(caPath, []byte(pem), 0o600); err != nil {
			return nil, nil, closeFn, fmt.Errorf("writing server CA: %w", err)
		}
		cfg.ServerCACertPath = caPath
	}
	store := runtime.NewTokenStore(cfg, "")
	conn, err := runtime.DialTunnel(cfg, store)
	if err != nil {
		return nil, nil, closeFn, err
	}
	dial = func(ctx context.Context, _ pbs.SnapshotRef) (net.Conn, error) {
		return proxy.Dial(ctx, conn, ticket)
	}
	return dial, nil, func() { _ = conn.Close() }, nil
}

func runWorker(ctx context.Context) workerOutcome {
	session, ticket, err := workerSession()
	if err != nil {
		return fail("startup", err)
	}
	dataPath := envDefault(EnvWorkerPath, "/data")
	session.BackupPaths = []string{dataPath}
	session.ExcludePaths = nil

	opts := backup.Options{Session: session, ArchiveName: spec.VolumeArchiveName}
	dial, direct, closeFn, err := workerTransport(ticket)
	if err != nil {
		return fail("connect", err)
	}
	defer closeFn()
	opts.Dial, opts.Direct = dial, direct

	runCtx, cancel := context.WithTimeout(ctx, workerUploadTimeout)
	defer cancel()
	result, err := backup.Run(runCtx, opts)
	if err != nil {
		return fail("upload", err)
	}
	return workerOutcome{Result: result}
}

func envDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
