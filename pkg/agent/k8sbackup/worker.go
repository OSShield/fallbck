package k8sbackup

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
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
)

// RunWorker is the worker-pod entrypoint: mount is at /data, credentials in the
// environment; the outcome is written to the termination-message file so the agent
// can read it from the pod status.
func RunWorker(ctx context.Context) error {
	resultPath := envDefault(EnvWorkerResult, "/dev/termination-log")
	outcome := runWorker(ctx)
	data, err := json.Marshal(outcome)
	if err != nil {
		data = []byte(`{"error":"failed to encode worker outcome"}`)
	}
	if err := os.WriteFile(resultPath, data, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "writing result to %s: %v\n", resultPath, err)
	}
	if outcome.Error != "" {
		return fmt.Errorf("%s", outcome.Error)
	}
	return nil
}

func runWorker(ctx context.Context) workerOutcome {
	fail := func(phase string, err error) workerOutcome {
		return workerOutcome{Error: err.Error(), Phase: phase}
	}

	serverURL := os.Getenv(EnvWorkerServerURL)
	token := os.Getenv(EnvWorkerToken)
	ticket := os.Getenv(EnvWorkerTicket)
	sessionJSON := os.Getenv(EnvWorkerSession)
	if sessionJSON == "" || ticket == "" {
		return fail("startup", fmt.Errorf("worker environment is incomplete (session/ticket missing)"))
	}
	var session temporal.BackupSessionInfo
	if err := json.Unmarshal([]byte(sessionJSON), &session); err != nil {
		return fail("startup", fmt.Errorf("parsing %s: %w", EnvWorkerSession, err))
	}
	dataPath := envDefault(EnvWorkerPath, "/data")
	session.BackupPaths = []string{dataPath}
	session.ExcludePaths = nil
	session.Ticket = ticket

	opts := backup.Options{Session: &session, ArchiveName: spec.VolumeArchiveName}

	if directJSON := os.Getenv(EnvWorkerPBSDirect); directJSON != "" {
		var direct backup.DirectOptions
		if err := json.Unmarshal([]byte(directJSON), &direct); err != nil {
			return fail("startup", fmt.Errorf("parsing %s: %w", EnvWorkerPBSDirect, err))
		}
		opts.Direct = &direct
	} else {
		if serverURL == "" || token == "" {
			return fail("startup", fmt.Errorf("worker environment is incomplete (server URL/token missing)"))
		}
		cfg := &config.AgentConfig{ServerURL: serverURL, AuthToken: token}
		if os.Getenv(EnvWorkerInsecure) == "true" {
			cfg.InsecureSkipVerify = true
		}
		if pem := os.Getenv(EnvWorkerServerCA); pem != "" {
			caPath := filepath.Join(os.TempDir(), "fallbck-server-ca.crt")
			if err := os.WriteFile(caPath, []byte(pem), 0o600); err != nil {
				return fail("startup", fmt.Errorf("writing server CA: %w", err))
			}
			cfg.ServerCACertPath = caPath
		}
		store := runtime.NewTokenStore(cfg, "")
		conn, err := runtime.DialTunnel(cfg, store)
		if err != nil {
			return fail("connect", err)
		}
		defer conn.Close()
		opts.Dial = func(ctx context.Context, _ pbs.SnapshotRef) (net.Conn, error) {
			return proxy.Dial(ctx, conn, ticket)
		}
	}

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
