package activities

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/agent/backup"
	"github.com/osshield/fallbck/pkg/db"
	"github.com/osshield/fallbck/pkg/proxy"
	"github.com/osshield/fallbck/pkg/temporal"
	"github.com/osshield/gopbs/pbs"
	sdktemporal "go.temporal.io/sdk/temporal"
	"google.golang.org/grpc"
)

// Shared run plumbing of the agent-side backup activities (filesystem, Proxmox VE,
// Docker, database, kubernetes resources): how the run reaches PBS, the phase tracker
// with its heartbeat and progress tickers, and the non-retryable precheck failure.
// Every activity keeps its own mapping of transport errors, because they differ on
// purpose (plain error vs. failure details); only the identical parts live here.

// Transport configuration errors: the agent cannot reach PBS at all for this run
var (
	errNoCredentialsFetcher = errors.New("job requires direct PBS access but the agent has no credentials fetcher")
	errNoTunnel             = errors.New("agent tunnel connection is not configured")
)

// isTransportConfigErr tells a misconfigured agent from a failed credentials fetch
func isTransportConfigErr(err error) bool {
	return errors.Is(err, errNoCredentialsFetcher) || errors.Is(err, errNoTunnel)
}

// pbsTransport is how one run reaches PBS: a dialer through the server tunnel, or
// direct credentials for jobs with direct_pbs. Exactly one is set.
type pbsTransport struct {
	dial   func(ctx context.Context, ref pbs.SnapshotRef) (net.Conn, error)
	direct *backup.DirectOptions
}

// openTransport picks the transport for the session. pt, when non-nil, shows
// "fetching PBS credentials" while direct credentials are requested.
func openTransport(ctx context.Context, session *temporal.BackupSessionInfo, tunnel grpc.ClientConnInterface,
	credentials func(ctx context.Context, ticket string) (*backup.DirectOptions, error), pt *phaseTracker) (pbsTransport, error) {
	if session.DirectPBS {
		if credentials == nil {
			return pbsTransport{}, errNoCredentialsFetcher
		}
		if pt != nil {
			pt.Set("fetching PBS credentials")
		}
		direct, err := credentials(ctx, session.Ticket)
		if err != nil {
			return pbsTransport{}, err
		}
		return pbsTransport{direct: direct}, nil
	}
	if tunnel == nil {
		return pbsTransport{}, errNoTunnel
	}
	return pbsTransport{dial: func(ctx context.Context, _ pbs.SnapshotRef) (net.Conn, error) {
		return proxy.Dial(ctx, tunnel, session.Ticket)
	}}, nil
}

// runTracking is the phase tracker of one activity run with its tickers
type runTracking struct {
	pt *phaseTracker
	// report posts the current phase to the server (best effort)
	report func()
	// stop ends the progress ticker, then the heartbeats
	stop func()
}

// startRunTracking heartbeats on a timer for the whole activity (scanning and session
// setup produce no upload progress and must not trip the heartbeat timeout) and
// reports the phase to the server every five seconds
func startRunTracking(ctx context.Context, ticket string, runID uuid.UUID, progress ProgressFunc) *runTracking {
	pt := newPhaseTracker()
	stopHeartbeats := startHeartbeats(ctx, pt)
	report := func() { reportPhase(progress, ctx, ticket, runID, pt.Current()) }
	stopProgress := startProgress(ctx, pt, 5*time.Second, func(string) { report() })
	return &runTracking{pt: pt, report: report, stop: func() {
		stopProgress()
		stopHeartbeats()
	}}
}

// precheckFailed maps a precheck error (bad job configuration, wrong host, missing
// tools) to a failed result and a non-retryable error carrying the phase and log tail
func precheckFailed(what string, err error, pt *phaseTracker, logTail func() string) (*temporal.BackupExecutionResult, error) {
	slog.Error(what+" precheck failed", "error", err)
	tail := ""
	if logTail != nil {
		tail = logTail()
	}
	return &temporal.BackupExecutionResult{Status: db.RunStatusFailed, ErrorMessage: err.Error()},
		sdktemporal.NewNonRetryableApplicationError(err.Error(), ErrTypeDBPrecheckFailed, err,
			temporal.BackupFailureDetails{Phase: pt.Current(), LogTail: tail})
}
