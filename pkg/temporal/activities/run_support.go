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
	errNoKeyFetcher         = errors.New("the target is encrypted but this agent has no encryption key fetcher (agent too old?)")
	errNoKey                = errors.New("the target is encrypted but the server handed out no key for the run")
)

// isTransportConfigErr tells a misconfigured agent from a failed credentials fetch
func isTransportConfigErr(err error) bool {
	return errors.Is(err, errNoCredentialsFetcher) || errors.Is(err, errNoTunnel) || errors.Is(err, errNoKeyFetcher) || errors.Is(err, errNoKey)
}

// KeyFetcher retrieves the run's client-side encryption key with its ticket
type KeyFetcher = func(ctx context.Context, ticket string) (*backup.Encryption, error)

// pbsTransport is how one run reaches PBS: a dialer through the server tunnel, or
// direct credentials for jobs with direct_pbs. Exactly one is set. crypt is the
// run's encryption (nil for a plaintext target).
type pbsTransport struct {
	dial   func(ctx context.Context, ref pbs.SnapshotRef) (net.Conn, error)
	direct *backup.DirectOptions
	crypt  *backup.Encryption
}

// options applies the transport to upload options
func (t pbsTransport) options(o backup.Options) backup.Options {
	o.Dial, o.Direct, o.Crypt = t.dial, t.direct, t.crypt
	return o
}

// close wipes the key material after the run
func (t pbsTransport) close() { t.crypt.Wipe() }

// openTransport picks the transport for the session and, for an encrypted target,
// fetches the key. pt, when non-nil, shows what is being fetched. A missing key is a
// configuration error: the run must not fall back to plaintext.
func openTransport(ctx context.Context, session *temporal.BackupSessionInfo, tunnel grpc.ClientConnInterface,
	credentials func(ctx context.Context, ticket string) (*backup.DirectOptions, error), keys KeyFetcher, pt *phaseTracker) (pbsTransport, error) {
	var tr pbsTransport
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
		tr.direct = direct
	} else {
		if tunnel == nil {
			return pbsTransport{}, errNoTunnel
		}
		tr.dial = func(ctx context.Context, _ pbs.SnapshotRef) (net.Conn, error) {
			return proxy.Dial(ctx, tunnel, session.Ticket)
		}
	}
	if session.Encrypted {
		if keys == nil {
			return pbsTransport{}, errNoKeyFetcher
		}
		if pt != nil {
			pt.Set("fetching encryption key")
		}
		enc, err := keys(ctx, session.Ticket)
		if err != nil {
			return pbsTransport{}, err
		}
		if enc == nil {
			return pbsTransport{}, errNoKey
		}
		tr.crypt = enc
	}
	return tr, nil
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
