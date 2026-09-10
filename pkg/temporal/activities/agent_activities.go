package activities

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/osshield/fallbck/pkg/agent/backup"
	"github.com/osshield/fallbck/pkg/db"
	"github.com/osshield/fallbck/pkg/proxy"
	"github.com/osshield/fallbck/pkg/temporal"
	"github.com/osshield/gopbs/pbs"
	"go.temporal.io/sdk/activity"
	"google.golang.org/grpc"
)

// AgentActivities provides activities executed on the client backup agent host
type AgentActivities struct {
	// Tunnel is the agent's gRPC connection to the FallBCK server (carrying its bearer
	// token); PBS backup sessions are opened through it.
	Tunnel grpc.ClientConnInterface
	// Workers bounds concurrent chunk uploads (0 = default)
	Workers int
	// Credentials fetches PBS connection details for jobs in direct mode
	// (GET /api/v1/agents/pbs-credentials with the run's ticket)
	Credentials func(ctx context.Context, ticket string) (*backup.DirectOptions, error)
	// RefreshTicket re-issues the run's ticket with a fresh snapshot timestamp for
	// retries (POST /api/v1/agents/ticket/refresh); nil keeps the session's timestamp
	RefreshTicket TicketRefreshFunc
	// LogTail returns the agent's recent log output, attached to failures
	LogTail func() string
	// ReportProgress posts live phase updates to the server (best-effort)
	ReportProgress ProgressFunc
}

// NewAgentActivities creates a new AgentActivities instance
func NewAgentActivities() *AgentActivities {
	return &AgentActivities{}
}

// ExecuteFilesystemBackup performs the filesystem backup on the agent host, streaming
// into PBS through the server-side tunnel.
func (a *AgentActivities) ExecuteFilesystemBackup(ctx context.Context, session *temporal.BackupSessionInfo) (*temporal.BackupExecutionResult, error) {
	info := activity.GetInfo(ctx)
	session = sessionForAttempt(ctx, session, a.RefreshTicket)
	slog.Info("Agent activity started: ExecuteFilesystemBackup",
		"activity_id", info.ActivityID,
		"attempt", info.Attempt,
		"job_id", session.JobID,
		"paths", session.BackupPaths,
		"datastore", session.Datastore,
		"format", session.PxarFormat,
		"direct_pbs", session.DirectPBS,
	)
	// Heartbeat on a timer for the whole activity: scanning and session setup produce
	// no upload progress, and must not trip the 60s heartbeat timeout.
	pt := newPhaseTracker()
	stopHeartbeats := startHeartbeats(ctx, pt)
	defer stopHeartbeats()
	reportPh := func() { reportPhase(a.ReportProgress, ctx, session.Ticket, session.BackupRunID, pt.Current()) }
	stopProgress := startProgress(ctx, pt, 5*time.Second, func(string) { reportPh() })
	defer stopProgress()

	opts := backup.Options{Session: session, Workers: a.Workers, OnPhase: func(p string) { pt.Set(p); reportPh() }}
	if session.DirectPBS {
		if a.Credentials == nil {
			return nil, errors.New("job requires direct PBS access but the agent has no credentials fetcher")
		}
		pt.Set("fetching PBS credentials")
		direct, err := a.Credentials(ctx, session.Ticket)
		if err != nil {
			slog.Error("Failed to fetch PBS credentials for direct backup", "error", err)
			return &temporal.BackupExecutionResult{Status: db.RunStatusFailed, ErrorMessage: err.Error()},
				backupFailure(ctx, err, pt, a.LogTail)
		}
		opts.Direct = direct
	} else {
		if a.Tunnel == nil {
			return nil, errors.New("agent tunnel connection is not configured")
		}
		opts.Dial = func(ctx context.Context, _ pbs.SnapshotRef) (net.Conn, error) {
			return proxy.Dial(ctx, a.Tunnel, session.Ticket)
		}
	}

	result, err := backup.Run(ctx, opts)
	if err != nil {
		slog.Error("Agent backup execution failed", "error", err, "phase", pt.Current())
		return &temporal.BackupExecutionResult{
				Status:       db.RunStatusFailed,
				ErrorMessage: fmt.Sprintf("Backup execution failed: %v", err),
			},
			backupFailure(ctx, err, pt, a.LogTail)
	}
	return result, nil
}
