package activities

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"

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
}

// NewAgentActivities creates a new AgentActivities instance
func NewAgentActivities() *AgentActivities {
	return &AgentActivities{}
}

// ExecuteFilesystemBackup performs the filesystem backup on the agent host, streaming
// into PBS through the server-side tunnel.
func (a *AgentActivities) ExecuteFilesystemBackup(ctx context.Context, session *temporal.BackupSessionInfo) (*temporal.BackupExecutionResult, error) {
	info := activity.GetInfo(ctx)
	slog.Info("Agent activity started: ExecuteFilesystemBackup",
		"activity_id", info.ActivityID,
		"job_id", session.JobID,
		"paths", session.BackupPaths,
		"datastore", session.Datastore,
		"format", session.PxarFormat,
		"direct_pbs", session.DirectPBS,
	)
	opts := backup.Options{Session: session, Workers: a.Workers}
	if session.DirectPBS {
		if a.Credentials == nil {
			return nil, errors.New("job requires direct PBS access but the agent has no credentials fetcher")
		}
		direct, err := a.Credentials(ctx, session.Ticket)
		if err != nil {
			slog.Error("Failed to fetch PBS credentials for direct backup", "error", err)
			return &temporal.BackupExecutionResult{Status: db.RunStatusFailed, ErrorMessage: err.Error()}, err
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

	result, err := backup.Run(ctx, backup.Options{
		Session: opts.Session,
		Workers: opts.Workers,
		Dial:    opts.Dial,
		Direct:  opts.Direct,
		OnProgress: func(archive string, stats pbs.UploadStats, done bool) {
			activity.RecordHeartbeat(ctx, temporal.BackupHeartbeatProgress{
				CurrentFile:   archive,
				BytesScanned:  int64(stats.Size),
				BytesUploaded: int64(stats.Size),
			})
		},
	})
	if err != nil {
		slog.Error("Agent backup execution failed", "error", err)
		return &temporal.BackupExecutionResult{
			Status:       db.RunStatusFailed,
			ErrorMessage: fmt.Sprintf("Backup execution failed: %v", err),
		}, err
	}
	return result, nil
}
