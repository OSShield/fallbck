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
	)
	if a.Tunnel == nil {
		return nil, errors.New("agent tunnel connection is not configured")
	}

	result, err := backup.Run(ctx, backup.Options{
		Session: session,
		Workers: a.Workers,
		Dial: func(ctx context.Context, _ pbs.SnapshotRef) (net.Conn, error) {
			return proxy.Dial(ctx, a.Tunnel, session.Ticket)
		},
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
