package activities

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/osshield/fallbck/pkg/agent/backup"
	dbrun "github.com/osshield/fallbck/pkg/agent/dbbackup"
	pverun "github.com/osshield/fallbck/pkg/agent/pvebackup"
	"github.com/osshield/fallbck/pkg/agent/vss"
	"github.com/osshield/fallbck/pkg/db"
	"github.com/osshield/fallbck/pkg/proxy"
	pvespec "github.com/osshield/fallbck/pkg/pvebackup"
	"github.com/osshield/fallbck/pkg/temporal"
	"github.com/osshield/gopbs"
	"github.com/osshield/gopbs/pbs"
	"go.temporal.io/sdk/activity"
	sdktemporal "go.temporal.io/sdk/temporal"
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
	// SpoolDir stages collected data for Proxmox VE host backups (<data dir>/spool)
	SpoolDir string
	// CacheDir holds the per-group metadata caches for change detection
	// (<data dir>/pxar-cache); empty disables change detection
	CacheDir string
	// VSSDir enables Volume Shadow Copies on Windows: paths are read through
	// shadow copies linked under this directory; empty reads the live filesystem
	VSSDir   string
	Hostname string
	Version  string
}

// groupCacheDir returns the change-detection cache directory of a session's group
func (a *AgentActivities) groupCacheDir(session *temporal.BackupSessionInfo) string {
	if a.CacheDir == "" {
		return ""
	}
	return backup.CacheGroupDir(a.CacheDir, session.BackupType, session.BackupID)
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

	opts := backup.Options{Session: session, Workers: a.Workers, CacheDir: a.groupCacheDir(session), OnPhase: func(p string) { pt.Set(p); reportPh() }}
	if a.VSSDir != "" && vss.Supported() {
		paths, err := db.ValidateLocalBackupPaths(session.BackupPaths)
		if err != nil {
			return &temporal.BackupExecutionResult{Status: db.RunStatusFailed, ErrorMessage: err.Error()},
				sdktemporal.NewNonRetryableApplicationError(err.Error(), ErrTypeDBPrecheckFailed, err)
		}
		pt.Set("creating volume shadow copies")
		reportPh()
		mapped, snaps, err := vss.Take(ctx, a.VSSDir, paths)
		if err != nil {
			slog.Error("Volume shadow copy failed", "error", err)
			return &temporal.BackupExecutionResult{Status: db.RunStatusFailed, ErrorMessage: err.Error()},
				backupFailure(ctx, fmt.Errorf("volume shadow copy: %w", err), pt, a.LogTail)
		}
		defer snaps.Release()
		s := *session
		s.BackupPaths = paths
		opts.Session = &s
		opts.ReadPaths = mapped
	}
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

// ExecutePVEBackup backs up the Proxmox VE host this agent runs on: the collected
// inventory (/etc/pve copy, package lists, storage/network/disk definitions, restore
// runbook), /etc, /root and the job's data paths go into one pve.pxar archive.
func (a *AgentActivities) ExecutePVEBackup(ctx context.Context, session *temporal.BackupSessionInfo) (*temporal.BackupExecutionResult, error) {
	info := activity.GetInfo(ctx)
	if session.JobType != db.JobTypePVE {
		return nil, sdktemporal.NewNonRetryableApplicationError("session is not a Proxmox VE backup", ErrTypeDBPrecheckFailed, nil)
	}
	session = sessionForAttempt(ctx, session, a.RefreshTicket)
	slog.Info("Agent activity started: ExecutePVEBackup", "activity_id", info.ActivityID, "attempt", info.Attempt,
		"job_id", session.JobID, "datastore", session.Datastore, "direct_pbs", session.DirectPBS)

	pt := newPhaseTracker()
	stopHeartbeats := startHeartbeats(ctx, pt)
	defer stopHeartbeats()
	reportPh := func() { reportPhase(a.ReportProgress, ctx, session.Ticket, session.BackupRunID, pt.Current()) }
	stopProgress := startProgress(ctx, pt, 5*time.Second, func(string) { reportPh() })
	defer stopProgress()

	failed := func(err error) (*temporal.BackupExecutionResult, error) {
		slog.Error("Proxmox VE backup failed", "error", err, "phase", pt.Current())
		return &temporal.BackupExecutionResult{Status: db.RunStatusFailed, ErrorMessage: err.Error()},
			backupFailure(ctx, err, pt, a.LogTail)
	}

	var dial func(ctx context.Context, ref pbs.SnapshotRef) (net.Conn, error)
	var direct *backup.DirectOptions
	if session.DirectPBS {
		if a.Credentials == nil {
			return failed(errors.New("job requires direct PBS access but the agent has no credentials fetcher"))
		}
		pt.Set("fetching PBS credentials")
		d, err := a.Credentials(ctx, session.Ticket)
		if err != nil {
			return failed(err)
		}
		direct = d
	} else {
		if a.Tunnel == nil {
			return failed(errors.New("agent tunnel connection is not configured"))
		}
		dial = func(ctx context.Context, _ pbs.SnapshotRef) (net.Conn, error) {
			return proxy.Dial(ctx, a.Tunnel, session.Ticket)
		}
	}

	upload := func(ctx context.Context, paths, excludes []string, blobs []gopbs.Blob) (*temporal.BackupExecutionResult, error) {
		s := *session
		s.BackupPaths = paths
		s.ExcludePaths = excludes
		return backup.Run(ctx, backup.Options{
			Session: &s, Workers: a.Workers, Dial: dial, Direct: direct,
			ArchiveName: pvespec.ArchiveName, Blobs: blobs, CacheDir: a.groupCacheDir(session),
			OnPhase: func(p string) { pt.Set(p); reportPh() },
		})
	}
	result, err := pverun.Run(ctx, pverun.RunOptions{
		Session: session, Spec: session.PVEConfig, SpoolDir: a.SpoolDir, Upload: upload,
		Hostname: a.Hostname, AgentVersion: a.Version,
		Progress: func(p string) { pt.Set(p); reportPh() },
	})
	if err != nil {
		if dbrun.IsPrecheck(err) {
			slog.Error("Proxmox VE backup precheck failed", "error", err)
			tail := ""
			if a.LogTail != nil {
				tail = a.LogTail()
			}
			return &temporal.BackupExecutionResult{Status: db.RunStatusFailed, ErrorMessage: err.Error()},
				sdktemporal.NewNonRetryableApplicationError(err.Error(), ErrTypeDBPrecheckFailed, err,
					temporal.BackupFailureDetails{Phase: pt.Current(), LogTail: tail})
		}
		if ctx.Err() != nil {
			return nil, err
		}
		return failed(err)
	}
	return result, nil
}
