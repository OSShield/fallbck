package activities

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"

	"github.com/osshield/fallbck/pkg/agent/backup"
	dbrun "github.com/osshield/fallbck/pkg/agent/dbbackup"
	dockerrun "github.com/osshield/fallbck/pkg/agent/dockerbackup"
	m365run "github.com/osshield/fallbck/pkg/agent/m365"
	pverun "github.com/osshield/fallbck/pkg/agent/pvebackup"
	"github.com/osshield/fallbck/pkg/agent/vss"
	"github.com/osshield/fallbck/pkg/db"
	dockerspec "github.com/osshield/fallbck/pkg/dockerbackup"
	"github.com/osshield/fallbck/pkg/m365"
	pvespec "github.com/osshield/fallbck/pkg/pvebackup"
	"github.com/osshield/fallbck/pkg/rundetail"
	"github.com/osshield/fallbck/pkg/temporal"
	"github.com/osshield/gopbs"
	"github.com/osshield/gopbs/scan"
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
	// EncryptionKey fetches the target's client-side encryption key for a run
	// (GET /api/v1/agents/encryption-key with the run's ticket)
	EncryptionKey KeyFetcher
	// RefreshTicket re-issues the run's ticket with a fresh snapshot timestamp for
	// retries (POST /api/v1/agents/ticket/refresh); nil keeps the session's timestamp
	RefreshTicket TicketRefreshFunc
	// LogTail returns the agent's recent log output, attached to failures
	LogTail func() string
	// ReportProgress posts live phase updates to the server (best-effort)
	ReportProgress ProgressFunc
	// SpoolDir stages collected data for Proxmox VE and Docker host backups (<data dir>/spool)
	SpoolDir string
	// Docker is the agent's docker_backup settings block (socket, volume access, helper image)
	Docker dockerspec.Config
	// M365Credentials fetches the tenant credentials of a Microsoft 365 job
	// (GET /api/v1/agents/m365-credentials with the run's ticket)
	M365Credentials func(ctx context.Context, ticket string) (*m365.Credentials, error)
	// SubTicket mints the ticket of one unit snapshot of a run (POST
	// /api/v1/agents/sub-ticket): the unit's group must extend the run's group
	SubTicket func(ctx context.Context, sessionTicket, group string) (ticket string, backupTime int64, err error)
	// M365StateDir holds the per-job unit indexes of Microsoft 365 jobs (<data dir>/m365-state)
	M365StateDir string
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
	rt := startRunTracking(ctx, session.Ticket, session.BackupRunID, a.ReportProgress)
	defer rt.stop()
	pt, reportPh := rt.pt, rt.report

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
	tr, err := openTransport(ctx, session, a.Tunnel, a.Credentials, a.EncryptionKey, pt)
	if err != nil {
		if isTransportConfigErr(err) {
			// A misconfigured agent: plain error, as before (no phase or log tail to add)
			return nil, err
		}
		slog.Error("Failed to fetch PBS credentials for direct backup", "error", err)
		return &temporal.BackupExecutionResult{Status: db.RunStatusFailed, ErrorMessage: err.Error()},
			backupFailure(ctx, err, pt, a.LogTail)
	}
	defer tr.close()
	opts = tr.options(opts)

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

	rt := startRunTracking(ctx, session.Ticket, session.BackupRunID, a.ReportProgress)
	defer rt.stop()
	pt, reportPh := rt.pt, rt.report

	failed := func(err error) (*temporal.BackupExecutionResult, error) {
		slog.Error("Proxmox VE backup failed", "error", err, "phase", pt.Current())
		return &temporal.BackupExecutionResult{Status: db.RunStatusFailed, ErrorMessage: err.Error()},
			backupFailure(ctx, err, pt, a.LogTail)
	}

	tr, err := openTransport(ctx, session, a.Tunnel, a.Credentials, a.EncryptionKey, pt)
	if err != nil {
		return failed(err)
	}
	defer tr.close()

	upload := func(ctx context.Context, paths, excludes []string, blobs []gopbs.Blob) (*temporal.BackupExecutionResult, error) {
		s := *session
		s.BackupPaths = paths
		s.ExcludePaths = excludes
		return backup.Run(ctx, tr.options(backup.Options{
			Session: &s, Workers: a.Workers,
			ArchiveName: pvespec.ArchiveName, Blobs: blobs, CacheDir: a.groupCacheDir(session),
			OnPhase: func(p string) { pt.Set(p); reportPh() },
		}))
	}
	result, err := pverun.Run(ctx, pverun.RunOptions{
		Session: session, Spec: session.PVEConfig, SpoolDir: a.SpoolDir, Upload: upload,
		Hostname: a.Hostname, AgentVersion: a.Version,
		Progress: func(p string) { pt.Set(p); reportPh() },
	})
	if err != nil {
		if dbrun.IsPrecheck(err) {
			return precheckFailed("Proxmox VE backup", err, pt, a.LogTail)
		}
		if ctx.Err() != nil {
			return nil, err
		}
		return failed(err)
	}
	return result, nil
}

// ExecuteDockerBackup backs up the Docker host this agent runs on: container,
// network, volume and image definitions, compose files and the daemon configuration
// (collect/) plus every named volume (vol-<name>) go into one docker.pxar archive.
func (a *AgentActivities) ExecuteDockerBackup(ctx context.Context, session *temporal.BackupSessionInfo) (*temporal.BackupExecutionResult, error) {
	info := activity.GetInfo(ctx)
	if session.JobType != db.JobTypeDocker {
		return nil, sdktemporal.NewNonRetryableApplicationError("session is not a Docker host backup", ErrTypeDBPrecheckFailed, nil)
	}
	session = sessionForAttempt(ctx, session, a.RefreshTicket)
	slog.Info("Agent activity started: ExecuteDockerBackup", "activity_id", info.ActivityID, "attempt", info.Attempt,
		"job_id", session.JobID, "datastore", session.Datastore, "direct_pbs", session.DirectPBS)

	rt := startRunTracking(ctx, session.Ticket, session.BackupRunID, a.ReportProgress)
	defer rt.stop()
	pt, reportPh := rt.pt, rt.report

	failed := func(err error) (*temporal.BackupExecutionResult, error) {
		slog.Error("Docker host backup failed", "error", err, "phase", pt.Current())
		return &temporal.BackupExecutionResult{Status: db.RunStatusFailed, ErrorMessage: err.Error()},
			backupFailure(ctx, err, pt, a.LogTail)
	}

	tr, err := openTransport(ctx, session, a.Tunnel, a.Credentials, a.EncryptionKey, pt)
	if err != nil {
		return failed(err)
	}
	defer tr.close()

	upload := func(ctx context.Context, paths, readPaths, excludes []string, blobs []gopbs.Blob) (*temporal.BackupExecutionResult, error) {
		s := *session
		s.BackupPaths = paths
		s.ExcludePaths = excludes
		return backup.Run(ctx, tr.options(backup.Options{
			Session: &s, Workers: a.Workers, ReadPaths: readPaths,
			ArchiveName: dockerspec.ArchiveName, Blobs: blobs, CacheDir: a.groupCacheDir(session),
			OnPhase: func(p string) { pt.Set(p); reportPh() },
		}))
	}
	result, err := dockerrun.Run(ctx, dockerrun.RunOptions{
		Session: session, Spec: session.DockerConfig, Settings: a.Docker, SpoolDir: a.SpoolDir, Upload: upload,
		Hostname: a.Hostname, AgentVersion: a.Version,
		Progress: func(p string) { pt.Set(p); reportPh() },
	})
	if err != nil {
		if dbrun.IsPrecheck(err) {
			return precheckFailed("Docker host backup", err, pt, a.LogTail)
		}
		return failed(err)
	}
	return result, nil
}

// ExecuteM365Backup backs up a Microsoft 365 tenant: one snapshot per user, site and
// team (each with its own sub-ticket and PBS session) plus the directory snapshot in
// the job's own group, which carries the run manifest.
func (a *AgentActivities) ExecuteM365Backup(ctx context.Context, session *temporal.BackupSessionInfo) (*temporal.BackupExecutionResult, error) {
	info := activity.GetInfo(ctx)
	if session.JobType != db.JobTypeM365 || session.M365Config == nil {
		return nil, sdktemporal.NewNonRetryableApplicationError("session is not a Microsoft 365 backup", ErrTypeDBPrecheckFailed, nil)
	}
	session = sessionForAttempt(ctx, session, a.RefreshTicket)
	slog.Info("Agent activity started: ExecuteM365Backup", "activity_id", info.ActivityID, "attempt", info.Attempt,
		"job_id", session.JobID, "group", session.BackupID, "datastore", session.Datastore, "direct_pbs", session.DirectPBS)
	if a.M365Credentials == nil || a.SubTicket == nil {
		return nil, errors.New("this agent has no Microsoft 365 credential or sub-ticket fetcher (agent too old?)")
	}

	rt := startRunTracking(ctx, session.Ticket, session.BackupRunID, a.ReportProgress)
	defer rt.stop()
	pt, reportPh := rt.pt, rt.report

	failed := func(result *temporal.BackupExecutionResult, err error) (*temporal.BackupExecutionResult, error) {
		slog.Error("Microsoft 365 backup failed", "error", err, "phase", pt.Current())
		if result == nil {
			result = &temporal.BackupExecutionResult{}
		}
		result.Status, result.ErrorMessage = db.RunStatusFailed, err.Error()
		return result, backupFailure(ctx, err, pt, a.LogTail)
	}

	pt.Set("fetching tenant credentials")
	reportPh()
	creds, err := a.M365Credentials(ctx, session.Ticket)
	if err != nil {
		return failed(nil, fmt.Errorf("fetching tenant credentials: %w", err))
	}

	upload := func(ctx context.Context, unit *m365run.Unit, tree *scan.Node, blobs []gopbs.Blob) (*temporal.BackupExecutionResult, error) {
		us := *session
		us.BackupPaths, us.ExcludePaths = nil, nil
		if unit.Group != session.BackupID {
			ticket, backupTime, err := a.SubTicket(ctx, session.Ticket, unit.Group)
			if err != nil {
				return nil, fmt.Errorf("minting the snapshot ticket: %w", err)
			}
			us.Ticket, us.BackupID, us.BackupTime = ticket, unit.Group, backupTime
		}
		tr, err := openTransport(ctx, &us, a.Tunnel, a.Credentials, a.EncryptionKey, nil)
		if err != nil {
			return nil, err
		}
		defer tr.close()
		return backup.Run(ctx, tr.options(backup.Options{
			Session: &us, Workers: a.Workers, Tree: tree, ArchiveName: unit.Archive, Blobs: blobs,
			CacheDir: a.groupCacheDir(&us),
			OnPhase:  func(p string) { pt.Set(unit.Name + ": " + p); reportPh() },
		}))
	}
	result, err := m365run.Run(ctx, m365run.RunOptions{
		Session: session, Spec: session.M365Config, Credentials: *creds,
		StateDir: filepath.Join(a.M365StateDir, session.JobID.String()), SpoolDir: a.SpoolDir,
		Upload:   upload,
		Progress: func(p string) { pt.Set(p); reportPh() },
		Items: func(items map[string]rundetail.ProgressItem) {
			reportItems(a.ReportProgress, ctx, session.Ticket, session.BackupRunID, items)
		},
		Hostname: a.Hostname, Version: a.Version,
	})
	if err != nil {
		if dbrun.IsPrecheck(err) {
			return precheckFailed("Microsoft 365 backup", err, pt, a.LogTail)
		}
		if isTransportConfigErr(err) {
			return nil, err
		}
		return failed(result, err)
	}
	return result, nil
}
