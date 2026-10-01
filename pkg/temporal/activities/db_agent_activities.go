package activities

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/osshield/fallbck/pkg/agent/backup"
	dbrun "github.com/osshield/fallbck/pkg/agent/dbbackup"
	"github.com/osshield/fallbck/pkg/db"
	"github.com/osshield/fallbck/pkg/dbbackup"
	"github.com/osshield/fallbck/pkg/temporal"
	"github.com/osshield/gopbs"
	"go.temporal.io/sdk/activity"
	sdktemporal "go.temporal.io/sdk/temporal"
	"google.golang.org/grpc"
)

// ErrTypeDBPrecheckFailed marks configuration/precheck failures of database backups;
// the workflow does not retry them.
const ErrTypeDBPrecheckFailed = "db_precheck_failed"

// DBAgentActivities are the database backup activities, registered by fallbck-agent
// next to its filesystem activities (agents of the retired type "database" that are
// still running their old binary poll the same activity name on their own queue)
type DBAgentActivities struct {
	// Tunnel is the agent's gRPC connection to the FallBCK server (PBS sessions)
	Tunnel grpc.ClientConnInterface
	// Workers bounds concurrent chunk uploads (0 = default)
	Workers int
	// Credentials fetches PBS connection details for jobs in direct mode
	Credentials func(ctx context.Context, ticket string) (*backup.DirectOptions, error)
	// EncryptionKey fetches the target's client-side encryption key for a run
	// (GET /api/v1/agents/encryption-key with the run's ticket)
	EncryptionKey KeyFetcher
	// DBPassword fetches the server-stored database password for a run
	DBPassword func(ctx context.Context, ticket string) (string, error)
	// RefreshTicket re-issues the run's ticket with a fresh snapshot timestamp for
	// retries; nil keeps the session's timestamp
	RefreshTicket TicketRefreshFunc
	// Config is the agent's db_backup configuration (defaults applied)
	Config   dbbackup.Config
	Hostname string
	Version  string
	// LogTail returns the agent's recent log output, attached to failures
	LogTail func() string
	// ReportProgress posts live phase updates to the server (best-effort)
	ReportProgress ProgressFunc
}

// NewDBAgentActivities creates a new DBAgentActivities instance
func NewDBAgentActivities() *DBAgentActivities {
	return &DBAgentActivities{}
}

// ExecuteDatabaseBackup dumps the job's databases into the spool directory and uploads
// the result to PBS (through the server tunnel or directly).
func (a *DBAgentActivities) ExecuteDatabaseBackup(ctx context.Context, session *temporal.BackupSessionInfo) (*temporal.BackupExecutionResult, error) {
	info := activity.GetInfo(ctx)
	if session.JobType != db.JobTypeDatabase || session.DBConfig == nil {
		return nil, sdktemporal.NewNonRetryableApplicationError("session is not a database backup", ErrTypeDBPrecheckFailed, nil)
	}
	session = sessionForAttempt(ctx, session, a.RefreshTicket)
	spec := session.DBConfig
	slog.Info("Agent activity started: ExecuteDatabaseBackup",
		"activity_id", info.ActivityID,
		"attempt", info.Attempt,
		"job_id", session.JobID,
		"engine", spec.Engine,
		"host", spec.Host,
		"databases", spec.Databases,
		"datastore", session.Datastore,
		"direct_pbs", session.DirectPBS,
	)

	rt := startRunTracking(ctx, session.Ticket, session.BackupRunID, a.ReportProgress)
	defer rt.stop()
	pt, reportPh := rt.pt, rt.report

	failed := func(err error) (*temporal.BackupExecutionResult, error) {
		return &temporal.BackupExecutionResult{Status: db.RunStatusFailed, ErrorMessage: err.Error()},
			backupFailure(ctx, err, pt, a.LogTail)
	}

	password := ""
	if session.DBPasswordOnServer {
		if a.DBPassword == nil {
			return failed(errors.New("job stores its database password on the server but the agent has no credentials fetcher"))
		}
		pw, err := a.DBPassword(ctx, session.Ticket)
		if err != nil {
			slog.Error("Failed to fetch database credentials", "error", err)
			return failed(fmt.Errorf("fetching database credentials: %w", err))
		}
		password = pw
	}

	// No phase for the credentials fetch here (nil tracker), as before
	tr, err := openTransport(ctx, session, a.Tunnel, a.Credentials, a.EncryptionKey, nil)
	if err != nil {
		if !isTransportConfigErr(err) {
			slog.Error("Failed to fetch PBS credentials for direct backup", "error", err)
		}
		return failed(err)
	}
	defer tr.close()

	upload := func(ctx context.Context, spoolDir string, blobs []gopbs.Blob) (*temporal.BackupExecutionResult, error) {
		s := *session
		s.BackupPaths = []string{spoolDir}
		s.ExcludePaths = nil
		return backup.Run(ctx, tr.options(backup.Options{
			Session:     &s,
			Workers:     a.Workers,
			ArchiveName: dbbackup.ArchiveName,
			Blobs:       blobs,
			OnPhase:     pt.Set,
		}))
	}

	result, err := dbrun.Run(ctx, dbrun.RunOptions{
		Session:      session,
		Spec:         spec,
		Password:     password,
		Config:       a.Config,
		Upload:       upload,
		Hostname:     a.Hostname,
		AgentVersion: a.Version,
		Progress: func(p dbrun.Progress) {
			pt.Set(p.Describe())
			reportPh()
		},
	})
	if err != nil {
		if dbrun.IsPrecheck(err) {
			return precheckFailed("Database backup", err, pt, a.LogTail)
		}
		if ctx.Err() != nil {
			return nil, err
		}
		slog.Error("Database backup failed", "error", err, "phase", pt.Current())
		return failed(fmt.Errorf("database backup failed: %w", err))
	}
	return result, nil
}
