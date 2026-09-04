package activities

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"

	"github.com/osshield/fallbck/pkg/agent/backup"
	dbrun "github.com/osshield/fallbck/pkg/agent/dbbackup"
	"github.com/osshield/fallbck/pkg/db"
	"github.com/osshield/fallbck/pkg/dbbackup"
	"github.com/osshield/fallbck/pkg/proxy"
	"github.com/osshield/fallbck/pkg/temporal"
	"github.com/osshield/gopbs"
	"github.com/osshield/gopbs/pbs"
	"go.temporal.io/sdk/activity"
	sdktemporal "go.temporal.io/sdk/temporal"
	"google.golang.org/grpc"
)

// ErrTypeDBPrecheckFailed marks configuration/precheck failures of database backups;
// the workflow does not retry them.
const ErrTypeDBPrecheckFailed = "db_precheck_failed"

// DBAgentActivities are the activities of fallbck-db-agent
type DBAgentActivities struct {
	// Tunnel is the agent's gRPC connection to the FallBCK server (PBS sessions)
	Tunnel grpc.ClientConnInterface
	// Workers bounds concurrent chunk uploads (0 = default)
	Workers int
	// Credentials fetches PBS connection details for jobs in direct mode
	Credentials func(ctx context.Context, ticket string) (*backup.DirectOptions, error)
	// DBPassword fetches the server-stored database password for a run
	DBPassword func(ctx context.Context, ticket string) (string, error)
	// Config is the agent's db_backup configuration (defaults applied)
	Config   dbbackup.Config
	Hostname string
	Version  string
	// LogTail returns the agent's recent log output, attached to failures
	LogTail func() string
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
	spec := session.DBConfig
	slog.Info("Agent activity started: ExecuteDatabaseBackup",
		"activity_id", info.ActivityID,
		"job_id", session.JobID,
		"engine", spec.Engine,
		"host", spec.Host,
		"databases", spec.Databases,
		"datastore", session.Datastore,
		"direct_pbs", session.DirectPBS,
	)

	pt := newPhaseTracker()
	stopHeartbeats := startHeartbeats(ctx, pt)
	defer stopHeartbeats()

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

	var dial func(ctx context.Context, ref pbs.SnapshotRef) (net.Conn, error)
	var direct *backup.DirectOptions
	if session.DirectPBS {
		if a.Credentials == nil {
			return failed(errors.New("job requires direct PBS access but the agent has no credentials fetcher"))
		}
		d, err := a.Credentials(ctx, session.Ticket)
		if err != nil {
			slog.Error("Failed to fetch PBS credentials for direct backup", "error", err)
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

	upload := func(ctx context.Context, spoolDir string, blobs []gopbs.Blob) (*temporal.BackupExecutionResult, error) {
		s := *session
		s.BackupPaths = []string{spoolDir}
		s.ExcludePaths = nil
		return backup.Run(ctx, backup.Options{
			Session:     &s,
			Workers:     a.Workers,
			Dial:        dial,
			Direct:      direct,
			ArchiveName: dbbackup.ArchiveName,
			Blobs:       blobs,
			OnPhase:     pt.Set,
		})
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
		},
	})
	if err != nil {
		var pe *dbrun.PrecheckError
		if errors.As(err, &pe) {
			slog.Error("Database backup precheck failed", "error", err)
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
		slog.Error("Database backup failed", "error", err, "phase", pt.Current())
		return failed(fmt.Errorf("database backup failed: %w", err))
	}
	return result, nil
}
