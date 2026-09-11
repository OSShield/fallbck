package activities

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	dbrun "github.com/osshield/fallbck/pkg/agent/dbbackup"
	k8sagent "github.com/osshield/fallbck/pkg/agent/k8sbackup"
	"github.com/osshield/fallbck/pkg/db"
	"github.com/osshield/fallbck/pkg/dbbackup"
	"github.com/osshield/fallbck/pkg/temporal"
	corev1 "k8s.io/api/core/v1"

	"go.temporal.io/sdk/activity"
	sdktemporal "go.temporal.io/sdk/temporal"
)

// dbWorkerTimeout bounds one dump pod; the workflow's StartToClose for agent
// activities is 6h, leave room for pod creation and cleanup
const dbWorkerTimeout = 5*time.Hour + 40*time.Minute

// dbProbeTimeout bounds the server-version probe that picks the dump image
const dbProbeTimeout = 20 * time.Second

// ExecuteKubernetesDatabaseBackup runs a database job assigned to this kubernetes
// agent: the database is dumped from a short-lived pod in its namespace (engine image
// with the client tools, this agent's binary injected) and uploaded to PBS from there.
func (a *K8sAgentActivities) ExecuteKubernetesDatabaseBackup(ctx context.Context, session *temporal.BackupSessionInfo) (*temporal.BackupExecutionResult, error) {
	info := activity.GetInfo(ctx)
	if session.JobType != db.JobTypeDatabase || session.DBConfig == nil || session.DBConfig.Kubernetes == nil {
		return nil, sdktemporal.NewNonRetryableApplicationError("session is not a kubernetes database backup", ErrTypeDBPrecheckFailed, nil)
	}
	session = sessionForAttempt(ctx, session, a.RefreshTicket)
	spec := session.DBConfig.Clone()
	if err := spec.Validate(); err != nil {
		return nil, sdktemporal.NewNonRetryableApplicationError(err.Error(), ErrTypeDBPrecheckFailed, err)
	}
	target := spec.Kubernetes
	slog.Info("Agent activity started: ExecuteKubernetesDatabaseBackup",
		"activity_id", info.ActivityID, "attempt", info.Attempt, "job_id", session.JobID,
		"engine", spec.Engine, "namespace", target.Namespace, "host", spec.EffectiveHost(),
		"databases", spec.Databases, "datastore", session.Datastore, "direct_pbs", session.DirectPBS)

	pt := newPhaseTracker()
	stopHeartbeats := startHeartbeats(ctx, pt)
	defer stopHeartbeats()
	reportPh := func() { reportPhase(a.ReportProgress, ctx, session.Ticket, session.BackupRunID, pt.Current()) }
	stopProgress := startProgress(ctx, pt, 5*time.Second, func(string) { reportPh() })
	defer stopProgress()
	untrack := a.Runs.track(session.BackupRunID.String())
	defer untrack()

	failed := func(err error) (*temporal.BackupExecutionResult, error) {
		slog.Error("Kubernetes database backup failed", "error", err, "phase", pt.Current())
		return &temporal.BackupExecutionResult{Status: db.RunStatusFailed, ErrorMessage: err.Error()},
			backupFailure(ctx, err, pt, a.LogTail)
	}
	precheckFailed := func(err error) (*temporal.BackupExecutionResult, error) {
		slog.Error("Kubernetes database backup precheck failed", "error", err)
		tail := ""
		if a.LogTail != nil {
			tail = a.LogTail()
		}
		return &temporal.BackupExecutionResult{Status: db.RunStatusFailed, ErrorMessage: err.Error()},
			sdktemporal.NewNonRetryableApplicationError(err.Error(), ErrTypeDBPrecheckFailed, err,
				temporal.BackupFailureDetails{Phase: pt.Current(), LogTail: tail})
	}

	// Credentials: the job's stored password wins, then the Secret in the namespace
	pt.Set("resolving credentials")
	password, user := "", ""
	switch {
	case session.DBPasswordOnServer:
		if a.DBPassword == nil {
			return failed(errors.New("job stores its database password on the server but the agent has no credentials fetcher"))
		}
		pw, err := a.DBPassword(ctx, session.Ticket)
		if err != nil {
			return failed(fmt.Errorf("fetching database credentials: %w", err))
		}
		password = pw
	case target.SecretName != "":
		pw, u, err := k8sagent.ReadSecretCredentials(ctx, a.Clients.Core, target.Namespace, target.SecretName, target.PasswordKey, target.UserKey)
		if err != nil {
			return precheckFailed(err)
		}
		password, user = pw, u
	}
	if user != "" {
		spec.User = user
	}

	// Image: the job override, else the per-engine template with the server's major
	// version (probed from here; MongoDB has no driver and uses the template default)
	pt.Set("selecting dump image")
	image := target.ToolsImage
	if image == "" {
		image = a.dbWorkerImage(ctx, spec, password)
	}

	prev, err := k8sagent.LoadDBState(ctx, a.Clients.Core, a.AgentNamespace, a.StateSecretName, session.JobID.String())
	if err != nil {
		slog.Warn("Ignoring unreadable job state", "error", err)
		prev = nil
	}

	pt.Set("preparing dump pod")
	env, err := a.workerEnv(ctx, session, session.BackupID, session.Ticket, session.BackupTime)
	if err != nil {
		return failed(err)
	}
	env = append(env,
		corev1.EnvVar{Name: k8sagent.EnvWorkerHostname, Value: a.Config.Hostname},
		corev1.EnvVar{Name: k8sagent.EnvWorkerAgentVersion, Value: a.Version},
	)
	if password != "" {
		env = append(env, corev1.EnvVar{Name: k8sagent.EnvWorkerDBPassword, Value: password})
	}
	if user != "" {
		env = append(env, corev1.EnvVar{Name: k8sagent.EnvWorkerDBUser, Value: user})
	}
	if prev != nil {
		if stateJSON, err := jsonMarshal(prev); err == nil {
			env = append(env, corev1.EnvVar{Name: k8sagent.EnvWorkerDBState, Value: stateJSON})
		}
	}

	out, err := k8sagent.BackupDatabase(ctx, a.Clients, k8sagent.DBBackupRequest{
		Namespace: target.Namespace,
		BackupID:  session.BackupID,
		RunID:     session.BackupRunID.String(),
		AgentID:   session.AgentID.String(),
		Timeout:   dbWorkerTimeout,
		Worker: k8sagent.DBWorkerConfig{
			Image:               image,
			AgentImage:          a.WorkerImage,
			ImagePullPolicy:     a.WorkerImagePullPolicy,
			ResourcesJSON:       a.DBWorkerResourcesJSON,
			SecurityContextJSON: a.DBWorkerSecurityContextJSON,
			SpoolSizeLimit:      a.DBWorkerSpoolSize,
			Env:                 env,
		},
		Progress: pt.Set,
	})
	if err != nil {
		if out != nil && out.Precheck {
			return precheckFailed(err)
		}
		return failed(err)
	}
	if out.State != nil {
		if err := k8sagent.SaveDBState(ctx, a.Clients.Core, a.AgentNamespace, a.StateSecretName, session.JobID.String(), out.State); err != nil {
			slog.Warn("Job state could not be saved; the next run starts a new chain", "error", err)
		}
	}
	return out.Result, nil
}

// dbWorkerImage renders the dump image for the job from the server's version
func (a *K8sAgentActivities) dbWorkerImage(ctx context.Context, spec *dbbackup.Spec, password string) string {
	major, flavor := 0, ""
	if spec.Engine != dbbackup.EngineMongoDB {
		creds, err := dbbackup.ResolveCredentials(spec, password, nil)
		if err == nil {
			probeCtx, cancel := context.WithTimeout(ctx, dbProbeTimeout)
			v, perr := dbrun.ProbeServerVersion(probeCtx, spec, creds)
			cancel()
			if perr != nil {
				slog.Warn("Could not probe the database server version; using the latest client image (set kubernetes.tools_image to pin one)", "error", perr)
			} else {
				major, flavor = v.Major, v.Flavor
				slog.Info("Database server probed", "version", v.Version, "flavor", v.Flavor)
			}
		} else {
			slog.Warn("Could not resolve credentials for the version probe", "error", err)
		}
	}
	image := k8sagent.RenderDBWorkerImage("", a.DBWorkerImages, spec.Engine, flavor, major)
	slog.Info("Dump pod image selected", "image", image)
	return image
}
