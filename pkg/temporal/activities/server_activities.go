package activities

import (
	"context"
	"fmt"
	"github.com/osshield/fallbck/pkg/dbbackup"
	"github.com/osshield/fallbck/pkg/k8sbackup"
	sdktemporal "go.temporal.io/sdk/temporal"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/auth"
	"github.com/osshield/fallbck/pkg/config"
	"github.com/osshield/fallbck/pkg/db"
	"github.com/osshield/fallbck/pkg/pbs"
	"github.com/osshield/fallbck/pkg/temporal"
	"go.temporal.io/sdk/activity"
)

// ServerActivities provides activities executed on the central FallBCK server
type ServerActivities struct {
	DB           *db.DB
	Config       *config.ServerConfig
	TokenManager *auth.TokenManager
}

// NewServerActivities creates a new ServerActivities instance
func NewServerActivities(database *db.DB, cfg *config.ServerConfig, tm *auth.TokenManager) *ServerActivities {
	return &ServerActivities{
		DB:           database,
		Config:       cfg,
		TokenManager: tm,
	}
}

// PrepareBackupSession validates job parameters and generates a short-lived backup ticket
func (s *ServerActivities) PrepareBackupSession(ctx context.Context, jobID uuid.UUID) (*temporal.BackupSessionInfo, error) {
	info := activity.GetInfo(ctx)
	slog.Info("Preparing backup session for job", "job_id", jobID, "workflow_id", info.WorkflowExecution.ID)

	if s.DB == nil {
		// Mock session for dev/test mode
		return &temporal.BackupSessionInfo{
			JobID:          jobID,
			AgentID:        uuid.New(),
			TargetID:       uuid.New(),
			AgentTaskQueue: "fallbck-agent-dev",
			ProxyURL:       s.Config.ProxyURL(),
			Ticket:         "dev-mock-ticket",
			Datastore:      "backup-store",
			BackupType:     "host",
			BackupID:       "dev-host",
			BackupTime:     time.Now().Unix(),
			PxarFormat:     db.PxarFormatV1,
			BackupPaths:    []string{"/var/data"},
			WorkflowID:     info.WorkflowExecution.ID,
			RunID:          info.WorkflowExecution.RunID,
			BackupRunID:    uuid.New(),
		}, nil
	}

	job, err := s.DB.GetJobByID(ctx, jobID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch job: %w", err)
	}

	agent, err := s.DB.GetAgentByID(ctx, job.AgentID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch agent: %w", err)
	}

	target, err := s.DB.GetTargetByID(ctx, job.TargetID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch backup target: %w", err)
	}

	// Generate short-lived backup ticket (2 hours TTL)
	now := time.Now().UTC()
	claims := auth.BackupTicketClaims{
		JobID:      job.ID,
		AgentID:    agent.ID,
		TargetID:   target.ID,
		Datastore:  target.Datastore,
		Namespace:  target.Namespace,
		BackupType: "host",
		BackupID:   agent.Hostname,
		BackupTime: now.Unix(),
	}
	jobType, _ := db.NormalizeAgentType(job.JobType)
	agentType, _ := db.NormalizeAgentType(agent.AgentType)
	if !db.JobAllowedOnAgent(jobType, agentType) {
		return nil, sdktemporal.NewNonRetryableApplicationError(
			fmt.Sprintf("job type %q cannot run on agent %s of type %q", jobType, agent.Hostname, agentType), "job_agent_mismatch", nil)
	}
	var sessionSpec *dbbackup.Spec
	var k8sSpec *k8sbackup.Spec
	passwordOnServer := false
	if jobType == db.JobTypeKubernetes {
		if job.K8sConfig == nil {
			return nil, sdktemporal.NewNonRetryableApplicationError("kubernetes job has no configuration", "job_invalid", nil)
		}
		k8sSpec = job.K8sConfig
		// Kubernetes snapshots use the PBS "ct" (container) backup type; the group id
		// stays k8s-<cluster> (agent hostname), volumes append -pvc-<ns>-<name>
		claims.BackupType = "ct"
	}
	if jobType == db.JobTypeDatabase {
		if job.DBConfig == nil {
			return nil, sdktemporal.NewNonRetryableApplicationError("database job has no database configuration", "job_invalid", nil)
		}
		claims.BackupID = dbbackup.DefaultBackupID(job.DBConfig)
		// The spec travels through Temporal history without the password; the agent
		// fetches it with its ticket when one is stored
		sessionSpec = job.DBConfig.Redacted()
		passwordOnServer = job.DBConfig.Password != ""
	}

	ticket, err := s.TokenManager.CreateBackupTicket(claims, 2*time.Hour)
	if err != nil {
		return nil, fmt.Errorf("failed to generate backup ticket: %w", err)
	}

	// Run record: the API creates a pending row when it starts the workflow; adopt it
	// (so cancellation and finalisation update the row the user sees), otherwise create one.
	var runID uuid.UUID
	if existing, err := s.DB.GetRunByWorkflowID(ctx, info.WorkflowExecution.ID); err == nil {
		runID = existing.ID
		if err := s.DB.MarkRunStarted(ctx, runID, info.WorkflowExecution.RunID, now); err != nil {
			slog.Warn("Failed to mark run as started", "error", err, "run_id", runID)
		}
	} else {
		runID = uuid.New()
		run := &db.BackupRun{
			ID:         runID,
			JobID:      job.ID,
			AgentID:    agent.ID,
			TargetID:   target.ID,
			WorkflowID: info.WorkflowExecution.ID,
			RunID:      info.WorkflowExecution.RunID,
			Status:     db.RunStatusRunning,
			StartTime:  &now,
		}
		if err := s.DB.CreateRun(ctx, run); err != nil {
			slog.Warn("Failed to create run record in database", "error", err)
		}
	}

	proxyURL := s.Config.ProxyURL()

	return &temporal.BackupSessionInfo{
		JobID:              job.ID,
		AgentID:            agent.ID,
		TargetID:           target.ID,
		AgentTaskQueue:     agent.TaskQueue,
		ProxyURL:           proxyURL,
		Ticket:             ticket,
		Datastore:          target.Datastore,
		Namespace:          target.Namespace,
		BackupType:         claims.BackupType,
		BackupID:           claims.BackupID,
		BackupTime:         claims.BackupTime,
		PxarFormat:         target.PxarFormat,
		DirectPBS:          job.DirectPBS,
		JobType:            jobType,
		AgentType:          agentType,
		JobName:            job.Name,
		DBConfig:           sessionSpec,
		DBPasswordOnServer: passwordOnServer,
		K8sConfig:          k8sSpec,
		BackupPaths:        job.BackupPaths,
		ExcludePaths:       job.ExcludePaths,
		RetentionPolicy:    job.RetentionPolicy,
		WorkflowID:         info.WorkflowExecution.ID,
		RunID:              info.WorkflowExecution.RunID,
		BackupRunID:        runID,
	}, nil
}

// FinalizeBackupRun updates the backup run record in the database with results and deduplication metrics
func (s *ServerActivities) FinalizeBackupRun(ctx context.Context, session *temporal.BackupSessionInfo, result *temporal.BackupExecutionResult) error {
	slog.Info("Finalizing backup run", "run_id", session.BackupRunID, "status", result.Status, "dedup_ratio", result.DedupRatio)

	if s.DB == nil {
		return nil
	}

	now := time.Now().UTC()
	run := &db.BackupRun{
		ID:            session.BackupRunID,
		Status:        result.Status,
		EndTime:       &now,
		BytesScanned:  result.BytesScanned,
		BytesUploaded: result.BytesUploaded,
		DedupRatio:    result.DedupRatio,
		ChunkCount:    result.ChunkCount,
		ErrorMessage:  result.ErrorMessage,
		PBSSnapshotID: result.SnapshotID,
		LogTail:       truncateTail(result.LogTail, 16*1024),
		Details:       result.Details,
	}

	if err := s.DB.UpdateRun(ctx, run); err != nil {
		return fmt.Errorf("failed to update run status in database: %w", err)
	}

	return nil
}

// PruneJob executes the retention policy prune on the target Proxmox Backup Server
func (s *ServerActivities) PruneJob(ctx context.Context, session *temporal.BackupSessionInfo) error {
	if s.DB == nil {
		return nil
	}

	target, err := s.DB.GetTargetByID(ctx, session.TargetID)
	if err != nil {
		return fmt.Errorf("failed to fetch target for pruning: %w", err)
	}

	// The prune group is the one the session backed up into (bound into the ticket)
	backupType, backupID := session.BackupType, session.BackupID
	if backupID == "" {
		agent, err := s.DB.GetAgentByID(ctx, session.AgentID)
		if err != nil {
			return fmt.Errorf("failed to fetch agent: %w", err)
		}
		backupType, backupID = "host", agent.Hostname
	}

	client := pbs.NewClient(target.Endpoint, target.AuthTokenEncrypted, target.TLSVerify, target.Fingerprint)

	r := session.RetentionPolicy
	if r.KeepLast > 0 || r.KeepDaily > 0 || r.KeepWeekly > 0 || r.KeepMonthly > 0 {
		slog.Info("Executing PBS prune job", "datastore", target.Datastore, "backup_type", backupType, "backup_id", backupID)
		err := client.PruneDatastore(
			ctx,
			target.Datastore,
			target.Namespace,
			backupType,
			backupID,
			r.KeepLast,
			r.KeepDaily,
			r.KeepWeekly,
			r.KeepMonthly,
		)
		if err != nil {
			slog.Warn("PBS prune returned error", "error", err)
			return err
		}
	}

	return nil
}

// PruneKubernetesJob applies the job's retention policy to every PBS group a
// kubernetes cluster writes: the resources group and each k8s-<cluster>-pvc-* group —
// including groups of PVCs deleted since earlier runs, which would otherwise never be
// pruned. activeGroups are the groups touched by this run; orphaned volume groups can
// additionally be forgotten entirely after volumes.forget_orphans_after_days.
func (s *ServerActivities) PruneKubernetesJob(ctx context.Context, session *temporal.BackupSessionInfo, activeGroups []string) error {
	if s.DB == nil || session == nil {
		return nil
	}
	target, err := s.DB.GetTargetByID(ctx, session.TargetID)
	if err != nil {
		return fmt.Errorf("failed to fetch target for pruning: %w", err)
	}
	client := pbs.NewClient(target.Endpoint, target.AuthTokenEncrypted, target.TLSVerify, target.Fingerprint)
	r := session.RetentionPolicy
	hasRetention := r.KeepLast > 0 || r.KeepDaily > 0 || r.KeepWeekly > 0 || r.KeepMonthly > 0
	forgetDays := 0
	if session.K8sConfig != nil {
		forgetDays = session.K8sConfig.Volumes.ForgetOrphansAfterDays
	}
	if !hasRetention && forgetDays == 0 {
		return nil
	}

	prune := func(backupID string) {
		if !hasRetention {
			return
		}
		if err := client.PruneDatastore(ctx, target.Datastore, target.Namespace, session.BackupType, backupID,
			r.KeepLast, r.KeepDaily, r.KeepWeekly, r.KeepMonthly); err != nil {
			slog.Warn("PBS prune returned error", "group", backupID, "error", err)
		}
	}
	prune(session.BackupID)

	groups, err := client.ListGroups(ctx, target.Datastore, target.Namespace)
	if err != nil {
		return fmt.Errorf("listing PBS groups: %w", err)
	}
	active := map[string]bool{}
	for _, g := range activeGroups {
		active[g] = true
	}
	for _, g := range groups {
		if g.BackupType != session.BackupType || !k8sbackup.IsVolumeGroup(session.BackupID, g.BackupID) {
			continue
		}
		prune(g.BackupID)
		if forgetDays > 0 && !active[g.BackupID] && g.LastBackup > 0 &&
			time.Since(time.Unix(g.LastBackup, 0)) > time.Duration(forgetDays)*24*time.Hour {
			slog.Info("Forgetting orphaned kubernetes volume group", "group", g.BackupID, "datastore", target.Datastore)
			if err := client.DeleteGroup(ctx, target.Datastore, target.Namespace, g.BackupType, g.BackupID); err != nil {
				slog.Warn("PBS group delete returned error", "group", g.BackupID, "error", err)
			}
		}
	}
	return nil
}

// truncateTail keeps the last max bytes of a log tail (the newest lines matter most)
func truncateTail(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := s[len(s)-max:]
	if i := strings.IndexByte(cut, '\n'); i >= 0 && i < len(cut)-1 {
		cut = cut[i+1:]
	}
	return cut
}
