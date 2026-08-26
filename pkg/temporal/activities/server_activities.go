package activities

import (
	"context"
	"fmt"
	"log/slog"
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
		JobID:           job.ID,
		AgentID:         agent.ID,
		TargetID:        target.ID,
		AgentTaskQueue:  agent.TaskQueue,
		ProxyURL:        proxyURL,
		Ticket:          ticket,
		Datastore:       target.Datastore,
		Namespace:       target.Namespace,
		BackupType:      claims.BackupType,
		BackupID:        claims.BackupID,
		BackupTime:      claims.BackupTime,
		PxarFormat:      target.PxarFormat,
		BackupPaths:     job.BackupPaths,
		ExcludePaths:    job.ExcludePaths,
		RetentionPolicy: job.RetentionPolicy,
		WorkflowID:      info.WorkflowExecution.ID,
		RunID:           info.WorkflowExecution.RunID,
		BackupRunID:     runID,
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

	agent, err := s.DB.GetAgentByID(ctx, session.AgentID)
	if err != nil {
		return fmt.Errorf("failed to fetch agent: %w", err)
	}

	client := pbs.NewClient(target.Endpoint, target.AuthTokenEncrypted, target.TLSVerify, target.Fingerprint)

	r := session.RetentionPolicy
	if r.KeepLast > 0 || r.KeepDaily > 0 || r.KeepWeekly > 0 || r.KeepMonthly > 0 {
		slog.Info("Executing PBS prune job", "datastore", target.Datastore, "backup_id", agent.Hostname)
		err := client.PruneDatastore(
			ctx,
			target.Datastore,
			target.Namespace,
			"host",
			agent.Hostname,
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
