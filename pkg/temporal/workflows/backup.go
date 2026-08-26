package workflows

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/db"
	fbtemporal "github.com/osshield/fallbck/pkg/temporal"
	"github.com/osshield/fallbck/pkg/temporal/activities"
	sdktemporal "go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

// BackupJobWorkflow orchestrates the end-to-end backup execution across server and agent
func BackupJobWorkflow(ctx workflow.Context, jobID uuid.UUID) (*fbtemporal.BackupExecutionResult, error) {
	logger := workflow.GetLogger(ctx)
	logger.Info("Starting BackupJobWorkflow", "job_id", jobID)

	var serverActs *activities.ServerActivities
	var agentActs *activities.AgentActivities

	// 1. Prepare Backup Session on Server
	serverActivityOpts := workflow.ActivityOptions{
		TaskQueue:              fbtemporal.ServerTaskQueue,
		StartToCloseTimeout:    2 * time.Minute,
		ScheduleToCloseTimeout: 5 * time.Minute,
		RetryPolicy: &sdktemporal.RetryPolicy{
			InitialInterval:    2 * time.Second,
			BackoffCoefficient: 2.0,
			MaximumAttempts:    3,
		},
	}
	serverCtx := workflow.WithActivityOptions(ctx, serverActivityOpts)

	var session fbtemporal.BackupSessionInfo
	err := workflow.ExecuteActivity(serverCtx, serverActs.PrepareBackupSession, jobID).Get(serverCtx, &session)
	if err != nil {
		logger.Error("Failed to prepare backup session on server", "error", err)
		return nil, fmt.Errorf("prepare backup session failed: %w", err)
	}

	logger.Info("Backup session prepared", "agent_queue", session.AgentTaskQueue, "proxy_url", session.ProxyURL)

	// 2. Execute Backup Activity on Target Agent Task Queue
	agentActivityOpts := workflow.ActivityOptions{
		TaskQueue:              session.AgentTaskQueue,
		StartToCloseTimeout:    6 * time.Hour,
		HeartbeatTimeout:       60 * time.Second,
		ScheduleToCloseTimeout: 12 * time.Hour,
		RetryPolicy: &sdktemporal.RetryPolicy{
			InitialInterval:    5 * time.Second,
			BackoffCoefficient: 2.0,
			MaximumAttempts:    3,
			NonRetryableErrorTypes: []string{
				"unauthorized datastore scope",
				"invalid or expired backup ticket",
			},
		},
	}
	agentCtx := workflow.WithActivityOptions(ctx, agentActivityOpts)

	var execResult fbtemporal.BackupExecutionResult

	execErr := workflow.ExecuteActivity(agentCtx, agentActs.ExecuteFilesystemBackup, &session).Get(agentCtx, &execResult)
	switch {
	case execErr == nil:
	case sdktemporal.IsCanceledError(execErr) || ctx.Err() != nil:
		// Operator cancelled the run: the agent activity has been told to stop
		logger.Info("Backup run cancelled", "job_id", jobID)
		execResult.Status = db.RunStatusCancelled
		execResult.ErrorMessage = "cancelled by operator"
	default:
		logger.Error("Agent backup activity failed", "error", execErr)
		execResult.Status = db.RunStatusFailed
		execResult.ErrorMessage = execErr.Error()
	}

	// 3. Finalize Run Status on Server. Runs on a disconnected context so it still
	// executes after a cancellation.
	disconnected, cancelFinalize := workflow.NewDisconnectedContext(ctx)
	defer cancelFinalize()
	finalizeCtx := workflow.WithActivityOptions(disconnected, serverActivityOpts)
	finalizeErr := workflow.ExecuteActivity(finalizeCtx, serverActs.FinalizeBackupRun, &session, &execResult).Get(finalizeCtx, nil)
	if finalizeErr != nil {
		logger.Warn("Failed to finalize backup run in database", "error", finalizeErr)
	}

	// 4. Execute Prune Retention Policy on PBS if backup succeeded
	if execErr == nil && execResult.Status == db.RunStatusCompleted {
		_ = workflow.ExecuteActivity(serverCtx, serverActs.PruneJob, &session).Get(serverCtx, nil)
	}

	if execErr != nil {
		return &execResult, execErr
	}

	logger.Info("BackupJobWorkflow completed successfully", "job_id", jobID, "dedup_ratio", execResult.DedupRatio)
	return &execResult, nil
}
