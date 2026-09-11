package workflows

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/db"
	fbtemporal "github.com/osshield/fallbck/pkg/temporal"
	"github.com/osshield/fallbck/pkg/temporal/activities"
	enumspb "go.temporal.io/api/enums/v1"
	sdktemporal "go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

// BackupJobWorkflow orchestrates the end-to-end backup execution across server and agent
func BackupJobWorkflow(ctx workflow.Context, jobID uuid.UUID) (*fbtemporal.BackupExecutionResult, error) {
	logger := workflow.GetLogger(ctx)
	logger.Info("Starting BackupJobWorkflow", "job_id", jobID)

	var serverActs *activities.ServerActivities
	var agentActs *activities.AgentActivities
	var dbAgentActs *activities.DBAgentActivities
	var k8sActs *activities.K8sAgentActivities

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
				activities.ErrTypeDBPrecheckFailed,
			},
		},
	}
	agentCtx := workflow.WithActivityOptions(ctx, agentActivityOpts)

	var execResult fbtemporal.BackupExecutionResult

	var execErr error
	var k8sGroups []string
	switch session.JobType {
	case db.JobTypeKubernetes:
		outcome := runKubernetesBackup(ctx, &session)
		execResult, execErr, k8sGroups = outcome.result, outcome.err, outcome.activeGroups
	case db.JobTypeDatabase:
		if session.AgentType == db.AgentTypeKubernetes {
			// A kubernetes agent dumps the database from a pod inside the cluster
			execErr = workflow.ExecuteActivity(agentCtx, k8sActs.ExecuteKubernetesDatabaseBackup, &session).Get(agentCtx, &execResult)
		} else {
			execErr = workflow.ExecuteActivity(agentCtx, dbAgentActs.ExecuteDatabaseBackup, &session).Get(agentCtx, &execResult)
		}
	default:
		execErr = workflow.ExecuteActivity(agentCtx, agentActs.ExecuteFilesystemBackup, &session).Get(agentCtx, &execResult)
	}
	switch {
	case execErr == nil:
		if execResult.Status == "" {
			execResult.Status = db.RunStatusCompleted
		}
	case sdktemporal.IsCanceledError(execErr) || ctx.Err() != nil:
		// Operator cancelled the run: the agent activity has been told to stop
		logger.Info("Backup run cancelled", "job_id", jobID)
		execResult.Status = db.RunStatusCancelled
		execResult.ErrorMessage = "cancelled by operator"
	default:
		logger.Error("Agent backup activity failed", "error", execErr)
		execResult.Status = db.RunStatusFailed
		execResult.ErrorMessage = execErr.Error()
		// The activity attaches its phase and the agent's log tail as error details
		var appErr *sdktemporal.ApplicationError
		if errors.As(execErr, &appErr) && appErr.HasDetails() {
			var details fbtemporal.BackupFailureDetails
			if appErr.Details(&details) == nil {
				execResult.LogTail = details.LogTail
			}
		}
		// A heartbeat timeout means the agent went silent: say so, and name the phase
		// it last reported instead of Temporal's bare "activity Heartbeat timeout"
		var timeoutErr *sdktemporal.TimeoutError
		if errors.As(execErr, &timeoutErr) && timeoutErr.TimeoutType() == enumspb.TIMEOUT_TYPE_HEARTBEAT {
			msg := "the agent stopped sending heartbeats for over 60s and all retries were exhausted (agent crashed, host overloaded, or the connection to the server was lost)"
			var hb fbtemporal.BackupHeartbeatProgress
			if timeoutErr.HasLastHeartbeatDetails() && timeoutErr.LastHeartbeatDetails(&hb) == nil && hb.Phase != "" {
				msg += "; last reported phase: " + hb.Phase
			} else {
				msg += "; no heartbeat was ever recorded — the activity likely never started or died immediately"
			}
			execResult.ErrorMessage = msg
		}
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
		if session.JobType == db.JobTypeKubernetes {
			_ = workflow.ExecuteActivity(serverCtx, serverActs.PruneKubernetesJob, &session, k8sGroups).Get(serverCtx, nil)
		} else {
			_ = workflow.ExecuteActivity(serverCtx, serverActs.PruneJob, &session).Get(serverCtx, nil)
		}
	}

	if execErr != nil {
		return &execResult, execErr
	}

	logger.Info("BackupJobWorkflow completed successfully", "job_id", jobID, "dedup_ratio", execResult.DedupRatio)
	return &execResult, nil
}
