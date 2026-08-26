package agent_test

import (
	"context"

	"github.com/osshield/fallbck/pkg/temporal"
	"github.com/osshield/fallbck/pkg/temporal/activities"
	"go.temporal.io/sdk/testsuite"
	"go.temporal.io/sdk/worker"
)

// runActivity executes the agent activity inside Temporal's activity test environment
// (so activity.GetInfo / RecordHeartbeat work) and decodes the result.
func runActivity(ctx context.Context, acts *activities.AgentActivities, session *temporal.BackupSessionInfo) (*temporal.BackupExecutionResult, error) {
	env := (&testsuite.WorkflowTestSuite{}).NewTestActivityEnvironment()
	env.SetWorkerOptions(worker.Options{BackgroundActivityContext: ctx})
	env.RegisterActivity(acts.ExecuteFilesystemBackup)
	val, err := env.ExecuteActivity(acts.ExecuteFilesystemBackup, session)
	if err != nil {
		return nil, err
	}
	var result temporal.BackupExecutionResult
	if err := val.Get(&result); err != nil {
		return nil, err
	}
	return &result, nil
}
