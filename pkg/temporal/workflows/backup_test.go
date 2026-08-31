package workflows

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/db"
	"github.com/osshield/fallbck/pkg/dbbackup"
	"github.com/osshield/fallbck/pkg/temporal"
	"github.com/osshield/fallbck/pkg/temporal/activities"
	"github.com/stretchr/testify/mock"
	sdktemporal "go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/testsuite"
)

func TestBackupJobWorkflowSuccess(t *testing.T) {
	testSuite := &testsuite.WorkflowTestSuite{}
	env := testSuite.NewTestWorkflowEnvironment()

	jobID := uuid.New()
	session := &temporal.BackupSessionInfo{
		JobID:          jobID,
		AgentID:        uuid.New(),
		TargetID:       uuid.New(),
		AgentTaskQueue: "fallbck-agent-test",
		ProxyURL:       "http://localhost:8443/pbs-proxy",
		Ticket:         "test-ticket",
		Datastore:      "backup-store",
		BackupPaths:    []string{"/var/data"},
		BackupRunID:    uuid.New(),
	}

	execResult := &temporal.BackupExecutionResult{
		Status:        db.RunStatusCompleted,
		BytesScanned:  1024 * 1024 * 100, // 100 MB
		BytesUploaded: 1024 * 1024 * 10,  // 10 MB
		DedupRatio:    10.0,
		ChunkCount:    25,
		SnapshotID:    "host/test-host/2026-08-24T15:00:00Z",
		Duration:      5 * time.Second,
	}

	var serverActs *activities.ServerActivities
	var agentActs *activities.AgentActivities

	// Mock Server Activities
	env.OnActivity(serverActs.PrepareBackupSession, mock.Anything, jobID).Return(session, nil)
	env.OnActivity(serverActs.FinalizeBackupRun, mock.Anything, session, execResult).Return(nil)
	env.OnActivity(serverActs.PruneJob, mock.Anything, session).Return(nil)

	// Mock Agent Activity
	env.OnActivity(agentActs.ExecuteFilesystemBackup, mock.Anything, session).Return(execResult, nil)

	env.ExecuteWorkflow(BackupJobWorkflow, jobID)

	if !env.IsWorkflowCompleted() {
		t.Fatal("Workflow did not complete")
	}

	var result temporal.BackupExecutionResult
	err := env.GetWorkflowResult(&result)
	if err != nil {
		t.Fatalf("Workflow failed: %v", err)
	}

	if result.Status != db.RunStatusCompleted {
		t.Errorf("Expected status Completed, got %s", result.Status)
	}
	if result.DedupRatio != 10.0 {
		t.Errorf("Expected DedupRatio 10.0, got %f", result.DedupRatio)
	}
}

func TestBackupJobWorkflowCancelled(t *testing.T) {
	testSuite := &testsuite.WorkflowTestSuite{}
	env := testSuite.NewTestWorkflowEnvironment()

	jobID := uuid.New()
	session := &temporal.BackupSessionInfo{
		JobID:          jobID,
		AgentTaskQueue: "fallbck-agent-test",
		BackupRunID:    uuid.New(),
	}

	var serverActs *activities.ServerActivities
	var agentActs *activities.AgentActivities

	env.OnActivity(serverActs.PrepareBackupSession, mock.Anything, jobID).Return(session, nil)
	// The agent activity is still running when the operator cancels
	env.OnActivity(agentActs.ExecuteFilesystemBackup, mock.Anything, session).
		After(time.Hour).Return(&temporal.BackupExecutionResult{Status: db.RunStatusCompleted}, nil)

	var finalized *temporal.BackupExecutionResult
	env.OnActivity(serverActs.FinalizeBackupRun, mock.Anything, session, mock.Anything).
		Run(func(args mock.Arguments) { finalized = args.Get(2).(*temporal.BackupExecutionResult) }).
		Return(nil)

	env.RegisterDelayedCallback(func() { env.CancelWorkflow() }, time.Minute)
	env.ExecuteWorkflow(BackupJobWorkflow, jobID)

	if !env.IsWorkflowCompleted() {
		t.Fatal("Workflow did not complete")
	}
	if err := env.GetWorkflowError(); err == nil || !sdktemporal.IsCanceledError(err) {
		t.Fatalf("expected the workflow to end as cancelled, got %v", err)
	}
	if finalized == nil {
		t.Fatal("FinalizeBackupRun must still run after cancellation")
	}
	if finalized.Status != db.RunStatusCancelled {
		t.Errorf("finalised status = %s, want cancelled", finalized.Status)
	}
	env.AssertNotCalled(t, "PruneJob", mock.Anything, mock.Anything)
}

func TestBackupJobWorkflowDatabase(t *testing.T) {
	testSuite := &testsuite.WorkflowTestSuite{}
	env := testSuite.NewTestWorkflowEnvironment()

	jobID := uuid.New()
	session := &temporal.BackupSessionInfo{
		JobID: jobID, AgentTaskQueue: "fallbck-agent-db", BackupRunID: uuid.New(),
		JobType:  db.JobTypeDatabase,
		DBConfig: &dbbackup.Spec{Engine: dbbackup.EnginePostgres, Host: "db01"},
	}
	execResult := &temporal.BackupExecutionResult{Status: db.RunStatusCompleted, SnapshotID: "host/db-postgres-db01/2026-08-28T01:00:00Z"}

	var serverActs *activities.ServerActivities
	var agentActs *activities.AgentActivities
	var dbActs *activities.DBAgentActivities
	env.OnActivity(serverActs.PrepareBackupSession, mock.Anything, jobID).Return(session, nil)
	env.OnActivity(dbActs.ExecuteDatabaseBackup, mock.Anything, session).Return(execResult, nil)
	env.OnActivity(agentActs.ExecuteFilesystemBackup, mock.Anything, mock.Anything).Return(nil, nil)
	env.OnActivity(serverActs.FinalizeBackupRun, mock.Anything, session, execResult).Return(nil)
	env.OnActivity(serverActs.PruneJob, mock.Anything, session).Return(nil)

	env.ExecuteWorkflow(BackupJobWorkflow, jobID)
	if !env.IsWorkflowCompleted() {
		t.Fatal("Workflow did not complete")
	}
	var result temporal.BackupExecutionResult
	if err := env.GetWorkflowResult(&result); err != nil {
		t.Fatalf("Workflow failed: %v", err)
	}
	if result.SnapshotID != execResult.SnapshotID {
		t.Errorf("result %+v", result)
	}
	env.AssertNotCalled(t, "ExecuteFilesystemBackup", mock.Anything, mock.Anything)
	env.AssertCalled(t, "PruneJob", mock.Anything, session)
}
