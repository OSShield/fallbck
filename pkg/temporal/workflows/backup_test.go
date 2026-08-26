package workflows

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/db"
	"github.com/osshield/fallbck/pkg/temporal"
	"github.com/osshield/fallbck/pkg/temporal/activities"
	"github.com/stretchr/testify/mock"
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
