package workflows

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/db"
	"github.com/osshield/fallbck/pkg/dbbackup"
	"github.com/osshield/fallbck/pkg/k8sbackup"
	"github.com/osshield/fallbck/pkg/m365"
	"github.com/osshield/fallbck/pkg/temporal"
	"github.com/osshield/fallbck/pkg/temporal/activities"
	"github.com/stretchr/testify/mock"
	enumspb "go.temporal.io/api/enums/v1"
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
}

func TestBackupJobWorkflowM365(t *testing.T) {
	testSuite := &testsuite.WorkflowTestSuite{}
	env := testSuite.NewTestWorkflowEnvironment()

	jobID := uuid.New()
	session := &temporal.BackupSessionInfo{
		JobID: jobID, AgentTaskQueue: "fallbck-agent-m365", BackupRunID: uuid.New(),
		JobType: db.JobTypeM365, BackupID: "m365-contoso",
		M365Config: &m365.Spec{TenantID: uuid.New()},
	}
	execResult := &temporal.BackupExecutionResult{Status: db.RunStatusCompleted, SnapshotID: "host/m365-contoso/2026-10-10T01:00:00Z"}

	var serverActs *activities.ServerActivities
	var agentActs *activities.AgentActivities
	env.OnActivity(serverActs.PrepareBackupSession, mock.Anything, jobID).Return(session, nil)
	env.OnActivity(agentActs.ExecuteM365Backup, mock.Anything, session).Return(execResult, nil)
	env.OnActivity(agentActs.ExecuteFilesystemBackup, mock.Anything, mock.Anything).Return(nil, nil)
	env.OnActivity(serverActs.FinalizeBackupRun, mock.Anything, session, execResult).Return(nil)

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
}

func TestBackupJobWorkflowFailureCarriesDetails(t *testing.T) {
	testSuite := &testsuite.WorkflowTestSuite{}
	env := testSuite.NewTestWorkflowEnvironment()

	jobID := uuid.New()
	session := &temporal.BackupSessionInfo{JobID: jobID, AgentTaskQueue: "q", BackupRunID: uuid.New()}
	var serverActs *activities.ServerActivities
	var agentActs *activities.AgentActivities
	env.OnActivity(serverActs.PrepareBackupSession, mock.Anything, jobID).Return(session, nil)
	env.OnActivity(agentActs.ExecuteFilesystemBackup, mock.Anything, session).Return(nil,
		sdktemporal.NewApplicationError("boom [phase: uploading root.pxar.didx (2m0s)]", "backup_failed",
			temporal.BackupFailureDetails{Phase: "uploading root.pxar.didx (2m0s)", LogTail: "ERROR something broke"}))
	var finalized *temporal.BackupExecutionResult
	env.OnActivity(serverActs.FinalizeBackupRun, mock.Anything, session, mock.Anything).
		Run(func(args mock.Arguments) { finalized = args.Get(2).(*temporal.BackupExecutionResult) }).Return(nil)

	env.ExecuteWorkflow(BackupJobWorkflow, jobID)
	if !env.IsWorkflowCompleted() {
		t.Fatal("Workflow did not complete")
	}
	if finalized == nil {
		t.Fatal("FinalizeBackupRun not called")
	}
	if finalized.Status != db.RunStatusFailed || finalized.LogTail != "ERROR something broke" {
		t.Errorf("finalized: %+v", finalized)
	}
	if !strings.Contains(finalized.ErrorMessage, "phase: uploading root.pxar.didx") {
		t.Errorf("error message lost the phase: %q", finalized.ErrorMessage)
	}
}

func TestBackupJobWorkflowHeartbeatTimeoutMessage(t *testing.T) {
	testSuite := &testsuite.WorkflowTestSuite{}
	env := testSuite.NewTestWorkflowEnvironment()

	jobID := uuid.New()
	session := &temporal.BackupSessionInfo{JobID: jobID, AgentTaskQueue: "q", BackupRunID: uuid.New()}
	var serverActs *activities.ServerActivities
	var agentActs *activities.AgentActivities
	env.OnActivity(serverActs.PrepareBackupSession, mock.Anything, jobID).Return(session, nil)
	env.OnActivity(agentActs.ExecuteFilesystemBackup, mock.Anything, session).Return(nil,
		sdktemporal.NewTimeoutError(enumspb.TIMEOUT_TYPE_HEARTBEAT, nil,
			temporal.BackupHeartbeatProgress{Phase: "uploading root.pxar.didx (4m30s)"}))
	var finalized *temporal.BackupExecutionResult
	env.OnActivity(serverActs.FinalizeBackupRun, mock.Anything, session, mock.Anything).
		Run(func(args mock.Arguments) { finalized = args.Get(2).(*temporal.BackupExecutionResult) }).Return(nil)

	env.ExecuteWorkflow(BackupJobWorkflow, jobID)
	if !env.IsWorkflowCompleted() {
		t.Fatal("Workflow did not complete")
	}
	if finalized == nil {
		t.Fatal("FinalizeBackupRun not called")
	}
	msg := finalized.ErrorMessage
	if !strings.Contains(msg, "stopped sending heartbeats") || !strings.Contains(msg, "last reported phase: uploading root.pxar.didx") {
		t.Errorf("heartbeat timeout message not descriptive: %q", msg)
	}
}

func TestBackupJobWorkflowKubernetes(t *testing.T) {
	testSuite := &testsuite.WorkflowTestSuite{}
	env := testSuite.NewTestWorkflowEnvironment()

	jobID := uuid.New()
	k8sSpec := &k8sbackup.Spec{}
	if err := k8sSpec.Validate(); err != nil {
		t.Fatal(err)
	}
	session := &temporal.BackupSessionInfo{
		JobID: jobID, AgentTaskQueue: "fallbck-agent-k8s", BackupRunID: uuid.New(),
		JobType: db.JobTypeKubernetes, K8sConfig: k8sSpec,
		BackupType: "host", BackupID: "k8s-prod",
	}
	plan := &k8sbackup.Plan{ClusterName: "prod", Volumes: []k8sbackup.VolumePlan{
		{Namespace: "app", PVCName: "good", GroupID: "k8s-prod-pvc-app-good", Mode: k8sbackup.ModeSnapshot},
		{Namespace: "app", PVCName: "bad", GroupID: "k8s-prod-pvc-app-bad", Mode: k8sbackup.ModeLive},
	}}
	resResult := &temporal.BackupExecutionResult{Status: db.RunStatusCompleted, SnapshotID: "host/k8s-prod/2026-09-05T02:00:00Z", BytesScanned: 50, BytesUploaded: 5, ChunkCount: 2}

	var serverActs *activities.ServerActivities
	var k8sActs *activities.K8sAgentActivities
	env.OnActivity(serverActs.PrepareBackupSession, mock.Anything, jobID).Return(session, nil)
	env.OnActivity(k8sActs.DiscoverKubernetesBackup, mock.Anything, session).Return(plan, nil)
	env.OnActivity(k8sActs.BackupKubernetesVolume, mock.Anything, mock.Anything, mock.Anything).Return(
		func(_ context.Context, _ *temporal.BackupSessionInfo, vol k8sbackup.VolumePlan) (*k8sbackup.VolumeResult, error) {
			if vol.PVCName == "bad" {
				return nil, errors.New("worker pod failed: disk gremlins")
			}
			return &k8sbackup.VolumeResult{
				Namespace: vol.Namespace, PVCName: vol.PVCName, GroupID: vol.GroupID, Mode: vol.Mode,
				Status: "completed", SnapshotID: "host/" + vol.GroupID + "/2026-09-05T02:00:00Z",
				BytesScanned: 100, BytesUploaded: 10, ChunkCount: 4,
			}, nil
		})
	env.OnActivity(k8sActs.BackupKubernetesResources, mock.Anything, session, mock.Anything, mock.Anything).Return(resResult, nil)
	var finalized *temporal.BackupExecutionResult
	env.OnActivity(serverActs.FinalizeBackupRun, mock.Anything, session, mock.Anything).
		Run(func(args mock.Arguments) { finalized = args.Get(2).(*temporal.BackupExecutionResult) }).Return(nil)

	env.ExecuteWorkflow(BackupJobWorkflow, jobID)
	if !env.IsWorkflowCompleted() {
		t.Fatal("Workflow did not complete")
	}
	if err := env.GetWorkflowError(); err != nil {
		t.Fatalf("workflow error (continue_on_error should complete): %v", err)
	}
	if finalized == nil {
		t.Fatal("FinalizeBackupRun not called")
	}
	if finalized.Status != db.RunStatusPartial || finalized.SnapshotID != resResult.SnapshotID {
		t.Errorf("finalized: %+v", finalized)
	}
	if finalized.BytesScanned != 150 || finalized.ChunkCount != 6 {
		t.Errorf("aggregation: scanned=%d chunks=%d", finalized.BytesScanned, finalized.ChunkCount)
	}
	if !strings.Contains(finalized.ErrorMessage, "app/bad") || !strings.Contains(finalized.ErrorMessage, "volumes failed") {
		t.Errorf("error message: %q", finalized.ErrorMessage)
	}
}

func TestBackupJobWorkflowKubernetesAllVolumesFail(t *testing.T) {
	testSuite := &testsuite.WorkflowTestSuite{}
	env := testSuite.NewTestWorkflowEnvironment()
	jobID := uuid.New()
	k8sSpec := &k8sbackup.Spec{}
	_ = k8sSpec.Validate()
	session := &temporal.BackupSessionInfo{JobID: jobID, AgentTaskQueue: "q", BackupRunID: uuid.New(), JobType: db.JobTypeKubernetes, K8sConfig: k8sSpec}
	plan := &k8sbackup.Plan{Volumes: []k8sbackup.VolumePlan{{Namespace: "a", PVCName: "x", GroupID: "g-pvc-a-x", Mode: k8sbackup.ModeLive}}}

	var serverActs *activities.ServerActivities
	var k8sActs *activities.K8sAgentActivities
	env.OnActivity(serverActs.PrepareBackupSession, mock.Anything, jobID).Return(session, nil)
	env.OnActivity(k8sActs.DiscoverKubernetesBackup, mock.Anything, session).Return(plan, nil)
	env.OnActivity(k8sActs.BackupKubernetesVolume, mock.Anything, mock.Anything, mock.Anything).Return(nil, errors.New("all broken"))
	env.OnActivity(k8sActs.BackupKubernetesResources, mock.Anything, session, mock.Anything, mock.Anything).
		Return(&temporal.BackupExecutionResult{Status: db.RunStatusCompleted, SnapshotID: "host/g/t"}, nil)
	var finalized *temporal.BackupExecutionResult
	env.OnActivity(serverActs.FinalizeBackupRun, mock.Anything, session, mock.Anything).
		Run(func(args mock.Arguments) { finalized = args.Get(2).(*temporal.BackupExecutionResult) }).Return(nil)

	env.ExecuteWorkflow(BackupJobWorkflow, jobID)
	if err := env.GetWorkflowError(); err == nil {
		t.Fatal("run with every volume failed must fail")
	}
	if finalized == nil || finalized.Status != db.RunStatusFailed {
		t.Errorf("finalized: %+v", finalized)
	}
}

// A failed resources step must not lose the volume outcomes: the run page shows
// which PVCs made it to PBS from a server-assembled partial manifest
func TestBackupJobWorkflowKubernetesResourcesFailKeepsVolumes(t *testing.T) {
	testSuite := &testsuite.WorkflowTestSuite{}
	env := testSuite.NewTestWorkflowEnvironment()
	jobID := uuid.New()
	k8sSpec := &k8sbackup.Spec{}
	_ = k8sSpec.Validate()
	session := &temporal.BackupSessionInfo{JobID: jobID, JobName: "cluster", AgentTaskQueue: "q", BackupRunID: uuid.New(), JobType: db.JobTypeKubernetes, K8sConfig: k8sSpec}
	plan := &k8sbackup.Plan{Volumes: []k8sbackup.VolumePlan{
		{Namespace: "a", PVCName: "good", GroupID: "g-pvc-a-good", Mode: k8sbackup.ModeLive},
		{Namespace: "a", PVCName: "bad", GroupID: "g-pvc-a-bad", Mode: k8sbackup.ModeLive},
	}}

	var serverActs *activities.ServerActivities
	var k8sActs *activities.K8sAgentActivities
	env.OnActivity(serverActs.PrepareBackupSession, mock.Anything, jobID).Return(session, nil)
	env.OnActivity(k8sActs.DiscoverKubernetesBackup, mock.Anything, session).Return(plan, nil)
	env.OnActivity(k8sActs.BackupKubernetesVolume, mock.Anything, mock.Anything, mock.Anything).Return(
		func(_ context.Context, _ *temporal.BackupSessionInfo, vol k8sbackup.VolumePlan) (*k8sbackup.VolumeResult, error) {
			if vol.PVCName == "bad" {
				return nil, errors.New("PodSecurity baseline: DAC_READ_SEARCH")
			}
			return &k8sbackup.VolumeResult{Namespace: vol.Namespace, PVCName: vol.PVCName, GroupID: vol.GroupID, Mode: vol.Mode,
				Status: "completed", SnapshotID: "host/" + vol.GroupID + "/2026-09-25T02:00:00Z", BytesScanned: 100, BytesUploaded: 10, ChunkCount: 4}, nil
		})
	env.OnActivity(k8sActs.BackupKubernetesResources, mock.Anything, session, mock.Anything, mock.Anything).
		Return(nil, errors.New("upload tunnel closed"))
	var finalized *temporal.BackupExecutionResult
	env.OnActivity(serverActs.FinalizeBackupRun, mock.Anything, session, mock.Anything).
		Run(func(args mock.Arguments) { finalized = args.Get(2).(*temporal.BackupExecutionResult) }).Return(nil)

	env.ExecuteWorkflow(BackupJobWorkflow, jobID)
	if err := env.GetWorkflowError(); err == nil {
		t.Fatal("a failed resources step must fail the run")
	}
	if finalized == nil || finalized.Status != db.RunStatusFailed {
		t.Fatalf("finalized: %+v", finalized)
	}
	if !strings.Contains(finalized.ErrorMessage, "after 1 of 2 volumes completed (1 failed)") || !strings.Contains(finalized.ErrorMessage, "upload tunnel closed") {
		t.Errorf("error message: %q", finalized.ErrorMessage)
	}
	if finalized.BytesUploaded != 10 || finalized.ChunkCount != 4 {
		t.Errorf("completed volume not aggregated: %+v", finalized)
	}
	var wrapper struct {
		Type     string             `json:"type"`
		Manifest k8sbackup.Manifest `json:"manifest"`
	}
	if err := json.Unmarshal(finalized.Details, &wrapper); err != nil {
		t.Fatalf("details %s: %v", finalized.Details, err)
	}
	m := wrapper.Manifest
	if wrapper.Type != "kubernetes" || !m.Partial || m.Job.Name != "cluster" || len(m.Volumes) != 2 {
		t.Fatalf("partial manifest: type=%s %+v", wrapper.Type, m)
	}
	byName := map[string]k8sbackup.VolumeResult{}
	for _, v := range m.Volumes {
		byName[v.PVCName] = v
	}
	if byName["good"].Status != "completed" || byName["good"].SnapshotID == "" || byName["bad"].Status != "failed" || !strings.Contains(byName["bad"].Error, "DAC_READ_SEARCH") {
		t.Errorf("volumes: %+v", byName)
	}
}
