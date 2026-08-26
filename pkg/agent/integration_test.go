package agent_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/auth"
	"github.com/osshield/fallbck/pkg/config"
	"github.com/osshield/fallbck/pkg/db"
	"github.com/osshield/fallbck/pkg/proxy"
	"github.com/osshield/fallbck/pkg/temporal"
	"github.com/osshield/fallbck/pkg/temporal/activities"
	"github.com/osshield/fallbck/pkg/temporal/workflows"
	"github.com/stretchr/testify/mock"
	"go.temporal.io/sdk/testsuite"
)

func TestEndToEndBackupFlow(t *testing.T) {
	// 1. Mock Proxmox Backup Server (Upstream)
	var mu sync.Mutex
	receivedChunks := make(map[string][]byte)
	var receivedAuthHeader string

	mockPBS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		receivedAuthHeader = r.Header.Get("Authorization")
		digest := r.URL.Query().Get("digest")
		body, _ := io.ReadAll(r.Body)

		if digest != "" {
			receivedChunks[digest] = body
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{"status":"ok"}}`))
	}))
	defer mockPBS.Close()

	// 2. Setup Security & Proxy
	secret := "secret-jwt-key-32-bytes-long-1234"
	tm := auth.NewTokenManager(secret)

	pbsProxy := proxy.NewPBSProxy(nil, tm)
	proxyServer := httptest.NewServer(http.HandlerFunc(pbsProxy.HandleProxyRequest))
	defer proxyServer.Close()

	// 3. Create Test Directory Structure to Backup
	backupDir := t.TempDir()
	file1 := filepath.Join(backupDir, "app.conf")
	file2 := filepath.Join(backupDir, "data.bin")
	_ = os.WriteFile(file1, []byte("database_host = 10.0.0.1\nport = 5432\n"), 0644)
	_ = os.WriteFile(file2, []byte("Binary payload test content for deduplication and chunk verification"), 0644)

	// 4. IDs & Session
	jobID := uuid.New()
	agentID := uuid.New()
	targetID := uuid.New()

	// Register mock target in proxy cache
	pbsProxy.SetTarget(&db.BackupTarget{
		ID:                 targetID,
		Name:               "Mock PBS Target",
		TargetType:         "pbs",
		Endpoint:           mockPBS.URL,
		Datastore:          "backup-store",
		Namespace:          "production",
		AuthTokenEncrypted: "PBSAPIToken=root@pam!dev=secret",
		TLSVerify:          false,
	})

	claims := auth.BackupTicketClaims{
		JobID:      jobID,
		AgentID:    agentID,
		TargetID:   targetID,
		Datastore:  "backup-store",
		Namespace:  "production",
		BackupType: "host",
		BackupID:   "test-host",
		BackupTime: time.Now().Unix(),
	}

	ticket, err := tm.CreateBackupTicket(claims, 2*time.Hour)
	if err != nil {
		t.Fatalf("CreateBackupTicket failed: %v", err)
	}

	session := &temporal.BackupSessionInfo{
		JobID:          jobID,
		AgentID:        agentID,
		TargetID:       targetID,
		AgentTaskQueue: "fallbck-agent-test-queue",
		ProxyURL:       proxyServer.URL,
		Ticket:         ticket,
		Datastore:      "backup-store",
		Namespace:      "production",
		BackupPaths:    []string{backupDir},
		ExcludePaths:   []string{"*.tmp"},
		WorkflowID:     "backup-workflow-e2e",
		RunID:          "run-e2e-1",
		BackupRunID:    uuid.New(),
	}

	// 5. Test with Temporal Workflow Test Environment
	testSuite := &testsuite.WorkflowTestSuite{}
	env := testSuite.NewTestWorkflowEnvironment()

	serverConfig := config.DefaultServerConfig()
	serverActs := activities.NewServerActivities(nil, serverConfig, tm)
	agentActs := activities.NewAgentActivities()

	// Register actual activities
	env.RegisterActivity(serverActs.PrepareBackupSession)
	env.RegisterActivity(agentActs.ExecuteFilesystemBackup)
	env.RegisterActivity(serverActs.FinalizeBackupRun)
	env.RegisterActivity(serverActs.PruneJob)

	// Execute Workflow with custom session returned by PrepareBackupSession mock
	env.OnActivity(serverActs.PrepareBackupSession, mock.Anything, jobID).Return(session, nil)

	env.ExecuteWorkflow(workflows.BackupJobWorkflow, jobID)

	if !env.IsWorkflowCompleted() {
		t.Fatal("E2E Backup workflow failed to complete")
	}

	var result temporal.BackupExecutionResult
	err = env.GetWorkflowResult(&result)
	if err != nil {
		t.Fatalf("Workflow finished with error: %v", err)
	}

	// 6. Assertions
	if result.Status != db.RunStatusCompleted {
		t.Errorf("Expected status Completed, got %s (Error: %s)", result.Status, result.ErrorMessage)
	}

	if result.BytesScanned <= 0 {
		t.Errorf("Expected BytesScanned > 0, got %d", result.BytesScanned)
	}

	if result.ChunkCount != 2 {
		t.Errorf("Expected 2 chunks scanned & processed, got %d", result.ChunkCount)
	}

	mu.Lock()
	defer mu.Unlock()

	if len(receivedChunks) != 2 {
		t.Errorf("Expected 2 chunks received upstream by mock PBS, got %d", len(receivedChunks))
	}

	if receivedAuthHeader != "PBSAPIToken=root@pam!dev=secret" {
		t.Errorf("Expected upstream auth header 'PBSAPIToken=root@pam!dev=secret', got '%s'", receivedAuthHeader)
	}
}
