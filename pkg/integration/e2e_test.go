//go:build sqlite

// Package integration boots the real embedded Temporal server, the agent gateway over
// h2c, a server-side worker and an agent worker that authenticates through the gateway,
// and runs BackupJobWorkflow end to end.
package integration

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/auth"
	"github.com/osshield/fallbck/pkg/config"
	"github.com/osshield/fallbck/pkg/db"
	"github.com/osshield/fallbck/pkg/gateway"
	fbtemporal "github.com/osshield/fallbck/pkg/temporal"
	"github.com/osshield/fallbck/pkg/temporal/activities"
	"github.com/osshield/fallbck/pkg/temporal/embedded"
	"github.com/osshield/fallbck/pkg/temporal/workflows"
	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/worker"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// agentStore is the revocation-state store backing the verifier (no Postgres in tests)
type agentStore struct {
	states map[uuid.UUID]*db.AgentAuthState
}

func (s *agentStore) GetAgentAuthState(_ context.Context, id uuid.UUID) (*db.AgentAuthState, error) {
	st, ok := s.states[id]
	if !ok {
		return nil, db.ErrNotFound
	}
	return st, nil
}

// fakeAgentActivities stands in for the filesystem backup on the agent side
type fakeAgentActivities struct {
	executed chan *fbtemporal.BackupSessionInfo
	// block makes the activity heartbeat until its context is cancelled (cancellation test)
	block   bool
	started chan struct{}
}

func (f *fakeAgentActivities) ExecuteFilesystemBackup(ctx context.Context, session *fbtemporal.BackupSessionInfo) (*fbtemporal.BackupExecutionResult, error) {
	activity.RecordHeartbeat(ctx, "working")
	f.executed <- session
	if f.block {
		select {
		case f.started <- struct{}{}:
		default:
		}
		// Like the real engine: keep heartbeating, stop when the server cancels us
		for {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(200 * time.Millisecond):
				activity.RecordHeartbeat(ctx, "still working")
			}
		}
	}
	return &fbtemporal.BackupExecutionResult{
		Status:        db.RunStatusCompleted,
		BytesScanned:  4096,
		BytesUploaded: 1024,
		DedupRatio:    4.0,
		ChunkCount:    2,
		SnapshotID:    "snap-1",
	}, nil
}

func freePortBase(t *testing.T) int {
	t.Helper()
	for base := 30233; base < 60000; base += 100 {
		ok := true
		for _, off := range []int{0, 1, 2, 3, 6, -300, -299, -298, -297, -294} {
			l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", itoa(base+off)))
			if err != nil {
				ok = false
				break
			}
			_ = l.Close()
		}
		if ok {
			return base
		}
	}
	t.Fatal("no free port range")
	return 0
}

func itoa(i int) string { return uuid.Nil.String()[:0] + fmtInt(i) }

func fmtInt(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

func TestBackupWorkflowThroughGateway(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// 1. Embedded Temporal (sqlite, in-memory)
	emb, err := embedded.New(embedded.Config{
		PortBase:    freePortBase(t),
		Persistence: embedded.PersistenceSQLite,
		Namespace:   "default",
		StopTimeout: 5 * time.Second,
	}, logger)
	if err != nil {
		t.Fatalf("embedded.New: %v", err)
	}
	if err := emb.Start(ctx); err != nil {
		t.Fatalf("embedded.Start: %v", err)
	}
	defer func() { _ = emb.Stop() }()

	// 2. Server-side pieces: token manager, verifier, gateway on an h2c listener
	cfg := config.DefaultServerConfig()
	cfg.JWTSecret = "e2e-test-jwt-secret-that-is-long-enough-123456"
	cfg.PublicURL = "http://fallbck.test"
	tm := auth.NewTokenManager(cfg.JWTSecret)

	// PrepareBackupSession's DB-less branch dispatches to this queue
	const agentQueue = "fallbck-agent-dev"
	agentID, otherID := uuid.New(), uuid.New()
	store := &agentStore{states: map[uuid.UUID]*db.AgentAuthState{
		agentID: {ID: agentID, TaskQueue: agentQueue, TokenVersion: 1},
		otherID: {ID: otherID, TaskQueue: "fallbck-agent-other", TokenVersion: 1},
	}}
	verifier := auth.NewAgentVerifier(tm, store, time.Second)

	backendConn, err := gateway.Dial(emb.FrontendAddr(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer backendConn.Close()
	gw := gateway.New(workflowservice.NewWorkflowServiceClient(backendConn), verifier, "default", logger)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	httpSrv := &http.Server{Handler: h2c.NewHandler(gw.Handler(fallback), &http2.Server{}), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = httpSrv.Serve(l) }()
	defer func() {
		gw.GracefulStop()
		_ = httpSrv.Close()
	}()
	gatewayAddr := l.Addr().String()

	// 3. Server worker (workflow + server activities) straight on the loopback frontend
	serverClient, err := fbtemporal.NewLoopbackClient(emb.FrontendAddr(), "default")
	if err != nil {
		t.Fatal(err)
	}
	defer serverClient.Close()
	serverWorker := fbtemporal.NewServerWorker(serverClient, nil, cfg, tm)
	serverWorker.Register(workflows.BackupJobWorkflow, activities.NewServerActivities(nil, cfg, tm))
	if err := serverWorker.Start(); err != nil {
		t.Fatal(err)
	}
	defer serverWorker.Stop()

	// 4. Agent worker: reaches Temporal only through the gateway with its bearer token
	token, _, err := tm.CreateAgentToken(agentID, agentQueue, 1, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	agentClient, err := client.Dial(client.Options{
		HostPort:          gatewayAddr,
		Namespace:         "default",
		Credentials:       client.NewAPIKeyStaticCredentials(token),
		ConnectionOptions: client.ConnectionOptions{TLSDisabled: true},
	})
	if err != nil {
		t.Fatalf("agent client dial through gateway: %v", err)
	}
	defer agentClient.Close()

	acts := &fakeAgentActivities{executed: make(chan *fbtemporal.BackupSessionInfo, 1)}
	agentWorker := worker.New(agentClient, agentQueue, worker.Options{DisableWorkflowWorker: true})
	agentWorker.RegisterActivityWithOptions(acts.ExecuteFilesystemBackup, activity.RegisterOptions{Name: "ExecuteFilesystemBackup"})
	if err := agentWorker.Start(); err != nil {
		t.Fatalf("agent worker start: %v", err)
	}
	defer agentWorker.Stop()

	// A second agent whose token belongs to another queue must not be able to serve this one
	otherToken, _, _ := tm.CreateAgentToken(otherID, "fallbck-agent-other", 1, time.Hour)
	otherClient, err := client.Dial(client.Options{
		HostPort:          gatewayAddr,
		Namespace:         "default",
		Credentials:       client.NewAPIKeyStaticCredentials(otherToken),
		ConnectionOptions: client.ConnectionOptions{TLSDisabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer otherClient.Close()
	intruder := worker.New(otherClient, agentQueue, worker.Options{DisableWorkflowWorker: true})
	stolen := make(chan struct{}, 1)
	intruder.RegisterActivityWithOptions(func(context.Context, *fbtemporal.BackupSessionInfo) (*fbtemporal.BackupExecutionResult, error) {
		stolen <- struct{}{}
		return nil, nil
	}, activity.RegisterOptions{Name: "ExecuteFilesystemBackup"})
	if err := intruder.Start(); err != nil {
		t.Fatal(err)
	}
	defer intruder.Stop()

	// 5. Run the real workflow
	jobID := uuid.New()
	run, err := serverClient.ExecuteWorkflow(ctx, client.StartWorkflowOptions{
		ID:        "backup-job-" + jobID.String(),
		TaskQueue: fbtemporal.ServerTaskQueue,
	}, workflows.BackupJobWorkflow, jobID)
	if err != nil {
		t.Fatalf("ExecuteWorkflow: %v", err)
	}

	var result fbtemporal.BackupExecutionResult
	if err := run.Get(ctx, &result); err != nil {
		t.Fatalf("workflow failed: %v", err)
	}
	if result.Status != db.RunStatusCompleted || result.SnapshotID != "snap-1" {
		t.Errorf("unexpected result %+v", result)
	}

	select {
	case session := <-acts.executed:
		if session.JobID != jobID || session.AgentTaskQueue != agentQueue {
			t.Errorf("agent received unexpected session %+v", session)
		}
	default:
		t.Error("agent activity did not execute")
	}
	select {
	case <-stolen:
		t.Error("intruder agent was able to execute an activity on a foreign queue")
	default:
	}

	// 6. Cancellation: a long-running backup is cancelled by the operator. The agent
	// learns about it through its heartbeat, stops, and the run finalises as cancelled.
	agentWorker.Stop()
	blocking := &fakeAgentActivities{executed: make(chan *fbtemporal.BackupSessionInfo, 1), block: true, started: make(chan struct{}, 1)}
	cancelWorker := worker.New(agentClient, agentQueue, worker.Options{DisableWorkflowWorker: true})
	cancelWorker.RegisterActivityWithOptions(blocking.ExecuteFilesystemBackup, activity.RegisterOptions{Name: "ExecuteFilesystemBackup"})
	if err := cancelWorker.Start(); err != nil {
		t.Fatal(err)
	}
	defer cancelWorker.Stop()

	cancelJob := uuid.New()
	cancelRun, err := serverClient.ExecuteWorkflow(ctx, client.StartWorkflowOptions{
		ID:        "backup-job-" + cancelJob.String(),
		TaskQueue: fbtemporal.ServerTaskQueue,
	}, workflows.BackupJobWorkflow, cancelJob)
	if err != nil {
		t.Fatalf("ExecuteWorkflow (cancel scenario): %v", err)
	}
	select {
	case <-blocking.started:
	case <-time.After(30 * time.Second):
		t.Fatal("agent activity did not start")
	}
	if err := serverClient.CancelWorkflow(ctx, cancelRun.GetID(), cancelRun.GetRunID()); err != nil {
		t.Fatalf("CancelWorkflow: %v", err)
	}
	var cancelled fbtemporal.BackupExecutionResult
	err = cancelRun.Get(ctx, &cancelled)
	if err == nil {
		t.Fatalf("expected the workflow to end cancelled, got result %+v", cancelled)
	}
	var canceledErr *temporal.CanceledError
	if !errors.As(err, &canceledErr) {
		t.Fatalf("expected CanceledError, got %v", err)
	}
	// The workflow's result payload is not available on cancellation; confirm via history
	// that FinalizeBackupRun ran after the cancel request.
	finalized := false
	iter := serverClient.GetWorkflowHistory(ctx, cancelRun.GetID(), cancelRun.GetRunID(), false, enumspb.HISTORY_EVENT_FILTER_TYPE_ALL_EVENT)
	for iter.HasNext() {
		ev, err := iter.Next()
		if err != nil {
			t.Fatal(err)
		}
		if a := ev.GetActivityTaskScheduledEventAttributes(); a != nil && a.GetActivityType().GetName() == "FinalizeBackupRun" {
			finalized = true
		}
	}
	if !finalized {
		t.Error("FinalizeBackupRun was not scheduled after cancellation")
	}
}
