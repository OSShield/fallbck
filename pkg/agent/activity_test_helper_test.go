package agent_test

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/auth"
	"github.com/osshield/fallbck/pkg/db"
	"github.com/osshield/fallbck/pkg/gateway"
	"github.com/osshield/fallbck/pkg/proxy"
	"github.com/osshield/fallbck/pkg/temporal"
	"github.com/osshield/fallbck/pkg/temporal/activities"
	"go.temporal.io/sdk/testsuite"
	"go.temporal.io/sdk/worker"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
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

type staticVerifier struct{ claims *auth.AgentClaims }

func (s staticVerifier) Verify(_ context.Context, bearer string) (*auth.AgentClaims, error) {
	if bearer == "Bearer agent-token" {
		return s.claims, nil
	}
	return nil, auth.ErrInvalidToken
}

type oneTarget struct{ target *db.BackupTarget }

func (o oneTarget) GetTargetByID(_ context.Context, id uuid.UUID, _ db.Scope) (*db.BackupTarget, error) {
	if id == o.target.ID {
		return o.target, nil
	}
	return nil, db.ErrNotFound
}

type tokenCreds struct{}

func (tokenCreds) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{"authorization": "Bearer agent-token"}, nil
}
func (tokenCreds) RequireTransportSecurity() bool { return false }

// tunnelHarness is the server side of a run for one target (gateway with agent auth
// and the backup tunnel, on an h2c listener) plus the agent's connection to it
type tunnelHarness struct {
	tm      *auth.TokenManager
	agentID uuid.UUID
	target  *db.BackupTarget
	conn    *grpc.ClientConn
}

func startTunnel(t *testing.T, target *db.BackupTarget) *tunnelHarness {
	t.Helper()
	h := &tunnelHarness{tm: auth.NewTokenManager("secret-jwt-key-32-bytes-long-1234"), agentID: uuid.New(), target: target}
	gw := gateway.New(nil, staticVerifier{&auth.AgentClaims{AgentID: h.agentID, TaskQueue: "q"}}, "default", nil)
	proxy.NewBackupTunnel(h.tm, oneTarget{target}, nil).Register(gw)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h2c.NewHandler(gw.Handler(http.NotFoundHandler()), &http2.Server{}), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { gw.GracefulStop(); _ = srv.Close() })

	h.conn, err = grpc.NewClient(l.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithPerRPCCredentials(tokenCreds{}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.conn.Close() })
	return h
}

// session is what PrepareBackupSession would produce for a host backup of paths
func (h *tunnelHarness) session(t *testing.T, backupID string, backupTime int64, paths ...string) *temporal.BackupSessionInfo {
	t.Helper()
	claims := auth.BackupTicketClaims{
		JobID: uuid.New(), AgentID: h.agentID, TargetID: h.target.ID, Datastore: h.target.Datastore, Namespace: h.target.Namespace,
		BackupType: "host", BackupID: backupID, BackupTime: backupTime,
	}
	ticket, err := h.tm.CreateBackupTicket(claims, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return &temporal.BackupSessionInfo{
		JobID: claims.JobID, AgentID: h.agentID, TargetID: h.target.ID, AgentTaskQueue: "q",
		Ticket: ticket, Datastore: h.target.Datastore, Namespace: h.target.Namespace,
		BackupType: claims.BackupType, BackupID: backupID, BackupTime: backupTime,
		PxarFormat: h.target.PxarFormat, BackupPaths: paths, BackupRunID: uuid.New(),
	}
}
