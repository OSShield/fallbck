package gateway

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/auth"
	commonpb "go.temporal.io/api/common/v1"
	namespacepb "go.temporal.io/api/namespace/v1"
	taskqueuepb "go.temporal.io/api/taskqueue/v1"
	"go.temporal.io/api/workflowservice/v1"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// fakeBackend records what reaches the "real" frontend
type fakeBackend struct {
	workflowservice.WorkflowServiceClient // nil: any unexpected call panics
	polled                                []string
	lastMD                                metadata.MD
}

func (f *fakeBackend) GetSystemInfo(ctx context.Context, _ *workflowservice.GetSystemInfoRequest, _ ...grpc.CallOption) (*workflowservice.GetSystemInfoResponse, error) {
	f.lastMD, _ = metadata.FromOutgoingContext(ctx)
	return &workflowservice.GetSystemInfoResponse{ServerVersion: "fake"}, nil
}

func (f *fakeBackend) DescribeNamespace(context.Context, *workflowservice.DescribeNamespaceRequest, ...grpc.CallOption) (*workflowservice.DescribeNamespaceResponse, error) {
	return &workflowservice.DescribeNamespaceResponse{NamespaceInfo: &namespacepb.NamespaceInfo{
		Name:         "default",
		Capabilities: &namespacepb.NamespaceInfo_Capabilities{EagerWorkflowStart: true, WorkerHeartbeats: true},
	}}, nil
}

func (f *fakeBackend) PollActivityTaskQueue(ctx context.Context, req *workflowservice.PollActivityTaskQueueRequest, _ ...grpc.CallOption) (*workflowservice.PollActivityTaskQueueResponse, error) {
	f.lastMD, _ = metadata.FromOutgoingContext(ctx)
	f.polled = append(f.polled, req.GetTaskQueue().GetName())
	return &workflowservice.PollActivityTaskQueueResponse{TaskToken: []byte("tok"), ActivityId: "a1"}, nil
}

func (f *fakeBackend) RespondActivityTaskCompleted(context.Context, *workflowservice.RespondActivityTaskCompletedRequest, ...grpc.CallOption) (*workflowservice.RespondActivityTaskCompletedResponse, error) {
	return &workflowservice.RespondActivityTaskCompletedResponse{}, nil
}

type fakeVerifier struct{ tokens map[string]*auth.AgentClaims }

func (f *fakeVerifier) Verify(_ context.Context, bearer string) (*auth.AgentClaims, error) {
	c, ok := f.tokens[bearer]
	if !ok {
		return nil, auth.ErrInvalidToken
	}
	return c, nil
}

type bearer string

func (b bearer) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{"authorization": string(b)}, nil
}
func (bearer) RequireTransportSecurity() bool { return false }

// startGateway serves the gateway through an h2c http.Server exactly like production
func startGateway(t *testing.T, backend *fakeBackend, verifier AgentVerifier) string {
	t.Helper()
	g := New(backend, verifier, "default", nil)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTeapot) })
	srv := &http.Server{Handler: h2c.NewHandler(g.Handler(fallback), &http2.Server{}), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() {
		g.GracefulStop()
		_ = srv.Close()
	})
	return l.Addr().String()
}

func dial(t *testing.T, addr string, token string) workflowservice.WorkflowServiceClient {
	t.Helper()
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	if token != "" {
		opts = append(opts, grpc.WithPerRPCCredentials(bearer(token)))
	}
	conn, err := grpc.NewClient(addr, opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return workflowservice.NewWorkflowServiceClient(conn)
}

func TestGatewayAuthorization(t *testing.T) {
	agentA, agentB := uuid.New(), uuid.New()
	verifier := &fakeVerifier{tokens: map[string]*auth.AgentClaims{
		"Bearer token-a": {AgentID: agentA, TaskQueue: "fallbck-agent-a"},
		"Bearer token-b": {AgentID: agentB, TaskQueue: "fallbck-agent-b"},
	}}
	backend := &fakeBackend{}
	addr := startGateway(t, backend, verifier)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	a := dial(t, addr, "Bearer token-a")
	anon := dial(t, addr, "")
	bad := dial(t, addr, "Bearer nope")

	code := func(err error) codes.Code { return status.Code(err) }

	// unauthenticated / invalid
	if _, err := anon.GetSystemInfo(ctx, &workflowservice.GetSystemInfoRequest{}); code(err) != codes.Unauthenticated {
		t.Errorf("anonymous GetSystemInfo: %v", err)
	}
	if _, err := bad.GetSystemInfo(ctx, &workflowservice.GetSystemInfoRequest{}); code(err) != codes.Unauthenticated {
		t.Errorf("bad token GetSystemInfo: %v", err)
	}

	// allowed, and the agent's authorization header must not reach the backend
	ctxWithClient := metadata.AppendToOutgoingContext(ctx, "client-name", "temporal-go")
	if _, err := a.GetSystemInfo(ctxWithClient, &workflowservice.GetSystemInfoRequest{}); err != nil {
		t.Fatalf("GetSystemInfo: %v", err)
	}
	if len(backend.lastMD.Get("authorization")) != 0 {
		t.Error("authorization header leaked to backend")
	}
	if got := backend.lastMD.Get("client-name"); len(got) != 1 || got[0] != "temporal-go" {
		t.Errorf("client metadata not forwarded: %v", backend.lastMD)
	}

	// DescribeNamespace: capabilities stripped
	ns, err := a.DescribeNamespace(ctx, &workflowservice.DescribeNamespaceRequest{Namespace: "default"})
	if err != nil {
		t.Fatalf("DescribeNamespace: %v", err)
	}
	if caps := ns.GetNamespaceInfo().GetCapabilities(); caps.GetWorkerHeartbeats() || !caps.GetEagerWorkflowStart() {
		t.Errorf("capabilities not shaped as expected: %+v", caps)
	}
	if _, err := a.DescribeNamespace(ctx, &workflowservice.DescribeNamespaceRequest{Namespace: "other"}); code(err) != codes.PermissionDenied {
		t.Errorf("foreign namespace: %v", err)
	}

	// Polling own queue works; polling another agent's queue is denied
	if _, err := a.PollActivityTaskQueue(ctx, &workflowservice.PollActivityTaskQueueRequest{
		Namespace: "default", TaskQueue: &taskqueuepb.TaskQueue{Name: "fallbck-agent-a"},
	}); err != nil {
		t.Fatalf("poll own queue: %v", err)
	}
	if _, err := a.PollActivityTaskQueue(ctx, &workflowservice.PollActivityTaskQueueRequest{
		Namespace: "default", TaskQueue: &taskqueuepb.TaskQueue{Name: "fallbck-agent-b"},
	}); code(err) != codes.PermissionDenied {
		t.Errorf("poll foreign queue: %v", err)
	}
	if _, err := a.PollActivityTaskQueue(ctx, &workflowservice.PollActivityTaskQueueRequest{
		Namespace: "default", TaskQueue: &taskqueuepb.TaskQueue{Name: "fallbck-server-queue"},
	}); code(err) != codes.PermissionDenied {
		t.Errorf("poll server queue: %v", err)
	}
	if len(backend.polled) != 1 || backend.polled[0] != "fallbck-agent-a" {
		t.Errorf("backend polls = %v", backend.polled)
	}

	// Respond by task token is forwarded
	if _, err := a.RespondActivityTaskCompleted(ctx, &workflowservice.RespondActivityTaskCompletedRequest{Namespace: "default", TaskToken: []byte("tok")}); err != nil {
		t.Errorf("RespondActivityTaskCompleted: %v", err)
	}

	// Explicitly denied and unimplemented methods
	if _, err := a.RespondActivityTaskCompletedById(ctx, &workflowservice.RespondActivityTaskCompletedByIdRequest{Namespace: "default", WorkflowId: "wf", ActivityId: "a1"}); code(err) != codes.PermissionDenied {
		t.Errorf("ById variant: %v", err)
	}
	if _, err := a.PollWorkflowTaskQueue(ctx, &workflowservice.PollWorkflowTaskQueueRequest{Namespace: "default", TaskQueue: &taskqueuepb.TaskQueue{Name: "fallbck-agent-a"}}); code(err) != codes.PermissionDenied {
		t.Errorf("PollWorkflowTaskQueue: %v", err)
	}
	if _, err := a.StartWorkflowExecution(ctx, &workflowservice.StartWorkflowExecutionRequest{Namespace: "default", WorkflowId: "x", WorkflowType: &commonpb.WorkflowType{Name: "Backup"}, TaskQueue: &taskqueuepb.TaskQueue{Name: "fallbck-server-queue"}}); code(err) != codes.Unimplemented {
		t.Errorf("StartWorkflowExecution: %v", err)
	}
	if _, err := a.TerminateWorkflowExecution(ctx, &workflowservice.TerminateWorkflowExecutionRequest{Namespace: "default"}); code(err) != codes.Unimplemented {
		t.Errorf("TerminateWorkflowExecution: %v", err)
	}

	// Non-gRPC traffic on the same port reaches the fallback handler
	resp, err := http.Get("http://" + addr + "/api/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusTeapot {
		t.Errorf("fallback handler status = %d", resp.StatusCode)
	}
}

func TestVerifierErrorsMapToInternal(t *testing.T) {
	backend := &fakeBackend{}
	addr := startGateway(t, backend, verifierFunc(func(context.Context, string) (*auth.AgentClaims, error) {
		return nil, errors.New("database down")
	}))
	c := dial(t, addr, "Bearer x")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := c.GetSystemInfo(ctx, &workflowservice.GetSystemInfoRequest{}); status.Code(err) != codes.Internal {
		t.Errorf("expected Internal for verifier failure, got %v", err)
	}
}

type verifierFunc func(context.Context, string) (*auth.AgentClaims, error)

func (f verifierFunc) Verify(ctx context.Context, b string) (*auth.AgentClaims, error) {
	return f(ctx, b)
}
