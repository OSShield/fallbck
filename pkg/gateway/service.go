package gateway

import (
	"context"

	"github.com/osshield/fallbck/pkg/auth"
	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/api/workflowservice/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// service implements exactly the WorkflowService methods an activity-only SDK worker
// uses. Everything else falls through to UnimplementedWorkflowServiceServer, or is
// explicitly denied below where the SDK could otherwise be tricked into calling it.
type service struct {
	workflowservice.UnimplementedWorkflowServiceServer
	g *Gateway
}

type namespaced interface{ GetNamespace() string }

// checkNamespace confines agents to the server's namespace
func (s *service) checkNamespace(ctx context.Context, req namespaced) error {
	if req.GetNamespace() != s.g.namespace {
		claims := auth.AgentFrom(ctx)
		s.g.logger.Warn("Agent attempted to access another namespace", "agent_id", claims.AgentID, "namespace", req.GetNamespace())
		return status.Errorf(codes.PermissionDenied, "namespace %q is not accessible", req.GetNamespace())
	}
	return nil
}

func (s *service) GetSystemInfo(ctx context.Context, req *workflowservice.GetSystemInfoRequest) (*workflowservice.GetSystemInfoResponse, error) {
	return s.g.backend.GetSystemInfo(s.g.outgoing(ctx), req)
}

// DescribeNamespace forwards the call but hides the worker-heartbeat capability so the
// SDK never attempts RecordWorkerHeartbeat (PollNexusTaskQueue is denied explicitly).
func (s *service) DescribeNamespace(ctx context.Context, req *workflowservice.DescribeNamespaceRequest) (*workflowservice.DescribeNamespaceResponse, error) {
	if err := s.checkNamespace(ctx, req); err != nil {
		return nil, err
	}
	resp, err := s.g.backend.DescribeNamespace(s.g.outgoing(ctx), req)
	if err != nil {
		return nil, err
	}
	if caps := resp.GetNamespaceInfo().GetCapabilities(); caps != nil {
		caps.WorkerHeartbeats = false
	}
	return resp, nil
}

// PollActivityTaskQueue is the one RPC where the agent names a task queue: it must be
// its own, and it must be a normal (non-sticky) queue.
func (s *service) PollActivityTaskQueue(ctx context.Context, req *workflowservice.PollActivityTaskQueueRequest) (*workflowservice.PollActivityTaskQueueResponse, error) {
	if err := s.checkNamespace(ctx, req); err != nil {
		return nil, err
	}
	claims := auth.AgentFrom(ctx)
	queue := req.GetTaskQueue()
	if queue.GetName() != claims.TaskQueue {
		s.g.logger.Warn("Agent attempted to poll a foreign task queue", "agent_id", claims.AgentID, "task_queue", queue.GetName(), "own_task_queue", claims.TaskQueue)
		return nil, status.Errorf(codes.PermissionDenied, "task queue %q does not belong to this agent", queue.GetName())
	}
	if kind := queue.GetKind(); kind != enumspb.TASK_QUEUE_KIND_NORMAL && kind != enumspb.TASK_QUEUE_KIND_UNSPECIFIED {
		return nil, status.Errorf(codes.PermissionDenied, "task queue kind %s is not permitted", kind)
	}
	return s.g.backend.PollActivityTaskQueue(s.g.outgoing(ctx), req)
}

func (s *service) RecordActivityTaskHeartbeat(ctx context.Context, req *workflowservice.RecordActivityTaskHeartbeatRequest) (*workflowservice.RecordActivityTaskHeartbeatResponse, error) {
	if err := s.checkNamespace(ctx, req); err != nil {
		return nil, err
	}
	return s.g.backend.RecordActivityTaskHeartbeat(s.g.outgoing(ctx), req)
}

func (s *service) RespondActivityTaskCompleted(ctx context.Context, req *workflowservice.RespondActivityTaskCompletedRequest) (*workflowservice.RespondActivityTaskCompletedResponse, error) {
	if err := s.checkNamespace(ctx, req); err != nil {
		return nil, err
	}
	return s.g.backend.RespondActivityTaskCompleted(s.g.outgoing(ctx), req)
}

func (s *service) RespondActivityTaskFailed(ctx context.Context, req *workflowservice.RespondActivityTaskFailedRequest) (*workflowservice.RespondActivityTaskFailedResponse, error) {
	if err := s.checkNamespace(ctx, req); err != nil {
		return nil, err
	}
	return s.g.backend.RespondActivityTaskFailed(s.g.outgoing(ctx), req)
}

func (s *service) RespondActivityTaskCanceled(ctx context.Context, req *workflowservice.RespondActivityTaskCanceledRequest) (*workflowservice.RespondActivityTaskCanceledResponse, error) {
	if err := s.checkNamespace(ctx, req); err != nil {
		return nil, err
	}
	return s.g.backend.RespondActivityTaskCanceled(s.g.outgoing(ctx), req)
}

func (s *service) ShutdownWorker(ctx context.Context, req *workflowservice.ShutdownWorkerRequest) (*workflowservice.ShutdownWorkerResponse, error) {
	if err := s.checkNamespace(ctx, req); err != nil {
		return nil, err
	}
	return s.g.backend.ShutdownWorker(s.g.outgoing(ctx), req)
}

// --- explicitly denied: reachable by an activity worker in principle, but they would
// let an agent act on activities it did not poll, or on other queues ---

func denied(method string) error {
	return status.Errorf(codes.PermissionDenied, "%s is not available to agents", method)
}

func (s *service) RecordActivityTaskHeartbeatById(context.Context, *workflowservice.RecordActivityTaskHeartbeatByIdRequest) (*workflowservice.RecordActivityTaskHeartbeatByIdResponse, error) {
	return nil, denied("RecordActivityTaskHeartbeatById")
}

func (s *service) RespondActivityTaskCompletedById(context.Context, *workflowservice.RespondActivityTaskCompletedByIdRequest) (*workflowservice.RespondActivityTaskCompletedByIdResponse, error) {
	return nil, denied("RespondActivityTaskCompletedById")
}

func (s *service) RespondActivityTaskFailedById(context.Context, *workflowservice.RespondActivityTaskFailedByIdRequest) (*workflowservice.RespondActivityTaskFailedByIdResponse, error) {
	return nil, denied("RespondActivityTaskFailedById")
}

func (s *service) RespondActivityTaskCanceledById(context.Context, *workflowservice.RespondActivityTaskCanceledByIdRequest) (*workflowservice.RespondActivityTaskCanceledByIdResponse, error) {
	return nil, denied("RespondActivityTaskCanceledById")
}

func (s *service) PollWorkflowTaskQueue(context.Context, *workflowservice.PollWorkflowTaskQueueRequest) (*workflowservice.PollWorkflowTaskQueueResponse, error) {
	return nil, denied("PollWorkflowTaskQueue")
}

func (s *service) PollNexusTaskQueue(context.Context, *workflowservice.PollNexusTaskQueueRequest) (*workflowservice.PollNexusTaskQueueResponse, error) {
	return nil, denied("PollNexusTaskQueue")
}

func (s *service) RecordWorkerHeartbeat(context.Context, *workflowservice.RecordWorkerHeartbeatRequest) (*workflowservice.RecordWorkerHeartbeatResponse, error) {
	return nil, denied("RecordWorkerHeartbeat")
}
