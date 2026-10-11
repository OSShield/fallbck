package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/db"
	"github.com/osshield/fallbck/pkg/temporal"
	"go.temporal.io/sdk/client"
)

// agentOpsTimeout bounds one operator action end to end (queueing included)
const agentOpsTimeout = 2 * time.Minute

// runAgentOp starts the AgentOpsWorkflow for the agent and waits for its result
func (s *ServerAPI) runAgentOp(ctx context.Context, agent *db.Agent, action string) (*temporal.AgentOpsResult, error) {
	if s.Temporal == nil {
		return nil, errors.New("temporal client is not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, agentOpsTimeout)
	defer cancel()
	we, err := s.Temporal.ExecuteWorkflow(ctx, client.StartWorkflowOptions{
		ID:                       fmt.Sprintf("agent-%s-%s-%d", action, agent.ID, time.Now().UnixNano()),
		TaskQueue:                "fallbck-server-queue",
		WorkflowExecutionTimeout: agentOpsTimeout,
	}, temporal.AgentOpsWorkflowName, temporal.AgentOpsRequest{AgentTaskQueue: agent.TaskQueue, Action: action})
	if err != nil {
		return nil, err
	}
	var res temporal.AgentOpsResult
	if err := we.Get(ctx, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// agentOpError maps a failed action to a status and message the UI can show
func agentOpError(err error) (int, string) {
	msg := err.Error()
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return http.StatusGatewayTimeout, "The agent did not answer in time (is it online?)"
	case containsAny(msg, "ScheduleToStart", "schedule to start", "activity ScheduleToStart"):
		return http.StatusGatewayTimeout, "The agent did not pick up the request: it is offline or not polling its task queue"
	case containsAny(msg, "unable to find activity", "activity type", "not registered"):
		return http.StatusNotImplemented, "The agent runs a version without this action; update it"
	}
	return http.StatusBadGateway, "Agent action failed: " + msg
}

func containsAny(s string, subs ...string) bool {
	l := strings.ToLower(s)
	for _, sub := range subs {
		if strings.Contains(l, strings.ToLower(sub)) {
			return true
		}
	}
	return false
}

// HandleAgentLogs fetches the agent's recent log lines (POST /agents/{id}/logs)
func (s *ServerAPI) HandleAgentLogs(w http.ResponseWriter, r *http.Request) {
	agent, ok := s.agentFromPath(w, r)
	if !ok {
		return
	}
	res, err := s.runAgentOp(r.Context(), agent, "logs")
	if err != nil {
		code, msg := agentOpError(err)
		slog.Warn("Agent logs action failed", "agent", agent.Hostname, "error", err)
		s.writeError(w, code, msg)
		return
	}
	s.writeJSON(w, http.StatusOK, res.Logs)
}

// HandleAgentInventory refreshes the agent's full inventory and stores it
// (POST /agents/{id}/inventory)
func (s *ServerAPI) HandleAgentInventory(w http.ResponseWriter, r *http.Request) {
	agent, ok := s.agentFromPath(w, r)
	if !ok {
		return
	}
	res, err := s.runAgentOp(r.Context(), agent, "inventory")
	if err != nil {
		code, msg := agentOpError(err)
		slog.Warn("Agent inventory action failed", "agent", agent.Hostname, "error", err)
		s.writeError(w, code, msg)
		return
	}
	data, err := json.Marshal(res.Inventory)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to encode inventory")
		return
	}
	if err := s.DB.SetAgentInventoryDetail(r.Context(), agent.ID, data); err != nil {
		slog.Warn("Storing agent inventory failed", "agent", agent.Hostname, "error", err)
	}
	// The summary part is fresh too
	if sum, err := json.Marshal(res.Inventory.Summary); err == nil {
		_, _ = s.DB.UpdateAgentHeartbeat(r.Context(), agent.ID, agent.Status, db.AgentCapabilities{PVEHost: agent.PVEHost, DockerHost: agent.DockerHost, DBTools: agent.DBTools, DBEngines: agent.DBEngines, Inventory: sum, SelfUpdate: agent.SelfUpdate, UpdateError: agent.UpdateError})
	}
	s.writeJSON(w, http.StatusOK, res.Inventory)
}

func (s *ServerAPI) agentFromPath(w http.ResponseWriter, r *http.Request) (*db.Agent, bool) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid agent ID")
		return nil, false
	}
	agent, err := s.DB.GetAgentByID(r.Context(), id)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "Agent not found")
		return nil, false
	}
	return agent, true
}
