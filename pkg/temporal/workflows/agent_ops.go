package workflows

import (
	"fmt"
	"time"

	"github.com/osshield/fallbck/pkg/inventory"
	fbtemporal "github.com/osshield/fallbck/pkg/temporal"
	"github.com/osshield/fallbck/pkg/temporal/activities"
	sdktemporal "go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

// AgentOpsWorkflow runs one operator action as an activity on the agent's queue. It is
// short-lived and never retried: an agent that does not pick the task up within the
// schedule timeout is simply offline, which the caller reports.
func AgentOpsWorkflow(ctx workflow.Context, req fbtemporal.AgentOpsRequest) (*fbtemporal.AgentOpsResult, error) {
	if req.AgentTaskQueue == "" {
		return nil, fmt.Errorf("agent task queue is required")
	}
	opts := workflow.ActivityOptions{
		TaskQueue:              req.AgentTaskQueue,
		ScheduleToStartTimeout: 20 * time.Second,
		StartToCloseTimeout:    90 * time.Second,
		RetryPolicy:            &sdktemporal.RetryPolicy{MaximumAttempts: 1},
	}
	actx := workflow.WithActivityOptions(ctx, opts)
	var ops *activities.AgentOpsActivities
	out := &fbtemporal.AgentOpsResult{}
	switch req.Action {
	case "logs":
		var logs inventory.LogsResult
		if err := workflow.ExecuteActivity(actx, ops.GetAgentLogs).Get(actx, &logs); err != nil {
			return nil, err
		}
		out.Logs = &logs
	case "inventory":
		var detail inventory.Detail
		if err := workflow.ExecuteActivity(actx, ops.GetAgentInventory).Get(actx, &detail); err != nil {
			return nil, err
		}
		out.Inventory = &detail
	default:
		return nil, fmt.Errorf("unknown agent action %q", req.Action)
	}
	return out, nil
}
