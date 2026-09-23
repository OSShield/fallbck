package workflows

import (
	"errors"
	"testing"

	"github.com/osshield/fallbck/pkg/inventory"
	fbtemporal "github.com/osshield/fallbck/pkg/temporal"
	"github.com/osshield/fallbck/pkg/temporal/activities"
	"github.com/stretchr/testify/mock"
	"go.temporal.io/sdk/testsuite"
)

func TestAgentOpsWorkflowLogs(t *testing.T) {
	env := (&testsuite.WorkflowTestSuite{}).NewTestWorkflowEnvironment()
	var ops *activities.AgentOpsActivities
	env.OnActivity(ops.GetAgentLogs, mock.Anything).Return(&inventory.LogsResult{Lines: "hello", Level: "info"}, nil)
	env.ExecuteWorkflow(AgentOpsWorkflow, fbtemporal.AgentOpsRequest{AgentTaskQueue: "q", Action: "logs"})
	if !env.IsWorkflowCompleted() {
		t.Fatal("did not complete")
	}
	var res fbtemporal.AgentOpsResult
	if err := env.GetWorkflowResult(&res); err != nil || res.Logs == nil || res.Logs.Lines != "hello" || res.Inventory != nil {
		t.Fatalf("result %+v err %v", res, err)
	}
}

func TestAgentOpsWorkflowRejectsBadInput(t *testing.T) {
	env := (&testsuite.WorkflowTestSuite{}).NewTestWorkflowEnvironment()
	env.ExecuteWorkflow(AgentOpsWorkflow, fbtemporal.AgentOpsRequest{Action: "logs"})
	if err := env.GetWorkflowError(); err == nil {
		t.Error("missing task queue accepted")
	}
	env = (&testsuite.WorkflowTestSuite{}).NewTestWorkflowEnvironment()
	var ops *activities.AgentOpsActivities
	env.OnActivity(ops.GetAgentInventory, mock.Anything).Return(nil, errors.New("offline"))
	env.ExecuteWorkflow(AgentOpsWorkflow, fbtemporal.AgentOpsRequest{AgentTaskQueue: "q", Action: "inventory"})
	if err := env.GetWorkflowError(); err == nil {
		t.Error("activity failure not propagated")
	}
}
