package activities

import (
	"context"
	"log/slog"
	"time"

	"github.com/osshield/fallbck/pkg/inventory"
)

// AgentOpsActivities are the operator actions of the agent status page, run on the
// agent's own task queue like backups: the recent log lines and the full inventory.
// Every agent binary registers one; the inventory collector is per agent type.
type AgentOpsActivities struct {
	// LogTail returns the agent's recent log output (the in-memory ring)
	LogTail func() string
	// LogLevel names the current log level for the logs answer
	LogLevel func() string
	// Detail builds the full inventory (nil: only the summary parts are known)
	Detail func(ctx context.Context) *inventory.Detail
}

// GetAgentLogs returns the agent's recent log lines
func (a *AgentOpsActivities) GetAgentLogs(ctx context.Context) (*inventory.LogsResult, error) {
	res := &inventory.LogsResult{At: time.Now().UTC()}
	if a.LogTail != nil {
		res.Lines = a.LogTail()
	}
	if a.LogLevel != nil {
		res.Level = a.LogLevel()
	}
	slog.Debug("Agent logs requested by the server", "bytes", len(res.Lines))
	return res, nil
}

// GetAgentInventory builds and returns the full inventory
func (a *AgentOpsActivities) GetAgentInventory(ctx context.Context) (*inventory.Detail, error) {
	if a.Detail == nil {
		return &inventory.Detail{}, nil
	}
	slog.Info("Inventory requested by the server")
	return a.Detail(ctx), nil
}
