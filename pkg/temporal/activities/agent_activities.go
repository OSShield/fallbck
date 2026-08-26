package activities

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/osshield/fallbck/pkg/agent/backup"
	"github.com/osshield/fallbck/pkg/db"
	"github.com/osshield/fallbck/pkg/temporal"
	"go.temporal.io/sdk/activity"
)

// AgentActivities provides activities executed on the client backup agent host
type AgentActivities struct {
	// ServerURL is the FallBCK server URL this agent is configured to talk to.
	// When set, the PBS proxy is reached through it instead of the server-advertised
	// public URL, which may not be routable from the agent's network (e.g. containers).
	ServerURL string
}

// NewAgentActivities creates a new AgentActivities instance
func NewAgentActivities() *AgentActivities {
	return &AgentActivities{}
}

// proxyURL resolves the PBS proxy base URL for a backup session
func (a *AgentActivities) proxyURL(session *temporal.BackupSessionInfo) string {
	if a.ServerURL != "" {
		return strings.TrimRight(a.ServerURL, "/") + "/pbs-proxy"
	}
	return session.ProxyURL
}

// ExecuteFilesystemBackup performs the filesystem backup on the agent host and streams chunks through the proxy
func (a *AgentActivities) ExecuteFilesystemBackup(ctx context.Context, session *temporal.BackupSessionInfo) (*temporal.BackupExecutionResult, error) {
	activityInfo := activity.GetInfo(ctx)
	proxyURL := a.proxyURL(session)
	slog.Info("Agent activity started: ExecuteFilesystemBackup",
		"activity_id", activityInfo.ActivityID,
		"job_id", session.JobID,
		"paths", session.BackupPaths,
		"proxy_url", proxyURL,
	)

	engine := backup.NewBackupEngine(proxyURL, session.Ticket, session.Datastore, session.Namespace)

	// Heartbeat callback feeding into Temporal activity progress
	onProgress := func(currentFile string, scanned, uploaded int64, chunks int) {
		progress := temporal.BackupHeartbeatProgress{
			CurrentFile:   currentFile,
			BytesScanned:  scanned,
			BytesUploaded: uploaded,
		}
		activity.RecordHeartbeat(ctx, progress)
	}

	result, err := engine.ExecuteFilesystemBackup(ctx, session.BackupPaths, session.ExcludePaths, onProgress)
	if err != nil {
		slog.Error("Agent backup execution failed", "error", err)
		return &temporal.BackupExecutionResult{
			Status:       db.RunStatusFailed,
			ErrorMessage: fmt.Sprintf("Backup execution failed: %v", err),
		}, err
	}

	return result, nil
}
