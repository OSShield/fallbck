package temporal

import (
	"fmt"
	"log/slog"

	"github.com/osshield/fallbck/pkg/auth"
	"github.com/osshield/fallbck/pkg/config"
	"github.com/osshield/fallbck/pkg/db"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
)

// ServerWorker manages the Temporal worker for server workflows and server activities
type ServerWorker struct {
	client       client.Client
	worker       worker.Worker
	database     *db.DB
	config       *config.ServerConfig
	tokenManager *auth.TokenManager
}

// NewServerWorker initializes the server-side Temporal workflow and activity worker
func NewServerWorker(c client.Client, database *db.DB, cfg *config.ServerConfig, tm *auth.TokenManager) *ServerWorker {
	w := worker.New(c, ServerTaskQueue, worker.Options{})
	return &ServerWorker{
		client:       c,
		worker:       w,
		database:     database,
		config:       cfg,
		tokenManager: tm,
	}
}

// RegisterWorkflowAndActivities registers workflows and server activities
func (sw *ServerWorker) Register(workflowFunc interface{}, serverActivities interface{}) {
	sw.worker.RegisterWorkflow(workflowFunc)
	sw.worker.RegisterActivity(serverActivities)
}

// Start launches the worker in the background
func (sw *ServerWorker) Start() error {
	slog.Info("Starting FallBCK Server Temporal worker", "task_queue", ServerTaskQueue)
	if err := sw.worker.Start(); err != nil {
		return fmt.Errorf("failed to start Temporal server worker: %w", err)
	}
	return nil
}

// Stop halts the worker gracefully
func (sw *ServerWorker) Stop() {
	if sw.worker != nil {
		sw.worker.Stop()
	}
}
