package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/agent/enrollment"
	"github.com/osshield/fallbck/pkg/api"
	"github.com/osshield/fallbck/pkg/config"
	"github.com/osshield/fallbck/pkg/temporal"
	"go.temporal.io/sdk/worker"
)

var AgentVersion = "0.1.0"

func main() {
	enrollCmd := flag.NewFlagSet("enroll", flag.ExitOnError)
	enrollServer := enrollCmd.String("server", "http://localhost:8080", "FallBCK server URL")
	enrollToken := enrollCmd.String("token", "", "One-time enrollment token")
	enrollDir := enrollCmd.String("data-dir", "", "Agent data directory")

	runCmd := flag.NewFlagSet("run", flag.ExitOnError)
	runConfig := runCmd.String("config", "", "Path to agent YAML configuration file")

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "enroll":
		_ = enrollCmd.Parse(os.Args[2:])
		if *enrollToken == "" {
			fmt.Println("Error: --token is required for enrollment")
			os.Exit(1)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		cfg, err := enrollment.EnrollAgent(ctx, *enrollServer, *enrollToken, *enrollDir)
		if err != nil {
			slog.Error("Agent enrollment failed", "error", err)
			os.Exit(1)
		}

		fmt.Println("✓ Agent enrolled successfully!")
		fmt.Printf("  Agent ID:   %s\n", cfg.AgentID)
		fmt.Printf("  Task Queue: %s\n", cfg.TaskQueue)
		fmt.Printf("  Config:     %s\n", filepath.Join(cfg.DataDir, "agent.yaml"))

	case "run", "daemon":
		_ = runCmd.Parse(os.Args[2:])

		configPath := *runConfig
		if configPath == "" {
			home, _ := os.UserHomeDir()
			defaultPath := filepath.Join(home, ".fallbck", "agent", "agent.yaml")
			if _, err := os.Stat(defaultPath); err == nil {
				configPath = defaultPath
			}
		}

		cfg, err := config.LoadAgentConfig(configPath)
		if err != nil {
			slog.Error("Failed to load agent configuration", "error", err)
			os.Exit(1)
		}

		runAgent(cfg)

	case "version":
		fmt.Printf("fallbck-agent v%s\n", AgentVersion)

	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`FallBCK Backup Agent

Usage:
  fallbck-agent <command> [arguments]

Commands:
  enroll    Register this host with a FallBCK central server
  run       Start the backup agent worker daemon
  version   Print version information`)
}

func runAgent(cfg *config.AgentConfig) {
	slog.Info("Starting FallBCK Agent daemon", "agent_id", cfg.AgentID, "task_queue", cfg.TaskQueue)

	if cfg.AgentID == "" || cfg.TaskQueue == "" {
		slog.Error("Agent is not enrolled yet. Please run 'fallbck-agent enroll --server <url> --token <token>' first.")
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Connect to Temporal
	temporalClient, err := temporal.NewClient(cfg.Temporal)
	if err != nil {
		slog.Error("Failed to connect to Temporal cluster", "error", err, "host", cfg.Temporal.HostPort)
		os.Exit(1)
	}
	defer temporalClient.Close()
	slog.Info("Connected to Temporal cluster", "host", cfg.Temporal.HostPort)

	// Create Temporal Worker on agent task queue
	w := worker.New(temporalClient, cfg.TaskQueue, worker.Options{})

	// Start worker in background
	if err := w.Start(); err != nil {
		slog.Error("Failed to start Temporal worker", "error", err)
		os.Exit(1)
	}
	defer w.Stop()
	slog.Info("Agent Temporal worker listening", "queue", cfg.TaskQueue)

	// Start heartbeat loop to server
	go startHeartbeat(ctx, cfg)

	// Graceful shutdown
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	<-stopChan
	slog.Info("Shutting down FallBCK Agent...")
}

func startHeartbeat(ctx context.Context, cfg *config.AgentConfig) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	agentUUID, err := uuid.Parse(cfg.AgentID)
	if err != nil {
		return
	}

	client := &http.Client{Timeout: 5 * time.Second}
	heartbeatURL := fmt.Sprintf("%s/api/v1/agents/heartbeat", cfg.ServerURL)

	sendHeartbeat := func() {
		reqData := api.HeartbeatRequest{
			AgentID: agentUUID,
			Status:  "online",
			Version: AgentVersion,
		}
		b, _ := json.Marshal(reqData)
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, heartbeatURL, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			slog.Debug("Heartbeat ping failed", "error", err)
			return
		}
		_ = resp.Body.Close()
	}

	// Send initial heartbeat
	sendHeartbeat()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sendHeartbeat()
		}
	}
}
