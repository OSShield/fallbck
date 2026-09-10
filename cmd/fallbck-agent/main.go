package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/osshield/fallbck/pkg/agent/enrollment"
	"github.com/osshield/fallbck/pkg/agent/runtime"
	"github.com/osshield/fallbck/pkg/config"
	"github.com/osshield/fallbck/pkg/temporal/activities"
	"go.temporal.io/sdk/worker"
)

var AgentVersion = "0.1.0"

var agent = runtime.Agent{Name: "fallbck-agent", Type: config.AgentTypeFilesystem}

func main() {
	agent.Version = AgentVersion

	enrollCmd := flag.NewFlagSet("enroll", flag.ExitOnError)
	enrollServer := enrollCmd.String("server", "http://localhost:8080", "FallBCK server URL")
	enrollToken := enrollCmd.String("token", "", "One-time enrollment token")
	enrollCA := enrollCmd.String("ca-cert", "", "PEM bundle of a private CA to trust for the server URL")
	enrollInsecure := enrollCmd.Bool("insecure-skip-verify", false, "Skip TLS certificate verification for the server URL (not recommended)")
	enrollDir := enrollCmd.String("data-dir", "", "Agent data directory (default: $FALLBCK_AGENT_DATA_DIR, "+config.SystemAgentDataDir+" as root, else ~/.fallbck/agent)")

	runCmd := flag.NewFlagSet("run", flag.ExitOnError)
	runConfig := runCmd.String("config", "", "Path to agent YAML configuration file")

	logging := runtime.SetupLogging()
	agent.Logging = logging
	enrollment.AgentVersion = AgentVersion

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
		cfg, err := enrollment.Enroll(ctx, enrollment.Options{
			ServerURL: *enrollServer, Token: *enrollToken, DataDir: *enrollDir, AgentType: agent.Type, Version: AgentVersion,
			CACertPath: *enrollCA, InsecureSkipVerify: *enrollInsecure,
		})
		if err != nil {
			slog.Error("Agent enrollment failed", "error", err)
			os.Exit(1)
		}
		runtime.PrintEnrolled(agent, cfg)

	case "run", "daemon":
		_ = runCmd.Parse(os.Args[2:])
		cfg, configPath, err := runtime.LoadConfig(agent, *runConfig)
		if err != nil {
			slog.Error("Agent startup failed", "error", err)
			os.Exit(1)
		}
		logging.ApplyConfigLogLevel(cfg)
		err = runtime.Run(agent, cfg, configPath, func(w worker.Worker, conns *runtime.Conns, store *runtime.TokenStore) error {
			acts := activities.NewAgentActivities()
			acts.Tunnel = conns.Tunnel
			acts.Credentials = runtime.PBSCredentialsFetcher(cfg, store)
			acts.RefreshTicket = runtime.TicketRefresher(cfg, store)
			acts.LogTail = logging.Tail
			acts.ReportProgress = runtime.ProgressReporter(cfg, store)
			w.RegisterActivity(acts)
			return nil
		})
		if err != nil {
			slog.Error("Agent stopped with an error", "error", err)
			os.Exit(1)
		}

	case "version":
		fmt.Printf("fallbck-agent v%s\n", AgentVersion)

	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`FallBCK Backup Agent (filesystem)

Usage:
  fallbck-agent <command> [arguments]

Commands:
  enroll    Register this host with a FallBCK central server
  run       Start the backup agent worker daemon
  version   Print version information`)
}
