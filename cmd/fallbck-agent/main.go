package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/osshield/fallbck/pkg/agent/enrollment"
	"github.com/osshield/fallbck/pkg/agent/runtime"
	"github.com/osshield/fallbck/pkg/agent/vss"
	"github.com/osshield/fallbck/pkg/config"
	"github.com/osshield/fallbck/pkg/temporal/activities"
	"go.temporal.io/sdk/worker"
)

var AgentVersion = "0.1.0"

var agent = runtime.Agent{Name: "fallbck-agent", Type: config.AgentTypeFilesystem}

// serviceName is the Windows service name
const serviceName = "fallbck-agent"

// redirectServiceLog sends the process output to <data dir>\logs\fallbck-agent.log;
// the service control manager offers no console
func redirectServiceLog() {
	dir := filepath.Join(config.DefaultAgentDataDirFor(agent.Type), "logs")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	f, err := os.OpenFile(filepath.Join(dir, "fallbck-agent.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	os.Stdout, os.Stderr = f, f
}

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

	serviceCmd := flag.NewFlagSet("service", flag.ExitOnError)
	serviceConfig := serviceCmd.String("config", "", "Path to agent YAML configuration file the service runs with")

	// Under the Windows service control manager there is no console: keep the log
	// in the data directory instead
	if runtime.IsWindowsService() {
		redirectServiceLog()
	}
	logging := runtime.SetupLogging()
	agent.Logging = logging
	enrollment.AgentVersion = AgentVersion

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "service":
		// Windows: fallbck-agent service install|uninstall|start|stop|status
		if len(os.Args) < 3 {
			fmt.Println("usage: fallbck-agent service install [--config <path>] | uninstall | start | stop | status")
			os.Exit(2)
		}
		action := os.Args[2]
		_ = serviceCmd.Parse(os.Args[3:])
		cfgPath := *serviceConfig
		if cfgPath == "" {
			cfgPath = runtime.FindDefaultConfig(agent.Type)
		}
		if err := runtime.ServiceCommand(serviceName, "FallBCK Backup Agent", "Backs up this host to Proxmox Backup Server through the FallBCK server", action, cfgPath); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

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
		register := func(w worker.Worker, conns *runtime.Conns, store *runtime.TokenStore) error {
			acts := activities.NewAgentActivities()
			acts.Tunnel = conns.Tunnel
			acts.Credentials = runtime.PBSCredentialsFetcher(cfg, store)
			acts.RefreshTicket = runtime.TicketRefresher(cfg, store)
			acts.LogTail = logging.Tail
			acts.ReportProgress = runtime.ProgressReporter(cfg, store)
			acts.SpoolDir = filepath.Join(cfg.DataDir, "spool")
			acts.CacheDir = filepath.Join(cfg.DataDir, "pxar-cache")
			acts.Hostname = cfg.Hostname
			acts.Version = AgentVersion
			if vss.Supported() && cfg.UseVSS() {
				acts.VSSDir = filepath.Join(cfg.DataDir, "vss")
				vss.Sweep(acts.VSSDir)
			}
			w.RegisterActivity(acts)
			return nil
		}
		if runtime.IsWindowsService() {
			err = runtime.RunAsService(serviceName, func(stop <-chan struct{}) error {
				return runtime.RunUntil(agent, cfg, configPath, register, stop)
			})
		} else {
			err = runtime.Run(agent, cfg, configPath, register)
		}
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
  service   Windows: install|uninstall|start|stop|status the Windows service
  version   Print version information`)
}
