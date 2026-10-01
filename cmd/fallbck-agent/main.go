package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	dbrun "github.com/osshield/fallbck/pkg/agent/dbbackup"
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

	toolsCmd := flag.NewFlagSet("tools", flag.ExitOnError)
	toolsConfig := toolsCmd.String("config", "", "Path to agent YAML configuration file")

	migrateCmd := flag.NewFlagSet("migrate-db-agent", flag.ExitOnError)
	migrateFrom := migrateCmd.String("from", config.SystemDBAgentDataDir, "Data directory of the fallbck-db-agent installation to take over")
	migrateConfig := migrateCmd.String("config", "", "Path to this agent's YAML configuration file (default: the enrolled agent.yaml)")

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
		// Database jobs run on this agent too when the host has the client tools:
		// the probe feeds the db_engines list in heartbeats, which gates the jobs server-side
		dbCfg := cfg.DBBackup
		dbCfg.ApplyDefaults(cfg.DataDir)
		if err := dbrun.CleanSpool(dbCfg); err != nil {
			slog.Warn("Could not clean the spool directory", "dir", dbCfg.SpoolDir, "error", err)
		}
		agent.DBEngines = runtime.DBEnginesProbe(dbCfg, 10*time.Minute)
		agent.Inventory = runtime.NewInventory(cfg, configPath, AgentVersion)
		register := func(w worker.Worker, conns *runtime.Conns, store *runtime.TokenStore) error {
			acts := activities.NewAgentActivities()
			acts.Tunnel = conns.Tunnel
			acts.Credentials = runtime.PBSCredentialsFetcher(cfg, store)
			acts.EncryptionKey = runtime.EncryptionKeyFetcher(cfg, store)
			acts.RefreshTicket = runtime.TicketRefresher(cfg, store)
			acts.LogTail = logging.Tail
			acts.ReportProgress = runtime.ProgressReporter(cfg, store)
			acts.SpoolDir = filepath.Join(cfg.DataDir, "spool")
			acts.CacheDir = filepath.Join(cfg.DataDir, "pxar-cache")
			acts.Hostname = cfg.Hostname
			acts.Version = AgentVersion
			acts.Docker = cfg.DockerBackup
			if vss.Supported() && cfg.UseVSS() {
				acts.VSSDir = filepath.Join(cfg.DataDir, "vss")
				vss.Sweep(acts.VSSDir)
			}
			w.RegisterActivity(acts)

			dbActs := activities.NewDBAgentActivities()
			dbActs.Tunnel = conns.Tunnel
			dbActs.Credentials = runtime.PBSCredentialsFetcher(cfg, store)
			dbActs.EncryptionKey = runtime.EncryptionKeyFetcher(cfg, store)
			dbActs.RefreshTicket = runtime.TicketRefresher(cfg, store)
			dbActs.DBPassword = runtime.DBPasswordFetcher(cfg, store)
			dbActs.Config = dbCfg
			dbActs.Hostname = cfg.Hostname
			dbActs.Version = AgentVersion
			dbActs.LogTail = logging.Tail
			dbActs.ReportProgress = runtime.ProgressReporter(cfg, store)
			w.RegisterActivity(dbActs)

			ops := &activities.AgentOpsActivities{LogTail: logging.Tail, LogLevel: func() string { return logging.Control.Level().String() }, Detail: agent.Inventory.Detail}
			w.RegisterActivity(ops)
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

	case "tools":
		_ = toolsCmd.Parse(os.Args[2:])
		var tools config.AgentConfig
		if path := *toolsConfig; path != "" || runtime.FindDefaultConfig(agent.Type) != "" {
			if path == "" {
				path = runtime.FindDefaultConfig(agent.Type)
			}
			if cfg, err := config.LoadAgentConfig(path); err == nil {
				tools = *cfg
			}
		}
		for _, d := range dbrun.DetectAll(context.Background(), dbrun.NewRunner(0), tools.DBBackup.Tools) {
			fmt.Print(d.Format())
		}

	case "migrate-db-agent":
		// Take over a fallbck-db-agent installation on this host: chain state and
		// credential profiles move into this agent; the server-side move of the jobs
		// is done with fallbck-ctl agents merge (printed at the end)
		_ = migrateCmd.Parse(os.Args[2:])
		cfgPath := *migrateConfig
		if cfgPath == "" {
			cfgPath = runtime.FindDefaultConfig(agent.Type)
		}
		if err := runtime.MigrateDBAgent(*migrateFrom, cfgPath); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

	case "database":
		if err := databaseCommand(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
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
  enroll            Register this host with a FallBCK central server
  run               Start the backup agent worker daemon (filesystem, Proxmox VE, Docker
                    and, when the client tools are installed, database jobs)
  tools             Show the detected database client tools (pg_dump, mariadb-dump, mongodump, ...)
  database          Credential profiles in the encrypted store (profile create|list|delete|import)
                    and the db_backup settings (config <key> [<value>]); see database --help
  migrate-db-agent  Take over a fallbck-db-agent installation on this host (state and
                    credential profiles), then retire it with fallbck-ctl agents merge
  service           Windows: install|uninstall|start|stop|status the Windows service
  version           Print version information`)
}
