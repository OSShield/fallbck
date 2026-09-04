// fallbck-db-agent backs up databases (PostgreSQL, MySQL/MariaDB, MongoDB) to Proxmox
// Backup Server through the FallBCK server.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	dbrun "github.com/osshield/fallbck/pkg/agent/dbbackup"
	"github.com/osshield/fallbck/pkg/agent/enrollment"
	"github.com/osshield/fallbck/pkg/agent/runtime"
	"github.com/osshield/fallbck/pkg/api"
	"github.com/osshield/fallbck/pkg/config"
	"github.com/osshield/fallbck/pkg/temporal/activities"
	"go.temporal.io/sdk/worker"
)

var AgentVersion = "0.1.0"

var agent = runtime.Agent{Name: "fallbck-db-agent", Type: config.AgentTypeDatabase}

func main() {
	agent.Version = AgentVersion

	enrollCmd := flag.NewFlagSet("enroll", flag.ExitOnError)
	enrollServer := enrollCmd.String("server", "http://localhost:8080", "FallBCK server URL")
	enrollToken := enrollCmd.String("token", "", "One-time enrollment token")
	enrollDir := enrollCmd.String("data-dir", "", "Agent data directory (default: $FALLBCK_AGENT_DATA_DIR, "+config.SystemDBAgentDataDir+" as root, else ~/.fallbck/db-agent)")

	runCmd := flag.NewFlagSet("run", flag.ExitOnError)
	runConfig := runCmd.String("config", "", "Path to agent YAML configuration file")

	toolsCmd := flag.NewFlagSet("tools", flag.ExitOnError)
	toolsConfig := toolsCmd.String("config", "", "Path to agent YAML configuration file")

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
		cfg, err := enrollment.Enroll(ctx, enrollment.Options{ServerURL: *enrollServer, Token: *enrollToken, DataDir: *enrollDir, AgentType: agent.Type, Version: AgentVersion})
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
		dbCfg := cfg.DBBackup
		dbCfg.ApplyDefaults(cfg.DataDir)
		if err := dbrun.CleanSpool(dbCfg); err != nil {
			slog.Warn("Could not clean the spool directory", "dir", dbCfg.SpoolDir, "error", err)
		}
		for _, d := range dbrun.DetectAll(context.Background(), dbrun.NewRunner(dbCfg.KillGrace), dbCfg.Tools) {
			if d.Err != nil {
				slog.Warn("Database client tools missing", "engine", d.Engine, "error", d.Err)
				continue
			}
			for name, b := range d.Tools.Binaries {
				slog.Info("Database client tool", "engine", d.Engine, "tool", name, "path", b.Path, "version", b.Version)
			}
		}
		err = runtime.Run(agent, cfg, configPath, func(w worker.Worker, conns *runtime.Conns, store *runtime.TokenStore) error {
			acts := activities.NewDBAgentActivities()
			acts.Tunnel = conns.Tunnel
			acts.Credentials = runtime.PBSCredentialsFetcher(cfg, store)
			acts.DBPassword = dbPasswordFetcher(cfg, store)
			acts.Config = dbCfg
			acts.Hostname = cfg.Hostname
			acts.Version = AgentVersion
			acts.LogTail = logging.Tail
			w.RegisterActivity(acts)
			return nil
		})
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

	case "version":
		fmt.Printf("fallbck-db-agent v%s\n", AgentVersion)

	default:
		printUsage()
		os.Exit(1)
	}
}

// dbPasswordFetcher retrieves the server-stored database password for a run
func dbPasswordFetcher(cfg *config.AgentConfig, store *runtime.TokenStore) func(ctx context.Context, ticket string) (string, error) {
	httpClient := runtime.ServerHTTPClient(cfg)
	return func(ctx context.Context, ticket string) (string, error) {
		var creds api.DBCredentials
		if err := runtime.TicketGet(ctx, httpClient, cfg, store, "/api/v1/agents/db-credentials", ticket, &creds); err != nil {
			return "", err
		}
		return creds.Password, nil
	}
}

func printUsage() {
	fmt.Println(`FallBCK Database Backup Agent

Usage:
  fallbck-db-agent <command> [arguments]

Commands:
  enroll    Register this host with a FallBCK central server (agent type: database)
  run       Start the database backup agent daemon
  tools     Show the detected database client tools (pg_dump, mysqldump, mongodump, ...)
  version   Print version information`)
}
