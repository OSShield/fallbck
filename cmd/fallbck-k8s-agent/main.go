// fallbck-k8s-agent backs up a Kubernetes cluster (API resources + PVC data) to
// Proxmox Backup Server through the FallBCK server. It runs inside the target cluster
// (Helm chart), persists its enrolled identity in a Secret, and spawns worker pods
// (this same binary in "worker" mode) to upload volume data.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/osshield/fallbck/pkg/agent/enrollment"
	k8sagent "github.com/osshield/fallbck/pkg/agent/k8sbackup"
	"github.com/osshield/fallbck/pkg/agent/runtime"
	"github.com/osshield/fallbck/pkg/api"
	"github.com/osshield/fallbck/pkg/config"
	"github.com/osshield/fallbck/pkg/temporal/activities"
	"go.temporal.io/sdk/worker"
)

var AgentVersion = "0.1.0"

var agent = runtime.Agent{Name: "fallbck-k8s-agent", Type: config.AgentTypeKubernetes}

const sweepInterval = 6 * time.Hour

func main() {
	agent.Version = AgentVersion
	logging := runtime.SetupLogging()
	agent.Logging = logging
	enrollment.AgentVersion = AgentVersion

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "run":
		runAgent(logging)
	case "worker":
		// Worker mode: upload the mounted volume and report via the termination message
		if err := k8sagent.RunWorker(context.Background()); err != nil {
			slog.Error("Worker failed", "error", err)
			os.Exit(1)
		}
	case "version":
		fmt.Printf("fallbck-k8s-agent v%s\n", AgentVersion)
	default:
		printUsage()
		os.Exit(1)
	}
}

func runAgent(logging *runtime.Logging) {
	clusterName := os.Getenv("FALLBCK_CLUSTER_NAME")
	if clusterName == "" {
		slog.Error("FALLBCK_CLUSTER_NAME is required (set clusterName in the Helm values)")
		os.Exit(1)
	}
	namespace := os.Getenv("POD_NAMESPACE")
	if namespace == "" {
		namespace = "default"
	}
	identitySecret := os.Getenv("FALLBCK_IDENTITY_SECRET")
	if identitySecret == "" {
		identitySecret = "fallbck-k8s-agent-identity"
	}
	workerImage := os.Getenv("FALLBCK_WORKER_IMAGE")
	if workerImage == "" {
		slog.Error("FALLBCK_WORKER_IMAGE is required (the chart sets it to the agent image)")
		os.Exit(1)
	}

	clients, err := k8sagent.InClusterClients()
	if err != nil {
		slog.Error("Kubernetes API access failed", "error", err)
		os.Exit(1)
	}

	// Environment config (FALLBCK_AGENT_* set by the chart) + identity from the Secret
	cfg, err := config.LoadAgentConfig("")
	if err != nil {
		slog.Error("Failed to load configuration", "error", err)
		os.Exit(1)
	}
	logging.ApplyConfigLogLevel(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	identity, err := k8sagent.LoadIdentity(ctx, clients.Core, namespace, identitySecret)
	cancel()
	if err != nil {
		slog.Error("Failed to read the identity secret", "error", err)
		os.Exit(1)
	}
	if identity != nil {
		cfg.AgentID = identity.AgentID
		cfg.Hostname = identity.Hostname
		cfg.TaskQueue = identity.TaskQueue
		cfg.AuthToken = identity.AuthToken
		cfg.TokenExpiresAt = identity.TokenExpiresAt
		if cfg.Namespace == "" || cfg.Namespace == "default" {
			cfg.Namespace = identity.Namespace
		}
		slog.Info("Loaded identity from secret", "agent_id", cfg.AgentID, "secret", namespace+"/"+identitySecret)
	}

	if cfg.AgentID == "" {
		if cfg.EnrollmentKey == "" {
			slog.Error("Agent is not enrolled and no enrollment key is configured; set enrollment.key in the Helm values")
			os.Exit(1)
		}
		slog.Info("Enrolling with the FallBCK server", "server", cfg.ServerURL, "cluster", clusterName)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		enrolled, err := enrollment.Enroll(ctx, enrollment.Options{
			ServerURL: cfg.ServerURL, Token: cfg.EnrollmentKey,
			DataDir: os.TempDir(), AgentType: config.AgentTypeKubernetes,
			Version: AgentVersion, Hostname: "k8s-" + clusterName,
		})
		cancel()
		if err != nil {
			slog.Error("Enrollment failed", "error", err)
			os.Exit(1)
		}
		cfg.AgentID = enrolled.AgentID
		cfg.Hostname = enrolled.Hostname
		cfg.TaskQueue = enrolled.TaskQueue
		cfg.Namespace = enrolled.Namespace
		cfg.AuthToken = enrolled.AuthToken
		cfg.TokenExpiresAt = enrolled.TokenExpiresAt
		if enrolled.ServerCACertPath != "" {
			cfg.ServerCACertPath = enrolled.ServerCACertPath
		}
		ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
		err = k8sagent.SaveIdentity(ctx, clients.Core, namespace, identitySecret, cfg)
		cancel()
		if err != nil {
			slog.Error("Enrolled but the identity secret could not be written (RBAC?)", "error", err)
			os.Exit(1)
		}
		slog.Info("Enrolled and identity persisted", "agent_id", cfg.AgentID, "secret", namespace+"/"+identitySecret)
	}

	agent.PersistToken = k8sagent.IdentityPersist(clients.Core, namespace, identitySecret)

	dataDir := cfg.DataDir
	if dataDir == "" {
		dataDir = os.TempDir()
	}

	err = runtime.Run(agent, cfg, "", func(w worker.Worker, conns *runtime.Conns, store *runtime.TokenStore) error {
		httpClient := runtime.ServerHTTPClient(cfg)
		acts := activities.NewK8sAgentActivities()
		acts.Tunnel = conns.Tunnel
		acts.Clients = clients
		acts.Config = cfg
		acts.ClusterName = clusterName
		acts.AgentNamespace = namespace
		acts.Version = AgentVersion
		acts.WorkerImage = workerImage
		acts.WorkerImagePullPolicy = os.Getenv("FALLBCK_WORKER_PULL_POLICY")
		acts.WorkerResourcesJSON = os.Getenv("FALLBCK_WORKER_RESOURCES")
		acts.WorkerSecurityContextJSON = os.Getenv("FALLBCK_WORKER_SECURITY_CONTEXT")
		acts.SpoolDir = dataDir + "/spool"
		acts.LogTail = logging.Tail
		acts.Credentials = runtime.PBSCredentialsFetcher(cfg, store)
		acts.VolumeTicket = func(ctx context.Context, sessionTicket, volumeBackupID string) (string, error) {
			var resp api.VolumeTicketResponse
			err := runtime.TicketPost(ctx, httpClient, cfg, store, "/api/v1/agents/volume-ticket", sessionTicket,
				api.VolumeTicketRequest{VolumeBackupID: volumeBackupID}, &resp)
			return resp.Ticket, err
		}
		acts.WorkerToken = func(ctx context.Context, sessionTicket string) (string, time.Time, error) {
			var resp api.WorkerTokenResponse
			err := runtime.TicketPost(ctx, httpClient, cfg, store, "/api/v1/agents/token/worker", sessionTicket,
				struct{}{}, &resp)
			return resp.AuthToken, resp.TokenExpiresAt, err
		}
		w.RegisterActivity(acts)

		// Orphan sweep: at start and periodically, remove leftovers of crashed runs
		go func() {
			sweep := func() {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				defer cancel()
				k8sagent.Sweep(ctx, clients, cfg.AgentID, acts.Runs.Active)
			}
			sweep()
			ticker := time.NewTicker(sweepInterval)
			defer ticker.Stop()
			for range ticker.C {
				sweep()
			}
		}()
		return nil
	})
	if err != nil {
		slog.Error("Agent stopped with an error", "error", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`FallBCK Kubernetes Backup Agent

Usage:
  fallbck-k8s-agent <command>

Commands:
  run       Start the in-cluster backup agent (enrolls itself on first start)
  worker    Volume-upload worker mode (used by the pods the agent spawns)
  version   Print version information`)
}
