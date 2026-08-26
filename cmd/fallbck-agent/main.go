package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/agent/enrollment"
	"github.com/osshield/fallbck/pkg/api"
	"github.com/osshield/fallbck/pkg/config"
	"github.com/osshield/fallbck/pkg/temporal/activities"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

var AgentVersion = "0.1.0"

const (
	heartbeatInterval = 30 * time.Second
	// tokenRotateBefore triggers a token rotation when less than this remains
	tokenRotateBefore = 30 * 24 * time.Hour
)

func main() {
	enrollCmd := flag.NewFlagSet("enroll", flag.ExitOnError)
	enrollServer := enrollCmd.String("server", "http://localhost:8080", "FallBCK server URL")
	enrollToken := enrollCmd.String("token", "", "One-time enrollment token")
	enrollDir := enrollCmd.String("data-dir", "", "Agent data directory (default: $FALLBCK_AGENT_DATA_DIR, "+config.SystemAgentDataDir+" as root, else ~/.fallbck/agent)")

	runCmd := flag.NewFlagSet("run", flag.ExitOnError)
	runConfig := runCmd.String("config", "", "Path to agent YAML configuration file")

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)
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

		cfg, err := enrollment.EnrollAgent(ctx, *enrollServer, *enrollToken, *enrollDir)
		if err != nil {
			slog.Error("Agent enrollment failed", "error", err)
			os.Exit(1)
		}

		fmt.Println("✓ Agent enrolled successfully!")
		fmt.Printf("  Agent ID:   %s\n", cfg.AgentID)
		fmt.Printf("  Task Queue: %s\n", cfg.TaskQueue)
		fmt.Printf("  Server:     %s\n", cfg.ServerURL)
		fmt.Printf("  Config:     %s\n", filepath.Join(cfg.DataDir, enrollment.ConfigFileName))
		if cfg.DataDir == config.SystemAgentDataDir {
			fmt.Println("\nStart the service:  systemctl enable --now fallbck-agent   (OpenRC: rc-update add fallbck-agent default && rc-service fallbck-agent start)")
		} else {
			fmt.Printf("\nRun the agent:      fallbck-agent run --config %s\n", filepath.Join(cfg.DataDir, enrollment.ConfigFileName))
		}

	case "run", "daemon":
		_ = runCmd.Parse(os.Args[2:])

		configPath := *runConfig
		if configPath == "" {
			configPath = findDefaultConfig()
		}

		cfg, err := config.LoadAgentConfig(configPath)
		if err != nil {
			slog.Error("Failed to load agent configuration", "error", err)
			os.Exit(1)
		}

		// Self-enroll on first start when an enrollment key is provided (config file or
		// FALLBCK_AGENT_ENROLLMENT_KEY), so containers / provisioning tools do not need a
		// separate "enroll" step.
		if cfg.AgentID == "" && cfg.EnrollmentKey != "" {
			slog.Info("Agent not enrolled yet, enrolling with server", "server", cfg.ServerURL, "data_dir", cfg.DataDir)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			_, err := enrollment.EnrollAgent(ctx, cfg.ServerURL, cfg.EnrollmentKey, cfg.DataDir)
			cancel()
			if err != nil {
				slog.Error("Agent self-enrollment failed", "error", err)
				os.Exit(1)
			}
			configPath = filepath.Join(cfg.DataDir, enrollment.ConfigFileName)
			slog.Info("Agent enrolled successfully", "config", configPath)

			// Reload so environment overrides are applied on top of the enrolled config
			cfg, err = config.LoadAgentConfig(configPath)
			if err != nil {
				slog.Error("Failed to load agent configuration after enrollment", "error", err)
				os.Exit(1)
			}
		}

		runAgent(cfg, configPath)

	case "version":
		fmt.Printf("fallbck-agent v%s\n", AgentVersion)

	default:
		printUsage()
		os.Exit(1)
	}
}

// findDefaultConfig returns the first existing agent.yaml among the conventional
// locations: the default data dir (env / system dir as root / home), then the others.
func findDefaultConfig() string {
	candidates := []string{filepath.Join(config.DefaultAgentDataDir(), enrollment.ConfigFileName)}
	candidates = append(candidates, filepath.Join(config.SystemAgentDataDir, enrollment.ConfigFileName))
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		candidates = append(candidates, filepath.Join(home, ".fallbck", "agent", enrollment.ConfigFileName))
	}

	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
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

// tokenStore holds the current agent token and persists rotations
type tokenStore struct {
	mu         sync.RWMutex
	cfg        *config.AgentConfig
	configPath string
}

func (t *tokenStore) Token() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.cfg.AuthToken
}

func (t *tokenStore) ExpiresAt() time.Time {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.cfg.TokenExpiresAt
}

func (t *tokenStore) Update(token string, expires time.Time) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.cfg.AuthToken = token
	t.cfg.TokenExpiresAt = expires
	if t.configPath == "" {
		return nil
	}
	return t.cfg.Save(t.configPath)
}

// agentTokenCredentials attaches the (rotating) agent bearer token to every RPC
type agentTokenCredentials struct{ store *tokenStore }

func (c agentTokenCredentials) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{"authorization": "Bearer " + c.store.Token()}, nil
}

func (agentTokenCredentials) RequireTransportSecurity() bool { return false }

// connectionOptions derives the Temporal gRPC endpoint and TLS settings from ServerURL.
// The FallBCK server multiplexes gRPC and HTTP on the same port; https → TLS, http → h2c.
func connectionOptions(cfg *config.AgentConfig) (string, client.ConnectionOptions, error) {
	u, err := url.Parse(cfg.ServerURL)
	if err != nil || u.Host == "" {
		return "", client.ConnectionOptions{}, fmt.Errorf("server_url %q is not a valid URL", cfg.ServerURL)
	}
	host, port := u.Hostname(), u.Port()
	var opts client.ConnectionOptions
	switch strings.ToLower(u.Scheme) {
	case "https":
		if port == "" {
			port = "443"
		}
		tlsCfg := &tls.Config{ServerName: host, InsecureSkipVerify: cfg.InsecureSkipVerify} //nolint:gosec // operator-controlled
		if cfg.ServerCACertPath != "" {
			pem, err := os.ReadFile(cfg.ServerCACertPath)
			if err != nil {
				return "", opts, fmt.Errorf("failed to read server CA bundle: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return "", opts, fmt.Errorf("server CA bundle %s contains no certificates", cfg.ServerCACertPath)
			}
			tlsCfg.RootCAs = pool
		}
		opts.TLS = tlsCfg
	case "http":
		if port == "" {
			port = "80"
		}
		opts.TLSDisabled = true
		slog.Warn("server_url uses plain http: agent traffic (including credentials) is unencrypted", "server_url", cfg.ServerURL)
	default:
		return "", opts, fmt.Errorf("server_url scheme %q is not supported (use https:// or http://)", u.Scheme)
	}
	return net.JoinHostPort(host, port), opts, nil
}

func runAgent(cfg *config.AgentConfig, configPath string) {
	slog.Info("Starting FallBCK Agent daemon", "agent_id", cfg.AgentID, "task_queue", cfg.TaskQueue, "server", cfg.ServerURL)

	if cfg.AgentID == "" || cfg.TaskQueue == "" || cfg.AuthToken == "" {
		slog.Error("Agent is not enrolled yet. Please run 'fallbck-agent enroll --server <url> --token <token>' first.")
		os.Exit(1)
	}
	if cfg.Namespace == "" {
		cfg.Namespace = "default"
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	store := &tokenStore{cfg: cfg, configPath: configPath}

	hostPort, connOpts, err := connectionOptions(cfg)
	if err != nil {
		slog.Error("Invalid agent configuration", "error", err)
		os.Exit(1)
	}

	// Connect to Temporal through the FallBCK server gateway (same host/port as the HTTP API)
	temporalClient, err := client.Dial(client.Options{
		HostPort:          hostPort,
		Namespace:         cfg.Namespace,
		Identity:          fmt.Sprintf("fallbck-agent@%s", cfg.Hostname),
		Credentials:       client.NewAPIKeyDynamicCredentials(func(context.Context) (string, error) { return store.Token(), nil }),
		ConnectionOptions: connOpts,
	})
	if err != nil {
		slog.Error("Failed to connect to FallBCK server gateway", "error", err, "endpoint", hostPort)
		os.Exit(1)
	}
	defer temporalClient.Close()
	slog.Info("Connected to FallBCK server gateway", "endpoint", hostPort)

	// Second connection to the same endpoint for PBS backup tunnels (authenticated with
	// the agent token like the Temporal traffic)
	transportCreds := credentials.NewTLS(connOpts.TLS)
	if connOpts.TLSDisabled {
		transportCreds = insecure.NewCredentials()
	}
	tunnelConn, err := grpc.NewClient(hostPort,
		grpc.WithTransportCredentials(transportCreds),
		grpc.WithPerRPCCredentials(agentTokenCredentials{store: store}),
	)
	if err != nil {
		slog.Error("Failed to create tunnel connection", "error", err)
		os.Exit(1)
	}
	defer tunnelConn.Close()

	// Activity-only worker on the agent's private task queue
	w := worker.New(temporalClient, cfg.TaskQueue, worker.Options{
		DisableWorkflowWorker: true,
		Identity:              fmt.Sprintf("fallbck-agent@%s", cfg.Hostname),
	})
	agentActs := activities.NewAgentActivities()
	agentActs.Tunnel = tunnelConn
	w.RegisterActivity(agentActs)

	if err := w.Start(); err != nil {
		slog.Error("Failed to start Temporal worker", "error", err)
		os.Exit(1)
	}
	defer w.Stop()
	slog.Info("Agent Temporal worker listening", "queue", cfg.TaskQueue)

	// Heartbeat + token rotation loop
	go startHeartbeat(ctx, cfg, store)

	// Graceful shutdown
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	<-stopChan
	slog.Info("Shutting down FallBCK Agent...")
}

func startHeartbeat(ctx context.Context, cfg *config.AgentConfig, store *tokenStore) {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	agentUUID, err := uuid.Parse(cfg.AgentID)
	if err != nil {
		slog.Error("Agent ID is not a UUID; heartbeats disabled", "agent_id", cfg.AgentID)
		return
	}

	httpClient := &http.Client{Timeout: 10 * time.Second}
	if strings.HasPrefix(strings.ToLower(cfg.ServerURL), "https://") {
		if _, connOpts, err := connectionOptions(cfg); err == nil && connOpts.TLS != nil {
			httpClient.Transport = &http.Transport{TLSClientConfig: connOpts.TLS}
		}
	}
	base := strings.TrimRight(cfg.ServerURL, "/")

	do := func(path string, payload any) (*http.Response, error) {
		b, _ := json.Marshal(payload)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+store.Token())
		return httpClient.Do(req)
	}

	sendHeartbeat := func() {
		resp, err := do("/api/v1/agents/heartbeat", api.HeartbeatRequest{AgentID: agentUUID, Status: "online", Version: AgentVersion})
		if err != nil {
			slog.Warn("Heartbeat failed", "error", err)
			return
		}
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized {
			slog.Error("Server rejected the agent token; the agent may have been revoked. Re-enroll to continue.")
		} else if resp.StatusCode >= 300 {
			slog.Warn("Heartbeat rejected", "status", resp.StatusCode)
		}
	}

	rotateIfNeeded := func() {
		expires := store.ExpiresAt()
		if expires.IsZero() || time.Until(expires) > tokenRotateBefore {
			return
		}
		resp, err := do("/api/v1/agents/token/rotate", map[string]any{})
		if err != nil {
			slog.Warn("Token rotation failed", "error", err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			slog.Warn("Token rotation rejected", "status", resp.StatusCode)
			return
		}
		var rotated api.RotateTokenResponse
		if err := json.NewDecoder(resp.Body).Decode(&rotated); err != nil || rotated.AuthToken == "" {
			slog.Warn("Token rotation returned an invalid response", "error", err)
			return
		}
		if err := store.Update(rotated.AuthToken, rotated.TokenExpiresAt); err != nil {
			slog.Warn("Rotated token could not be persisted", "error", err)
		}
		slog.Info("Agent token rotated", "expires_at", rotated.TokenExpiresAt)
	}

	sendHeartbeat()
	rotateIfNeeded()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sendHeartbeat()
			rotateIfNeeded()
		}
	}
}
