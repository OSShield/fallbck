// Package runtime is the shared daemon skeleton of the fallbck agents: configuration
// lookup and self-enrollment, the Temporal client and PBS tunnel connections through
// the server gateway, the activity worker, and the heartbeat / token-rotation loop.
// Agent binaries only add their activities.
package runtime

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	"github.com/osshield/fallbck/pkg/agent/backup"
	"github.com/osshield/fallbck/pkg/agent/enrollment"
	"github.com/osshield/fallbck/pkg/api"
	"github.com/osshield/fallbck/pkg/config"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	heartbeatInterval = 30 * time.Second
	// tokenRotateBefore triggers a token rotation when less than this remains
	tokenRotateBefore = 30 * 24 * time.Hour
)

// Agent identifies the binary using the runtime
type Agent struct {
	// Name is the binary name (fallbck-agent, fallbck-db-agent); used for identities and messages
	Name string
	// Type is config.AgentTypeFilesystem or config.AgentTypeDatabase
	Type    string
	Version string
	// Logging is the process logging setup (SetupLogging); the heartbeat loop applies
	// the server's per-agent debug toggle to it and failures attach its ring buffer
	Logging *Logging
	// PersistToken overrides where token rotations are stored (TokenStore.Persist);
	// used by the kubernetes agent to write into its identity Secret
	PersistToken func(cfg *config.AgentConfig) error
}

// FindDefaultConfig returns the first existing agent.yaml among the conventional
// locations for the agent type: the default data dir (env / system dir as root /
// home), then the others.
func FindDefaultConfig(agentType string) string {
	candidates := []string{filepath.Join(config.DefaultAgentDataDirFor(agentType), enrollment.ConfigFileName)}
	candidates = append(candidates, filepath.Join(config.SystemAgentDataDirFor(agentType), enrollment.ConfigFileName))
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		candidates = append(candidates, filepath.Join(home, ".fallbck", config.AgentDirName(agentType), enrollment.ConfigFileName))
	}
	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

// LoadConfig loads the agent configuration (configPath or the default location) and
// self-enrolls when the agent has no identity but an enrollment key is configured
// (config file or FALLBCK_AGENT_ENROLLMENT_KEY). It returns the configuration and the
// path it should be persisted to.
func LoadConfig(a Agent, configPath string) (*config.AgentConfig, string, error) {
	if configPath == "" {
		configPath = FindDefaultConfig(a.Type)
	}
	cfg, err := config.LoadAgentConfig(configPath)
	if err != nil {
		return nil, "", fmt.Errorf("failed to load agent configuration: %w", err)
	}
	if cfg.AgentID == "" && cfg.EnrollmentKey != "" {
		slog.Info("Agent not enrolled yet, enrolling with server", "server", cfg.ServerURL, "data_dir", cfg.DataDir, "agent_type", a.Type)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_, err := enrollment.Enroll(ctx, enrollment.Options{ServerURL: cfg.ServerURL, Token: cfg.EnrollmentKey, DataDir: cfg.DataDir, AgentType: a.Type, Version: a.Version})
		cancel()
		if err != nil {
			return nil, "", fmt.Errorf("agent self-enrollment failed: %w", err)
		}
		configPath = filepath.Join(cfg.DataDir, enrollment.ConfigFileName)
		slog.Info("Agent enrolled successfully", "config", configPath)

		// Reload so environment overrides are applied on top of the enrolled config
		cfg, err = config.LoadAgentConfig(configPath)
		if err != nil {
			return nil, "", fmt.Errorf("failed to load agent configuration after enrollment: %w", err)
		}
	}
	return cfg, configPath, nil
}

// TokenStore holds the current agent token and persists rotations
type TokenStore struct {
	mu         sync.RWMutex
	cfg        *config.AgentConfig
	configPath string
	// Persist overrides where rotations are stored (e.g. a Kubernetes Secret);
	// default: rewrite the token fields of the config file
	Persist func(cfg *config.AgentConfig) error
}

// NewTokenStore wraps the loaded configuration; rotations are written to configPath
func NewTokenStore(cfg *config.AgentConfig, configPath string) *TokenStore {
	return &TokenStore{cfg: cfg, configPath: configPath}
}

func (t *TokenStore) Token() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.cfg.AuthToken
}

func (t *TokenStore) ExpiresAt() time.Time {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.cfg.TokenExpiresAt
}

// Update installs a rotated token and persists it (only the token fields are rewritten)
func (t *TokenStore) Update(token string, expires time.Time) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.cfg.AuthToken = token
	t.cfg.TokenExpiresAt = expires
	if t.Persist != nil {
		return t.Persist(t.cfg)
	}
	if t.configPath == "" {
		return nil
	}
	if err := config.UpdateAgentToken(t.configPath, token, expires); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return t.cfg.Save(t.configPath)
		}
		return err
	}
	return nil
}

// tokenCredentials attaches the (rotating) agent bearer token to every RPC
type tokenCredentials struct{ store *TokenStore }

func (c tokenCredentials) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{"authorization": "Bearer " + c.store.Token()}, nil
}

func (tokenCredentials) RequireTransportSecurity() bool { return false }

// ConnectionOptions derives the Temporal gRPC endpoint and TLS settings from ServerURL.
// The FallBCK server multiplexes gRPC and HTTP on the same port; https → TLS, http → h2c.
func ConnectionOptions(cfg *config.AgentConfig) (string, client.ConnectionOptions, error) {
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

// Conns are the agent's connections to the server gateway
type Conns struct {
	HostPort string
	Temporal client.Client
	// Tunnel carries PBS backup sessions and other agent-authenticated gRPC services
	Tunnel *grpc.ClientConn
}

// Close releases both connections
func (c *Conns) Close() {
	if c.Tunnel != nil {
		_ = c.Tunnel.Close()
	}
	if c.Temporal != nil {
		c.Temporal.Close()
	}
}

// DialTunnel opens only the agent-authenticated gRPC connection to the gateway
// (PBS tunnel and other agent services); used by worker processes that need no
// Temporal client.
func DialTunnel(cfg *config.AgentConfig, store *TokenStore) (*grpc.ClientConn, error) {
	hostPort, connOpts, err := ConnectionOptions(cfg)
	if err != nil {
		return nil, fmt.Errorf("invalid agent configuration: %w", err)
	}
	transportCreds := credentials.NewTLS(connOpts.TLS)
	if connOpts.TLSDisabled {
		transportCreds = insecure.NewCredentials()
	}
	conn, err := grpc.NewClient(hostPort,
		grpc.WithTransportCredentials(transportCreds),
		grpc.WithPerRPCCredentials(tokenCredentials{store: store}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create tunnel connection: %w", err)
	}
	return conn, nil
}

// Connect opens the Temporal client and the tunnel connection through the gateway,
// both authenticated with the agent token
func Connect(cfg *config.AgentConfig, store *TokenStore, identity string) (*Conns, error) {
	hostPort, connOpts, err := ConnectionOptions(cfg)
	if err != nil {
		return nil, fmt.Errorf("invalid agent configuration: %w", err)
	}
	temporalClient, err := client.Dial(client.Options{
		HostPort:          hostPort,
		Namespace:         cfg.Namespace,
		Identity:          identity,
		Credentials:       client.NewAPIKeyDynamicCredentials(func(context.Context) (string, error) { return store.Token(), nil }),
		ConnectionOptions: connOpts,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to FallBCK server gateway at %s: %w", hostPort, err)
	}

	tunnelConn, err := DialTunnel(cfg, store)
	if err != nil {
		temporalClient.Close()
		return nil, err
	}
	return &Conns{HostPort: hostPort, Temporal: temporalClient, Tunnel: tunnelConn}, nil
}

// ServerHTTPClient builds the HTTP client for the FallBCK server (trusting a private CA if configured)
func ServerHTTPClient(cfg *config.AgentConfig) *http.Client {
	httpClient := &http.Client{Timeout: 15 * time.Second}
	if strings.HasPrefix(strings.ToLower(cfg.ServerURL), "https://") {
		if _, connOpts, err := ConnectionOptions(cfg); err == nil && connOpts.TLS != nil {
			httpClient.Transport = &http.Transport{TLSClientConfig: connOpts.TLS}
		}
	}
	return httpClient
}

// TicketPost performs an agent-authenticated POST carrying a backup ticket, a JSON
// body, and decodes the JSON response into out.
func TicketPost(ctx context.Context, httpClient *http.Client, cfg *config.AgentConfig, store *TokenStore, path, ticket string, body, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	base := strings.TrimRight(cfg.ServerURL, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+store.Token())
	req.Header.Set(api.BackupTicketHeader, ticket)
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// TicketGet performs an agent-authenticated GET carrying a backup ticket and decodes
// the JSON response into out.
func TicketGet(ctx context.Context, httpClient *http.Client, cfg *config.AgentConfig, store *TokenStore, path, ticket string, out any) error {
	base := strings.TrimRight(cfg.ServerURL, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+store.Token())
	req.Header.Set(api.BackupTicketHeader, ticket)
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// PBSCredentialsFetcher retrieves PBS connection details for direct-mode jobs
func PBSCredentialsFetcher(cfg *config.AgentConfig, store *TokenStore) func(ctx context.Context, ticket string) (*backup.DirectOptions, error) {
	httpClient := ServerHTTPClient(cfg)
	return func(ctx context.Context, ticket string) (*backup.DirectOptions, error) {
		var creds api.PBSCredentials
		if err := TicketGet(ctx, httpClient, cfg, store, "/api/v1/agents/pbs-credentials", ticket, &creds); err != nil {
			return nil, fmt.Errorf("fetching PBS credentials: %w", err)
		}
		slog.Debug("Received PBS credentials for direct backup", "endpoint", creds.Endpoint, "datastore", creds.Datastore)
		return &backup.DirectOptions{Endpoint: creds.Endpoint, Namespace: creds.Namespace, Fingerprint: creds.Fingerprint, TLSVerify: creds.TLSVerify, APIToken: creds.APIToken}, nil
	}
}

// StartHeartbeat reports the agent online every 30 s, applies the server's remote
// debug-logging toggle from the response, and rotates the token when it approaches
// expiry; it returns when ctx is cancelled. logging may be nil.
func StartHeartbeat(ctx context.Context, cfg *config.AgentConfig, store *TokenStore, version string, logging *Logging) {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	agentUUID, err := uuid.Parse(cfg.AgentID)
	if err != nil {
		slog.Error("Agent ID is not a UUID; heartbeats disabled", "agent_id", cfg.AgentID)
		return
	}

	httpClient := ServerHTTPClient(cfg)
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
		resp, err := do("/api/v1/agents/heartbeat", api.HeartbeatRequest{AgentID: agentUUID, Status: "online", Version: version})
		if err != nil {
			slog.Warn("Heartbeat failed", "error", err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized {
			slog.Error("Server rejected the agent token; the agent may have been revoked. Re-enroll to continue.")
			return
		}
		if resp.StatusCode >= 300 {
			slog.Warn("Heartbeat rejected", "status", resp.StatusCode)
			return
		}
		var ack api.HeartbeatResponse
		if err := json.NewDecoder(resp.Body).Decode(&ack); err != nil {
			return
		}
		if logging != nil && logging.Control.SetRemoteDebug(ack.DebugLogging) {
			if ack.DebugLogging {
				slog.Info("Debug logging enabled remotely (web UI toggle)")
			} else {
				slog.Info("Debug logging disabled remotely; back to the configured level")
			}
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

// Run starts the daemon: connections, an activity-only worker on the agent's task
// queue with the activities registered by register, and the heartbeat loop; it blocks
// until SIGINT/SIGTERM.
func Run(a Agent, cfg *config.AgentConfig, configPath string, register func(w worker.Worker, conns *Conns, store *TokenStore) error) error {
	slog.Info("Starting "+a.Name+" daemon", "agent_id", cfg.AgentID, "task_queue", cfg.TaskQueue, "server", cfg.ServerURL, "version", a.Version)

	if cfg.AgentID == "" || cfg.TaskQueue == "" || cfg.AuthToken == "" {
		return fmt.Errorf("agent is not enrolled yet; run '%s enroll --server <url> --token <token>' first", a.Name)
	}
	if cfg.Namespace == "" {
		cfg.Namespace = "default"
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	store := NewTokenStore(cfg, configPath)
	store.Persist = a.PersistToken
	identity := fmt.Sprintf("%s@%s", a.Name, cfg.Hostname)

	conns, err := Connect(cfg, store, identity)
	if err != nil {
		return err
	}
	defer conns.Close()
	slog.Info("Connected to FallBCK server gateway", "endpoint", conns.HostPort)

	// Activity-only worker on the agent's private task queue
	w := worker.New(conns.Temporal, cfg.TaskQueue, worker.Options{
		DisableWorkflowWorker: true,
		Identity:              identity,
	})
	if err := register(w, conns, store); err != nil {
		return err
	}
	if err := w.Start(); err != nil {
		return fmt.Errorf("failed to start Temporal worker: %w", err)
	}
	defer w.Stop()
	slog.Info("Agent Temporal worker listening", "queue", cfg.TaskQueue)

	go StartHeartbeat(ctx, cfg, store, a.Version, a.Logging)

	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)
	<-stopChan
	slog.Info("Shutting down " + a.Name + "...")
	return nil
}

// PrintEnrolled prints the post-enrollment summary and how to start the service
func PrintEnrolled(a Agent, cfg *config.AgentConfig) {
	configPath := filepath.Join(cfg.DataDir, enrollment.ConfigFileName)
	fmt.Println("✓ Agent enrolled successfully!")
	fmt.Printf("  Agent ID:   %s\n", cfg.AgentID)
	fmt.Printf("  Type:       %s\n", a.Type)
	fmt.Printf("  Task Queue: %s\n", cfg.TaskQueue)
	fmt.Printf("  Server:     %s\n", cfg.ServerURL)
	fmt.Printf("  Config:     %s\n", configPath)
	if cfg.DataDir == config.SystemAgentDataDirFor(a.Type) {
		fmt.Printf("\nStart the service:  systemctl enable --now %s   (OpenRC: rc-update add %s default && rc-service %s start)\n", a.Name, a.Name, a.Name)
	} else {
		fmt.Printf("\nRun the agent:      %s run --config %s\n", a.Name, configPath)
	}
}
