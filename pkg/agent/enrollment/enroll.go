// Package enrollment registers an agent with the FallBCK server using a one-time token
package enrollment

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/osshield/fallbck/pkg/api"
	"github.com/osshield/fallbck/pkg/config"
	"github.com/osshield/fallbck/pkg/dockerbackup"
	"github.com/osshield/fallbck/pkg/pvebackup"
)

// AgentVersion is reported to the server at enrollment; set by the agent binary
var AgentVersion = "0.1.0"

// ConfigFileName is the agent configuration file inside the data directory
const ConfigFileName = "agent.yaml"

// Options parameterise an enrollment
type Options struct {
	ServerURL string
	Token     string
	// DataDir receives agent.yaml; default: the type's default data directory
	DataDir string
	// AgentType is config.AgentTypeFilesystem (default) or config.AgentTypeDatabase
	AgentType string
	// Version reported to the server (default AgentVersion)
	Version string
	// Hostname overrides the reported hostname (e.g. k8s-<cluster>); default os.Hostname()
	Hostname string
	// CACertPath is a PEM bundle of a private CA to trust for ServerURL; it is used for
	// the enrollment request itself and persisted in agent.yaml
	CACertPath string
	// InsecureSkipVerify disables certificate verification for ServerURL (enrollment
	// request and agent.yaml)
	InsecureSkipVerify bool
	// DockerSocket overrides the Docker daemon socket probed for the docker_host flag
	// (filesystem agents; default DOCKER_HOST or /var/run/docker.sock)
	DockerSocket string
	// DBTools reports database client tools on the host (the combined filesystem agent)
	DBTools bool
}

// EnrollAgent enrolls a filesystem agent (see Enroll)
func EnrollAgent(ctx context.Context, serverURL, token, dataDir string) (*config.AgentConfig, error) {
	return Enroll(ctx, Options{ServerURL: serverURL, Token: token, DataDir: dataDir})
}

// Enroll exchanges a one-time enrollment token for an agent identity and bearer token,
// and writes agent.yaml (and an optional server CA bundle) into the data directory.
// The enrollment request honours o.CACertPath / o.InsecureSkipVerify, so a server with
// a private or self-signed certificate can be enrolled with. Operator settings already
// present in an existing agent.yaml (db_backup, TLS options) are preserved.
func Enroll(ctx context.Context, o Options) (*config.AgentConfig, error) {
	if o.AgentType == "" {
		o.AgentType = config.AgentTypeFilesystem
	}
	if o.Version == "" {
		o.Version = AgentVersion
	}
	// Clean the directory: a trailing separator (Windows directory properties end
	// with one) or a "\." from a command line must not end up in agent.yaml
	dataDir := o.DataDir
	if dataDir != "" {
		dataDir = filepath.Clean(dataDir)
	}
	if dataDir == "" {
		dataDir = config.DefaultAgentDataDirFor(o.AgentType)
	}
	serverURL := strings.TrimRight(o.ServerURL, "/")
	token := o.Token

	hostname := o.Hostname
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	reqBody := api.EnrollRequest{
		Token:      token,
		Hostname:   hostname,
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
		Version:    o.Version,
		AgentType:  o.AgentType,
		PVEHost:    pvebackup.IsPVEHost(),
		DockerHost: o.AgentType == "" || o.AgentType == config.AgentTypeFilesystem,
	}
	if reqBody.DockerHost {
		reqBody.DockerHost = dockerbackup.IsDockerHost(o.DockerSocket)
		reqBody.DBTools = o.DBTools
	}

	jsonBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal enrollment request: %w", err)
	}

	endpoint := serverURL + "/api/v1/agents/enroll"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(jsonBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client, err := httpClient(serverURL, o)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to server at %s: %w", serverURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("enrollment failed with status %d: %s", resp.StatusCode, string(body))
	}

	var enrollResp api.EnrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&enrollResp); err != nil {
		return nil, fmt.Errorf("failed to decode server response: %w", err)
	}
	if enrollResp.AuthToken == "" || enrollResp.TaskQueue == "" {
		return nil, fmt.Errorf("server response is missing credentials")
	}

	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	cfg := &config.AgentConfig{
		AgentID:        enrollResp.AgentID.String(),
		Hostname:       hostname,
		ServerURL:      serverURL,
		DataDir:        dataDir,
		TaskQueue:      enrollResp.TaskQueue,
		Namespace:      enrollResp.Namespace,
		AuthToken:      enrollResp.AuthToken,
		TokenExpiresAt: enrollResp.TokenExpiresAt,
	}
	// The server advertises its public URL; prefer it unless the operator enrolled
	// through a different (e.g. internal) address on purpose.
	if enrollResp.ServerURL != "" && serverURL == "" {
		cfg.ServerURL = enrollResp.ServerURL
	}
	if cfg.Namespace == "" {
		cfg.Namespace = "default"
	}

	// TLS trust for ServerURL: an operator-supplied CA wins (the certificate the agent
	// sees may belong to a proxy in front of the server), then the CA the server
	// advertises, then whatever an existing agent.yaml already had.
	cfg.ServerCACertPath = o.CACertPath
	cfg.InsecureSkipVerify = o.InsecureSkipVerify
	if enrollResp.ServerCAPEM != "" && cfg.ServerCACertPath == "" {
		caPath := filepath.Join(dataDir, "server-ca.crt")
		if err := os.WriteFile(caPath, []byte(enrollResp.ServerCAPEM), 0o644); err != nil {
			return nil, fmt.Errorf("failed to write server CA bundle: %w", err)
		}
		cfg.ServerCACertPath = caPath
	}

	configPath := filepath.Join(dataDir, ConfigFileName)
	if existing, err := config.ReadAgentConfigFile(configPath); err == nil {
		cfg.DBBackup = existing.DBBackup
		cfg.InsecureSkipVerify = cfg.InsecureSkipVerify || existing.InsecureSkipVerify
		if cfg.ServerCACertPath == "" {
			cfg.ServerCACertPath = existing.ServerCACertPath
		}
	}

	if err := cfg.Save(configPath); err != nil {
		return nil, err
	}
	return cfg, nil
}

// httpClient builds the client for the enrollment request, applying the operator's
// TLS trust settings when the server is reached over https
func httpClient(serverURL string, o Options) (*http.Client, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	if !strings.HasPrefix(strings.ToLower(serverURL), "https://") {
		return client, nil
	}
	tlsCfg, err := (&config.AgentConfig{
		ServerURL:          serverURL,
		ServerCACertPath:   o.CACertPath,
		InsecureSkipVerify: o.InsecureSkipVerify,
	}).ServerTLSConfig()
	if err != nil {
		return nil, err
	}
	client.Transport = &http.Transport{TLSClientConfig: tlsCfg}
	return client, nil
}
