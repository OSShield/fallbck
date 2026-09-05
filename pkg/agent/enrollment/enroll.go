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
}

// EnrollAgent enrolls a filesystem agent (see Enroll)
func EnrollAgent(ctx context.Context, serverURL, token, dataDir string) (*config.AgentConfig, error) {
	return Enroll(ctx, Options{ServerURL: serverURL, Token: token, DataDir: dataDir})
}

// Enroll exchanges a one-time enrollment token for an agent identity and bearer token,
// and writes agent.yaml (and an optional server CA bundle) into the data directory.
// Operator settings already present in an existing agent.yaml (db_backup, TLS options)
// are preserved.
func Enroll(ctx context.Context, o Options) (*config.AgentConfig, error) {
	if o.AgentType == "" {
		o.AgentType = config.AgentTypeFilesystem
	}
	if o.Version == "" {
		o.Version = AgentVersion
	}
	dataDir := o.DataDir
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
		Token:     token,
		Hostname:  hostname,
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		Version:   o.Version,
		AgentType: o.AgentType,
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

	client := &http.Client{Timeout: 15 * time.Second}
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

	if enrollResp.ServerCAPEM != "" {
		caPath := filepath.Join(dataDir, "server-ca.crt")
		if err := os.WriteFile(caPath, []byte(enrollResp.ServerCAPEM), 0o644); err != nil {
			return nil, fmt.Errorf("failed to write server CA bundle: %w", err)
		}
		cfg.ServerCACertPath = caPath
	}

	configPath := filepath.Join(dataDir, ConfigFileName)
	if existing, err := config.ReadAgentConfigFile(configPath); err == nil {
		cfg.DBBackup = existing.DBBackup
		cfg.InsecureSkipVerify = existing.InsecureSkipVerify
		if cfg.ServerCACertPath == "" {
			cfg.ServerCACertPath = existing.ServerCACertPath
		}
	}

	if err := cfg.Save(configPath); err != nil {
		return nil, err
	}
	return cfg, nil
}
