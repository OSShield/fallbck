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
	"time"

	"github.com/osshield/fallbck/pkg/api"
	"github.com/osshield/fallbck/pkg/config"
	"gopkg.in/yaml.v3"
)

// EnrollAgent contacts the FallBCK server with an enrollment token, retrieves mTLS certs and saves agent config
func EnrollAgent(ctx context.Context, serverURL, token, dataDir string) (*config.AgentConfig, error) {
	if dataDir == "" {
		home, _ := os.UserHomeDir()
		dataDir = filepath.Join(home, ".fallbck", "agent")
	}

	hostname, _ := os.Hostname()
	reqBody := api.EnrollRequest{
		Token:    token,
		Hostname: hostname,
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		Version:  "0.1.0",
	}

	jsonBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal enrollment request: %w", err)
	}

	endpoint := fmt.Sprintf("%s/api/v1/agents/enroll", serverURL)
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

	// Prepare data directory
	certsDir := filepath.Join(dataDir, "certs")
	if err := os.MkdirAll(certsDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create certs directory: %w", err)
	}

	caCertPath := filepath.Join(certsDir, "ca.crt")
	clientCertPath := filepath.Join(certsDir, "client.crt")
	clientKeyPath := filepath.Join(certsDir, "client.key")

	if enrollResp.CACertPEM != "" {
		if err := os.WriteFile(caCertPath, []byte(enrollResp.CACertPEM), 0644); err != nil {
			return nil, fmt.Errorf("failed to write CA cert: %w", err)
		}
	}
	if enrollResp.ClientCertPEM != "" && enrollResp.ClientKeyPEM != "" {
		if err := os.WriteFile(clientCertPath, []byte(enrollResp.ClientCertPEM), 0644); err != nil {
			return nil, fmt.Errorf("failed to write client cert: %w", err)
		}
		if err := os.WriteFile(clientKeyPath, []byte(enrollResp.ClientKeyPEM), 0600); err != nil {
			return nil, fmt.Errorf("failed to write client key: %w", err)
		}
	}

	// Construct AgentConfig
	cfg := &config.AgentConfig{
		AgentID:   enrollResp.AgentID.String(),
		Hostname:  hostname,
		ServerURL: serverURL,
		DataDir:   dataDir,
		TaskQueue: enrollResp.TaskQueue,
		Temporal: config.TemporalConfig{
			HostPort:           enrollResp.TemporalHost,
			Namespace:          enrollResp.TemporalNamespace,
			EnableTLS:          enrollResp.TemporalTLS,
			CACertPath:         caCertPath,
			ClientCertPath:     clientCertPath,
			ClientKeyPath:      clientKeyPath,
			InsecureSkipVerify: false,
			ConnectTimeout:     10 * time.Second,
		},
	}

	configFile := filepath.Join(dataDir, "agent.yaml")
	cfgBytes, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize agent config: %w", err)
	}

	if err := os.WriteFile(configFile, cfgBytes, 0600); err != nil {
		return nil, fmt.Errorf("failed to write agent config file %s: %w", configFile, err)
	}

	return cfg, nil
}
