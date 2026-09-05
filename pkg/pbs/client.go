package pbs

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client is an HTTP client for Proxmox Backup Server
type Client struct {
	Endpoint    string
	APIToken    string
	TLSVerify   bool
	Fingerprint string
	httpClient  *http.Client
}

// NewClient creates a new PBS API client
func NewClient(endpoint, apiToken string, tlsVerify bool, fingerprint string) *Client {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: !tlsVerify,
	}

	transport := &http.Transport{
		TLSClientConfig:    tlsConfig,
		MaxIdleConns:       50,
		IdleConnTimeout:    90 * time.Second,
		DisableCompression: false,
	}

	return &Client{
		Endpoint:    strings.TrimRight(endpoint, "/"),
		APIToken:    apiToken,
		TLSVerify:   tlsVerify,
		Fingerprint: fingerprint,
		httpClient:  &http.Client{Transport: transport, Timeout: 30 * time.Second},
	}
}

// Ping checks if the PBS endpoint is reachable
func (c *Client) Ping(ctx context.Context) error {
	reqURL := fmt.Sprintf("%s/api2/json/version", c.Endpoint)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return err
	}
	c.setAuth(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to connect to PBS endpoint %s: %w", c.Endpoint, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("PBS ping returned status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// PruneDatastore executes a prune job on the PBS datastore according to retention policy
func (c *Client) PruneDatastore(ctx context.Context, datastore, namespace, backupType, backupID string, keepLast, keepDaily, keepWeekly, keepMonthly int) error {
	reqURL := fmt.Sprintf("%s/api2/json/admin/datastore/%s/prune", c.Endpoint, url.PathEscape(datastore))

	params := url.Values{}
	if namespace != "" {
		params.Set("ns", namespace)
	}
	if backupType != "" {
		params.Set("backup-type", backupType)
	}
	if backupID != "" {
		params.Set("backup-id", backupID)
	}
	if keepLast > 0 {
		params.Set("keep-last", fmt.Sprintf("%d", keepLast))
	}
	if keepDaily > 0 {
		params.Set("keep-daily", fmt.Sprintf("%d", keepDaily))
	}
	if keepWeekly > 0 {
		params.Set("keep-weekly", fmt.Sprintf("%d", keepWeekly))
	}
	if keepMonthly > 0 {
		params.Set("keep-monthly", fmt.Sprintf("%d", keepMonthly))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, strings.NewReader(params.Encode()))
	if err != nil {
		return err
	}
	c.setAuth(req)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute PBS prune: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("PBS prune failed with status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

func (c *Client) setAuth(req *http.Request) {
	if c.APIToken != "" {
		req.Header.Set("Authorization", AuthorizationHeader(c.APIToken))
	}
}

// DecodePBSResponse helper
func DecodePBSResponse(body io.Reader, out interface{}) error {
	var envelope struct {
		Data    json.RawMessage `json:"data"`
		Message string          `json:"message"`
	}
	if err := json.NewDecoder(body).Decode(&envelope); err != nil {
		return err
	}
	if out != nil && len(envelope.Data) > 0 {
		return json.Unmarshal(envelope.Data, out)
	}
	return nil
}
