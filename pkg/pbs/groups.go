package pbs

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// BackupGroup is one backup group in a PBS datastore
type BackupGroup struct {
	BackupType  string `json:"backup-type"`
	BackupID    string `json:"backup-id"`
	LastBackup  int64  `json:"last-backup"` // unix time of the newest snapshot
	BackupCount int64  `json:"backup-count"`
}

// ListGroups lists the backup groups of a datastore (optionally within a namespace)
func (c *Client) ListGroups(ctx context.Context, datastore, namespace string) ([]BackupGroup, error) {
	reqURL := fmt.Sprintf("%s/api2/json/admin/datastore/%s/groups", c.Endpoint, url.PathEscape(datastore))
	params := url.Values{}
	if namespace != "" {
		params.Set("ns", namespace)
	}
	if len(params) > 0 {
		reqURL += "?" + params.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	c.setAuth(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("listing PBS groups: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("PBS group list returned status %d: %s", resp.StatusCode, string(body))
	}
	var payload struct {
		Data []BackupGroup `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decoding PBS group list: %w", err)
	}
	return payload.Data, nil
}

// DeleteGroup removes a whole backup group (all its snapshots) from the datastore
func (c *Client) DeleteGroup(ctx context.Context, datastore, namespace, backupType, backupID string) error {
	params := url.Values{}
	params.Set("backup-type", backupType)
	params.Set("backup-id", backupID)
	if namespace != "" {
		params.Set("ns", namespace)
	}
	reqURL := fmt.Sprintf("%s/api2/json/admin/datastore/%s/groups?%s", c.Endpoint, url.PathEscape(datastore), params.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, reqURL, nil)
	if err != nil {
		return err
	}
	c.setAuth(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("deleting PBS group: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("PBS group delete returned status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}
