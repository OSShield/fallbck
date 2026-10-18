package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/osshield/fallbck/pkg/db"
	"github.com/osshield/fallbck/pkg/pbs"
)

// TokenPermissions asks PBS what the target's API token may do: GET
// /api2/json/access/permissions as the token itself, which needs no privilege
// ("limited to own privileges"). path "" lists every path where the token holds
// something; a path asks about that one. TLS is the backup tunnel's: the target's
// fingerprint pin, else chain verification unless TLSVerify is off.
func TokenPermissions(ctx context.Context, target *db.BackupTarget, path string) (map[string]map[string]bool, error) {
	addr, err := pbsAddr(target.Endpoint)
	if err != nil {
		return nil, err
	}
	host, _, _ := net.SplitHostPort(addr)
	tlsCfg, err := tlsConfigFor(target, host)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}}
	defer client.CloseIdleConnections()

	u := url.URL{Scheme: "https", Host: addr, Path: "/api2/json/access/permissions"}
	if path != "" {
		u.RawQuery = url.Values{"path": {path}}.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", pbs.AuthorizationHeader(target.AuthToken))
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("asking PBS %s for the token's permissions: %w", addr, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("PBS answered %s to the permission query: %s", resp.Status, truncate(string(body), 200))
	}
	var envelope struct {
		Data map[string]map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("PBS permission answer is not JSON: %w", err)
	}
	// propagate comes as a bool, or as 0/1 from older versions
	out := make(map[string]map[string]bool, len(envelope.Data))
	for p, privs := range envelope.Data {
		out[p] = make(map[string]bool, len(privs))
		for priv, v := range privs {
			switch b := v.(type) {
			case bool:
				out[p][priv] = b
			case float64:
				out[p][priv] = b != 0
			default:
				out[p][priv] = true
			}
		}
	}
	return out, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
