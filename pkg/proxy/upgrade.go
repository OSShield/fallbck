// Package proxy carries agents' Proxmox Backup Server sessions through the FallBCK
// server.
//
// PBS ingests backups over its own protocol: an HTTP/1.1 request upgraded with
// `proxmox-backup-protocol-v1`, after which the connection speaks HTTP/2. Agents never
// hold PBS credentials; instead the server opens the session (this file), scoped to the
// snapshot identity bound into the agent's backup ticket, and pipes the bytes to the
// agent over a gRPC stream (tunnel.go). The agent side (client.go) exposes that stream
// as a net.Conn for gopbs.
package proxy

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/osshield/fallbck/pkg/db"
	"github.com/osshield/fallbck/pkg/pbs"
)

// BackupProtocol is the PBS backup protocol identifier
const BackupProtocol = "proxmox-backup-protocol-v1"

// SessionParams identifies the snapshot a backup session writes
type SessionParams struct {
	Datastore  string
	Namespace  string
	BackupType string // host | vm | ct
	BackupID   string
	BackupTime int64 // unix seconds
}

// UpgradeError is returned when PBS refuses the protocol upgrade
type UpgradeError struct {
	Status int
	Body   string
}

func (e *UpgradeError) Error() string {
	return fmt.Sprintf("PBS refused the backup session: %d %s: %s", e.Status, http.StatusText(e.Status), e.Body)
}

// pbsAddr derives host:port from a target endpoint (default port 8007)
func pbsAddr(endpoint string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("invalid PBS endpoint %q", endpoint)
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("PBS endpoint %q must use https", endpoint)
	}
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "8007")
	}
	return host, nil
}

// parseFingerprint accepts "SHA256:aa:bb:…", "aa:bb:…" or bare hex
func parseFingerprint(s string) ([32]byte, error) {
	var out [32]byte
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "SHA256:"), "sha256:")
	s = strings.ReplaceAll(s, ":", "")
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != 32 {
		return out, fmt.Errorf("fingerprint must be the SHA-256 of the certificate as colon-separated hex")
	}
	copy(out[:], raw)
	return out, nil
}

// tlsConfigFor builds the client TLS configuration for a target: a configured
// fingerprint pins the server certificate (like proxmox-backup-client), otherwise
// standard chain verification applies unless TLSVerify is off.
func tlsConfigFor(target *db.BackupTarget, serverName string) (*tls.Config, error) {
	cfg := &tls.Config{ServerName: serverName, NextProtos: []string{"http/1.1"}}
	if target.Fingerprint != "" {
		want, err := parseFingerprint(target.Fingerprint)
		if err != nil {
			return nil, err
		}
		cfg.InsecureSkipVerify = true //nolint:gosec // replaced by the fingerprint pin below
		cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("PBS presented no certificate")
			}
			if got := sha256.Sum256(rawCerts[0]); got != want {
				return fmt.Errorf("PBS certificate fingerprint mismatch: got %s", formatFingerprint(got))
			}
			return nil
		}
		return cfg, nil
	}
	cfg.InsecureSkipVerify = !target.TLSVerify //nolint:gosec // operator-controlled setting
	return cfg, nil
}

func formatFingerprint(sum [32]byte) string {
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02x", b)
	}
	return strings.Join(parts, ":")
}

// DialPBS opens a TLS connection to the target
func DialPBS(ctx context.Context, target *db.BackupTarget) (net.Conn, error) {
	addr, err := pbsAddr(target.Endpoint)
	if err != nil {
		return nil, err
	}
	host, _, _ := net.SplitHostPort(addr)
	tlsCfg, err := tlsConfigFor(target, host)
	if err != nil {
		return nil, err
	}
	dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 15 * time.Second}, Config: tlsCfg}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("connecting to PBS %s: %w", addr, err)
	}
	return conn, nil
}

// apiTokenHeader normalises the stored token into the PBS Authorization header value
func apiTokenHeader(token string) string {
	return pbs.AuthorizationHeader(token)
}

// upgradedConn preserves bytes the response reader consumed past the 101
type upgradedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *upgradedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// CloseWrite half-closes the underlying TLS connection when supported
func (c *upgradedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// UpgradeBackupSession performs the PBS protocol upgrade on conn with the target's API
// token for the snapshot described by p. On success the returned connection speaks
// HTTP/2 (the backup session); on refusal the error is an *UpgradeError.
func UpgradeBackupSession(ctx context.Context, conn net.Conn, host, apiToken string, p SessionParams) (net.Conn, error) {
	if p.Datastore == "" || p.BackupType == "" || p.BackupID == "" || p.BackupTime <= 0 {
		return nil, errors.New("incomplete backup session parameters")
	}
	query := url.Values{
		"store":       {p.Datastore},
		"backup-type": {p.BackupType},
		"backup-id":   {p.BackupID},
		"backup-time": {strconv.FormatInt(p.BackupTime, 10)},
	}
	if p.Namespace != "" {
		query.Set("ns", p.Namespace)
	}

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	}

	// The double slash mirrors proxmox-backup-client's request verbatim.
	var req strings.Builder
	fmt.Fprintf(&req, "GET //api2/json/backup?%s HTTP/1.1\r\n", query.Encode())
	fmt.Fprintf(&req, "Host: %s\r\n", host)
	fmt.Fprintf(&req, "Authorization: %s\r\n", apiTokenHeader(apiToken))
	fmt.Fprintf(&req, "Upgrade: %s\r\nConnection: Upgrade\r\n\r\n", BackupProtocol)
	slog.Debug("PBS upgrade request", "host", host, "query", query.Encode(), "token_id", pbs.TokenID(apiToken), "protocol", BackupProtocol)
	if _, err := io.WriteString(conn, req.String()); err != nil {
		return nil, fmt.Errorf("sending PBS upgrade request: %w", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return nil, fmt.Errorf("reading PBS upgrade response: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		_ = resp.Body.Close()
		slog.Debug("PBS upgrade refused", "host", host, "status", resp.Status, "body", strings.TrimSpace(string(body)), "www_authenticate", resp.Header.Get("WWW-Authenticate"))
		return nil, &UpgradeError{Status: resp.StatusCode, Body: strings.TrimSpace(string(body))}
	}
	slog.Debug("PBS upgrade accepted", "host", host, "upgrade", resp.Header.Get("Upgrade"))
	_ = conn.SetDeadline(time.Time{})
	return &upgradedConn{Conn: conn, r: br}, nil
}

// OpenBackupSession dials the target and opens a backup session for p
func OpenBackupSession(ctx context.Context, target *db.BackupTarget, p SessionParams) (net.Conn, error) {
	if target.AuthTokenEncrypted == "" {
		return nil, errors.New("backup target has no PBS API token configured")
	}
	addr, err := pbsAddr(target.Endpoint)
	if err != nil {
		return nil, err
	}
	conn, err := DialPBS(ctx, target)
	if err != nil {
		return nil, err
	}
	sess, err := UpgradeBackupSession(ctx, conn, addr, target.AuthTokenEncrypted, p)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return sess, nil
}
