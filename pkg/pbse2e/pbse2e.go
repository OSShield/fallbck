//go:build pbse2e

// Package pbse2e starts a throwaway Proxmox Backup Server (github.com/osshield/ephemeral-pbs)
// for the tests that need the real thing instead of the pbstest fake. Run them with
//
//	go test -tags pbse2e -count=1 ./pkg/tokencheck/ ./pkg/agent/
//
// Docker is required. FALLBCK_E2E_PBS_IMAGE overrides the image, e.g. a local build of
// ephemeral-pbs's advanced container. Users, tokens and namespaces are in pbs-config.yml.
package pbse2e

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/db"
)

const (
	DefaultImage = "ghcr.io/osshield/ephemeral-pbs:advanced"
	Datastore    = "data"
	// TokenSecret is the secret of every token in pbs-config.yml
	TokenSecret = "12345678-1234-1234-1234-1234567890ab"
	// rootPassword is ephemeral-pbs's root@pam password
	rootPassword = "demo"
)

//go:embed pbs-config.yml
var config []byte

// PBS is a running ephemeral-pbs container
type PBS struct {
	container string
	configDir string
	// URL is the API endpoint on the host (https://127.0.0.1:<port>)
	URL string
	// Fingerprint is the SHA-256 of the server certificate, colon-separated hex
	Fingerprint string
}

// Main starts the server, runs the package's tests and stops it; for TestMain:
//
//	func TestMain(m *testing.M) { os.Exit(pbse2e.Main(m, &srv)) }
func Main(m *testing.M, srv **PBS) int {
	p, err := Start()
	if err != nil {
		fmt.Fprintln(os.Stderr, "pbse2e:", err)
		return 1
	}
	*srv = p
	defer p.Stop()
	return m.Run()
}

// Start runs the container and waits until ephemeral-pbs has applied pbs-config.yml
func Start() (*PBS, error) {
	image := os.Getenv("FALLBCK_E2E_PBS_IMAGE")
	if image == "" {
		image = DefaultImage
	}
	dir, err := os.MkdirTemp("", "pbse2e-")
	if err != nil {
		return nil, err
	}
	cfg := filepath.Join(dir, "pbs-config.yml")
	if err := os.WriteFile(cfg, config, 0o644); err != nil {
		return nil, err
	}
	p := &PBS{container: "fallbck-pbse2e-" + uuid.NewString()[:8], configDir: dir}
	if _, err := docker(nil, "run", "-d", "--name", p.container, "--tmpfs", "/run", "-e", "POSTFIX=N",
		"-v", cfg+":/etc/pbs-config.yml:ro", "-p", "127.0.0.1::8007", image); err != nil {
		p.Stop()
		return nil, err
	}
	if err := p.waitReady(3 * time.Minute); err != nil {
		logs, _ := docker(nil, "logs", "--tail", "40", p.container)
		p.Stop()
		return nil, fmt.Errorf("%w\n%s", err, logs)
	}
	port, err := docker(nil, "port", p.container, "8007/tcp")
	if err != nil {
		p.Stop()
		return nil, err
	}
	// "127.0.0.1:32768", possibly followed by an IPv6 line
	p.URL = "https://" + strings.Fields(port)[0]
	if p.Fingerprint, err = fingerprint(strings.TrimPrefix(p.URL, "https://")); err != nil {
		p.Stop()
		return nil, err
	}
	return p, nil
}

// waitReady polls the log for the summary ephemeral-pbs prints after the config
// applied and every token authenticated; a failed setup stops the container
func (p *PBS) waitReady(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if logs, _ := docker(nil, "logs", p.container); strings.Contains(logs, "API tokens:") {
			return nil
		}
		if running, _ := docker(nil, "inspect", "-f", "{{.State.Running}}", p.container); strings.TrimSpace(running) == "false" {
			return fmt.Errorf("PBS container %s exited during setup", p.container)
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("PBS container %s not ready after %s", p.container, timeout)
}

// Stop removes the container
func (p *PBS) Stop() {
	_, _ = docker(nil, "rm", "-f", "-v", p.container)
	_ = os.RemoveAll(p.configDir)
}

// Target is a backup target for user's token (<user>@pbs!fallbck in pbs-config.yml)
func (p *PBS) Target(user, namespace string) *db.BackupTarget {
	return &db.BackupTarget{
		ID: uuid.New(), Name: "pbse2e-" + user, Endpoint: p.URL, Datastore: Datastore, Namespace: namespace,
		AuthToken: user + "@pbs!fallbck:" + TokenSecret, Fingerprint: p.Fingerprint, PxarFormat: db.PxarFormatV1,
	}
}

// Exec runs a command in the container as root, with env (KEY=value) and optional stdin
func (p *PBS) Exec(env []string, stdin []byte, args ...string) (string, error) {
	cmd := []string{"exec", "-i"}
	for _, e := range env {
		cmd = append(cmd, "-e", e)
	}
	cmd = append(cmd, p.container)
	return docker(stdin, append(cmd, args...)...)
}

// Client runs proxmox-backup-client in the container as root@pam on the datastore;
// env adds variables such as PBS_ENCRYPTION_PASSWORD
func (p *PBS) Client(env []string, args ...string) (string, error) {
	env = append([]string{
		"PBS_REPOSITORY=root@pam@localhost:" + Datastore,
		"PBS_PASSWORD=" + rootPassword,
		"PBS_FINGERPRINT=" + p.Fingerprint,
	}, env...)
	return p.Exec(env, nil, append([]string{"proxmox-backup-client"}, args...)...)
}

// WriteFile writes data to path inside the container
func (p *PBS) WriteFile(path string, data []byte) error {
	_, err := p.Exec(nil, data, "sh", "-c", `cat > "$1"`, "sh", path)
	return err
}

// Chunks counts the chunk files of the datastore
func (p *PBS) Chunks() (int, error) {
	out, err := p.Exec(nil, nil, "sh", "-c", "find /var/lib/proxmox-backup/datastore/.chunks -type f | wc -l")
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(out))
}

func docker(stdin []byte, args ...string) (string, error) {
	cmd := exec.Command("docker", args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("docker %s: %w: %s", args[0], err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func fingerprint(addr string) (string, error) {
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // reading the self-signed cert to pin it
	if err != nil {
		return "", err
	}
	defer conn.Close()
	sum := sha256.Sum256(conn.ConnectionState().PeerCertificates[0].Raw)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02x", b)
	}
	return strings.Join(parts, ":"), nil
}
