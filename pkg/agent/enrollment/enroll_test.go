package enrollment

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/api"
	"github.com/osshield/fallbck/pkg/config"
)

// selfSignedServer serves the enrollment endpoint over TLS with httptest's self-signed
// certificate, which no system trust store accepts
func selfSignedServer(t *testing.T, caPEM string) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agents/enroll" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		var req api.EnrollRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Token != "tok" {
			http.Error(w, "bad token", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(api.EnrollResponse{
			AgentID: uuid.New(), TaskQueue: "agent-q", Namespace: "default",
			AuthToken: "bearer", TokenExpiresAt: time.Now().Add(time.Hour), ServerCAPEM: caPEM,
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func writeServerCA(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	cert := srv.Certificate()
	if cert == nil {
		t.Fatal("test server has no certificate")
	}
	path := filepath.Join(t.TempDir(), "ca.crt")
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestEnrollRejectsUntrustedServerByDefault(t *testing.T) {
	srv := selfSignedServer(t, "")
	_, err := Enroll(context.Background(), Options{ServerURL: srv.URL, Token: "tok", DataDir: t.TempDir()})
	if err == nil {
		t.Fatal("expected a certificate error, got success")
	}
	var unknown x509.UnknownAuthorityError
	if !strings.Contains(err.Error(), "certificate") && !errorsAs(err, &unknown) {
		t.Fatalf("expected a TLS verification error, got: %v", err)
	}
}

func TestEnrollTrustsOperatorCA(t *testing.T) {
	srv := selfSignedServer(t, "")
	caPath := writeServerCA(t, srv)
	dataDir := t.TempDir()

	cfg, err := Enroll(context.Background(), Options{ServerURL: srv.URL, Token: "tok", DataDir: dataDir, CACertPath: caPath})
	if err != nil {
		t.Fatalf("enroll with CA: %v", err)
	}
	if cfg.ServerCACertPath != caPath {
		t.Fatalf("operator CA not persisted: got %q", cfg.ServerCACertPath)
	}
	if cfg.AuthToken != "bearer" || cfg.TaskQueue != "agent-q" {
		t.Fatalf("unexpected identity: %+v", cfg)
	}
	saved, err := config.ReadAgentConfigFile(filepath.Join(dataDir, ConfigFileName))
	if err != nil {
		t.Fatal(err)
	}
	if saved.ServerCACertPath != caPath || saved.InsecureSkipVerify {
		t.Fatalf("agent.yaml TLS settings wrong: ca=%q insecure=%v", saved.ServerCACertPath, saved.InsecureSkipVerify)
	}
}

func TestEnrollOperatorCAWinsOverAdvertisedCA(t *testing.T) {
	srv := selfSignedServer(t, "-----BEGIN CERTIFICATE-----\nadvertised\n-----END CERTIFICATE-----\n")
	caPath := writeServerCA(t, srv)
	dataDir := t.TempDir()

	cfg, err := Enroll(context.Background(), Options{ServerURL: srv.URL, Token: "tok", DataDir: dataDir, CACertPath: caPath})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if cfg.ServerCACertPath != caPath {
		t.Fatalf("advertised CA replaced the operator's: %q", cfg.ServerCACertPath)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "server-ca.crt")); !os.IsNotExist(err) {
		t.Fatalf("advertised CA should not be written when the operator supplied one (stat err=%v)", err)
	}
}

func TestEnrollAdvertisedCAUsedWhenNoOperatorCA(t *testing.T) {
	srv := selfSignedServer(t, "-----BEGIN CERTIFICATE-----\nadvertised\n-----END CERTIFICATE-----\n")
	dataDir := t.TempDir()

	cfg, err := Enroll(context.Background(), Options{ServerURL: srv.URL, Token: "tok", DataDir: dataDir, InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	want := filepath.Join(dataDir, "server-ca.crt")
	if cfg.ServerCACertPath != want {
		t.Fatalf("advertised CA path: got %q want %q", cfg.ServerCACertPath, want)
	}
	if !cfg.InsecureSkipVerify {
		t.Fatal("insecure_skip_verify not persisted")
	}
}

func TestEnrollInsecureSkipVerify(t *testing.T) {
	srv := selfSignedServer(t, "")
	cfg, err := Enroll(context.Background(), Options{ServerURL: srv.URL, Token: "tok", DataDir: t.TempDir(), InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("enroll with insecure_skip_verify: %v", err)
	}
	if !cfg.InsecureSkipVerify {
		t.Fatal("insecure_skip_verify not persisted")
	}
}

func TestEnrollUnreadableCAFailsEarly(t *testing.T) {
	srv := selfSignedServer(t, "")
	_, err := Enroll(context.Background(), Options{ServerURL: srv.URL, Token: "tok", DataDir: t.TempDir(), CACertPath: filepath.Join(t.TempDir(), "missing.crt")})
	if err == nil || !strings.Contains(err.Error(), "server CA bundle") {
		t.Fatalf("expected a CA bundle error, got: %v", err)
	}
}

func TestEnrollPreservesExistingInsecureSetting(t *testing.T) {
	srv := selfSignedServer(t, "")
	dataDir := t.TempDir()
	existing := &config.AgentConfig{InsecureSkipVerify: true}
	if err := existing.Save(filepath.Join(dataDir, ConfigFileName)); err != nil {
		t.Fatal(err)
	}
	caPath := writeServerCA(t, srv)
	cfg, err := Enroll(context.Background(), Options{ServerURL: srv.URL, Token: "tok", DataDir: dataDir, CACertPath: caPath})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if !cfg.InsecureSkipVerify {
		t.Fatal("existing insecure_skip_verify was dropped on re-enrollment")
	}
}

func errorsAs(err error, target *x509.UnknownAuthorityError) bool {
	for e := err; e != nil; e = unwrap(e) {
		if u, ok := e.(x509.UnknownAuthorityError); ok {
			*target = u
			return true
		}
	}
	return false
}

func unwrap(err error) error {
	if u, ok := err.(interface{ Unwrap() error }); ok {
		return u.Unwrap()
	}
	return nil
}
