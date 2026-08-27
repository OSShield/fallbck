package agent_test

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/auth"
	"github.com/osshield/fallbck/pkg/db"
	"github.com/osshield/fallbck/pkg/gateway"
	"github.com/osshield/fallbck/pkg/proxy"
	"github.com/osshield/fallbck/pkg/proxy/pbstest"
	"github.com/osshield/fallbck/pkg/temporal"
	"github.com/osshield/fallbck/pkg/temporal/activities"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type staticVerifier struct{ claims *auth.AgentClaims }

func (s staticVerifier) Verify(_ context.Context, bearer string) (*auth.AgentClaims, error) {
	if bearer == "Bearer agent-token" {
		return s.claims, nil
	}
	return nil, auth.ErrInvalidToken
}

type oneTarget struct{ target *db.BackupTarget }

func (o oneTarget) GetTargetByID(_ context.Context, id uuid.UUID) (*db.BackupTarget, error) {
	if id == o.target.ID {
		return o.target, nil
	}
	return nil, db.ErrNotFound
}

type tokenCreds struct{}

func (tokenCreds) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{"authorization": "Bearer agent-token"}, nil
}
func (tokenCreds) RequireTransportSecurity() bool { return false }

// TestEndToEndBackupFlow runs the real agent activity: the server side (gateway +
// tunnel) opens a session on a fake PBS with the target's token, and the agent streams
// a real pxar archive through it with gopbs.
func TestEndToEndBackupFlow(t *testing.T) {
	fake := pbstest.New(t)
	fake.ExpectAuthorization = "PBSAPIToken=backup@pbs!fallbck:secret"

	tm := auth.NewTokenManager("secret-jwt-key-32-bytes-long-1234")
	agentID, targetID, jobID := uuid.New(), uuid.New(), uuid.New()
	target := &db.BackupTarget{
		ID: targetID, Name: "fake-pbs", Endpoint: fake.URL(), Datastore: "backup-store", Namespace: "prod",
		AuthTokenEncrypted: "PBSAPIToken=backup@pbs!fallbck=secret", Fingerprint: fake.Fingerprint(), PxarFormat: db.PxarFormatV1,
	}

	// Server: gateway (agent auth) + tunnel on an h2c listener
	gw := gateway.New(nil, staticVerifier{&auth.AgentClaims{AgentID: agentID, TaskQueue: "q"}}, "default", nil)
	proxy.NewBackupTunnel(tm, oneTarget{target}, nil).Register(gw)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h2c.NewHandler(gw.Handler(http.NotFoundHandler()), &http2.Server{}), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(l) }()
	defer func() { gw.GracefulStop(); _ = srv.Close() }()

	// What PrepareBackupSession would produce
	now := time.Now().UTC()
	claims := auth.BackupTicketClaims{
		JobID: jobID, AgentID: agentID, TargetID: targetID, Datastore: target.Datastore, Namespace: target.Namespace,
		BackupType: "host", BackupID: "web-01", BackupTime: now.Unix(),
	}
	ticket, err := tm.CreateBackupTicket(claims, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	backupDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(backupDir, "app.conf"), []byte("[app]\nname=fallbck\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 3*1024*1024)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	if err := os.WriteFile(filepath.Join(backupDir, "data.bin"), payload, 0o644); err != nil {
		t.Fatal(err)
	}

	session := &temporal.BackupSessionInfo{
		JobID: jobID, AgentID: agentID, TargetID: targetID, AgentTaskQueue: "q",
		Ticket: ticket, Datastore: target.Datastore, Namespace: target.Namespace,
		BackupType: claims.BackupType, BackupID: claims.BackupID, BackupTime: claims.BackupTime,
		PxarFormat: target.PxarFormat, BackupPaths: []string{backupDir}, BackupRunID: uuid.New(),
	}

	// Agent: tunnel connection with its bearer token, then the real activity
	conn, err := grpc.NewClient(l.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithPerRPCCredentials(tokenCreds{}))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	acts := activities.NewAgentActivities()
	acts.Tunnel = conn

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	result, err := runActivity(ctx, acts, session)
	if err != nil {
		t.Fatalf("ExecuteFilesystemBackup: %v", err)
	}
	if result.Status != db.RunStatusCompleted || result.ChunkCount == 0 || result.BytesScanned < int64(len(payload)) {
		t.Errorf("unexpected result %+v", result)
	}
	if !strings.HasPrefix(result.SnapshotID, "host/web-01/") {
		t.Errorf("snapshot id %q", result.SnapshotID)
	}

	// The fake PBS saw one session, opened with the target's token and the ticket's identity
	ups := fake.Upgrades()
	if len(ups) != 1 {
		t.Fatalf("expected 1 PBS session, got %d", len(ups))
	}
	q := ups[0].URL.Query()
	if q.Get("store") != "backup-store" || q.Get("ns") != "prod" || q.Get("backup-id") != "web-01" {
		t.Errorf("session scoped incorrectly: %s", ups[0].URL.RawQuery)
	}
	if fake.Finished() != 1 {
		t.Error("session was not finished")
	}
	idx := fake.Indexes()
	for _, name := range []string{"catalog.pcat1.didx"} {
		if _, ok := idx[name]; !ok {
			t.Errorf("index %s missing", name)
		}
	}
	pxarFound := false
	for name := range idx {
		if strings.HasSuffix(name, ".pxar.didx") {
			pxarFound = true
		}
	}
	if !pxarFound {
		t.Errorf("no pxar index uploaded: %v", idx)
	}
	if _, ok := fake.Blobs()["index.json.blob"]; !ok {
		t.Error("manifest missing")
	}
}
