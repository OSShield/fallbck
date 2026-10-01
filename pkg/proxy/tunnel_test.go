package proxy_test

import (
	"context"
	"crypto/sha256"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/auth"
	"github.com/osshield/fallbck/pkg/db"
	"github.com/osshield/fallbck/pkg/gateway"
	"github.com/osshield/fallbck/pkg/proxy"
	"github.com/osshield/fallbck/pkg/proxy/pbstest"
	"github.com/osshield/gopbs/pbs"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

type fakeVerifier struct{ tokens map[string]*auth.AgentClaims }

func (f *fakeVerifier) Verify(_ context.Context, bearer string) (*auth.AgentClaims, error) {
	if c, ok := f.tokens[bearer]; ok {
		return c, nil
	}
	return nil, auth.ErrInvalidToken
}

type fakeTargets struct {
	targets map[uuid.UUID]*db.BackupTarget
}

func (f *fakeTargets) GetTargetByID(_ context.Context, id uuid.UUID) (*db.BackupTarget, error) {
	if t, ok := f.targets[id]; ok {
		return t, nil
	}
	return nil, db.ErrNotFound
}

type bearer string

func (b bearer) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{"authorization": "Bearer " + string(b)}, nil
}
func (bearer) RequireTransportSecurity() bool { return false }

// harness = fake PBS + gateway (auth) + tunnel on an h2c listener, like production
type harness struct {
	pbs      *pbstest.Server
	tm       *auth.TokenManager
	agentID  uuid.UUID
	targetID uuid.UUID
	conn     *grpc.ClientConn
}

func newHarness(t *testing.T, mutate func(*db.BackupTarget)) *harness {
	t.Helper()
	fake := pbstest.New(t)
	fake.ExpectAuthorization = "PBSAPIToken=root@pam!fallbck:s3cret" // canonical form; the target stores the "=" spelling

	tm := auth.NewTokenManager("test-secret-key-must-be-very-long-123456")
	agentID, targetID := uuid.New(), uuid.New()
	target := &db.BackupTarget{
		ID: targetID, Name: "fake", Endpoint: fake.URL(), Datastore: "store1", Namespace: "ns1",
		AuthToken: "root@pam!fallbck=s3cret", Fingerprint: fake.Fingerprint(), TLSVerify: true,
	}
	if mutate != nil {
		mutate(target)
	}

	verifier := &fakeVerifier{tokens: map[string]*auth.AgentClaims{
		"Bearer agent-a": {AgentID: agentID, TaskQueue: "q-a"},
		"Bearer agent-b": {AgentID: uuid.New(), TaskQueue: "q-b"},
	}}
	gw := gateway.New(nil, verifier, "default", nil)
	proxy.NewBackupTunnel(tm, &fakeTargets{targets: map[uuid.UUID]*db.BackupTarget{targetID: target}}, nil).Register(gw)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h2c.NewHandler(gw.Handler(http.NotFoundHandler()), &http2.Server{}), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { gw.GracefulStop(); _ = srv.Close() })

	conn, err := grpc.NewClient(l.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithPerRPCCredentials(bearer("agent-a")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &harness{pbs: fake, tm: tm, agentID: agentID, targetID: targetID, conn: conn}
}

func (h *harness) ticket(t *testing.T, agentID uuid.UUID) string {
	t.Helper()
	ticket, err := h.tm.CreateBackupTicket(auth.BackupTicketClaims{
		JobID: uuid.New(), AgentID: agentID, TargetID: h.targetID,
		Datastore: "store1", Namespace: "ns1", BackupType: "host", BackupID: "node6", BackupTime: 1700000000,
	}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return ticket
}

func TestTunnelCarriesBackupSession(t *testing.T) {
	h := newHarness(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ticket := h.ticket(t, h.agentID)

	// gopbs drives the session over the tunnelled connection
	client, err := pbs.NewClient(pbs.Config{DialSession: func(ctx context.Context, ref pbs.SnapshotRef) (net.Conn, error) {
		return proxy.Dial(ctx, h.conn, ticket)
	}})
	if err != nil {
		t.Fatal(err)
	}
	sess, err := client.StartBackup(ctx, pbs.SnapshotRef{Type: "host", ID: "node6", Time: time.Unix(1700000000, 0)})
	if err != nil {
		t.Fatalf("StartBackup through tunnel: %v", err)
	}
	wid, err := sess.CreateDynamicIndex(ctx, "root.pxar.didx")
	if err != nil {
		t.Fatalf("CreateDynamicIndex: %v", err)
	}
	plain := make([]byte, 300*1024) // spans several tunnel frames
	for i := range plain {
		plain[i] = byte(i)
	}
	digest := sha256.Sum256(plain)
	if err := sess.UploadDynamicChunk(ctx, pbs.NewBlobEncoder(), wid, digest, plain); err != nil {
		t.Fatalf("UploadDynamicChunk: %v", err)
	}
	if err := sess.AppendDynamicIndex(ctx, wid, []string{hexDigest(digest)}, []uint64{0}); err != nil {
		t.Fatalf("AppendDynamicIndex: %v", err)
	}
	if err := sess.CloseDynamicIndex(ctx, wid, [32]byte{}, uint64(len(plain)), 1); err != nil {
		t.Fatalf("CloseDynamicIndex: %v", err)
	}
	if err := sess.Finish(ctx); err != nil {
		t.Fatalf("Finish: %v", err)
	}

	if h.pbs.Finished() != 1 {
		t.Errorf("fake PBS finished sessions = %d", h.pbs.Finished())
	}
	ups := h.pbs.Upgrades()
	if len(ups) != 1 {
		t.Fatalf("upgrade requests = %d", len(ups))
	}
	q := ups[0].URL.Query()
	// Session identity comes from the ticket, never from the agent
	if q.Get("store") != "store1" || q.Get("ns") != "ns1" || q.Get("backup-id") != "node6" || q.Get("backup-type") != "host" || q.Get("backup-time") != "1700000000" {
		t.Errorf("unexpected upgrade query %q", ups[0].URL.RawQuery)
	}
	if ups[0].Header.Get("Authorization") != "PBSAPIToken=root@pam!fallbck:s3cret" {
		t.Errorf("token not injected: %q", ups[0].Header.Get("Authorization"))
	}
	if _, ok := h.pbs.Blobs()["index.json.blob"]; !ok {
		t.Error("manifest not uploaded")
	}
}

func hexDigest(d [32]byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 64)
	for i, b := range d {
		out[i*2], out[i*2+1] = digits[b>>4], digits[b&0x0f]
	}
	return string(out)
}

func TestTunnelRejections(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	t.Run("ticket of another agent", func(t *testing.T) {
		h := newHarness(t, nil)
		other := uuid.New()
		_, err := proxy.Dial(ctx, h.conn, h.ticket(t, other))
		if status.Code(err) != codes.PermissionDenied {
			t.Errorf("expected PermissionDenied, got %v", err)
		}
	})
	t.Run("no ticket", func(t *testing.T) {
		h := newHarness(t, nil)
		if _, err := proxy.Dial(ctx, h.conn, ""); err == nil {
			t.Error("expected error without ticket")
		}
	})
	t.Run("garbage ticket", func(t *testing.T) {
		h := newHarness(t, nil)
		_, err := proxy.Dial(ctx, h.conn, "not-a-jwt")
		if status.Code(err) != codes.Unauthenticated {
			t.Errorf("expected Unauthenticated, got %v", err)
		}
	})
	t.Run("agent token missing", func(t *testing.T) {
		h := newHarness(t, nil)
		anon, err := grpc.NewClient(h.conn.Target(), grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			t.Fatal(err)
		}
		defer anon.Close()
		_, err = proxy.Dial(ctx, anon, h.ticket(t, h.agentID))
		if status.Code(err) != codes.Unauthenticated {
			t.Errorf("expected Unauthenticated, got %v", err)
		}
	})
	t.Run("target without token", func(t *testing.T) {
		h := newHarness(t, func(tg *db.BackupTarget) { tg.AuthToken = "" })
		_, err := proxy.Dial(ctx, h.conn, h.ticket(t, h.agentID))
		if status.Code(err) != codes.FailedPrecondition {
			t.Errorf("expected FailedPrecondition, got %v", err)
		}
	})
	t.Run("PBS refuses credentials", func(t *testing.T) {
		h := newHarness(t, func(tg *db.BackupTarget) { tg.AuthToken = "root@pam!fallbck=wrong" })
		_, err := proxy.Dial(ctx, h.conn, h.ticket(t, h.agentID))
		if status.Code(err) != codes.PermissionDenied {
			t.Errorf("expected PermissionDenied from PBS 401, got %v", err)
		}
	})
	t.Run("fingerprint mismatch", func(t *testing.T) {
		h := newHarness(t, func(tg *db.BackupTarget) {
			tg.Fingerprint = "00:" + tg.Fingerprint[3:]
		})
		_, err := proxy.Dial(ctx, h.conn, h.ticket(t, h.agentID))
		if status.Code(err) != codes.Unavailable {
			t.Errorf("expected Unavailable on TLS pin failure, got %v", err)
		}
	})
	t.Run("agent closes mid-session", func(t *testing.T) {
		h := newHarness(t, nil)
		c, err := proxy.Dial(ctx, h.conn, h.ticket(t, h.agentID))
		if err != nil {
			t.Fatal(err)
		}
		_ = c.Close()
		// Whatever PBS already sent (its HTTP/2 preface) drains, then the stream errors
		deadline := time.Now().Add(5 * time.Second)
		for {
			if _, err := c.Read(make([]byte, 4096)); err != nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("read after close never failed")
			}
		}
	})
}

func TestTunnelUsesTargetNamespaceNotTicket(t *testing.T) {
	// Target is configured for "production"; the client presents a ticket claiming
	// "default". The tunnel must open the PBS session in the target's namespace.
	h := newHarness(t, func(tgt *db.BackupTarget) { tgt.Namespace = "production" })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ticket, err := h.tm.CreateBackupTicket(auth.BackupTicketClaims{
		JobID: uuid.New(), AgentID: h.agentID, TargetID: h.targetID,
		Datastore: "store1", Namespace: "default", BackupType: "host", BackupID: "node6", BackupTime: 1700000000,
	}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	client, err := pbs.NewClient(pbs.Config{DialSession: func(ctx context.Context, ref pbs.SnapshotRef) (net.Conn, error) {
		return proxy.Dial(ctx, h.conn, ticket)
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.StartBackup(ctx, pbs.SnapshotRef{Type: "host", ID: "node6", Time: time.Unix(1700000000, 0)}); err != nil {
		t.Fatalf("StartBackup: %v", err)
	}
	ups := h.pbs.Upgrades()
	if len(ups) != 1 {
		t.Fatalf("expected one PBS session, got %d", len(ups))
	}
	if ns := ups[0].URL.Query().Get("ns"); ns != "production" {
		t.Errorf("tunnel opened namespace %q, want the target's %q (ticket namespace must be ignored)", ns, "production")
	}
}
