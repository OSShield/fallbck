// Package gateway exposes a narrow, authenticated slice of the Temporal WorkflowService
// to backup agents on the server's public port.
//
// Agents are Temporal SDK activity workers. Instead of reaching the Temporal frontend
// directly they speak gRPC to fallbck-server, which authenticates the agent bearer
// token, allows only the RPCs an activity-only worker needs, pins every call to the
// agent's own task queue and forwards it to the real frontend (embedded loopback or an
// external cluster). This makes the gateway the single authorization boundary for
// agents regardless of how Temporal is deployed.
package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/osshield/fallbck/pkg/auth"
	"go.temporal.io/api/workflowservice/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// MaxMessageSize matches Temporal's default frontend limit (4 MiB) with headroom
const MaxMessageSize = 64 * 1024 * 1024

// AgentVerifier authenticates agent bearer tokens (implemented by *auth.AgentVerifier)
type AgentVerifier interface {
	Verify(ctx context.Context, bearer string) (*auth.AgentClaims, error)
}

// Gateway is the authenticating WorkflowService proxy
type Gateway struct {
	namespace string
	verifier  AgentVerifier
	backend   workflowservice.WorkflowServiceClient
	logger    *slog.Logger
	server    *grpc.Server
}

// New builds a gateway in front of backend for the given namespace
func New(backend workflowservice.WorkflowServiceClient, verifier AgentVerifier, namespace string, logger *slog.Logger) *Gateway {
	if logger == nil {
		logger = slog.Default()
	}
	g := &Gateway{namespace: namespace, verifier: verifier, backend: backend, logger: logger.With("component", "gateway")}
	g.server = grpc.NewServer(
		grpc.ChainUnaryInterceptor(g.authenticate),
		grpc.ChainStreamInterceptor(g.authenticateStream),
		grpc.MaxRecvMsgSize(MaxMessageSize),
		grpc.MaxSendMsgSize(MaxMessageSize),
	)
	workflowservice.RegisterWorkflowServiceServer(g.server, &service{g: g})
	return g
}

// Dial connects to a Temporal frontend for use as the gateway backend. tlsConfig nil
// means plaintext (the embedded loopback frontend).
func Dial(addr string, tlsConfig *tls.Config) (*grpc.ClientConn, error) {
	creds := insecure.NewCredentials()
	if tlsConfig != nil {
		creds = credentials.NewTLS(tlsConfig)
	}
	return grpc.NewClient(addr,
		grpc.WithTransportCredentials(creds),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(MaxMessageSize), grpc.MaxCallSendMsgSize(MaxMessageSize)),
	)
}

// GRPCServer exposes the underlying server (for ServeHTTP or a dedicated listener)
func (g *Gateway) GRPCServer() *grpc.Server {
	return g.server
}

// IsGRPCRequest reports whether an HTTP/2 request carries gRPC
func IsGRPCRequest(r *http.Request) bool {
	return r.ProtoMajor == 2 && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc")
}

// Handler routes gRPC requests to the gateway and everything else to next. Mount it as
// the root handler of an h2c-enabled http.Server.
func (g *Gateway) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if IsGRPCRequest(r) {
			g.server.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// GracefulStop stops accepting new RPCs and waits for in-flight ones
func (g *Gateway) GracefulStop() {
	g.server.GracefulStop()
}

// RegisterService adds another gRPC service (e.g. the PBS backup tunnel) to the
// gateway server. Its RPCs are subject to the same agent authentication.
func (g *Gateway) RegisterService(desc *grpc.ServiceDesc, impl any) {
	g.server.RegisterService(desc, impl)
}

// verify resolves the agent identity from the request metadata
func (g *Gateway) verify(ctx context.Context, method string) (*auth.AgentClaims, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	values := md.Get("authorization")
	if len(values) == 0 || strings.TrimSpace(values[0]) == "" {
		return nil, status.Error(codes.Unauthenticated, "agent token required")
	}
	claims, err := g.verifier.Verify(ctx, values[0])
	if err != nil {
		if errors.Is(err, auth.ErrInvalidToken) || errors.Is(err, auth.ErrAgentRevoked) {
			g.logger.Warn("Rejected agent RPC", "method", method, "reason", err.Error())
			return nil, status.Error(codes.Unauthenticated, "invalid or revoked agent token")
		}
		g.logger.Error("Agent authentication failed", "method", method, "error", err)
		return nil, status.Error(codes.Internal, "authentication error")
	}
	return claims, nil
}

// authenticate is the unary interceptor: every RPC needs a valid agent token
func (g *Gateway) authenticate(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	claims, err := g.verify(ctx, info.FullMethod)
	if err != nil {
		return nil, err
	}
	return handler(auth.WithAgent(ctx, claims), req)
}

// authenticateStream is the streaming counterpart (used by the PBS tunnel)
func (g *Gateway) authenticateStream(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	claims, err := g.verify(ss.Context(), info.FullMethod)
	if err != nil {
		return err
	}
	return handler(srv, &authenticatedStream{ServerStream: ss, ctx: auth.WithAgent(ss.Context(), claims)})
}

// authenticatedStream carries the agent claims in the stream context
type authenticatedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *authenticatedStream) Context() context.Context { return s.ctx }

// outgoing derives the backend call context: incoming metadata minus the agent's
// authorization header. The deadline of ctx (from grpc-timeout) is preserved.
func (g *Gateway) outgoing(ctx context.Context) context.Context {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ctx
	}
	out := metadata.MD{}
	for k, v := range md {
		switch strings.ToLower(k) {
		case "authorization", ":authority", "content-type", "user-agent", "te":
			continue
		}
		out[k] = v
	}
	return metadata.NewOutgoingContext(ctx, out)
}
