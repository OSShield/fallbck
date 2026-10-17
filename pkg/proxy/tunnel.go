package proxy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/auth"
	"github.com/osshield/fallbck/pkg/db"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// gRPC wire identifiers of the tunnel. Frames are google.protobuf.BytesValue, so no
// generated code is needed on either side.
const (
	ServiceName       = "fallbck.pbs.v1.BackupTunnel"
	MethodSession     = "/" + ServiceName + "/Session"
	TicketMetadataKey = "x-fallbck-backup-ticket"
	readyHeaderKey    = "x-fallbck-tunnel"
	frameSize         = 64 * 1024
)

// TargetStore looks up backup targets (implemented by *db.DB)
type TargetStore interface {
	GetTargetByID(ctx context.Context, id uuid.UUID, scope db.Scope) (*db.BackupTarget, error)
}

// SessionOpener opens a PBS backup session for a target (OpenBackupSession by default)
type SessionOpener func(ctx context.Context, target *db.BackupTarget, p SessionParams) (net.Conn, error)

// BackupTunnel is the server side: it authenticates the agent's backup ticket, opens
// the PBS session it describes with the target's API token, and pipes bytes.
type BackupTunnel struct {
	tm      *auth.TokenManager
	targets TargetStore
	open    SessionOpener
	logger  *slog.Logger
}

// NewBackupTunnel creates the tunnel service
func NewBackupTunnel(tm *auth.TokenManager, targets TargetStore, logger *slog.Logger) *BackupTunnel {
	if logger == nil {
		logger = slog.Default()
	}
	return &BackupTunnel{tm: tm, targets: targets, open: OpenBackupSession, logger: logger.With("component", "pbs-tunnel")}
}

// WithOpener overrides how PBS sessions are opened (tests)
func (t *BackupTunnel) WithOpener(open SessionOpener) *BackupTunnel {
	t.open = open
	return t
}

// Register adds the tunnel service to a gRPC server (e.g. the agent gateway, whose
// interceptors authenticate the agent token first)
func (t *BackupTunnel) Register(s grpc.ServiceRegistrar) {
	s.RegisterService(&ServiceDesc, t)
}

type sessionServer interface {
	Session(grpc.ServerStream) error
}

// ServiceDesc describes the tunnel service for grpc.Server / grpc.ClientConn
var ServiceDesc = grpc.ServiceDesc{
	ServiceName: ServiceName,
	HandlerType: (*sessionServer)(nil),
	Streams: []grpc.StreamDesc{{
		StreamName:    "Session",
		Handler:       func(srv any, ss grpc.ServerStream) error { return srv.(sessionServer).Session(ss) },
		ServerStreams: true,
		ClientStreams: true,
	}},
	Metadata: "fallbck/pbs/v1/tunnel",
}

// SessionStreamDesc is the client-side stream descriptor
var SessionStreamDesc = grpc.StreamDesc{StreamName: "Session", ServerStreams: true, ClientStreams: true}

// Session handles one tunnelled backup session
func (t *BackupTunnel) Session(ss grpc.ServerStream) error {
	ctx := ss.Context()

	agent := auth.AgentFrom(ctx)
	if agent == nil {
		return status.Error(codes.Unauthenticated, "agent identity required")
	}
	md, _ := metadata.FromIncomingContext(ctx)
	tickets := md.Get(TicketMetadataKey)
	if len(tickets) == 0 || strings.TrimSpace(tickets[0]) == "" {
		return status.Error(codes.Unauthenticated, "backup ticket required")
	}
	claims, err := t.tm.ValidateBackupTicket(tickets[0])
	if err != nil {
		t.logger.Warn("Rejected tunnel: invalid backup ticket", "agent_id", agent.AgentID, "error", err)
		return status.Error(codes.Unauthenticated, "invalid or expired backup ticket")
	}
	if claims.AgentID != agent.AgentID {
		t.logger.Warn("Rejected tunnel: ticket belongs to another agent", "agent_id", agent.AgentID, "ticket_agent_id", claims.AgentID)
		return status.Error(codes.PermissionDenied, "backup ticket was not issued to this agent")
	}

	target, err := t.targets.GetTargetByID(ctx, claims.TargetID, db.Unscoped)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return status.Error(codes.NotFound, "backup target no longer exists")
		}
		t.logger.Error("Failed to load backup target", "target_id", claims.TargetID, "error", err)
		return status.Error(codes.Internal, "failed to load backup target")
	}
	if target.AuthToken == "" {
		return status.Error(codes.FailedPrecondition, "backup target has no PBS API token configured")
	}

	// The PBS namespace is configured by an administrator on the target and is the
	// single source of truth; a namespace carried in the (client-held) ticket is
	// ignored so a client can never redirect a backup into another namespace.
	if claims.Namespace != "" && claims.Namespace != target.Namespace {
		t.logger.Warn("Ignoring namespace from the backup ticket; using the target's configured namespace",
			"agent_id", agent.AgentID, "ticket_namespace", claims.Namespace, "target_namespace", target.Namespace)
	}
	params := SessionParams{
		Datastore:  claims.Datastore,
		Namespace:  target.Namespace,
		BackupType: claims.BackupType,
		BackupID:   claims.BackupID,
		BackupTime: claims.BackupTime,
	}
	t.logger.Info("Opening PBS backup session", "agent_id", agent.AgentID, "target", target.Name,
		"datastore", params.Datastore, "namespace", params.Namespace, "backup_id", params.BackupID, "backup_time", params.BackupTime)

	pbsConn, err := t.open(ctx, target, params)
	if err != nil {
		var refused *UpgradeError
		if errors.As(err, &refused) {
			t.logger.Warn("PBS refused backup session", "target", target.Name, "status", refused.Status, "body", refused.Body)
			switch refused.Status {
			case http.StatusUnauthorized, http.StatusForbidden:
				return status.Error(codes.PermissionDenied, err.Error())
			case http.StatusBadRequest, http.StatusNotFound:
				return status.Error(codes.InvalidArgument, err.Error())
			}
			return status.Error(codes.Unavailable, err.Error())
		}
		t.logger.Error("Failed to open PBS backup session", "target", target.Name, "error", err)
		return status.Error(codes.Unavailable, "failed to open PBS backup session: "+err.Error())
	}
	defer pbsConn.Close()

	// Tell the agent the session is live before any bytes flow
	if err := ss.SendHeader(metadata.Pairs(readyHeaderKey, "ready")); err != nil {
		return err
	}

	t.logger.Debug("PBS backup session established, piping bytes", "agent_id", agent.AgentID, "backup_id", params.BackupID)
	err = pipe(ss, pbsConn)
	if err != nil {
		t.logger.Warn("PBS backup session ended with error", "agent_id", agent.AgentID, "error", err)
		return status.Error(codes.Unavailable, "backup session interrupted: "+err.Error())
	}
	t.logger.Info("PBS backup session closed", "agent_id", agent.AgentID, "backup_id", params.BackupID)
	return nil
}

// pipe copies bytes between the gRPC stream and the PBS connection until either side
// finishes. The agent closing its send side half-closes the PBS connection; PBS closing
// ends the stream.
func pipe(ss grpc.ServerStream, conn net.Conn) error {
	fromPBS := make(chan error, 1)
	go func() {
		buf := make([]byte, frameSize)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				if serr := ss.SendMsg(&wrapperspb.BytesValue{Value: append([]byte(nil), buf[:n]...)}); serr != nil {
					fromPBS <- serr
					return
				}
			}
			if err != nil {
				if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
					fromPBS <- nil
				} else {
					fromPBS <- err
				}
				return
			}
		}
	}()

	var frame wrapperspb.BytesValue
	for {
		if err := ss.RecvMsg(&frame); err != nil {
			if errors.Is(err, io.EOF) {
				// Agent finished sending: let PBS see EOF, then drain its remaining output
				if cw, ok := conn.(interface{ CloseWrite() error }); ok {
					_ = cw.CloseWrite()
				}
				return <-fromPBS
			}
			_ = conn.Close()
			<-fromPBS
			if status.Code(err) == codes.Canceled {
				return nil
			}
			return err
		}
		if _, err := conn.Write(frame.Value); err != nil {
			<-fromPBS
			return err
		}
		select {
		case err := <-fromPBS:
			// PBS went away first (closed the session, or the upgrade connection dropped)
			return err
		default:
		}
	}
}
