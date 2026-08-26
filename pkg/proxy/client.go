package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// Dial opens a tunnelled PBS backup session through the FallBCK server. cc must carry
// the agent's bearer token (per-RPC credentials); ticket is the backup ticket for the
// run. The returned connection already speaks the backup protocol (HTTP/2) and is
// meant for gopbs's pbs.Config.DialSession.
func Dial(ctx context.Context, cc grpc.ClientConnInterface, ticket string) (net.Conn, error) {
	if ticket == "" {
		return nil, errors.New("backup ticket is required")
	}
	ctx, cancel := context.WithCancel(ctx)
	ctx = metadata.AppendToOutgoingContext(ctx, TicketMetadataKey, ticket)
	stream, err := cc.NewStream(ctx, &SessionStreamDesc, MethodSession)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("opening backup tunnel: %w", err)
	}
	// Header() blocks until the server accepted the session (or failed it)
	hdr, err := stream.Header()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("backup tunnel rejected: %w", err)
	}
	if len(hdr.Get(readyHeaderKey)) == 0 {
		// No headers: the server ended the stream before accepting; surface its status
		var frame wrapperspb.BytesValue
		err := stream.RecvMsg(&frame)
		cancel()
		if err == nil || errors.Is(err, io.EOF) {
			return nil, errors.New("backup tunnel did not confirm the session")
		}
		return nil, fmt.Errorf("backup tunnel rejected: %w", err)
	}
	return &streamConn{stream: stream, cancel: cancel}, nil
}

// streamConn adapts a bidirectional gRPC stream to net.Conn
type streamConn struct {
	stream grpc.ClientStream
	cancel context.CancelFunc

	rmu    sync.Mutex
	rbuf   []byte
	rerr   error
	wmu    sync.Mutex
	closed sync.Once
}

func (c *streamConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for len(c.rbuf) == 0 {
		if c.rerr != nil {
			return 0, c.rerr
		}
		var frame wrapperspb.BytesValue
		if err := c.stream.RecvMsg(&frame); err != nil {
			if errors.Is(err, io.EOF) {
				c.rerr = io.EOF
			} else {
				c.rerr = fmt.Errorf("backup tunnel: %w", err)
			}
			return 0, c.rerr
		}
		c.rbuf = frame.Value
	}
	n := copy(p, c.rbuf)
	c.rbuf = c.rbuf[n:]
	return n, nil
}

func (c *streamConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	for off := 0; off < len(p); off += frameSize {
		end := off + frameSize
		if end > len(p) {
			end = len(p)
		}
		if err := c.stream.SendMsg(&wrapperspb.BytesValue{Value: append([]byte(nil), p[off:end]...)}); err != nil {
			return off, fmt.Errorf("backup tunnel: %w", err)
		}
	}
	return len(p), nil
}

// Close ends the session: the send side is closed so the server half-closes PBS, then
// the stream is cancelled.
func (c *streamConn) Close() error {
	c.closed.Do(func() {
		c.wmu.Lock()
		_ = c.stream.CloseSend()
		c.wmu.Unlock()
		c.cancel()
	})
	return nil
}

type tunnelAddr string

func (a tunnelAddr) Network() string { return "fallbck-tunnel" }
func (a tunnelAddr) String() string  { return string(a) }

func (c *streamConn) LocalAddr() net.Addr              { return tunnelAddr("agent") }
func (c *streamConn) RemoteAddr() net.Addr             { return tunnelAddr("fallbck-server") }
func (c *streamConn) SetDeadline(time.Time) error      { return nil }
func (c *streamConn) SetReadDeadline(time.Time) error  { return nil }
func (c *streamConn) SetWriteDeadline(time.Time) error { return nil }
