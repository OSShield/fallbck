package dockerbackup

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

// detectTimeout bounds the ping used for host detection (enrollment, heartbeats)
const detectTimeout = 2 * time.Second

// IsDockerHost reports whether a Docker daemon answers on the socket (empty: the
// default socket). It is called from enrollment and every heartbeat, so it is cheap:
// a stat, then one /_ping with a short timeout (a socket the agent may not open
// fails the ping and counts as absent).
func IsDockerHost(socket string) bool {
	if socket == "" {
		socket = SocketPath()
	}
	st, err := os.Stat(socket)
	if err != nil || st.Mode()&os.ModeSocket == 0 {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), detectTimeout)
	defer cancel()
	return Ping(ctx, socket) == nil
}

// Ping performs GET /_ping over the unix socket
func Ping(ctx context.Context, socket string) error {
	client := &http.Client{Transport: SocketTransport(socket), Timeout: detectTimeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/_ping", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return &StatusError{Status: resp.StatusCode}
	}
	return nil
}

// SocketTransport dials the unix socket for every request
func SocketTransport(socket string) *http.Transport {
	return &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
		DisableCompression: true,
	}
}

// StatusError is a non-2xx daemon answer
type StatusError struct {
	Status  int
	Message string
}

func (e *StatusError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return http.StatusText(e.Status)
}
