package temporal

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/osshield/fallbck/pkg/config"
	"go.temporal.io/sdk/client"
)

// NewClient initializes a Temporal SDK client for an external cluster, with optional (m)TLS
func NewClient(cfg config.TemporalConfig) (client.Client, error) {
	opts := client.Options{
		HostPort:  cfg.HostPort,
		Namespace: cfg.Namespace,
	}

	if cfg.EnableTLS {
		tlsConfig, err := cfg.BuildTLSConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to build Temporal TLS config: %w", err)
		}
		opts.ConnectionOptions.TLS = tlsConfig
		slog.Info("Temporal mTLS enabled", "host", cfg.HostPort, "namespace", cfg.Namespace)
	} else {
		slog.Info("Temporal connecting without TLS", "host", cfg.HostPort, "namespace", cfg.Namespace)
	}

	c, err := client.Dial(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Temporal at %s: %w", cfg.HostPort, err)
	}

	return c, nil
}

// NewLoopbackClient connects to the embedded (loopback, plaintext) Temporal frontend
func NewLoopbackClient(hostPort, namespace string) (client.Client, error) {
	c, err := client.Dial(client.Options{HostPort: hostPort, Namespace: namespace})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to embedded Temporal at %s: %w", hostPort, err)
	}
	return c, nil
}

// DialWithRetry retries dial until it succeeds or ctx expires
func DialWithRetry(ctx context.Context, dial func() (client.Client, error)) (client.Client, error) {
	delay := time.Second
	for {
		c, err := dial()
		if err == nil {
			return c, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("giving up connecting to Temporal: %w (last error: %v)", ctx.Err(), err)
		case <-time.After(delay):
		}
		slog.Warn("Temporal not reachable yet, retrying", "error", err)
		if delay < 10*time.Second {
			delay *= 2
		}
	}
}

// CheckHealth verifies connection to Temporal cluster
func CheckHealth(ctx context.Context, c client.Client) error {
	_, err := c.CheckHealth(ctx, &client.CheckHealthRequest{})
	return err
}
