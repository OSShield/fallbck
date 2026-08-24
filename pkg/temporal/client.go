package temporal

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/osshield/fallbck/pkg/config"
	"go.temporal.io/sdk/client"
)

// NewClient initializes a Temporal SDK client configured with optional mTLS
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

// CheckHealth verifies connection to Temporal cluster
func CheckHealth(ctx context.Context, c client.Client) error {
	_, err := c.CheckHealth(ctx, &client.CheckHealthRequest{})
	return err
}
