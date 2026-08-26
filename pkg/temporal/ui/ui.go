// Package ui embeds the Temporal Web UI (temporalio/ui-server) in fallbck-server.
//
// ui-server only knows how to bind its own listener, so it runs on a loopback port and
// fallbck-server reverse-proxies it under PublicPath behind admin authentication.
package ui

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"

	uiserver "github.com/temporalio/ui-server/v2/server"
	uiconfig "github.com/temporalio/ui-server/v2/server/config"
	uiopts "github.com/temporalio/ui-server/v2/server/server_options"
)

// PublicPath is the path prefix the UI is served under on the public port
const PublicPath = "/temporal"

// DefaultPort is the loopback port of the UI server
const DefaultPort = 8233

// TLS configures the UI server's client connection to a TLS-enabled Temporal frontend
type TLS struct {
	CAFile             string
	CertFile           string
	KeyFile            string
	ServerName         string
	InsecureSkipVerify bool
}

// Config for the embedded UI
type Config struct {
	// BindIP and Port are the loopback listener (default 127.0.0.1:8233)
	BindIP string
	Port   int
	// TemporalAddr is the frontend host:port the UI talks to
	TemporalAddr string
	// TLS is nil for a plaintext (embedded, loopback) frontend
	TLS *TLS
	// Namespace pre-selected in the UI
	Namespace string
}

// Server is a running UI server
type Server struct {
	cfg  Config
	srv  *uiserver.Server
	addr string
	done chan error
}

// Addr is the loopback address the UI listens on (host:port)
func (s *Server) Addr() string { return s.addr }

// Start launches the UI server and waits until it answers
func Start(ctx context.Context, cfg Config, logger *slog.Logger) (_ *Server, err error) {
	if cfg.BindIP == "" {
		cfg.BindIP = "127.0.0.1"
	}
	if cfg.Port == 0 {
		cfg.Port = DefaultPort
	}
	if cfg.TemporalAddr == "" {
		return nil, errors.New("temporal ui: TemporalAddr is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	addr := net.JoinHostPort(cfg.BindIP, strconv.Itoa(cfg.Port))

	// ui-server fatally exits the process if the port is taken; check first.
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("temporal ui port %s is not available: %w", addr, err)
	}
	_ = l.Close()

	uiCfg := &uiconfig.Config{
		TemporalGRPCAddress: cfg.TemporalAddr,
		Host:                cfg.BindIP,
		Port:                cfg.Port,
		PublicPath:          PublicPath,
		EnableUI:            true,
		DefaultNamespace:    cfg.Namespace,
		DisableNewsFetch:    true,
		HideLogs:            true,
		Auth:                uiconfig.Auth{Enabled: false},
	}
	if cfg.TLS != nil {
		uiCfg.TLS = uiconfig.TLS{
			CaFile:                 cfg.TLS.CAFile,
			CertFile:               cfg.TLS.CertFile,
			KeyFile:                cfg.TLS.KeyFile,
			ServerName:             cfg.TLS.ServerName,
			EnableHostVerification: !cfg.TLS.InsecureSkipVerify,
		}
	}

	// NewServer panics instead of returning errors for bad configuration
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("temporal ui server failed to initialise: %v", r)
		}
	}()
	srv := uiserver.NewServer(uiopts.WithConfigProvider(uiCfg))

	s := &Server{cfg: cfg, srv: srv, addr: addr, done: make(chan error, 1)}
	go func() {
		s.done <- srv.Start()
	}()

	if err := s.waitReady(ctx); err != nil {
		s.Stop()
		return nil, err
	}
	logger.Info("Embedded Temporal Web UI started", "addr", addr, "public_path", PublicPath, "temporal", cfg.TemporalAddr)
	return s, nil
}

func (s *Server) waitReady(ctx context.Context) error {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
	}
	httpClient := &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	url := "http://" + s.addr + PublicPath + "/"
	for {
		select {
		case err := <-s.done:
			return fmt.Errorf("temporal ui server exited during startup: %v", err)
		default:
		}
		resp, err := httpClient.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode < 500 {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for temporal ui on %s: %w", s.addr, ctx.Err())
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// Stop shuts the UI server down
func (s *Server) Stop() {
	if s == nil || s.srv == nil {
		return
	}
	s.srv.Stop()
	s.srv = nil
}
