package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/osshield/fallbck/pkg/api"
	"github.com/osshield/fallbck/pkg/auth"
	"github.com/osshield/fallbck/pkg/config"
	"github.com/osshield/fallbck/pkg/db"
	"github.com/osshield/fallbck/pkg/gateway"
	"github.com/osshield/fallbck/pkg/proxy"
	"github.com/osshield/fallbck/pkg/temporal"
	"github.com/osshield/fallbck/pkg/temporal/activities"
	"github.com/osshield/fallbck/pkg/temporal/embedded"
	"github.com/osshield/fallbck/pkg/temporal/scheduler"
	temporalui "github.com/osshield/fallbck/pkg/temporal/ui"
	"github.com/osshield/fallbck/pkg/temporal/workflows"
	"github.com/osshield/fallbck/web"
	"go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/sdk/client"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

var ServerVersion = "0.1.0"

func main() {
	configPath := flag.String("config", "", "Path to server YAML configuration file")
	portFlag := flag.Int("port", 0, "Override HTTP port")
	devFlag := flag.Bool("dev", false, "Development mode: permits auth.insecure_disable and UI preview without Postgres/Temporal")
	flag.Parse()

	logLevel := config.LogLevel()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger)
	slog.Info("Starting FallBCK Central Server", "version", ServerVersion, "log_level", logLevel.String())

	cfg, err := config.LoadServerConfig(*configPath)
	if err != nil {
		slog.Error("Failed to load server configuration", "error", err)
		os.Exit(1)
	}
	if *portFlag > 0 {
		cfg.HTTPPort = *portFlag
	}
	if err := cfg.Validate(*devFlag); err != nil {
		slog.Error("Invalid server configuration", "error", err)
		os.Exit(1)
	}
	if cfg.Auth.InsecureDisable {
		slog.Warn("!!! ADMIN AUTHENTICATION IS DISABLED (auth.insecure_disable) — development only, never expose this instance !!!")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ---------------------------------------------------------------- Database
	database, err := db.New(ctx, cfg.Database)
	if err != nil {
		if !*devFlag {
			slog.Error("Failed to connect to PostgreSQL database", "error", err)
			os.Exit(1)
		}
		slog.Warn("PostgreSQL not reachable, continuing in UI preview mode (--dev): no Temporal, no gateway", "error", err)
		database = nil
	} else {
		defer database.Close()
		slog.Info("Connected to PostgreSQL database successfully")
	}

	tokenManager := auth.NewTokenManager(cfg.JWTSecret)

	// ---------------------------------------------------------------- Temporal
	var (
		temporalClient  client.Client
		frontendAddr    string
		backendTLS      *tls.Config
		embeddedServer  *embedded.Server
		serverWorker    *temporal.ServerWorker
		agentGateway    *gateway.Gateway
		uiServer        *temporalui.Server
		uiTLS           *temporalui.TLS
		temporalEnabled = database != nil
	)
	if temporalEnabled {
		switch cfg.Temporal.Mode {
		case config.TemporalModeEmbedded:
			embCfg := embedded.Config{
				BindIP:        cfg.Temporal.Embedded.BindIP,
				PortBase:      cfg.Temporal.Embedded.PortBase,
				DatabaseURL:   cfg.Temporal.Embedded.DatabaseURL,
				HistoryShards: cfg.Temporal.Embedded.HistoryShards,
				Namespace:     cfg.Temporal.Namespace,
				Retention:     cfg.Temporal.Embedded.Retention,
				ClusterName:   cfg.Temporal.Embedded.ClusterName,
				DataDir:       cfg.DataDir,
			}
			// Temporal is chatty: warnings only unless debugging
			temporalLevel := slog.LevelWarn
			if logLevel <= slog.LevelDebug {
				temporalLevel = slog.LevelInfo
			}
			temporalLogger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: temporalLevel}))
			if err := embedded.BootstrapSchema(ctx, embCfg, temporalLogger); err != nil {
				slog.Error("Failed to bootstrap embedded Temporal schema", "error", err)
				os.Exit(1)
			}
			embeddedServer, err = embedded.New(embCfg, temporalLogger)
			if err != nil {
				slog.Error("Failed to construct embedded Temporal server", "error", err)
				os.Exit(1)
			}
			if err := embeddedServer.Start(ctx); err != nil {
				slog.Error("Failed to start embedded Temporal server", "error", err)
				os.Exit(1)
			}
			defer func() { _ = embeddedServer.Stop() }()
			frontendAddr = embeddedServer.FrontendAddr()

		case config.TemporalModeExternal:
			frontendAddr = cfg.Temporal.External.HostPort
			backendTLS, err = cfg.Temporal.External.BuildTLSConfig()
			if err != nil {
				slog.Error("Invalid external Temporal TLS configuration", "error", err)
				os.Exit(1)
			}
			if cfg.Temporal.External.EnableTLS {
				uiTLS = &temporalui.TLS{
					CAFile:             cfg.Temporal.External.CACertPath,
					CertFile:           cfg.Temporal.External.ClientCertPath,
					KeyFile:            cfg.Temporal.External.ClientKeyPath,
					ServerName:         cfg.Temporal.External.ServerName,
					InsecureSkipVerify: cfg.Temporal.External.InsecureSkipVerify,
				}
			}
		}

		// SDK client for the server-side worker and API (fatal if unreachable)
		dialCtx, dialCancel := context.WithTimeout(ctx, 60*time.Second)
		temporalClient, err = temporal.DialWithRetry(dialCtx, func() (client.Client, error) {
			if cfg.Temporal.Mode == config.TemporalModeEmbedded {
				return temporal.NewLoopbackClient(frontendAddr, cfg.Temporal.Namespace)
			}
			return temporal.NewClient(cfg.Temporal.External)
		})
		dialCancel()
		if err != nil {
			slog.Error("Failed to connect to Temporal", "error", err, "host", frontendAddr)
			os.Exit(1)
		}
		defer temporalClient.Close()
		slog.Info("Connected to Temporal", "mode", cfg.Temporal.Mode, "host", frontendAddr, "namespace", cfg.Temporal.Namespace)

		// Server-side worker: workflows + server activities
		serverWorker = temporal.NewServerWorker(temporalClient, database, cfg, tokenManager)
		serverActs := activities.NewServerActivities(database, cfg, tokenManager)
		serverWorker.Register(workflows.BackupJobWorkflow, serverActs)
		if err := serverWorker.Start(); err != nil {
			slog.Error("Failed to start Temporal server worker", "error", err)
			os.Exit(1)
		}
		defer serverWorker.Stop()

		// Embedded Temporal Web UI (loopback; proxied under /temporal/ behind admin auth)
		if cfg.Temporal.UI.Enabled {
			uiServer, err = temporalui.Start(ctx, temporalui.Config{
				Port:         cfg.Temporal.UI.Port,
				TemporalAddr: frontendAddr,
				TLS:          uiTLS,
				Namespace:    cfg.Temporal.Namespace,
			}, logger)
			if err != nil {
				slog.Error("Failed to start embedded Temporal Web UI", "error", err)
				os.Exit(1)
			}
			defer uiServer.Stop()
		}
	}

	// ---------------------------------------------------------------- Auth
	agentVerifier := auth.NewAgentVerifier(tokenManager, database, 30*time.Second)
	if database == nil {
		agentVerifier = nil
	}
	var keyStore auth.APIKeyStore
	if database != nil {
		keyStore = database
	}
	adminAuth := auth.NewAdminAuth(tokenManager, keyStore, cfg.Auth.InsecureDisable)
	agentAuth := &auth.AgentAuth{Verifier: agentVerifier}
	requireAgent := func(next http.Handler) http.Handler {
		if agentVerifier == nil {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, `{"error":"agent services unavailable"}`, http.StatusServiceUnavailable)
			})
		}
		return agentAuth.RequireAgent(next)
	}

	var oidcProvider *auth.OIDC
	if !cfg.Auth.InsecureDisable {
		redirectURL := strings.TrimRight(cfg.PublicURL, "/") + "/auth/callback"
		oidcCtx, oidcCancel := context.WithTimeout(ctx, 60*time.Second)
		for {
			oidcProvider, err = auth.NewOIDC(oidcCtx, cfg.Auth.OIDC, redirectURL)
			if err == nil {
				break
			}
			slog.Warn("OIDC provider discovery failed, retrying", "issuer", cfg.Auth.OIDC.Issuer, "error", err)
			select {
			case <-oidcCtx.Done():
				slog.Error("Giving up on OIDC provider discovery", "issuer", cfg.Auth.OIDC.Issuer, "error", err)
				os.Exit(1)
			case <-time.After(3 * time.Second):
			}
		}
		oidcCancel()
		slog.Info("OIDC provider ready", "issuer", cfg.Auth.OIDC.Issuer, "redirect_url", redirectURL)
	}

	// ---------------------------------------------------------------- Agent gateway
	if temporalEnabled {
		backendConn, err := gateway.Dial(frontendAddr, backendTLS)
		if err != nil {
			slog.Error("Failed to connect gateway to Temporal frontend", "error", err)
			os.Exit(1)
		}
		defer backendConn.Close()
		agentGateway = gateway.New(workflowservice.NewWorkflowServiceClient(backendConn), agentVerifier, cfg.Temporal.Namespace, logger)
		defer agentGateway.GracefulStop()
	}

	// ---------------------------------------------------------------- HTTP router
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(web.SecurityHeaders)

	serverAPI := api.NewServerAPI(database, temporalClient, cfg, tokenManager, agentVerifier)
	if temporalClient != nil {
		db.SetScheduleLocation(cfg.ScheduleLocation())
		slog.Info("Cron schedules run in timezone", "timezone", cfg.Timezone)
		jobScheduler := scheduler.New(temporalClient, database, cfg.Timezone)
		serverAPI.Scheduler = jobScheduler
		// Align Temporal Schedules with the jobs table (create missing, fix drifted,
		// drop orphans); failures are retried on the next start
		go func() {
			reconcileCtx, cancelReconcile := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancelReconcile()
			if err := jobScheduler.ReconcileAll(reconcileCtx); err != nil {
				slog.Warn("Backup schedule reconciliation incomplete", "error", err)
			} else {
				slog.Info("Backup schedules reconciled with the jobs table")
			}
		}()
	}
	r.Group(func(r chi.Router) {
		r.Use(middleware.Timeout(60 * time.Second))
		serverAPI.RegisterRoutes(r, adminAuth.RequireAdmin, requireAgent)
	})

	// PBS backup tunnel: the server opens each agent's PBS session with the target's
	// API token, scoped by the backup ticket, and pipes it over the agent gateway.
	if agentGateway != nil {
		proxy.NewBackupTunnel(tokenManager, database, logger).Register(agentGateway)
	}

	uiHandler := web.NewUIHandler(database, cfg, web.Deps{
		TokenManager: tokenManager,
		OIDC:         oidcProvider,
		Admin:        adminAuth,
		TemporalUI:   uiServer,
		Version:      ServerVersion,
	})
	uiHandler.RegisterRoutes(r)

	// Root handler: gRPC (agents) → gateway, everything else → chi; both over h2c so a
	// TLS-terminating reverse proxy can forward HTTP/1.1, HTTP/2 and gRPC on one port.
	var root http.Handler = r
	if agentGateway != nil {
		root = agentGateway.Handler(r)
	}
	root = h2c.NewHandler(root, &http2.Server{})

	bindAddr := fmt.Sprintf("%s:%d", cfg.HTTPBind, cfg.HTTPPort)
	httpServer := &http.Server{
		Addr:              bindAddr,
		Handler:           root,
		ReadHeaderTimeout: 10 * time.Second,
		// No ReadTimeout/WriteTimeout: gRPC long polls (70s) and chunk uploads are long-lived
		IdleTimeout: 120 * time.Second,
	}

	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		fmt.Printf("\n🚀 FallBCK is listening on %s (public URL: %s)\n\n", bindAddr, cfg.PublicURL)
		slog.Info("FallBCK HTTP/gRPC server listening", "addr", bindAddr, "public_url", cfg.PublicURL)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("HTTP Server error", "error", err)
			os.Exit(1)
		}
	}()

	<-stopChan
	slog.Info("Shutting down FallBCK Server...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		slog.Error("HTTP server shutdown failed", "error", err)
	}
	// Deferred: gateway → UI → worker → SDK client → embedded Temporal → database
	slog.Info("FallBCK Server stopped gracefully")
}
