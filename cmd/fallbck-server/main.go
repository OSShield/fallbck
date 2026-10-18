package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
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
	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/agentupdate"
	"github.com/osshield/fallbck/pkg/api"
	"github.com/osshield/fallbck/pkg/auth"
	"github.com/osshield/fallbck/pkg/config"
	"github.com/osshield/fallbck/pkg/db"
	"github.com/osshield/fallbck/pkg/gateway"
	"github.com/osshield/fallbck/pkg/pbs"
	"github.com/osshield/fallbck/pkg/proxy"
	"github.com/osshield/fallbck/pkg/secrets"
	"github.com/osshield/fallbck/pkg/temporal"
	"github.com/osshield/fallbck/pkg/temporal/activities"
	"github.com/osshield/fallbck/pkg/temporal/embedded"
	"github.com/osshield/fallbck/pkg/temporal/scheduler"
	temporalui "github.com/osshield/fallbck/pkg/temporal/ui"
	"github.com/osshield/fallbck/pkg/temporal/workflows"
	"github.com/osshield/fallbck/web"
	"go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/sdk/client"
)

var ServerVersion = "0.1.0"

func main() {
	configPath := flag.String("config", "", "Path to server YAML configuration file")
	portFlag := flag.Int("port", 0, "Override HTTP port")
	devFlag := flag.Bool("dev", false, "Development mode: permits auth.insecure_disable and UI preview without Postgres/Temporal")
	devTokenFlag := flag.String("insecure-unlimited-dev-token", "", "Development only (requires --dev): UUID usable as an enrollment token with unlimited uses and no expiry")
	devRemote := flag.String("dev-create-remote", "", "Development only (requires --dev): name of a PBS remote to create at startup unless one with that name exists")
	devRemoteURL := flag.String("dev-remote-url", "", "PBS URL for --dev-create-remote")
	devRemoteDatastore := flag.String("dev-remote-datastore", "", "PBS datastore for --dev-create-remote")
	devRemoteNamespace := flag.String("dev-remote-namespace", "", "PBS namespace for --dev-create-remote (optional)")
	devRemoteToken := flag.String("dev-remote-token", "", "PBS API token (user@realm!tokenid:secret) for --dev-create-remote")
	devRemoteVerifyNone := flag.Bool("dev-remote-verify-none", false, "Skip TLS verification for --dev-create-remote")
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
	if *devTokenFlag != "" {
		if !*devFlag {
			slog.Error("--insecure-unlimited-dev-token is only permitted together with --dev")
			os.Exit(1)
		}
		if _, err := uuid.Parse(*devTokenFlag); err != nil {
			slog.Error("--insecure-unlimited-dev-token must be a UUID", "error", err)
			os.Exit(1)
		}
	}
	var devTarget *db.BackupTarget
	if *devRemote != "" {
		if !*devFlag {
			slog.Error("--dev-create-remote is only permitted together with --dev")
			os.Exit(1)
		}
		if *devRemoteURL == "" || *devRemoteDatastore == "" || *devRemoteToken == "" {
			slog.Error("--dev-create-remote requires --dev-remote-url, --dev-remote-datastore and --dev-remote-token")
			os.Exit(1)
		}
		token, err := pbs.NormalizeAPIToken(*devRemoteToken)
		if err != nil {
			slog.Error("--dev-remote-token: expected user@realm!tokenid:secret", "error", err)
			os.Exit(1)
		}
		devTarget = &db.BackupTarget{
			Name:       *devRemote,
			TargetType: "pbs",
			Endpoint:   strings.TrimRight(*devRemoteURL, "/"),
			Datastore:  *devRemoteDatastore,
			Namespace:  *devRemoteNamespace,
			AuthToken:  token,
			TLSVerify:  !*devRemoteVerifyNone,
			PxarFormat: db.PxarFormatV2,
		}
	}
	if cfg.Auth.InsecureDisable {
		slog.Warn("!!! ADMIN AUTHENTICATION IS DISABLED (auth.insecure_disable) — development only, never expose this instance !!!")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ---------------------------------------------------------------- Master key
	// Seals stored secrets (PBS API tokens, backup encryption keys). Generated on the
	// first start; from then on the database is useless without it, so it is backed
	// up together with the database.
	sealer, keyCreated, err := loadSealer(cfg)
	if err != nil {
		slog.Error("Master key unavailable", "error", err)
		os.Exit(1)
	}

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
		database.Sealer = sealer
		slog.Info("Connected to PostgreSQL database successfully")
		if keyCreated {
			if sealed, err := database.HasSealedSecrets(ctx); err != nil {
				slog.Error("Checking for sealed secrets failed", "error", err)
				os.Exit(1)
			} else if sealed {
				slog.Error("A new master key was just generated but the database already holds secrets sealed with another key: the key file was lost. Restore it (or set FALLBCK_MASTER_KEY) and remove the new file before starting again", "path", cfg.EffectiveMasterKeyFile())
				os.Exit(1)
			}
		}
		if n, err := database.SealLegacySecrets(ctx); err != nil {
			slog.Error("Sealing stored secrets with the master key failed", "error", err)
			os.Exit(1)
		} else if n > 0 {
			slog.Info("Sealed secrets that were stored in clear by earlier versions", "rows", n)
		}
		if *devTokenFlag != "" {
			if err := database.EnsureUnlimitedEnrollmentToken(ctx, auth.HashToken(*devTokenFlag), "insecure-unlimited-dev-token"); err != nil {
				slog.Error("Creating the unlimited dev enrollment token failed", "error", err)
				os.Exit(1)
			}
			slog.Warn("!!! UNLIMITED ENROLLMENT TOKEN ACTIVE (--insecure-unlimited-dev-token) — development only, never expose this instance !!!")
		}
		if devTarget != nil {
			if err := ensureDevTarget(ctx, database, devTarget); err != nil {
				slog.Error("Creating the dev PBS remote failed", "error", err)
				os.Exit(1)
			}
		}
	}

	if cfg.JWTSecret == "" {
		key, created, err := secrets.LoadOrCreateKeyFile(cfg.EffectiveJWTSecretFile())
		if err != nil {
			slog.Error("JWT secret unavailable", "error", err)
			os.Exit(1)
		}
		cfg.JWTSecret = hex.EncodeToString(key)
		if created {
			slog.Warn("Generated a JWT secret; losing it signs every agent out", "path", cfg.EffectiveJWTSecretFile())
		}
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
		serverWorker.RegisterWorkflow(workflows.AgentOpsWorkflow)
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
				ReadOnly:     cfg.Temporal.UI.ReadOnly,
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
	var rbac *auth.Resolver
	if database != nil {
		keyStore = database
		// Built-in roles take their permissions from the code at every start
		if err := database.SyncBuiltinRoles(ctx, auth.BuiltinRoles(), auth.BuiltinDescriptions); err != nil {
			slog.Error("Failed to write the built-in roles", "error", err)
			os.Exit(1)
		}
		rbac = auth.NewResolver(database, auth.DefaultResolverTTL)
	}
	adminAuth := auth.NewAdminAuth(tokenManager, keyStore, cfg.Auth.InsecureDisable)
	adminAuth.RBAC = rbac
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
			if len(cfg.Auth.OIDC.AllowedGroups) == 0 && len(cfg.Auth.OIDC.AllowedEmails) == 0 {
				slog.Info("OIDC has no allowed_groups or allowed_emails: any identity the provider issues may sign in, and gets access only through a role binding")
			}
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
	r.Use(web.ClientIP(cfg.TrustedProxies))
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(web.SecurityHeaders)

	serverAPI := api.NewServerAPI(database, temporalClient, cfg, tokenManager, agentVerifier)
	serverAPI.RBAC = rbac
	agentUpdates := agentupdate.New(ServerVersion, cfg.DataDir)
	serverAPI.Updates = agentUpdates
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
		Updates:      agentUpdates,
	})
	uiHandler.RegisterRoutes(r)

	// Root handler: gRPC (agents) → gateway, everything else → chi; both over h2c so a
	// TLS-terminating reverse proxy can forward HTTP/1.1, HTTP/2 and gRPC on one port.
	var root http.Handler = r
	if agentGateway != nil {
		root = agentGateway.Handler(r)
	}

	bindAddr := fmt.Sprintf("%s:%d", cfg.HTTPBind, cfg.HTTPPort)
	httpServer := &http.Server{
		Addr:              bindAddr,
		Handler:           root,
		ReadHeaderTimeout: 10 * time.Second,
		// No ReadTimeout/WriteTimeout: gRPC long polls (70s) and chunk uploads are long-lived
		IdleTimeout: 120 * time.Second,
		Protocols:   new(http.Protocols),
	}
	httpServer.Protocols.SetHTTP1(true)
	httpServer.Protocols.SetUnencryptedHTTP2(true)

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

// loadSealer builds the secrets sealer from FALLBCK_MASTER_KEY / security.master_key,
// else from the key file (created on first start)
func loadSealer(cfg *config.ServerConfig) (sealer *secrets.Sealer, created bool, err error) {
	if cfg.Security.MasterKey != "" {
		key, err := secrets.ParseKey(cfg.Security.MasterKey)
		if err != nil {
			return nil, false, err
		}
		slog.Info("Master key taken from configuration/environment")
		sealer, err = secrets.New(key)
		return sealer, false, err
	}
	path := cfg.EffectiveMasterKeyFile()
	key, created, err := secrets.LoadOrCreateKeyFile(path)
	if err != nil {
		return nil, false, err
	}
	if created {
		slog.Warn("Generated a new master key; back it up together with the database, stored secrets cannot be recovered without it", "path", path)
	} else {
		slog.Info("Master key loaded", "path", path)
	}
	sealer, err = secrets.New(key)
	return sealer, created, err
}

// ensureDevTarget creates the --dev-create-remote target unless one with that name
// already exists (an existing one is left as is)
func ensureDevTarget(ctx context.Context, database *db.DB, t *db.BackupTarget) error {
	targets, err := database.ListTargets(ctx, db.Unscoped)
	if err != nil {
		return err
	}
	for _, existing := range targets {
		if existing.Name == t.Name {
			slog.Info("Dev PBS remote already exists, leaving it unchanged", "name", t.Name)
			return nil
		}
	}
	if err := database.CreateTarget(ctx, t); err != nil {
		return err
	}
	slog.Info("Created dev PBS remote", "name", t.Name, "endpoint", t.Endpoint, "datastore", t.Datastore)
	return nil
}
