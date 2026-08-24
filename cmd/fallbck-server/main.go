package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/osshield/fallbck/pkg/api"
	"github.com/osshield/fallbck/pkg/auth"
	"github.com/osshield/fallbck/pkg/certs"
	"github.com/osshield/fallbck/pkg/config"
	"github.com/osshield/fallbck/pkg/db"
	"github.com/osshield/fallbck/pkg/temporal"
	"go.temporal.io/sdk/client"
)

var ServerVersion = "0.1.0"

func main() {
	configPath := flag.String("config", "", "Path to server YAML configuration file")
	flag.Parse()

	// Logger setup
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	slog.Info("Starting FallBCK Central Server", "version", ServerVersion)

	// Load configuration
	cfg, err := config.LoadServerConfig(*configPath)
	if err != nil {
		slog.Error("Failed to load server configuration", "error", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize PKI / CA
	caCertPath := cfg.CACertPath
	caKeyPath := cfg.CAKeyPath
	if caCertPath == "" || caKeyPath == "" {
		caCertPath = filepath.Join(cfg.DataDir, "certs", "ca.crt")
		caKeyPath = filepath.Join(cfg.DataDir, "certs", "ca.key")
	}

	ca, err := certs.LoadOrCreateCA(caCertPath, caKeyPath)
	if err != nil {
		slog.Warn("Failed to initialize internal CA (mTLS cert generation disabled)", "error", err)
	} else {
		slog.Info("Internal PKI Certificate Authority initialized", "ca_cert", caCertPath)
	}

	// Initialize Database Pool
	database, err := db.New(ctx, cfg.Database)
	if err != nil {
		slog.Error("Failed to connect to PostgreSQL database", "error", err, "db_url", cfg.Database.URL)
		os.Exit(1)
	}
	defer database.Close()
	slog.Info("Connected to PostgreSQL database successfully")

	// Token Manager
	tokenManager := auth.NewTokenManager(cfg.JWTSecret)

	// Initialize Temporal Client (graceful if Temporal cluster is not yet reachable during dev startup)
	var temporalClient client.Client
	temporalClient, err = temporal.NewClient(cfg.Temporal)
	if err != nil {
		slog.Warn("Could not connect to Temporal cluster on startup (will retry on workflow actions)", "error", err, "host", cfg.Temporal.HostPort)
	} else {
		defer temporalClient.Close()
		slog.Info("Connected to Temporal cluster successfully", "host", cfg.Temporal.HostPort, "namespace", cfg.Temporal.Namespace)
	}

	// Setup HTTP Router
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	// CORS configuration
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// Register API Routes
	serverAPI := api.NewServerAPI(database, temporalClient, cfg, ca, tokenManager)
	serverAPI.RegisterRoutes(r)

	// HTTP Server
	bindAddr := fmt.Sprintf("%s:%d", cfg.HTTPBind, cfg.HTTPPort)
	httpServer := &http.Server{
		Addr:         bindAddr,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown listener
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		slog.Info("FallBCK HTTP Server listening", "addr", bindAddr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("HTTP Server error", "error", err)
			os.Exit(1)
		}
	}()

	// Block until signal received
	<-stopChan
	slog.Info("Shutting down FallBCK Server...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		slog.Error("Server shutdown failed", "error", err)
	}

	slog.Info("FallBCK Server stopped gracefully")
}
