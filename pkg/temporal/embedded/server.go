package embedded

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"time"

	"go.temporal.io/api/serviceerror"
	"go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/server/common/authorization"
	"go.temporal.io/server/common/config"
	"go.temporal.io/server/common/dynamicconfig"
	"go.temporal.io/server/common/membership/static"
	"go.temporal.io/server/common/primitives"
	"go.temporal.io/server/temporal"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
)

// DefaultReadyTimeout bounds how long Start waits for the frontend to answer
const DefaultReadyTimeout = 90 * time.Second

// Server is an in-process Temporal cluster
type Server struct {
	cfg    Config
	logger *slog.Logger
	server temporal.Server
	conn   *grpc.ClientConn
}

// New validates the configuration and constructs the Temporal server (not yet started).
// For Postgres persistence, BootstrapSchema must have been run first.
func New(cfg Config, logger *slog.Logger) (out *Server, err error) {
	cfg = cfg.withDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}

	if err := checkPortsFree(cfg); err != nil {
		return nil, err
	}

	var (
		dataStores      map[string]config.DataStore
		defaultStore    string
		visibilityStore string
	)
	switch cfg.Persistence {
	case PersistencePostgres:
		defaultCfg, err := cfg.postgresSQLConfig(cfg.TemporalDatabase)
		if err != nil {
			return nil, err
		}
		visCfg, err := cfg.postgresSQLConfig(cfg.VisibilityDatabase)
		if err != nil {
			return nil, err
		}
		visCfg.MaxConns = 4
		visCfg.MaxIdleConns = 4
		dataStores = map[string]config.DataStore{
			"postgres-default":    {SQL: defaultCfg},
			"postgres-visibility": {SQL: visCfg},
		}
		defaultStore, visibilityStore = "postgres-default", "postgres-visibility"
	case PersistenceSQLite:
		sqlCfg, err := setupSQLite(cfg)
		if err != nil {
			return nil, err
		}
		dataStores = map[string]config.DataStore{"sqlite-default": {SQL: sqlCfg}}
		defaultStore, visibilityStore = "sqlite-default", "sqlite-default"
	}

	conf, err := cfg.buildServerConfig(dataStores, defaultStore, visibilityStore)
	if err != nil {
		return nil, err
	}

	hosts := map[primitives.ServiceName]static.Hosts{}
	for svc, p := range cfg.ports() {
		hosts[svc] = static.SingleLocalHost(net.JoinHostPort(cfg.BindIP, strconv.Itoa(p.grpc)))
	}

	dynConf := dynamicconfig.StaticClient{
		dynamicconfig.MaxIDLengthLimit.Key():                             255,
		dynamicconfig.HistoryCacheHostLevelMaxSize.Key():                 8192,
		dynamicconfig.FrontendMaxNamespaceVisibilityRPSPerInstance.Key(): 100,
		// Single process: nothing else to hand traffic to, drain quickly on shutdown
		dynamicconfig.FrontendShutdownDrainDuration.Key(): time.Second,
		dynamicconfig.HistoryShutdownDrainDuration.Key():  time.Second,
		dynamicconfig.MatchingShutdownDrainDuration.Key(): time.Second,
	}

	// Option order matters: WithConfig must precede WithClaimMapper.
	// The Temporal server panics on some configuration problems (notably when the
	// persisted cluster metadata disagrees with ours); surface those as errors.
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("embedded temporal server rejected its configuration: %v — if the %q/%q databases were created by another Temporal deployment, either set temporal.embedded.cluster_name to that deployment's cluster name or drop the databases", r, cfg.TemporalDatabase, cfg.VisibilityDatabase)
			out = nil
		}
	}()
	srv, err := temporal.NewServer(
		temporal.WithConfig(conf),
		temporal.ForServices(services()),
		temporal.WithStaticHosts(hosts),
		temporal.WithLogger(NewLogger(logger)),
		temporal.WithDynamicConfigClient(dynConf),
		// The frontend is loopback-only; authorization of agents happens in the gateway.
		temporal.WithAuthorizer(authorization.NewNoopAuthorizer()),
		temporal.WithClaimMapper(func(*config.Config) authorization.ClaimMapper { return authorization.NewNoopClaimMapper() }),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to construct embedded temporal server: %w", err)
	}

	out = &Server{cfg: cfg, logger: logger, server: srv}
	return out, nil
}

// FrontendAddr is the loopback host:port of the frontend gRPC service
func (s *Server) FrontendAddr() string {
	return s.cfg.FrontendAddr()
}

// Namespace is the namespace ensured by Start
func (s *Server) Namespace() string {
	return s.cfg.Namespace
}

// Start starts every service, waits until the frontend answers, and ensures the
// configured namespace exists. ctx bounds the readiness wait (DefaultReadyTimeout if none).
func (s *Server) Start(ctx context.Context) error {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultReadyTimeout)
		defer cancel()
	}

	s.logger.Info("Starting embedded Temporal server", "frontend", s.FrontendAddr(), "persistence", string(s.cfg.Persistence), "shards", s.cfg.HistoryShards)
	if err := s.server.Start(); err != nil {
		return fmt.Errorf("failed to start embedded temporal server: %w", err)
	}

	conn, err := grpc.NewClient(s.FrontendAddr(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		_ = s.server.Stop()
		return fmt.Errorf("failed to create frontend client: %w", err)
	}
	s.conn = conn
	client := workflowservice.NewWorkflowServiceClient(conn)

	if err := waitFor(ctx, "frontend", func(ctx context.Context) error {
		_, err := client.GetSystemInfo(ctx, &workflowservice.GetSystemInfoRequest{})
		return err
	}); err != nil {
		_ = s.Stop()
		return err
	}

	if err := s.ensureNamespace(ctx, client); err != nil {
		_ = s.Stop()
		return err
	}

	s.logger.Info("Embedded Temporal server ready", "frontend", s.FrontendAddr(), "namespace", s.cfg.Namespace)
	return nil
}

// ensureNamespace registers the namespace if missing and waits until it is visible
func (s *Server) ensureNamespace(ctx context.Context, client workflowservice.WorkflowServiceClient) error {
	_, err := client.RegisterNamespace(ctx, &workflowservice.RegisterNamespaceRequest{
		Namespace:                        s.cfg.Namespace,
		Description:                      "FallBCK backup orchestration",
		WorkflowExecutionRetentionPeriod: durationpb.New(s.cfg.Retention),
	})
	var exists *serviceerror.NamespaceAlreadyExists
	switch {
	case err == nil:
		s.logger.Info("Registered Temporal namespace", "namespace", s.cfg.Namespace, "retention", s.cfg.Retention)
	case errors.As(err, &exists), status.Code(err) == codes.AlreadyExists:
	default:
		return fmt.Errorf("failed to register temporal namespace %q: %w", s.cfg.Namespace, err)
	}

	// Namespace registration propagates through a cache; wait until it resolves.
	return waitFor(ctx, "namespace "+s.cfg.Namespace, func(ctx context.Context) error {
		_, err := client.DescribeNamespace(ctx, &workflowservice.DescribeNamespaceRequest{Namespace: s.cfg.Namespace})
		return err
	})
}

// Stop shuts the server down, waiting at most cfg.StopTimeout. Temporal's internal
// shutdown can block for minutes waiting for its own system workers' long polls; once
// the timeout passes the remaining teardown continues in the background (the process
// normally exits right after). Safe to call more than once.
func (s *Server) Stop() error {
	if s.conn != nil {
		_ = s.conn.Close()
		s.conn = nil
	}
	if s.server == nil {
		return nil
	}
	srv := s.server
	s.server = nil

	s.logger.Info("Stopping embedded Temporal server")
	done := make(chan error, 1)
	go func() { done <- srv.Stop() }()
	select {
	case err := <-done:
		return err
	case <-time.After(s.cfg.StopTimeout):
		s.logger.Warn("Embedded Temporal server did not stop in time; continuing shutdown", "timeout", s.cfg.StopTimeout)
		return nil
	}
}

// waitFor retries probe with backoff until it succeeds or ctx expires
func waitFor(ctx context.Context, what string, probe func(context.Context) error) error {
	delay := 250 * time.Millisecond
	var last error
	for {
		probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		last = probe(probeCtx)
		cancel()
		if last == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for embedded temporal %s: %w (last error: %v)", what, ctx.Err(), last)
		case <-time.After(delay):
		}
		if delay < 2*time.Second {
			delay *= 2
		}
	}
}

// checkPortsFree fails early with a clear message instead of letting Temporal Fatal-exit
func checkPortsFree(cfg Config) error {
	for svc, p := range cfg.ports() {
		for _, port := range []int{p.grpc, p.membership} {
			addr := net.JoinHostPort(cfg.BindIP, strconv.Itoa(port))
			l, err := net.Listen("tcp", addr)
			if err != nil {
				return fmt.Errorf("embedded temporal %s port %s is not available: %w", svc, addr, err)
			}
			_ = l.Close()
		}
	}
	return nil
}
