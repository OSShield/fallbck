//go:build sqlite

package embedded

import (
	"context"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"
)

// freePortBase finds a port base whose whole service/membership range is free
func freePortBase(t *testing.T) int {
	t.Helper()
	for base := 20233; base < 60000; base += 100 {
		cfg := Config{BindIP: "127.0.0.1", PortBase: base}
		if err := checkPortsFree(cfg); err == nil {
			return base
		}
	}
	t.Fatal("no free port range found")
	return 0
}

func helloWorkflow(ctx workflow.Context, name string) (string, error) {
	return "hello " + name, nil
}

func TestEmbeddedServerRunsWorkflow(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	cfg := Config{
		BindIP:      "127.0.0.1",
		PortBase:    freePortBase(t),
		Persistence: PersistenceSQLite,
		Namespace:   "fallbck-test",
		Retention:   24 * time.Hour,
		StopTimeout: 5 * time.Second,
	}

	phase := time.Now()
	mark := func(what string) {
		t.Logf("%-12s %v", what, time.Since(phase).Round(time.Millisecond))
		phase = time.Now()
	}
	srv, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	mark("New")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	mark("Start")
	defer func() {
		phase = time.Now()
		if err := srv.Stop(); err != nil {
			t.Errorf("Stop: %v", err)
		}
		mark("Stop")
	}()

	if _, err := net.Dial("tcp", srv.FrontendAddr()); err != nil {
		t.Fatalf("frontend not listening: %v", err)
	}

	c, err := client.Dial(client.Options{HostPort: srv.FrontendAddr(), Namespace: cfg.Namespace})
	if err != nil {
		t.Fatalf("client.Dial: %v", err)
	}
	defer c.Close()
	mark("Dial")

	w := worker.New(c, "embedded-test-queue", worker.Options{})
	w.RegisterWorkflow(helloWorkflow)
	if err := w.Start(); err != nil {
		t.Fatalf("worker.Start: %v", err)
	}
	defer w.Stop()

	run, err := c.ExecuteWorkflow(ctx, client.StartWorkflowOptions{TaskQueue: "embedded-test-queue"}, helloWorkflow, "fallbck")
	if err != nil {
		t.Fatalf("ExecuteWorkflow: %v", err)
	}
	mark("Execute")
	var result string
	if err := run.Get(ctx, &result); err != nil {
		t.Fatalf("workflow failed: %v", err)
	}
	mark("Result")
	if result != "hello fallbck" {
		t.Errorf("unexpected result %q", result)
	}
}

func TestConfigValidation(t *testing.T) {
	if err := (Config{Persistence: PersistencePostgres}).Validate(); err == nil {
		t.Error("postgres without database_url must fail validation")
	}
	if err := (Config{Persistence: PersistencePostgres, DatabaseURL: "mysql://x"}).Validate(); err == nil {
		t.Error("non-postgres URL must fail validation")
	}
	cfg := Config{Persistence: PersistencePostgres, DatabaseURL: "postgres://u:p@db:5433/fallbck?sslmode=disable"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	sqlCfg, err := cfg.withDefaults().postgresSQLConfig("temporal")
	if err != nil {
		t.Fatal(err)
	}
	if sqlCfg.ConnectAddr != "db:5433" || sqlCfg.User != "u" || sqlCfg.Password != "p" || sqlCfg.DatabaseName != "temporal" || sqlCfg.ConnectAttributes["sslmode"] != "disable" {
		t.Errorf("unexpected SQL config %+v", sqlCfg)
	}
	if got := cfg.FrontendAddr(); got != "127.0.0.1:7233" {
		t.Errorf("FrontendAddr = %q", got)
	}
}
