//go:build sqlite

package integration

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/db"
	fbtemporal "github.com/osshield/fallbck/pkg/temporal"
	"github.com/osshield/fallbck/pkg/temporal/embedded"
	"github.com/osshield/fallbck/pkg/temporal/scheduler"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"
)

// TestSchedulerLifecycle runs the scheduler against a real embedded Temporal: create,
// pause on disable, remove on cleared cron, and an actual firing of the workflow.
func TestSchedulerLifecycle(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	emb, err := embedded.New(embedded.Config{
		PortBase:    freePortBase(t),
		Persistence: embedded.PersistenceSQLite,
		Namespace:   "default",
		StopTimeout: 5 * time.Second,
	}, logger)
	if err != nil {
		t.Fatalf("embedded.New: %v", err)
	}
	if err := emb.Start(ctx); err != nil {
		t.Fatalf("embedded.Start: %v", err)
	}
	defer func() { _ = emb.Stop() }()

	c, err := client.Dial(client.Options{HostPort: emb.FrontendAddr(), Namespace: "default"})
	if err != nil {
		t.Fatalf("client.Dial: %v", err)
	}
	defer c.Close()

	// A stand-in registered under the real workflow name records scheduled firings
	fired := make(chan uuid.UUID, 8)
	w := worker.New(c, fbtemporal.ServerTaskQueue, worker.Options{})
	w.RegisterWorkflowWithOptions(func(_ workflow.Context, jobID uuid.UUID) error {
		fired <- jobID
		return nil
	}, workflow.RegisterOptions{Name: "BackupJobWorkflow"})
	if err := w.Start(); err != nil {
		t.Fatalf("worker.Start: %v", err)
	}
	defer w.Stop()

	sched := scheduler.New(c, nil)
	job := &db.BackupJob{ID: uuid.New(), Name: "sched-test", ScheduleCron: "@every 2s", Enabled: true}
	if err := sched.Sync(ctx, job); err != nil {
		t.Fatalf("Sync(create): %v", err)
	}
	handle := c.ScheduleClient().GetHandle(ctx, scheduler.ScheduleID(job.ID))
	desc, err := handle.Describe(ctx)
	if err != nil {
		t.Fatalf("Describe after create: %v", err)
	}
	if desc.Schedule.State.Paused {
		t.Error("enabled job created a paused schedule")
	}

	// The schedule actually fires the workflow with the job id
	select {
	case got := <-fired:
		if got != job.ID {
			t.Errorf("scheduled run for job %s, want %s", got, job.ID)
		}
	case <-time.After(45 * time.Second):
		t.Fatal("schedule never fired the workflow")
	}

	// Disabling pauses; Sync is idempotent
	job.Enabled = false
	if err := sched.Sync(ctx, job); err != nil {
		t.Fatalf("Sync(disable): %v", err)
	}
	if desc, err = handle.Describe(ctx); err != nil || !desc.Schedule.State.Paused {
		t.Fatalf("disabled job schedule not paused: %+v %v", desc, err)
	}
	if err := sched.Sync(ctx, job); err != nil {
		t.Fatalf("Sync(idempotent): %v", err)
	}

	// Clearing the cron removes the schedule; Remove tolerates absence
	job.ScheduleCron = ""
	if err := sched.Sync(ctx, job); err != nil {
		t.Fatalf("Sync(clear cron): %v", err)
	}
	if _, err := handle.Describe(ctx); err == nil {
		t.Error("schedule still exists after the cron was cleared")
	}
	if err := sched.Remove(ctx, job.ID); err != nil {
		t.Fatalf("Remove(absent): %v", err)
	}

	// ReconcileAll prunes orphaned fallbck schedules (no DB: everything is an orphan)
	orphan := &db.BackupJob{ID: uuid.New(), Name: "orphan", ScheduleCron: "0 3 * * *", Enabled: true}
	if err := sched.Sync(ctx, orphan); err != nil {
		t.Fatalf("Sync(orphan): %v", err)
	}
	// Standard visibility lists schedules with a small delay
	deadline := time.Now().Add(30 * time.Second)
	for {
		if err := sched.ReconcileAll(ctx); err != nil {
			t.Fatalf("ReconcileAll: %v", err)
		}
		if _, err := c.ScheduleClient().GetHandle(ctx, scheduler.ScheduleID(orphan.ID)).Describe(ctx); err != nil {
			break // gone
		}
		if time.Now().After(deadline) {
			t.Fatal("orphaned schedule was not removed")
		}
		time.Sleep(2 * time.Second)
	}
}
