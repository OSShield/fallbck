package activities

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/rundetail"

	"github.com/osshield/fallbck/pkg/temporal"
	"go.temporal.io/sdk/activity"
	sdktemporal "go.temporal.io/sdk/temporal"
)

// heartbeatInterval paces the liveness heartbeats; well under the workflow's 60s
// HeartbeatTimeout. Overridable in tests.
var activityHeartbeatInterval = 15 * time.Second

// ErrTypeBackupFailed marks a failed (but retryable) backup activity; the error carries
// temporal.BackupFailureDetails for the workflow.
const ErrTypeBackupFailed = "backup_failed"

// phaseTracker remembers what the activity is doing so heartbeats and failures can say
type phaseTracker struct {
	mu    sync.Mutex
	phase string
	since time.Time
}

func newPhaseTracker() *phaseTracker {
	return &phaseTracker{phase: "starting", since: time.Now()}
}

func (p *phaseTracker) Set(phase string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if phase != p.phase {
		p.phase = phase
		p.since = time.Now()
	}
}

// Current returns the phase annotated with how long it has been running
func (p *phaseTracker) Current() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return fmt.Sprintf("%s (%s)", p.phase, time.Since(p.since).Round(time.Second))
}

// startHeartbeats records an immediate heartbeat and then one per interval, each
// carrying the current phase, for the whole life of the activity — liveness no longer
// depends on upload progress. The returned stop function ends the ticker.
func startHeartbeats(ctx context.Context, pt *phaseTracker) (stop func()) {
	beat := func() {
		activity.RecordHeartbeat(ctx, temporal.BackupHeartbeatProgress{Phase: pt.Current(), CurrentFile: pt.Current()})
	}
	beat()
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(activityHeartbeatInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			case <-t.C:
				beat()
			}
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { close(done) }) }
}

// ProgressFunc posts live run progress (phase and/or per-item statuses) to the server.
type ProgressFunc func(ctx context.Context, ticket string, runID uuid.UUID, phase string, items map[string]rundetail.ProgressItem) error

// reportPhase / reportItems are nil-safe, best-effort progress helpers
func reportPhase(fn ProgressFunc, ctx context.Context, ticket string, runID uuid.UUID, phase string) {
	if fn != nil {
		_ = fn(ctx, ticket, runID, phase, nil)
	}
}
func reportItems(fn ProgressFunc, ctx context.Context, ticket string, runID uuid.UUID, items map[string]rundetail.ProgressItem) {
	if fn != nil {
		_ = fn(ctx, ticket, runID, "", items)
	}
}

// startProgress calls fn immediately and every interval with the current phase, until
// the returned stop function runs or ctx ends. Used to push live progress to the server.
func startProgress(ctx context.Context, pt *phaseTracker, interval time.Duration, fn func(phase string)) (stop func()) {
	if fn == nil {
		return func() {}
	}
	fn(pt.Current())
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			case <-t.C:
				fn(pt.Current())
			}
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { close(done) }) }
}

// TicketRefreshFunc re-issues a run's backup ticket with a fresh snapshot timestamp
type TicketRefreshFunc func(ctx context.Context, ticket string) (ticket2 string, backupTime int64, err error)

// sessionForAttempt returns the session a backup attempt should run with. The first
// attempt uses the session as prepared; a retry re-issues the ticket so the snapshot
// gets a new timestamp: PBS refuses a backup whose time is not newer than the group's
// latest snapshot, and the previous attempt may well have finalised its snapshot before
// failing. When the refresh fails the attempt proceeds with the original session (and
// gets the snapshot-conflict diagnosis from backupFailure if PBS refuses it).
func sessionForAttempt(ctx context.Context, session *temporal.BackupSessionInfo, refresh TicketRefreshFunc) *temporal.BackupSessionInfo {
	attempt := activity.GetInfo(ctx).Attempt
	if attempt <= 1 || refresh == nil {
		return session
	}
	ticket, backupTime, err := refresh(ctx, session.Ticket)
	if err != nil {
		slog.Warn("Could not re-issue the backup ticket for the retry; reusing the previous snapshot timestamp", "attempt", attempt, "error", err)
		return session
	}
	fresh := *session
	fresh.Ticket = ticket
	fresh.BackupTime = backupTime
	slog.Info("Retrying with a new snapshot timestamp", "attempt", attempt, "backup_id", fresh.BackupID, "previous_time", session.BackupTime, "backup_time", backupTime)
	return &fresh
}

// snapshotConflictMarker is PBS's response when a backup's timestamp is not newer than
// the group's latest snapshot; it reaches the agent through the tunnel's error string
const snapshotConflictMarker = "backup timestamp is older than last backup"

// isSnapshotConflict reports whether PBS refused the session because a snapshot at (or
// after) the requested timestamp already exists
func isSnapshotConflict(err error) bool {
	return err != nil && strings.Contains(err.Error(), snapshotConflictMarker)
}

// backupFailure wraps an activity failure with the current phase and the agent's log
// tail so the workflow can surface both on the run record. Cancellations pass through
// untouched (they must stay cancellations). A snapshot conflict is reported as
// non-retryable with an explanation: retrying with the same timestamp cannot succeed,
// and the most likely cause is a previous attempt that completed the upload but failed
// before it could report.
func backupFailure(ctx context.Context, err error, pt *phaseTracker, logTail func() string) error {
	if err == nil || ctx.Err() != nil {
		return err
	}
	tail := ""
	if logTail != nil {
		tail = logTail()
	}
	details := temporal.BackupFailureDetails{Phase: pt.Current(), LogTail: tail}
	if isSnapshotConflict(err) {
		msg := fmt.Sprintf("%v [phase: %s] — PBS already holds a snapshot of this backup group at or after the requested timestamp; "+
			"a previous attempt most likely completed the upload but failed before reporting. Check the group in PBS before re-running.", err, pt.Current())
		return sdktemporal.NewNonRetryableApplicationError(msg, ErrTypeBackupFailed, nil, details)
	}
	msg := fmt.Sprintf("%v [phase: %s]", err, pt.Current())
	return sdktemporal.NewApplicationError(msg, ErrTypeBackupFailed, details)
}
