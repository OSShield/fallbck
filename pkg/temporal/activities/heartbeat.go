package activities

import (
	"context"
	"fmt"
	"sync"
	"time"

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

// backupFailure wraps an activity failure with the current phase and the agent's log
// tail so the workflow can surface both on the run record. Cancellations pass through
// untouched (they must stay cancellations).
func backupFailure(ctx context.Context, err error, pt *phaseTracker, logTail func() string) error {
	if err == nil || ctx.Err() != nil {
		return err
	}
	tail := ""
	if logTail != nil {
		tail = logTail()
	}
	msg := fmt.Sprintf("%v [phase: %s]", err, pt.Current())
	return sdktemporal.NewApplicationError(msg, ErrTypeBackupFailed, temporal.BackupFailureDetails{Phase: pt.Current(), LogTail: tail})
}
