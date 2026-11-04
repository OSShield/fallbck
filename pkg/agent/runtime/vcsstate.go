package runtime

import (
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	vcsrun "github.com/osshield/fallbck/pkg/agent/vcs"
)

// vcsSweepInterval spaces the sweeps: the list arrives with every heartbeat, a
// directory scan every hour is plenty
const vcsSweepInterval = time.Hour

// VCSStateSweeper returns the heartbeat hook that deletes the mirrors of VCS jobs
// the server no longer assigns to this agent (after grace, see vcs.SweepJobs). It
// runs at most once per vcsSweepInterval.
func VCSStateSweeper(root string, grace time.Duration) func(jobs []uuid.UUID) {
	var mu sync.Mutex
	var last time.Time
	return func(jobs []uuid.UUID) {
		mu.Lock()
		defer mu.Unlock()
		if !last.IsZero() && time.Since(last) < vcsSweepInterval {
			return
		}
		last = time.Now()
		removed, err := vcsrun.SweepJobs(root, jobs, grace, time.Now())
		for _, dir := range removed {
			slog.Info("Deleted the mirrors of a VCS job no longer assigned to this agent", "dir", dir, "grace", grace)
		}
		if err != nil {
			slog.Warn("Sweeping the VCS state directory", "dir", root, "error", err)
		}
	}
}
