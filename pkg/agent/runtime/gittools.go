package runtime

import (
	"context"
	"log/slog"
	"sync"
	"time"

	vcsrun "github.com/osshield/fallbck/pkg/agent/vcs"
)

// GitProbe returns a cached probe for the git (and git-lfs) this agent can run VCS with
// Like DBEngineProbe it detects on first use and after refresh, so a heartbeat never
// executes git, and an installation made after the agent started is picked up
// after next refresh
func GitProbe(refresh time.Duration) func() (version string, lfs bool) {
	var mu sync.Mutex
	var last time.Time
	var known, foundLFS bool
	var found string
	return func() (string, bool) {
		mu.Lock()
		defer mu.Unlock()
		if known && time.Since(last) < refresh {
			return found, foundLFS
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		version, lfs := vcsrun.Probe(ctx)
		if !known || version != found || lfs != foundLFS {
			if version == "" {
				slog.Info("git not found; this agent cannot run VCS jobs")
			} else {
				slog.Info("git for VCS jobs", "version", version, "git_lfs", lfs)
			}
		}
		found, foundLFS, known, last = version, lfs, true, time.Now()
		return found, foundLFS
	}
}
