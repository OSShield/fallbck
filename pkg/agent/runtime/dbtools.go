package runtime

import (
	"context"
	"log/slog"
	"slices"
	"sync"
	"time"

	dbrun "github.com/osshield/fallbck/pkg/agent/dbbackup"
	dbspec "github.com/osshield/fallbck/pkg/dbbackup"
)

// DBEnginesProbe returns a cached probe for the database engines this agent can back
// up: postgres, mysql and mongodb when their client tools are found, mssql always
// (built-in driver). The first call runs the detection and logs what it found; later
// calls reuse the result for refresh and re-detect after that, so a heartbeat never
// pays for executing the tools. Tools installed after the agent started are picked up
// within one refresh interval.
func DBEnginesProbe(cfg dbspec.Config, refresh time.Duration) func() []string {
	var mu sync.Mutex
	var last time.Time
	var found []string
	var known bool
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		if known && time.Since(last) < refresh {
			return found
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		var now []string
		for _, d := range dbrun.DetectAll(ctx, dbrun.NewRunner(cfg.KillGrace), cfg.Tools) {
			if d.Err != nil {
				if !known {
					slog.Info("Database client tools not found", "engine", d.Engine, "error", d.Err)
				}
				continue
			}
			now = append(now, d.Engine)
			if !known || !slices.Contains(found, d.Engine) {
				for name, b := range d.Tools.Binaries {
					slog.Info("Database client tool", "engine", d.Engine, "tool", name, "path", b.Path, "version", b.Version)
				}
			}
		}
		if known && !slices.Equal(now, found) {
			slog.Info("Database engines available to this agent changed", "engines", now)
		}
		found, known, last = now, true, time.Now()
		return found
	}
}
