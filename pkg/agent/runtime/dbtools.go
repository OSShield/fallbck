package runtime

import (
	"context"
	"log/slog"
	"sync"
	"time"

	dbrun "github.com/osshield/fallbck/pkg/agent/dbbackup"
	dbspec "github.com/osshield/fallbck/pkg/dbbackup"
)

// DBToolsProbe returns a cached probe for database client tools (pg_dump,
// mysqldump/mariadb-dump, mongodump). The first call runs the detection and logs
// what it found; later calls reuse the result for refresh and re-detect after that,
// so a heartbeat never pays for executing the tools. Tools installed after the agent
// started are picked up within one refresh interval.
func DBToolsProbe(cfg dbspec.Config, refresh time.Duration) func() bool {
	var mu sync.Mutex
	var last time.Time
	var found bool
	var known bool
	return func() bool {
		mu.Lock()
		defer mu.Unlock()
		if known && time.Since(last) < refresh {
			return found
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		now := false
		for _, d := range dbrun.DetectAll(ctx, dbrun.NewRunner(cfg.KillGrace), cfg.Tools) {
			if d.Err != nil {
				if !known {
					slog.Info("Database client tools not found", "engine", d.Engine, "error", d.Err)
				}
				continue
			}
			now = true
			if !known || !found {
				for name, b := range d.Tools.Binaries {
					slog.Info("Database client tool", "engine", d.Engine, "tool", name, "path", b.Path, "version", b.Version)
				}
			}
		}
		if known && now != found {
			slog.Info("Database client tools availability changed", "available", now)
		}
		found, known, last = now, true, time.Now()
		return found
	}
}
