package dockerbackup

import (
	"context"
	"fmt"
	"time"

	dbrun "github.com/osshield/fallbck/pkg/agent/dbbackup"
)

// spaceGuard keeps a run from filling the spool filesystem: images and volumes
// copied into the spool must leave min bytes free. When the free space cannot be
// read the checks pass (a failed write still stops the copy).
type spaceGuard struct {
	dir  string
	min  uint64
	free func(path string) (uint64, error)
	// every is how often watch looks at the free space
	every time.Duration
}

func newSpaceGuard(dir string, min int64) *spaceGuard {
	return &spaceGuard{dir: dir, min: uint64(min), free: dbrun.FreeSpace, every: 2 * time.Second}
}

// room returns an error when need more bytes would leave less than min free
func (g *spaceGuard) room(need int64) error {
	free, err := g.free(g.dir)
	if err != nil {
		return nil
	}
	if need < 0 {
		need = 0
	}
	if free < g.min+uint64(need) {
		return fmt.Errorf("not enough space in the spool %s: %d MiB free, %d MiB needed plus %d MiB kept free (docker_backup.min_free_bytes)",
			g.dir, free>>20, need>>20, g.min>>20)
	}
	return nil
}

// watch returns a context cancelled when free space drops under min, for copies of
// unknown size; stop ends the watch and returns the space error if it fired
func (g *spaceGuard) watch(ctx context.Context) (context.Context, func() error) {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	fired := make(chan error, 1)
	go func() {
		t := time.NewTicker(g.every)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-t.C:
				if err := g.room(0); err != nil {
					fired <- err
					cancel()
					return
				}
			}
		}
	}()
	return ctx, func() error {
		close(done)
		cancel()
		select {
		case err := <-fired:
			return err
		default:
			return nil
		}
	}
}
