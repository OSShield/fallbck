package dockerbackup

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSpaceGuard(t *testing.T) {
	var free atomic.Uint64
	free.Store(5 << 30)
	g := &spaceGuard{dir: "/spool", min: 1 << 30, every: 5 * time.Millisecond,
		free: func(string) (uint64, error) { return free.Load(), nil }}

	if err := g.room(2 << 30); err != nil {
		t.Errorf("2 GiB into 5 GiB free with 1 GiB kept: %v", err)
	}
	if err := g.room(4<<30 + 1); err == nil || !strings.Contains(err.Error(), "min_free_bytes") {
		t.Errorf("4 GiB+ must not fit: %v", err)
	}

	// The watch stays quiet while there is room ...
	ctx, stop := g.watch(context.Background())
	time.Sleep(20 * time.Millisecond)
	if ctx.Err() != nil || stop() != nil {
		t.Error("watch fired with room to spare")
	}
	// ... and cancels the copy when the disk fills up
	ctx, stop = g.watch(context.Background())
	free.Store(512 << 20)
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("watch did not cancel the copy")
	}
	if err := stop(); err == nil {
		t.Error("stop must report why the copy was cancelled")
	}

	// Unknown free space never blocks a run (a failed write still stops the copy)
	g.free = func(string) (uint64, error) { return 0, errors.New("statfs: not supported") }
	if err := g.room(1 << 40); err != nil {
		t.Errorf("unknown free space: %v", err)
	}
}
