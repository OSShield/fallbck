package vcs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
)

// DefaultOrphanGrace is how long a job's state directory survives after the server stopped listing the job
// for this agent (moved to another agent, deleted). Long enough that a server
// briefly answering with the wrong list, or a job moved and moved back, costs
// nothing; the mirrors can always be fetched again.
const DefaultOrphanGrace = 7 * 24 * time.Hour

// marks a job directory the server no longer lists, with the time it was first
// seen missing
const orphanMarker = ".orphaned"

// SweepJobs deletes the state directories (<root>/<job id>) of jobs not in keep once they have
// been missing for grace. A directory missing for the first time gets a marker; a
// job that reappears loses its marker. Only directories named by a job id are
// touched. Returns the directories removed.
func SweepJobs(root string, keep []uuid.UUID, grace time.Duration, now time.Time) ([]string, error) {
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	kept := make(map[uuid.UUID]bool, len(keep))
	for _, id := range keep {
		kept[id] = true
	}
	var removed []string
	var errs []error
	for _, e := range entries {
		id, err := uuid.Parse(e.Name())
		if err != nil || !e.IsDir() || id.String() != e.Name() {
			continue
		}
		dir := filepath.Join(root, e.Name())
		marker := filepath.Join(dir, orphanMarker)
		if kept[id] {
			if err := os.Remove(marker); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, err)
			}
			continue
		}
		since, err := readMarker(marker)
		switch {
		case errors.Is(err, os.ErrNotExist):
			if err := os.WriteFile(marker, []byte(now.UTC().Format(time.RFC3339)+"\n"), 0o600); err != nil {
				errs = append(errs, err)
			}
		case err != nil:
			// An unreadable marker restarts the grace period rather than deleting early
			errs = append(errs, err)
			_ = os.WriteFile(marker, []byte(now.UTC().Format(time.RFC3339)+"\n"), 0o600)
		case now.Sub(since) >= grace:
			if err := os.RemoveAll(dir); err != nil {
				errs = append(errs, err)
				continue
			}
			removed = append(removed, dir)
		}
	}
	return removed, errors.Join(errs...)
}

func readMarker(path string) (time.Time, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}, err
	}
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(string(data)))
	if err != nil {
		return time.Time{}, fmt.Errorf("%s: %w", path, err)
	}
	return t, nil
}
