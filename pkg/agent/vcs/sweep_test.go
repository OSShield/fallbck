package vcs

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSweepJobs(t *testing.T) {
	root := t.TempDir()
	kept, gone, back := uuid.New(), uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{kept, gone, back} {
		if err := os.MkdirAll(filepath.Join(root, id.String(), "mirrors"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// Not job directories: left alone whatever the list says
	if err := os.Mkdir(filepath.Join(root, "lost+found"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "README"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	exists := func(id uuid.UUID) bool {
		_, err := os.Stat(filepath.Join(root, id.String()))
		return err == nil
	}
	grace := 7 * 24 * time.Hour
	day0 := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)

	// First sweep: the missing jobs get a marker, nothing is deleted
	if removed, err := SweepJobs(root, []uuid.UUID{kept}, grace, day0); err != nil || len(removed) != 0 {
		t.Fatalf("first sweep: %v %v", removed, err)
	}
	if _, err := os.Stat(filepath.Join(root, gone.String(), orphanMarker)); err != nil {
		t.Fatalf("no marker: %v", err)
	}

	// A day later the job is back (moved back, or a server hiccup): its marker goes
	if _, err := SweepJobs(root, []uuid.UUID{kept, back}, grace, day0.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, back.String(), orphanMarker)); !os.IsNotExist(err) {
		t.Errorf("a job that reappears must lose its marker: %v", err)
	}

	// Within the grace period nothing goes
	if removed, _ := SweepJobs(root, []uuid.UUID{kept}, grace, day0.Add(6*24*time.Hour)); len(removed) != 0 || !exists(gone) {
		t.Fatalf("deleted within the grace period: %v", removed)
	}

	// After it: the job missing since day 0 goes; the one that came back on day 1
	// and went again on day 6 has a fresh marker and stays
	removed, err := SweepJobs(root, []uuid.UUID{kept}, grace, day0.Add(7*24*time.Hour))
	if err != nil || len(removed) != 1 || exists(gone) {
		t.Fatalf("after the grace period: %v %v", removed, err)
	}
	if !exists(kept) || !exists(back) {
		t.Error("a listed job, or one within its grace period, was deleted")
	}
	if _, err := os.Stat(filepath.Join(root, "lost+found")); err != nil {
		t.Error("a directory that is not a job id was touched")
	}

	// An unreadable marker restarts the grace period instead of deleting
	if err := os.WriteFile(filepath.Join(root, back.String(), orphanMarker), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := SweepJobs(root, nil, grace, day0.Add(30*24*time.Hour)); err == nil || !exists(back) {
		t.Errorf("garbage marker: err=%v exists=%v", err, exists(back))
	}

	// No state directory yet: nothing to do
	if removed, err := SweepJobs(filepath.Join(root, "nope"), nil, grace, day0); err != nil || removed != nil {
		t.Errorf("missing root: %v %v", removed, err)
	}
}
