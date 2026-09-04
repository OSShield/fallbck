package db

import (
	"testing"
	"time"
)

func TestRunDurationString(t *testing.T) {
	start := time.Now().Add(-90 * time.Second)
	end := start.Add(83 * time.Second)
	cases := []struct {
		run  BackupRun
		want string
	}{
		{BackupRun{Status: RunStatusPending}, "-"},
		{BackupRun{Status: RunStatusCompleted, StartTime: &start, EndTime: &end}, "1m23s"},
		{BackupRun{Status: RunStatusFailed, StartTime: &start}, "-"}, // finished but end never recorded
	}
	for _, c := range cases {
		if got := c.run.DurationString(); got != c.want {
			t.Errorf("DurationString() = %q, want %q", got, c.want)
		}
	}
	running := BackupRun{Status: RunStatusRunning, StartTime: &start}
	if got := running.DurationString(); got == "-" {
		t.Errorf("running run should show elapsed time, got %q", got)
	}
}

func TestEnrollmentTokenStatus(t *testing.T) {
	future := time.Now().Add(time.Hour)
	past := time.Now().Add(-time.Hour)
	cases := []struct {
		tok  EnrollmentToken
		want string
	}{
		{EnrollmentToken{ExpiresAt: future, MaxUses: 1, UsesCount: 0}, "active"},
		{EnrollmentToken{ExpiresAt: future, MaxUses: 0, UsesCount: 99}, "active"},
		{EnrollmentToken{ExpiresAt: past, MaxUses: 1}, "expired"},
		{EnrollmentToken{ExpiresAt: future, MaxUses: 2, UsesCount: 2}, "exhausted"},
	}
	for _, c := range cases {
		if got := c.tok.Status(); got != c.want {
			t.Errorf("Status(%+v) = %q, want %q", c.tok, got, c.want)
		}
	}
}
