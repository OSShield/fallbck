package db

import (
	"strings"
	"testing"
	"time"
)

func TestValidateCron(t *testing.T) {
	for _, ok := range []string{"", "  ", "0 2 * * *", "*/15 * * * *", "@daily", "@every 6h", "30 4 1 * 1"} {
		if err := ValidateCron(ok); err != nil {
			t.Errorf("ValidateCron(%q): %v", ok, err)
		}
	}
	for _, bad := range []string{"every day", "0 2 * *", "61 * * * *", "0 0 0 0 0 0 0"} {
		if err := ValidateCron(bad); err == nil {
			t.Errorf("ValidateCron(%q) accepted", bad)
		}
	}
}

func TestNextRunString(t *testing.T) {
	j := &BackupJob{ScheduleCron: "0 2 * * *", Enabled: true}
	if s := j.NextRunString(); s == "" || !strings.Contains(s, " 02:00 UTC") {
		t.Errorf("next run %q", s)
	}
	// The display follows the configured schedule timezone
	loc, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	SetScheduleLocation(loc)
	t.Cleanup(func() { SetScheduleLocation(time.UTC) })
	if s := j.NextRunString(); !strings.Contains(s, " 02:00 E") { // EST or EDT
		t.Errorf("next run not in schedule timezone: %q", s)
	}
	if s := (&BackupJob{ScheduleCron: "0 2 * * *", Enabled: false}).NextRunString(); s != "" {
		t.Errorf("disabled job must not show a next run, got %q", s)
	}
	if s := (&BackupJob{Enabled: true}).NextRunString(); s != "" {
		t.Errorf("manual job must not show a next run, got %q", s)
	}
	if s := (&BackupJob{ScheduleCron: "junk", Enabled: true}).NextRunString(); s != "" {
		t.Errorf("bad cron must not show a next run, got %q", s)
	}
}
