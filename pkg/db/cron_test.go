package db

import (
	"strings"
	"testing"
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
	if s := j.NextRunString(); s == "" || !strings.Contains(s, " 02:0") {
		t.Errorf("next run %q", s)
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
