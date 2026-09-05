package db

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/robfig/cron/v3"
)

// scheduleLocation is the timezone cron schedules run in (server config); the server
// sets it once at startup, everything else defaults to UTC.
var scheduleLocation atomic.Pointer[time.Location]

// SetScheduleLocation installs the timezone used for next-run display
func SetScheduleLocation(loc *time.Location) {
	if loc != nil {
		scheduleLocation.Store(loc)
	}
}

func displayLocation() *time.Location {
	if loc := scheduleLocation.Load(); loc != nil {
		return loc
	}
	return time.UTC
}

// cronParser accepts standard 5-field cron expressions plus the descriptors Temporal
// also understands (@daily, @hourly, @every 30m, ...). Schedules run in UTC.
var cronParser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)

// ValidateCron rejects schedule expressions the scheduler cannot run; empty = manual
func ValidateCron(expr string) error {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil
	}
	if _, err := cronParser.Parse(expr); err != nil {
		return fmt.Errorf("invalid schedule %q: %v (use 5-field cron like \"0 2 * * *\", or @daily / @every 6h)", expr, err)
	}
	return nil
}

// NextRunString reports when the schedule fires next, in the schedule timezone with
// its abbreviation; empty when the job is manual, disabled, or the expression does
// not parse.
func (j *BackupJob) NextRunString() string {
	expr := strings.TrimSpace(j.ScheduleCron)
	if expr == "" || !j.Enabled {
		return ""
	}
	sched, err := cronParser.Parse(expr)
	if err != nil {
		return ""
	}
	loc := displayLocation()
	return sched.Next(time.Now().In(loc)).Format("2006-01-02 15:04 MST")
}
