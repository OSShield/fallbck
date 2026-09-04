package db

import (
	"fmt"
	"strings"
	"time"

	"github.com/robfig/cron/v3"
)

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

// NextRunString reports when the schedule fires next (UTC), for display; empty when
// the job is manual, disabled, or the expression does not parse.
func (j *BackupJob) NextRunString() string {
	expr := strings.TrimSpace(j.ScheduleCron)
	if expr == "" || !j.Enabled {
		return ""
	}
	sched, err := cronParser.Parse(expr)
	if err != nil {
		return ""
	}
	return sched.Next(time.Now().UTC()).Format("2006-01-02 15:04")
}
