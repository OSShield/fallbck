// Package scheduler keeps one Temporal Schedule per backup job with a cron expression.
// Temporal owns the firing (persistence, overlap policy, catch-up after downtime); each
// firing starts BackupJobWorkflow exactly like the manual "Run Now" trigger. The API
// handlers call Sync/Remove on job changes and ReconcileAll repairs drift at startup.
package scheduler

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/db"
	fbtemporal "github.com/osshield/fallbck/pkg/temporal"
	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/api/serviceerror"
	"go.temporal.io/sdk/client"
)

// scheduleIDPrefix namespaces the schedules this package owns; ReconcileAll only ever
// deletes schedules carrying it.
const scheduleIDPrefix = "backup-job-schedule-"

// catchupWindow bounds how far back a firing missed during server downtime is made up
const catchupWindow = time.Hour

// ScheduleID is the Temporal Schedule id for a job
func ScheduleID(jobID uuid.UUID) string { return scheduleIDPrefix + jobID.String() }

// jobIDFromScheduleID reverses ScheduleID
func jobIDFromScheduleID(id string) (uuid.UUID, bool) {
	raw, ok := strings.CutPrefix(id, scheduleIDPrefix)
	if !ok {
		return uuid.Nil, false
	}
	jobID, err := uuid.Parse(raw)
	return jobID, err == nil
}

// Scheduler reconciles backup jobs with Temporal Schedules
type Scheduler struct {
	Client client.Client
	DB     *db.DB
	// TimeZone is the IANA timezone cron expressions are evaluated in ("" = UTC)
	TimeZone string
}

// New creates a Scheduler; database may be nil (ReconcileAll then only prunes orphans)
func New(c client.Client, database *db.DB, timeZone string) *Scheduler {
	return &Scheduler{Client: c, DB: database, TimeZone: timeZone}
}

// spec builds the schedule spec: the job's cron, evaluated in the configured timezone
// (DST-aware — "0 2 * * *" fires at 02:00 local across DST changes)
func (s *Scheduler) spec(cron string) client.ScheduleSpec {
	return client.ScheduleSpec{CronExpressions: []string{cron}, TimeZoneName: s.TimeZone}
}

func isNotFound(err error) bool {
	var nf *serviceerror.NotFound
	return errors.As(err, &nf)
}

// action builds the schedule's workflow action: the same workflow and queue as the
// manual trigger; Temporal appends the fire time to the workflow id per run.
func action(job *db.BackupJob) *client.ScheduleWorkflowAction {
	return &client.ScheduleWorkflowAction{
		ID:        fmt.Sprintf("backup-job-%s-scheduled", job.ID),
		Workflow:  "BackupJobWorkflow",
		Args:      []interface{}{job.ID},
		TaskQueue: fbtemporal.ServerTaskQueue,
	}
}

// Sync makes the Temporal Schedule for a job match its configuration: a cron creates
// or updates it (paused while the job is disabled), no cron removes it. Cron
// expressions are evaluated in UTC.
func (s *Scheduler) Sync(ctx context.Context, job *db.BackupJob) error {
	if s == nil || s.Client == nil || job == nil {
		return nil
	}
	handle := s.Client.ScheduleClient().GetHandle(ctx, ScheduleID(job.ID))
	cron := strings.TrimSpace(job.ScheduleCron)
	if cron == "" {
		if err := handle.Delete(ctx); err != nil && !isNotFound(err) {
			return fmt.Errorf("removing schedule: %w", err)
		}
		return nil
	}
	note := fmt.Sprintf("managed by fallbck for backup job %q (%s)", job.Name, job.ID)

	if _, err := handle.Describe(ctx); err != nil {
		if !isNotFound(err) {
			return fmt.Errorf("describing schedule: %w", err)
		}
		_, err := s.Client.ScheduleClient().Create(ctx, client.ScheduleOptions{
			ID:     ScheduleID(job.ID),
			Spec:   s.spec(cron),
			Action: action(job),
			// Skip a firing while the previous run of this job is still going
			Overlap:       enumspb.SCHEDULE_OVERLAP_POLICY_SKIP,
			CatchupWindow: catchupWindow,
			Paused:        !job.Enabled,
			Note:          note,
		})
		if err != nil {
			return fmt.Errorf("creating schedule: %w", err)
		}
		slog.Info("Backup schedule created", "job_id", job.ID, "job", job.Name, "cron", cron, "timezone", s.TimeZone, "paused", !job.Enabled)
		return nil
	}

	err := handle.Update(ctx, client.ScheduleUpdateOptions{
		DoUpdate: func(in client.ScheduleUpdateInput) (*client.ScheduleUpdate, error) {
			sched := in.Description.Schedule
			spec := s.spec(cron)
			sched.Spec = &spec
			sched.Action = action(job)
			if sched.Policy == nil {
				sched.Policy = &client.SchedulePolicies{}
			}
			sched.Policy.Overlap = enumspb.SCHEDULE_OVERLAP_POLICY_SKIP
			sched.Policy.CatchupWindow = catchupWindow
			if sched.State == nil {
				sched.State = &client.ScheduleState{}
			}
			sched.State.Paused = !job.Enabled
			sched.State.Note = note
			return &client.ScheduleUpdate{Schedule: &sched}, nil
		},
	})
	if err != nil {
		return fmt.Errorf("updating schedule: %w", err)
	}
	slog.Debug("Backup schedule updated", "job_id", job.ID, "cron", cron, "paused", !job.Enabled)
	return nil
}

// Remove deletes a job's schedule (job deletion); a missing schedule is fine
func (s *Scheduler) Remove(ctx context.Context, jobID uuid.UUID) error {
	if s == nil || s.Client == nil {
		return nil
	}
	err := s.Client.ScheduleClient().GetHandle(ctx, ScheduleID(jobID)).Delete(ctx)
	if err != nil && !isNotFound(err) {
		return fmt.Errorf("removing schedule: %w", err)
	}
	return nil
}

// ReconcileAll aligns every schedule with the jobs table: it syncs each job and
// deletes fallbck-owned schedules whose job no longer exists. Run at server startup.
func (s *Scheduler) ReconcileAll(ctx context.Context) error {
	if s == nil || s.Client == nil {
		return nil
	}
	known := map[uuid.UUID]bool{}
	var firstErr error
	if s.DB != nil {
		jobs, err := s.DB.ListJobs(ctx)
		if err != nil {
			return fmt.Errorf("listing jobs: %w", err)
		}
		for _, job := range jobs {
			known[job.ID] = true
			if err := s.Sync(ctx, job); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("job %s (%s): %w", job.Name, job.ID, err)
			}
		}
	}

	iter, err := s.Client.ScheduleClient().List(ctx, client.ScheduleListOptions{PageSize: 100})
	if err != nil {
		if firstErr == nil {
			firstErr = fmt.Errorf("listing schedules: %w", err)
		}
		return firstErr
	}
	for iter.HasNext() {
		entry, err := iter.Next()
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("listing schedules: %w", err)
			}
			break
		}
		jobID, ok := jobIDFromScheduleID(entry.ID)
		if !ok || known[jobID] {
			continue
		}
		slog.Info("Removing orphaned backup schedule", "schedule_id", entry.ID)
		if err := s.Remove(ctx, jobID); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
