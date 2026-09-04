package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const runColumns = `id, job_id, agent_id, target_id, workflow_id, run_id, status, start_time, end_time,
	bytes_scanned, bytes_uploaded, dedup_ratio, chunk_count, error_message, pbs_snapshot_id, log_tail, created_at`

func scanRun(row pgx.Row) (*BackupRun, error) {
	var r BackupRun
	err := row.Scan(&r.ID, &r.JobID, &r.AgentID, &r.TargetID, &r.WorkflowID, &r.RunID, &r.Status,
		&r.StartTime, &r.EndTime, &r.BytesScanned, &r.BytesUploaded, &r.DedupRatio,
		&r.ChunkCount, &r.ErrorMessage, &r.PBSSnapshotID, &r.LogTail, &r.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &r, nil
}

// GetRunByID returns a single run
func (d *DB) GetRunByID(ctx context.Context, id uuid.UUID) (*BackupRun, error) {
	return scanRun(d.Pool.QueryRow(ctx, `SELECT `+runColumns+` FROM backup_runs WHERE id = $1`, id))
}

// GetRunByWorkflowID returns the run record created for a Temporal workflow execution
func (d *DB) GetRunByWorkflowID(ctx context.Context, workflowID string) (*BackupRun, error) {
	return scanRun(d.Pool.QueryRow(ctx,
		`SELECT `+runColumns+` FROM backup_runs WHERE workflow_id = $1 ORDER BY created_at DESC LIMIT 1`, workflowID))
}

// MarkRunStarted moves a pending run to running once the workflow has prepared the session
func (d *DB) MarkRunStarted(ctx context.Context, id uuid.UUID, temporalRunID string, startedAt time.Time) error {
	_, err := d.Pool.Exec(ctx,
		`UPDATE backup_runs SET status = $2, run_id = $3, start_time = $4 WHERE id = $1 AND status IN ($5, $6)`,
		id, RunStatusRunning, temporalRunID, startedAt, RunStatusPending, RunStatusRunning)
	return err
}

// SetRunStatus updates the status (and optionally end time / message) of a run
func (d *DB) SetRunStatus(ctx context.Context, id uuid.UUID, status RunStatus, message string, endTime *time.Time) error {
	tag, err := d.Pool.Exec(ctx,
		`UPDATE backup_runs SET status = $2, error_message = $3, end_time = COALESCE($4, end_time) WHERE id = $1`,
		id, status, message, endTime)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateJob replaces the editable fields of a job
func (d *DB) UpdateJob(ctx context.Context, job *BackupJob) error {
	backupPathsJSON, err := json.Marshal(job.BackupPaths)
	if err != nil {
		return fmt.Errorf("failed to serialize backup paths: %w", err)
	}
	excludePathsJSON, err := json.Marshal(job.ExcludePaths)
	if err != nil {
		return fmt.Errorf("failed to serialize exclude paths: %w", err)
	}
	retentionJSON, err := json.Marshal(job.RetentionPolicy)
	if err != nil {
		return fmt.Errorf("failed to serialize retention policy: %w", err)
	}
	jobType, dbConfigJSON, err := jobTypeColumns(job)
	if err != nil {
		return err
	}
	job.UpdatedAt = time.Now().UTC()
	tag, err := d.Pool.Exec(ctx, `
		UPDATE backup_jobs
		SET name = $2, agent_id = $3, target_id = $4, schedule_cron = $5, backup_paths = $6,
		    exclude_paths = $7, retention_policy = $8, enabled = $9, direct_pbs = $10, updated_at = $11,
		    job_type = $12, db_config = $13
		WHERE id = $1`,
		job.ID, job.Name, job.AgentID, job.TargetID, job.ScheduleCron, backupPathsJSON,
		excludePathsJSON, retentionJSON, job.Enabled, job.DirectPBS, job.UpdatedAt, jobType, dbConfigJSON)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
