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
	bytes_scanned, bytes_uploaded, dedup_ratio, chunk_count, error_message, pbs_snapshot_id, log_tail, details, progress, created_at, key_fingerprint`

func scanRun(row pgx.Row) (*BackupRun, error) {
	var r BackupRun
	var details, progress []byte
	err := row.Scan(&r.ID, &r.JobID, &r.AgentID, &r.TargetID, &r.WorkflowID, &r.RunID, &r.Status,
		&r.StartTime, &r.EndTime, &r.BytesScanned, &r.BytesUploaded, &r.DedupRatio,
		&r.ChunkCount, &r.ErrorMessage, &r.PBSSnapshotID, &r.LogTail, &details, &progress, &r.CreatedAt, &r.KeyFingerprint)
	if len(details) > 0 && string(details) != "{}" {
		r.Details = details
	}
	if len(progress) > 0 && string(progress) != "{}" {
		r.Progress = progress
	}
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &r, nil
}

// GetRunByID returns a single run whose job is within scope
func (d *DB) GetRunByID(ctx context.Context, id uuid.UUID, scope Scope) (*BackupRun, error) {
	where, args := scope.SQL("labels", []any{id})
	return scanRun(d.Pool.QueryRow(ctx, `SELECT `+runColumns+` FROM backup_runs WHERE id = $1 AND job_id IN (SELECT id FROM backup_jobs WHERE `+where+`)`, args...))
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
	cols, err := d.jobTypeColumns(job)
	if err != nil {
		return err
	}
	job.UpdatedAt = time.Now().UTC()
	tag, err := d.Pool.Exec(ctx, `
		UPDATE backup_jobs
		SET name = $2, agent_id = $3, target_id = $4, schedule_cron = $5, backup_paths = $6,
		    exclude_paths = $7, enabled = $8, direct_pbs = $9, updated_at = $10,
		    job_type = $11, db_config = $12, k8s_config = $13, pve_config = $14, docker_config = $15,
		    m365_config = $16, m365_tenant_id = $17, backup_id = $18, labels = $19
		WHERE id = $1`,
		job.ID, job.Name, job.AgentID, job.TargetID, job.ScheduleCron, backupPathsJSON,
		excludePathsJSON, job.Enabled, job.DirectPBS, job.UpdatedAt, cols.jobType, cols.db, cols.k8s, cols.pve, cols.docker,
		cols.m365, cols.tenantID, job.BackupID, job.Labels.JSON())
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetRunPhase records the current phase of an active run (jsonb_set: no read-modify-write)
func (d *DB) SetRunPhase(ctx context.Context, runID uuid.UUID, phase, updatedAt string) error {
	_, err := d.Pool.Exec(ctx, `
		UPDATE backup_runs
		SET progress = jsonb_set(jsonb_set(coalesce(progress,'{}'::jsonb), '{phase}', to_jsonb($2::text)), '{updated_at}', to_jsonb($3::text))
		WHERE id = $1 AND status IN ('pending','running','cancelling')`, runID, phase, updatedAt)
	return err
}

// SetRunItems merges per-item statuses into an active run's progress. Each item is
// written at progress.items.<key> so concurrent per-item updates never clobber.
func (d *DB) SetRunItems(ctx context.Context, runID uuid.UUID, updatedAt string, items map[string][]byte) error {
	batch := &pgx.Batch{}
	for key, val := range items {
		batch.Queue(`
			UPDATE backup_runs
			SET progress = jsonb_set(
				jsonb_set(coalesce(progress,'{}'::jsonb), '{items}', coalesce(progress->'items','{}'::jsonb), true),
				ARRAY['items', $2::text], $3::jsonb, true)
			WHERE id = $1 AND status IN ('pending','running','cancelling')`, runID, key, val)
	}
	batch.Queue(`UPDATE backup_runs SET progress = jsonb_set(coalesce(progress,'{}'::jsonb),'{updated_at}', to_jsonb($2::text)) WHERE id = $1 AND status IN ('pending','running','cancelling')`, runID, updatedAt)
	br := d.Pool.SendBatch(ctx, batch)
	defer br.Close()
	for range items {
		if _, err := br.Exec(); err != nil {
			return err
		}
	}
	_, err := br.Exec()
	return err
}
