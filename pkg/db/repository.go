package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/osshield/fallbck/pkg/dbbackup"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrNotFound = errors.New("record not found")
)

// ==========================================
// Agent Operations
// ==========================================

func (d *DB) CreateAgent(ctx context.Context, agent *Agent) error {
	if agent.ID == uuid.Nil {
		agent.ID = uuid.New()
	}
	if agent.Status == "" {
		agent.Status = AgentStatusOffline
	}
	now := time.Now().UTC()
	agent.CreatedAt = now
	agent.UpdatedAt = now

	query := `
		INSERT INTO agents (id, hostname, ip_address, os, arch, version, task_queue, status, last_seen_at, created_at, updated_at, agent_type)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING id, created_at, updated_at
	`
	if agent.AgentType == "" {
		agent.AgentType = AgentTypeFilesystem
	}
	return d.Pool.QueryRow(ctx, query,
		agent.ID, agent.Hostname, agent.IPAddress, agent.OS, agent.Arch,
		agent.Version, agent.TaskQueue, agent.Status, agent.LastSeenAt,
		agent.CreatedAt, agent.UpdatedAt, agent.AgentType,
	).Scan(&agent.ID, &agent.CreatedAt, &agent.UpdatedAt)
}

func (d *DB) UpsertAgent(ctx context.Context, agent *Agent) error {
	now := time.Now().UTC()
	agent.UpdatedAt = now

	query := `
		INSERT INTO agents (id, hostname, ip_address, os, arch, version, task_queue, status, last_seen_at, created_at, updated_at, agent_type)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT (id) DO UPDATE SET
			agent_type = EXCLUDED.agent_type,
			hostname = EXCLUDED.hostname,
			ip_address = EXCLUDED.ip_address,
			os = EXCLUDED.os,
			arch = EXCLUDED.arch,
			version = EXCLUDED.version,
			task_queue = EXCLUDED.task_queue,
			status = EXCLUDED.status,
			last_seen_at = EXCLUDED.last_seen_at,
			updated_at = EXCLUDED.updated_at
		RETURNING created_at, updated_at
	`
	return d.Pool.QueryRow(ctx, query,
		agent.ID, agent.Hostname, agent.IPAddress, agent.OS, agent.Arch,
		agent.Version, agent.TaskQueue, agent.Status, agent.LastSeenAt,
		now, now, agent.AgentType,
	).Scan(&agent.CreatedAt, &agent.UpdatedAt)
}

func (d *DB) GetAgentByID(ctx context.Context, id uuid.UUID) (*Agent, error) {
	query := `
		SELECT id, hostname, ip_address, os, arch, version, task_queue, status, last_seen_at, created_at, updated_at, agent_type, debug_logging
		FROM agents WHERE id = $1
	`
	row := d.Pool.QueryRow(ctx, query, id)
	var a Agent
	err := row.Scan(&a.ID, &a.Hostname, &a.IPAddress, &a.OS, &a.Arch, &a.Version, &a.TaskQueue, &a.Status, &a.LastSeenAt, &a.CreatedAt, &a.UpdatedAt, &a.AgentType, &a.DebugLogging)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &a, nil
}

func (d *DB) ListAgents(ctx context.Context) ([]*Agent, error) {
	query := `
		SELECT id, hostname, ip_address, os, arch, version, task_queue, status, last_seen_at, created_at, updated_at, agent_type, debug_logging
		FROM agents ORDER BY hostname ASC
	`
	rows, err := d.Pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var agents []*Agent
	for rows.Next() {
		var a Agent
		if err := rows.Scan(&a.ID, &a.Hostname, &a.IPAddress, &a.OS, &a.Arch, &a.Version, &a.TaskQueue, &a.Status, &a.LastSeenAt, &a.CreatedAt, &a.UpdatedAt, &a.AgentType, &a.DebugLogging); err != nil {
			return nil, err
		}
		agents = append(agents, &a)
	}
	return agents, rows.Err()
}

// UpdateAgentHeartbeat records the heartbeat and returns the agent's remote
// debug-logging setting for the response.
func (d *DB) UpdateAgentHeartbeat(ctx context.Context, id uuid.UUID, status AgentStatus) (bool, error) {
	now := time.Now().UTC()
	query := `UPDATE agents SET last_seen_at = $1, status = $2, updated_at = $1 WHERE id = $3 RETURNING debug_logging`
	var debug bool
	if err := d.Pool.QueryRow(ctx, query, now, status, id).Scan(&debug); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, ErrNotFound
		}
		return false, err
	}
	return debug, nil
}

// SetAgentDebugLogging flips the per-agent debug toggle (delivered on the next heartbeat)
func (d *DB) SetAgentDebugLogging(ctx context.Context, id uuid.UUID, enabled bool) error {
	tag, err := d.Pool.Exec(ctx, `UPDATE agents SET debug_logging = $2, updated_at = NOW() WHERE id = $1`, id, enabled)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (d *DB) DeleteAgent(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM agents WHERE id = $1`
	_, err := d.Pool.Exec(ctx, query, id)
	return err
}

// ==========================================
// Enrollment Tokens Operations
// ==========================================

func (d *DB) CreateEnrollmentToken(ctx context.Context, token *EnrollmentToken) error {
	if token.ID == uuid.Nil {
		token.ID = uuid.New()
	}
	token.CreatedAt = time.Now().UTC()

	query := `
		INSERT INTO enrollment_tokens (id, token_hash, name, max_uses, uses_count, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err := d.Pool.Exec(ctx, query,
		token.ID, token.TokenHash, token.Name, token.MaxUses, token.UsesCount, token.ExpiresAt, token.CreatedAt,
	)
	return err
}

func (d *DB) ValidateAndConsumeToken(ctx context.Context, tokenHash string) (*EnrollmentToken, error) {
	query := `
		UPDATE enrollment_tokens
		SET uses_count = uses_count + 1
		WHERE token_hash = $1 AND expires_at > NOW() AND (max_uses = 0 OR uses_count < max_uses)
		RETURNING id, token_hash, name, max_uses, uses_count, expires_at, created_at
	`
	row := d.Pool.QueryRow(ctx, query, tokenHash)
	var t EnrollmentToken
	err := row.Scan(&t.ID, &t.TokenHash, &t.Name, &t.MaxUses, &t.UsesCount, &t.ExpiresAt, &t.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("invalid or expired token")
		}
		return nil, err
	}
	return &t, nil
}

// DeleteEnrollmentToken invalidates a token immediately (enrollment looks tokens up
// by hash, so a deleted row can never be consumed again)
func (d *DB) DeleteEnrollmentToken(ctx context.Context, id uuid.UUID) error {
	tag, err := d.Pool.Exec(ctx, `DELETE FROM enrollment_tokens WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (d *DB) ListEnrollmentTokens(ctx context.Context) ([]*EnrollmentToken, error) {
	query := `SELECT id, token_hash, name, max_uses, uses_count, expires_at, created_at FROM enrollment_tokens ORDER BY created_at DESC`
	rows, err := d.Pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []*EnrollmentToken
	for rows.Next() {
		var t EnrollmentToken
		if err := rows.Scan(&t.ID, &t.TokenHash, &t.Name, &t.MaxUses, &t.UsesCount, &t.ExpiresAt, &t.CreatedAt); err != nil {
			return nil, err
		}
		tokens = append(tokens, &t)
	}
	return tokens, rows.Err()
}

// ==========================================
// Backup Targets Operations
// ==========================================

func (d *DB) CreateTarget(ctx context.Context, target *BackupTarget) error {
	if target.ID == uuid.Nil {
		target.ID = uuid.New()
	}
	now := time.Now().UTC()
	target.CreatedAt = now
	target.UpdatedAt = now

	query := `
		INSERT INTO backup_targets (id, name, target_type, endpoint, datastore, namespace, auth_token_encrypted, fingerprint, tls_verify, pxar_format, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING id
	`
	if target.PxarFormat == "" {
		target.PxarFormat = PxarFormatV1
	}
	return d.Pool.QueryRow(ctx, query,
		target.ID, target.Name, target.TargetType, target.Endpoint, target.Datastore,
		target.Namespace, target.AuthTokenEncrypted, target.Fingerprint, target.TLSVerify, target.PxarFormat,
		target.CreatedAt, target.UpdatedAt,
	).Scan(&target.ID)
}

func (d *DB) GetTargetByID(ctx context.Context, id uuid.UUID) (*BackupTarget, error) {
	query := `
		SELECT id, name, target_type, endpoint, datastore, namespace, auth_token_encrypted, fingerprint, tls_verify, pxar_format, created_at, updated_at
		FROM backup_targets WHERE id = $1
	`
	row := d.Pool.QueryRow(ctx, query, id)
	var t BackupTarget
	err := row.Scan(&t.ID, &t.Name, &t.TargetType, &t.Endpoint, &t.Datastore, &t.Namespace, &t.AuthTokenEncrypted, &t.Fingerprint, &t.TLSVerify, &t.PxarFormat, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return t.Sanitize(), nil
}

func (d *DB) ListTargets(ctx context.Context) ([]*BackupTarget, error) {
	query := `
		SELECT id, name, target_type, endpoint, datastore, namespace, auth_token_encrypted, fingerprint, tls_verify, pxar_format, created_at, updated_at
		FROM backup_targets ORDER BY name ASC
	`
	rows, err := d.Pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var targets []*BackupTarget
	for rows.Next() {
		var t BackupTarget
		if err := rows.Scan(&t.ID, &t.Name, &t.TargetType, &t.Endpoint, &t.Datastore, &t.Namespace, &t.AuthTokenEncrypted, &t.Fingerprint, &t.TLSVerify, &t.PxarFormat, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		targets = append(targets, t.Sanitize())
	}
	return targets, rows.Err()
}

func (d *DB) DeleteTarget(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM backup_targets WHERE id = $1`
	_, err := d.Pool.Exec(ctx, query, id)
	return err
}

// ==========================================
// Backup Jobs Operations
// ==========================================

func (d *DB) CreateJob(ctx context.Context, job *BackupJob) error {
	if job.ID == uuid.Nil {
		job.ID = uuid.New()
	}
	now := time.Now().UTC()
	job.CreatedAt = now
	job.UpdatedAt = now

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

	query := `
		INSERT INTO backup_jobs (id, name, agent_id, target_id, schedule_cron, backup_paths, exclude_paths, retention_policy, enabled, direct_pbs, created_at, updated_at, job_type, db_config)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		RETURNING id
	`
	return d.Pool.QueryRow(ctx, query,
		job.ID, job.Name, job.AgentID, job.TargetID, job.ScheduleCron,
		backupPathsJSON, excludePathsJSON, retentionJSON, job.Enabled, job.DirectPBS,
		job.CreatedAt, job.UpdatedAt, jobType, dbConfigJSON,
	).Scan(&job.ID)
}

func (d *DB) GetJobByID(ctx context.Context, id uuid.UUID) (*BackupJob, error) {
	query := `
		SELECT j.id, j.name, j.agent_id, j.target_id, j.schedule_cron, j.backup_paths, j.exclude_paths,
		       j.retention_policy, j.enabled, j.direct_pbs, j.created_at, j.updated_at,
		       j.job_type, j.db_config,
		       a.hostname as agent_name, t.name as target_name
		FROM backup_jobs j
		JOIN agents a ON j.agent_id = a.id
		JOIN backup_targets t ON j.target_id = t.id
		WHERE j.id = $1
	`
	row := d.Pool.QueryRow(ctx, query, id)
	var j BackupJob
	var backupPathsRaw, excludePathsRaw, retentionRaw, dbConfigRaw []byte
	err := row.Scan(
		&j.ID, &j.Name, &j.AgentID, &j.TargetID, &j.ScheduleCron,
		&backupPathsRaw, &excludePathsRaw, &retentionRaw,
		&j.Enabled, &j.DirectPBS, &j.CreatedAt, &j.UpdatedAt,
		&j.JobType, &dbConfigRaw,
		&j.AgentName, &j.TargetName,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	_ = json.Unmarshal(backupPathsRaw, &j.BackupPaths)
	_ = json.Unmarshal(excludePathsRaw, &j.ExcludePaths)
	_ = json.Unmarshal(retentionRaw, &j.RetentionPolicy)
	j.DBConfig = parseDBConfig(dbConfigRaw)

	return &j, nil
}

func (d *DB) ListJobs(ctx context.Context) ([]*BackupJob, error) {
	query := `
		SELECT j.id, j.name, j.agent_id, j.target_id, j.schedule_cron, j.backup_paths, j.exclude_paths,
		       j.retention_policy, j.enabled, j.direct_pbs, j.created_at, j.updated_at,
		       j.job_type, j.db_config,
		       a.hostname as agent_name, t.name as target_name
		FROM backup_jobs j
		JOIN agents a ON j.agent_id = a.id
		JOIN backup_targets t ON j.target_id = t.id
		ORDER BY j.name ASC
	`
	rows, err := d.Pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var jobs []*BackupJob
	for rows.Next() {
		var j BackupJob
		var backupPathsRaw, excludePathsRaw, retentionRaw, dbConfigRaw []byte
		if err := rows.Scan(
			&j.ID, &j.Name, &j.AgentID, &j.TargetID, &j.ScheduleCron,
			&backupPathsRaw, &excludePathsRaw, &retentionRaw,
			&j.Enabled, &j.DirectPBS, &j.CreatedAt, &j.UpdatedAt,
			&j.JobType, &dbConfigRaw,
			&j.AgentName, &j.TargetName,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(backupPathsRaw, &j.BackupPaths)
		_ = json.Unmarshal(excludePathsRaw, &j.ExcludePaths)
		_ = json.Unmarshal(retentionRaw, &j.RetentionPolicy)
		j.DBConfig = parseDBConfig(dbConfigRaw)
		jobs = append(jobs, &j)
	}
	return jobs, rows.Err()
}

// jobTypeColumns returns the job_type and db_config column values
func jobTypeColumns(job *BackupJob) (string, []byte, error) {
	jobType, ok := NormalizeAgentType(job.JobType)
	if !ok {
		return "", nil, fmt.Errorf("unknown job type %q", job.JobType)
	}
	job.JobType = jobType
	if jobType != JobTypeDatabase || job.DBConfig == nil {
		return jobType, []byte("{}"), nil
	}
	raw, err := json.Marshal(job.DBConfig)
	if err != nil {
		return "", nil, fmt.Errorf("failed to serialize database configuration: %w", err)
	}
	return jobType, raw, nil
}

// parseDBConfig decodes the db_config column; an empty object yields nil
func parseDBConfig(raw []byte) *dbbackup.Spec {
	if len(raw) == 0 {
		return nil
	}
	var spec dbbackup.Spec
	if err := json.Unmarshal(raw, &spec); err != nil || spec.Engine == "" {
		return nil
	}
	return &spec
}

func (d *DB) DeleteJob(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM backup_jobs WHERE id = $1`
	_, err := d.Pool.Exec(ctx, query, id)
	return err
}

// ==========================================
// Backup Runs Operations
// ==========================================

func (d *DB) CreateRun(ctx context.Context, run *BackupRun) error {
	if run.ID == uuid.Nil {
		run.ID = uuid.New()
	}
	run.CreatedAt = time.Now().UTC()
	if run.Status == "" {
		run.Status = RunStatusPending
	}
	if run.DedupRatio == 0 {
		run.DedupRatio = 1.00
	}

	query := `
		INSERT INTO backup_runs (id, job_id, agent_id, target_id, workflow_id, run_id, status, start_time, end_time, bytes_scanned, bytes_uploaded, dedup_ratio, chunk_count, error_message, pbs_snapshot_id, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
		RETURNING id
	`
	return d.Pool.QueryRow(ctx, query,
		run.ID, run.JobID, run.AgentID, run.TargetID, run.WorkflowID, run.RunID,
		run.Status, run.StartTime, run.EndTime, run.BytesScanned, run.BytesUploaded,
		run.DedupRatio, run.ChunkCount, run.ErrorMessage, run.PBSSnapshotID, run.CreatedAt,
	).Scan(&run.ID)
}

func (d *DB) UpdateRun(ctx context.Context, run *BackupRun) error {
	query := `
		UPDATE backup_runs
		SET status = $1, start_time = $2, end_time = $3, bytes_scanned = $4,
		    bytes_uploaded = $5, dedup_ratio = $6, chunk_count = $7,
		    error_message = $8, pbs_snapshot_id = $9, log_tail = $10
		WHERE id = $11
	`
	_, err := d.Pool.Exec(ctx, query,
		run.Status, run.StartTime, run.EndTime, run.BytesScanned,
		run.BytesUploaded, run.DedupRatio, run.ChunkCount,
		run.ErrorMessage, run.PBSSnapshotID, run.LogTail, run.ID,
	)
	return err
}

func (d *DB) ListRuns(ctx context.Context, limit int) ([]*BackupRun, error) {
	if limit <= 0 {
		limit = 50
	}
	query := `
		SELECT r.id, r.job_id, r.agent_id, r.target_id, r.workflow_id, r.run_id, r.status,
		       r.start_time, r.end_time, r.bytes_scanned, r.bytes_uploaded, r.dedup_ratio,
		       r.chunk_count, r.error_message, r.pbs_snapshot_id, r.log_tail, r.created_at,
		       j.name as job_name, a.hostname as agent_name
		FROM backup_runs r
		JOIN backup_jobs j ON r.job_id = j.id
		JOIN agents a ON r.agent_id = a.id
		ORDER BY r.created_at DESC
		LIMIT $1
	`
	rows, err := d.Pool.Query(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var runs []*BackupRun
	for rows.Next() {
		var r BackupRun
		if err := rows.Scan(
			&r.ID, &r.JobID, &r.AgentID, &r.TargetID, &r.WorkflowID, &r.RunID, &r.Status,
			&r.StartTime, &r.EndTime, &r.BytesScanned, &r.BytesUploaded, &r.DedupRatio,
			&r.ChunkCount, &r.ErrorMessage, &r.PBSSnapshotID, &r.LogTail, &r.CreatedAt,
			&r.JobName, &r.AgentName,
		); err != nil {
			return nil, err
		}
		runs = append(runs, &r)
	}
	return runs, rows.Err()
}
