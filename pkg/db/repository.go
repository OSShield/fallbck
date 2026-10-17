package db

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/osshield/fallbck/pkg/dbbackup"
	"github.com/osshield/fallbck/pkg/dockerbackup"
	"github.com/osshield/fallbck/pkg/k8sbackup"
	"github.com/osshield/fallbck/pkg/m365"
	"github.com/osshield/fallbck/pkg/pvebackup"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrNotFound = errors.New("record not found")
	// ErrInUse: the row is referenced by others and cannot be deleted
	ErrInUse = errors.New("record is in use")
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
		INSERT INTO agents (id, hostname, ip_address, os, arch, version, task_queue, status, last_seen_at, created_at, updated_at, agent_type, pve_host, docker_host, db_tools, db_engines, labels)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
		RETURNING id, created_at, updated_at
	`
	if agent.AgentType == "" {
		agent.AgentType = AgentTypeFilesystem
	}
	agent.Labels = agent.Labels.OrEmpty()
	return d.Pool.QueryRow(ctx, query,
		agent.ID, agent.Hostname, agent.IPAddress, agent.OS, agent.Arch,
		agent.Version, agent.TaskQueue, agent.Status, agent.LastSeenAt,
		agent.CreatedAt, agent.UpdatedAt, agent.AgentType, agent.PVEHost, agent.DockerHost, agent.DBTools, enginesOrEmpty(agent.DBEngines), agent.Labels.JSON(),
	).Scan(&agent.ID, &agent.CreatedAt, &agent.UpdatedAt)
}

func (d *DB) UpsertAgent(ctx context.Context, agent *Agent) error {
	now := time.Now().UTC()
	agent.UpdatedAt = now

	query := `
		INSERT INTO agents (id, hostname, ip_address, os, arch, version, task_queue, status, last_seen_at, created_at, updated_at, agent_type, pve_host, docker_host, db_tools, db_engines)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
		ON CONFLICT (id) DO UPDATE SET
			agent_type = EXCLUDED.agent_type,
			pve_host = EXCLUDED.pve_host,
			docker_host = EXCLUDED.docker_host,
			db_tools = EXCLUDED.db_tools,
			db_engines = EXCLUDED.db_engines,
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
		now, now, agent.AgentType, agent.PVEHost, agent.DockerHost, agent.DBTools, enginesOrEmpty(agent.DBEngines),
	).Scan(&agent.CreatedAt, &agent.UpdatedAt)
}

const agentSelect = `SELECT id, hostname, ip_address, os, arch, version, task_queue, status, last_seen_at, created_at, updated_at, agent_type, debug_logging, pve_host, docker_host, db_tools, db_engines, inventory, inventory_at, inventory_detail, inventory_detail_at, auto_update, self_update, update_requested_at, update_error, labels
	FROM agents`

func scanAgent(row pgx.Row) (*Agent, error) {
	var a Agent
	err := row.Scan(&a.ID, &a.Hostname, &a.IPAddress, &a.OS, &a.Arch, &a.Version, &a.TaskQueue, &a.Status, &a.LastSeenAt, &a.CreatedAt, &a.UpdatedAt, &a.AgentType, &a.DebugLogging, &a.PVEHost, &a.DockerHost, &a.DBTools, &a.DBEngines, &a.Inventory, &a.InventoryAt, &a.InventoryDetail, &a.InventoryDetailAt, &a.AutoUpdate, &a.SelfUpdate, &a.UpdateRequestedAt, &a.UpdateError, &a.Labels)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// GetAgentByID loads an agent within scope (ErrNotFound outside it)
func (d *DB) GetAgentByID(ctx context.Context, id uuid.UUID, scope Scope) (*Agent, error) {
	where, args := scope.SQL("labels", []any{id})
	return scanAgent(d.Pool.QueryRow(ctx, agentSelect+` WHERE id = $1 AND `+where, args...))
}

// ListAgents lists the agents within scope
func (d *DB) ListAgents(ctx context.Context, scope Scope) ([]*Agent, error) {
	where, args := scope.SQL("labels", nil)
	rows, err := d.Pool.Query(ctx, agentSelect+` WHERE `+where+` ORDER BY hostname ASC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var agents []*Agent
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		agents = append(agents, a)
	}
	return agents, rows.Err()
}

// SetAgentLabels replaces an agent's labels
func (d *DB) SetAgentLabels(ctx context.Context, id uuid.UUID, labels Labels) error {
	return d.execAgent(ctx, `UPDATE agents SET labels = $2, updated_at = NOW() WHERE id = $1`, id, labels.JSON())
}

// UpdateAgentHeartbeat records the heartbeat (status, capabilities, version) and
// returns what the response needs. An update error from the agent consumes a pending
// "update now" request so a failed manual update is not retried every heartbeat.
func (d *DB) UpdateAgentHeartbeat(ctx context.Context, id uuid.UUID, status AgentStatus, caps AgentCapabilities) (HeartbeatState, error) {
	now := time.Now().UTC()
	// An inventory summary in the heartbeat replaces the stored one; nil keeps it
	query := `UPDATE agents SET last_seen_at = $1, status = $2, updated_at = $1, pve_host = $4, docker_host = $5, db_tools = $6, db_engines = $7,
		inventory = COALESCE($8, inventory), inventory_at = CASE WHEN $8::jsonb IS NULL THEN inventory_at ELSE $1 END,
		version = COALESCE(NULLIF($9, ''), version), self_update = $10, update_error = $11,
		update_requested_at = CASE WHEN $11 <> '' THEN NULL ELSE update_requested_at END
		WHERE id = $3 RETURNING debug_logging, auto_update, update_requested_at IS NOT NULL, os, arch`
	var st HeartbeatState
	var inv []byte
	if len(caps.Inventory) > 0 {
		inv = caps.Inventory
	}
	if err := d.Pool.QueryRow(ctx, query, now, status, id, caps.PVEHost, caps.DockerHost, caps.DBTools, enginesOrEmpty(caps.DBEngines), inv,
		caps.Version, caps.SelfUpdate, caps.UpdateError).Scan(&st.DebugLogging, &st.AutoUpdate, &st.UpdateRequested, &st.OS, &st.Arch); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return st, ErrNotFound
		}
		return st, err
	}
	return st, nil
}

// SetAgentAutoUpdate flips the per-agent auto-update opt-in
func (d *DB) SetAgentAutoUpdate(ctx context.Context, id uuid.UUID, enabled bool) error {
	return d.execAgent(ctx, `UPDATE agents SET auto_update = $2, updated_at = NOW() WHERE id = $1`, id, enabled)
}

// RequestAgentUpdate asks the agent to update on its next heartbeat (the web UI's
// "Update now"); a previous error is cleared so the retry starts clean
func (d *DB) RequestAgentUpdate(ctx context.Context, id uuid.UUID) error {
	return d.execAgent(ctx, `UPDATE agents SET update_requested_at = NOW(), update_error = '', updated_at = NOW() WHERE id = $1`, id)
}

// ClearAgentUpdateRequest drops a pending request (the agent reached the version)
func (d *DB) ClearAgentUpdateRequest(ctx context.Context, id uuid.UUID) error {
	return d.execAgent(ctx, `UPDATE agents SET update_requested_at = NULL WHERE id = $1`, id)
}

func (d *DB) execAgent(ctx context.Context, sql string, args ...any) error {
	tag, err := d.Pool.Exec(ctx, sql, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
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

// MergeAgents moves every job and run of the agent from onto the agent into and
// deletes from, in one transaction. Deleting an agent cascades to its jobs and runs,
// so the move must come first. It returns the number of jobs and runs moved.
func (d *DB) MergeAgents(ctx context.Context, from, into uuid.UUID) (int64, int64, error) {
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	jobs, err := tx.Exec(ctx, `UPDATE backup_jobs SET agent_id = $2, updated_at = NOW() WHERE agent_id = $1`, from, into)
	if err != nil {
		return 0, 0, err
	}
	runs, err := tx.Exec(ctx, `UPDATE backup_runs SET agent_id = $2 WHERE agent_id = $1`, from, into)
	if err != nil {
		return 0, 0, err
	}
	tag, err := tx.Exec(ctx, `DELETE FROM agents WHERE id = $1`, from)
	if err != nil {
		return 0, 0, err
	}
	if tag.RowsAffected() == 0 {
		return 0, 0, ErrNotFound
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, 0, err
	}
	return jobs.RowsAffected(), runs.RowsAffected(), nil
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
		INSERT INTO enrollment_tokens (id, token_hash, name, max_uses, uses_count, expires_at, created_at, labels)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	_, err := d.Pool.Exec(ctx, query,
		token.ID, token.TokenHash, token.Name, token.MaxUses, token.UsesCount, token.ExpiresAt, token.CreatedAt, token.Labels.JSON(),
	)
	return err
}

// EnsureUnlimitedEnrollmentToken creates a never-expiring, unlimited-use token with the
// given hash unless it already exists (server --insecure-unlimited-dev-token)
func (d *DB) EnsureUnlimitedEnrollmentToken(ctx context.Context, tokenHash, name string) error {
	query := `
		INSERT INTO enrollment_tokens (id, token_hash, name, max_uses, uses_count, expires_at, created_at)
		VALUES ($1, $2, $3, 0, 0, $4, NOW())
		ON CONFLICT (token_hash) DO UPDATE SET max_uses = 0, expires_at = EXCLUDED.expires_at
	`
	_, err := d.Pool.Exec(ctx, query, uuid.New(), tokenHash, name, time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC))
	return err
}

func (d *DB) ValidateAndConsumeToken(ctx context.Context, tokenHash string) (*EnrollmentToken, error) {
	query := `
		UPDATE enrollment_tokens
		SET uses_count = uses_count + 1
		WHERE token_hash = $1 AND expires_at > NOW() AND (max_uses = 0 OR uses_count < max_uses)
		RETURNING id, token_hash, name, max_uses, uses_count, expires_at, created_at, agent_id, labels
	`
	row := d.Pool.QueryRow(ctx, query, tokenHash)
	var t EnrollmentToken
	err := row.Scan(&t.ID, &t.TokenHash, &t.Name, &t.MaxUses, &t.UsesCount, &t.ExpiresAt, &t.CreatedAt, &t.AgentID, &t.Labels)
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

// tokenColumns joins the hostname of the agent that used the token
const tokenColumns = `t.id, t.token_hash, t.name, t.max_uses, t.uses_count, t.expires_at, t.created_at, t.agent_id, COALESCE(a.hostname, ''), t.labels
		FROM enrollment_tokens t LEFT JOIN agents a ON a.id = t.agent_id`

// ListEnrollmentTokens lists the tokens within scope
func (d *DB) ListEnrollmentTokens(ctx context.Context, scope Scope) ([]*EnrollmentToken, error) {
	where, args := scope.SQL("t.labels", nil)
	rows, err := d.Pool.Query(ctx, `SELECT `+tokenColumns+` WHERE `+where+` ORDER BY t.created_at DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []*EnrollmentToken
	for rows.Next() {
		var t EnrollmentToken
		if err := rows.Scan(&t.ID, &t.TokenHash, &t.Name, &t.MaxUses, &t.UsesCount, &t.ExpiresAt, &t.CreatedAt, &t.AgentID, &t.AgentHostname, &t.Labels); err != nil {
			return nil, err
		}
		tokens = append(tokens, &t)
	}
	return tokens, rows.Err()
}

// GetEnrollmentToken loads one token within scope (with the hostname of the agent that used it)
func (d *DB) GetEnrollmentToken(ctx context.Context, id uuid.UUID, scope Scope) (*EnrollmentToken, error) {
	var t EnrollmentToken
	where, args := scope.SQL("t.labels", []any{id})
	err := d.Pool.QueryRow(ctx, `SELECT `+tokenColumns+` WHERE t.id = $1 AND `+where, args...).
		Scan(&t.ID, &t.TokenHash, &t.Name, &t.MaxUses, &t.UsesCount, &t.ExpiresAt, &t.CreatedAt, &t.AgentID, &t.AgentHostname, &t.Labels)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &t, nil
}

// BindTokenAgent records the agent that enrolled with the token
func (d *DB) BindTokenAgent(ctx context.Context, tokenID, agentID uuid.UUID) error {
	_, err := d.Pool.Exec(ctx, `UPDATE enrollment_tokens SET agent_id = $2 WHERE id = $1`, tokenID, agentID)
	return err
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
		INSERT INTO backup_targets (id, name, target_type, endpoint, datastore, namespace, auth_token_encrypted, fingerprint, tls_verify, pxar_format, created_at, updated_at, encryption_mode, key_ring_id, labels)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		RETURNING id
	`
	target.Labels = target.Labels.OrEmpty()
	if target.PxarFormat == "" {
		target.PxarFormat = PxarFormatV1
	}
	if target.EncryptionMode == "" {
		target.EncryptionMode = EncryptionNone
	}
	return d.Pool.QueryRow(ctx, query,
		target.ID, target.Name, target.TargetType, target.Endpoint, target.Datastore,
		target.Namespace, d.seal(target.AuthToken), target.Fingerprint, target.TLSVerify, target.PxarFormat,
		target.CreatedAt, target.UpdatedAt, target.EncryptionMode, target.KeyRingID, target.Labels.JSON(),
	).Scan(&target.ID)
}

// CloneTarget creates a new target from an existing one: same PBS endpoint,
// datastore, API token (the sealed column is copied as is), fingerprint, TLS setting,
// encryption mode, key ring and labels, and (unless overridden) pxar format, with a
// new name and namespace. Sharing the ring is the point of a clone: another namespace
// of the same datastore deduplicates against the source only with the same key.
func (d *DB) CloneTarget(ctx context.Context, sourceID uuid.UUID, name, namespace, pxarFormat string) (*BackupTarget, error) {
	id := uuid.New()
	now := time.Now().UTC()
	tag, err := d.Pool.Exec(ctx, `
		INSERT INTO backup_targets (id, name, target_type, endpoint, datastore, namespace, auth_token_encrypted, fingerprint, tls_verify, pxar_format, created_at, updated_at, encryption_mode, key_ring_id, labels)
		SELECT $1, $2, target_type, endpoint, datastore, $3, auth_token_encrypted, fingerprint, tls_verify, COALESCE(NULLIF($4::text, ''), pxar_format), $5, $5, encryption_mode, key_ring_id, labels
		FROM backup_targets WHERE id = $6`,
		id, name, namespace, pxarFormat, now, sourceID)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	return d.GetTargetByID(ctx, id, Unscoped)
}

// UpdateTarget replaces a target's editable fields (name, endpoint, datastore,
// namespace, token, fingerprint, TLS, format); the encryption mode and key ring
// change only through SetTargetEncryption. The caller supplies the final values,
// including AuthToken (kept unchanged by loading the existing row first when
// the operator leaves the token field blank).
func (d *DB) UpdateTarget(ctx context.Context, target *BackupTarget) error {
	if target.PxarFormat == "" {
		target.PxarFormat = PxarFormatV1
	}
	target.UpdatedAt = time.Now().UTC()
	tag, err := d.Pool.Exec(ctx, `
		UPDATE backup_targets
		SET name = $2, target_type = $3, endpoint = $4, datastore = $5, namespace = $6,
		    auth_token_encrypted = $7, fingerprint = $8, tls_verify = $9, pxar_format = $10, updated_at = $11, labels = $12
		WHERE id = $1`,
		target.ID, target.Name, target.TargetType, target.Endpoint, target.Datastore, target.Namespace,
		d.seal(target.AuthToken), target.Fingerprint, target.TLSVerify, target.PxarFormat, target.UpdatedAt, target.Labels.JSON())
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// GetTargetByID loads a target within scope (ErrNotFound outside it)
func (d *DB) GetTargetByID(ctx context.Context, id uuid.UUID, scope Scope) (*BackupTarget, error) {
	where, args := scope.SQL("t.labels", []any{id})
	row := d.Pool.QueryRow(ctx, targetSelect+` WHERE t.id = $1 AND `+where, args...)
	t, err := scanTarget(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if t.AuthToken, err = d.open(t.AuthToken); err != nil {
		return nil, fmt.Errorf("target %s: %w", t.Name, err)
	}
	return t.Sanitize(), nil
}

// targetSelect joins the key ring and its active key onto the target
const targetSelect = `
	SELECT t.id, t.name, t.target_type, t.endpoint, t.datastore, t.namespace, t.auth_token_encrypted, t.fingerprint, t.tls_verify, t.pxar_format, t.created_at, t.updated_at,
	       t.encryption_mode, t.key_ring_id, COALESCE(r.name, ''), r.active_key_id, COALESCE(r.master_public_key, ''), COALESCE(k.fingerprint, ''), k.created_at, t.labels
	FROM backup_targets t LEFT JOIN key_rings r ON r.id = t.key_ring_id LEFT JOIN target_keys k ON k.id = r.active_key_id`

func scanTarget(row pgx.Row) (*BackupTarget, error) {
	var t BackupTarget
	err := row.Scan(&t.ID, &t.Name, &t.TargetType, &t.Endpoint, &t.Datastore, &t.Namespace, &t.AuthToken, &t.Fingerprint, &t.TLSVerify, &t.PxarFormat, &t.CreatedAt, &t.UpdatedAt,
		&t.EncryptionMode, &t.KeyRingID, &t.KeyRingName, &t.EncryptionKeyID, &t.MasterPublicKey, &t.KeyFingerprint, &t.KeyCreatedAt, &t.Labels)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// ListTargets lists the targets within scope
func (d *DB) ListTargets(ctx context.Context, scope Scope) ([]*BackupTarget, error) {
	where, args := scope.SQL("t.labels", nil)
	rows, err := d.Pool.Query(ctx, targetSelect+` WHERE `+where+` ORDER BY t.name ASC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var targets []*BackupTarget
	for rows.Next() {
		t, err := scanTarget(rows)
		if err != nil {
			return nil, err
		}
		if t.AuthToken, err = d.open(t.AuthToken); err != nil {
			return nil, fmt.Errorf("target %s: %w", t.Name, err)
		}
		targets = append(targets, t.Sanitize())
	}
	return targets, rows.Err()
}

// ---- Encryption key rings and keys ---------------------------------------------

const ringSelect = `
	SELECT r.id, r.name, r.active_key_id, r.master_public_key, r.created_at, r.updated_at, r.created_by, COALESCE(k.fingerprint, ''), k.created_at,
	       COALESCE((SELECT array_agg(t.name ORDER BY t.name) FROM backup_targets t WHERE t.key_ring_id = r.id), '{}'), r.labels
	FROM key_rings r LEFT JOIN target_keys k ON k.id = r.active_key_id`

func scanRing(row pgx.Row) (*KeyRing, error) {
	var r KeyRing
	if err := row.Scan(&r.ID, &r.Name, &r.ActiveKeyID, &r.MasterPublicKey, &r.CreatedAt, &r.UpdatedAt, &r.CreatedBy, &r.KeyFingerprint, &r.KeyCreatedAt, &r.Targets, &r.Labels); err != nil {
		return nil, err
	}
	if r.Targets == nil {
		r.Targets = []string{}
	}
	return &r, nil
}

// CreateKeyRing stores an empty ring (the caller activates a key next)
func (d *DB) CreateKeyRing(ctx context.Context, r *KeyRing) error {
	if r.ID == uuid.Nil {
		r.ID = uuid.New()
	}
	now := time.Now().UTC()
	r.CreatedAt, r.UpdatedAt = now, now
	r.Labels = r.Labels.OrEmpty()
	_, err := d.Pool.Exec(ctx, `INSERT INTO key_rings (id, name, active_key_id, master_public_key, created_at, updated_at, created_by, labels) VALUES ($1, $2, NULL, $3, $4, $4, $5, $6)`,
		r.ID, r.Name, r.MasterPublicKey, now, r.CreatedBy, r.Labels.JSON())
	return err
}

// GetKeyRing loads a ring within scope (ErrNotFound outside it)
func (d *DB) GetKeyRing(ctx context.Context, id uuid.UUID, scope Scope) (*KeyRing, error) {
	where, args := scope.SQL("r.labels", []any{id})
	r, err := scanRing(d.Pool.QueryRow(ctx, ringSelect+` WHERE r.id = $1 AND `+where, args...))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return r, err
}

// ListKeyRings lists the rings within scope
func (d *DB) ListKeyRings(ctx context.Context, scope Scope) ([]*KeyRing, error) {
	where, args := scope.SQL("r.labels", nil)
	rows, err := d.Pool.Query(ctx, ringSelect+` WHERE `+where+` ORDER BY r.name ASC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*KeyRing{}
	for rows.Next() {
		r, err := scanRing(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// UpdateKeyRing writes a ring's name, master public key and labels
func (d *DB) UpdateKeyRing(ctx context.Context, r *KeyRing) error {
	tag, err := d.Pool.Exec(ctx, `UPDATE key_rings SET name = $2, master_public_key = $3, labels = $4, updated_at = $5 WHERE id = $1`,
		r.ID, r.Name, r.MasterPublicKey, r.Labels.JSON(), time.Now().UTC())
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteKeyRing removes a ring and its keys; refused (ErrInUse) while a target uses it
func (d *DB) DeleteKeyRing(ctx context.Context, id uuid.UUID) error {
	var n int
	if err := d.Pool.QueryRow(ctx, `SELECT count(*) FROM backup_targets WHERE key_ring_id = $1`, id).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return ErrInUse
	}
	tag, err := d.Pool.Exec(ctx, `DELETE FROM key_rings WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetRingActiveKey points the ring at a key (nil: no active key)
func (d *DB) SetRingActiveKey(ctx context.Context, ringID uuid.UUID, keyID *uuid.UUID) error {
	tag, err := d.Pool.Exec(ctx, `UPDATE key_rings SET active_key_id = $2, updated_at = $3 WHERE id = $1`, ringID, keyID, time.Now().UTC())
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// CreateTargetKey stores a key (sealed) on a ring
func (d *DB) CreateTargetKey(ctx context.Context, k *TargetKey) error {
	if k.ID == uuid.Nil {
		k.ID = uuid.New()
	}
	if k.CreatedAt.IsZero() {
		k.CreatedAt = time.Now().UTC()
	}
	_, err := d.Pool.Exec(ctx, `
		INSERT INTO target_keys (id, ring_id, key_sealed, fingerprint, created_at, retired_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		k.ID, k.RingID, d.seal(hex.EncodeToString(k.Key[:])), k.Fingerprint, k.CreatedAt, k.RetiredAt, k.CreatedBy)
	return err
}

// GetTargetKey loads one key with its material
func (d *DB) GetTargetKey(ctx context.Context, id uuid.UUID) (*TargetKey, error) {
	var k TargetKey
	var sealed string
	err := d.Pool.QueryRow(ctx, `SELECT id, ring_id, key_sealed, fingerprint, created_at, retired_at, created_by FROM target_keys WHERE id = $1`, id).
		Scan(&k.ID, &k.RingID, &sealed, &k.Fingerprint, &k.CreatedAt, &k.RetiredAt, &k.CreatedBy)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	hexKey, err := d.open(sealed)
	if err != nil {
		return nil, fmt.Errorf("encryption key %s: %w", k.Fingerprint, err)
	}
	raw, err := hex.DecodeString(hexKey)
	if err != nil || len(raw) != 32 {
		return nil, fmt.Errorf("encryption key %s is corrupt", k.Fingerprint)
	}
	copy(k.Key[:], raw)
	return &k, nil
}

// ListRingKeys lists a ring's keys (newest first) without their material
func (d *DB) ListRingKeys(ctx context.Context, ringID uuid.UUID) ([]*TargetKey, error) {
	rows, err := d.Pool.Query(ctx, `SELECT id, ring_id, fingerprint, created_at, retired_at, created_by FROM target_keys WHERE ring_id = $1 ORDER BY created_at DESC`, ringID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*TargetKey{}
	for rows.Next() {
		var k TargetKey
		if err := rows.Scan(&k.ID, &k.RingID, &k.Fingerprint, &k.CreatedAt, &k.RetiredAt, &k.CreatedBy); err != nil {
			return nil, err
		}
		out = append(out, &k)
	}
	return out, rows.Err()
}

// SetTargetEncryption switches a target's mode and key ring in one statement; mode
// none keeps the ring attached so re-enabling reuses it (and old snapshots keep
// their keys)
func (d *DB) SetTargetEncryption(ctx context.Context, targetID uuid.UUID, mode string, ringID *uuid.UUID) error {
	tag, err := d.Pool.Exec(ctx, `UPDATE backup_targets SET encryption_mode = $2, key_ring_id = $3, updated_at = $4 WHERE id = $1`,
		targetID, mode, ringID, time.Now().UTC())
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// RetireTargetKey marks a key as no longer used for new snapshots
func (d *DB) RetireTargetKey(ctx context.Context, id uuid.UUID) error {
	_, err := d.Pool.Exec(ctx, `UPDATE target_keys SET retired_at = $2 WHERE id = $1 AND retired_at IS NULL`, id, time.Now().UTC())
	return err
}

// CountRunsWithKey counts runs whose snapshot was written with the key
func (d *DB) CountRunsWithKey(ctx context.Context, fingerprint string) (int, error) {
	var n int
	err := d.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM backup_runs WHERE key_fingerprint = $1`, fingerprint).Scan(&n)
	return n, err
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
	cols, err := d.jobTypeColumns(job)
	if err != nil {
		return err
	}

	query := `
		INSERT INTO backup_jobs (id, name, agent_id, target_id, schedule_cron, backup_paths, exclude_paths, enabled, direct_pbs, created_at, updated_at, job_type, db_config, k8s_config, pve_config, docker_config, m365_config, m365_tenant_id, backup_id, labels)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
		RETURNING id
	`
	job.Labels = job.Labels.OrEmpty()
	return d.Pool.QueryRow(ctx, query,
		job.ID, job.Name, job.AgentID, job.TargetID, job.ScheduleCron,
		backupPathsJSON, excludePathsJSON, job.Enabled, job.DirectPBS,
		job.CreatedAt, job.UpdatedAt, cols.jobType, cols.db, cols.k8s, cols.pve, cols.docker, cols.m365, cols.tenantID, job.BackupID, job.Labels.JSON(),
	).Scan(&job.ID)
}

const jobSelect = `
	SELECT j.id, j.name, j.agent_id, j.target_id, j.schedule_cron, j.backup_paths, j.exclude_paths,
	       j.enabled, j.direct_pbs, j.created_at, j.updated_at,
	       j.job_type, j.db_config, j.k8s_config, j.pve_config, j.docker_config, j.m365_config, j.backup_id, j.labels,
	       a.hostname as agent_name, t.name as target_name
	FROM backup_jobs j
	JOIN agents a ON j.agent_id = a.id
	JOIN backup_targets t ON j.target_id = t.id`

func (d *DB) scanJob(row pgx.Row) (*BackupJob, error) {
	var j BackupJob
	var backupPathsRaw, excludePathsRaw, dbConfigRaw, k8sConfigRaw, pveConfigRaw, dockerConfigRaw, m365ConfigRaw []byte
	err := row.Scan(
		&j.ID, &j.Name, &j.AgentID, &j.TargetID, &j.ScheduleCron,
		&backupPathsRaw, &excludePathsRaw,
		&j.Enabled, &j.DirectPBS, &j.CreatedAt, &j.UpdatedAt,
		&j.JobType, &dbConfigRaw, &k8sConfigRaw, &pveConfigRaw, &dockerConfigRaw, &m365ConfigRaw, &j.BackupID, &j.Labels,
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
	if j.DBConfig, err = d.parseDBConfig(dbConfigRaw); err != nil {
		return nil, err
	}
	j.K8sConfig = parseK8sConfig(j.JobType, k8sConfigRaw)
	j.PVEConfig = parsePVEConfig(j.JobType, pveConfigRaw)
	j.DockerConfig = parseDockerConfig(j.JobType, dockerConfigRaw)
	j.M365Config = parseM365Config(j.JobType, m365ConfigRaw)
	return &j, nil
}

// GetJobByID loads a job within scope (ErrNotFound outside it)
func (d *DB) GetJobByID(ctx context.Context, id uuid.UUID, scope Scope) (*BackupJob, error) {
	where, args := scope.SQL("j.labels", []any{id})
	return d.scanJob(d.Pool.QueryRow(ctx, jobSelect+` WHERE j.id = $1 AND `+where, args...))
}

// ListJobs lists the jobs within scope
func (d *DB) ListJobs(ctx context.Context, scope Scope) ([]*BackupJob, error) {
	where, args := scope.SQL("j.labels", nil)
	rows, err := d.Pool.Query(ctx, jobSelect+` WHERE `+where+` ORDER BY j.name ASC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var jobs []*BackupJob
	for rows.Next() {
		j, err := d.scanJob(rows)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, j)
	}
	return jobs, rows.Err()
}

// jobColumns are the type-specific column values of a job row
type jobColumns struct {
	jobType                    string
	db, k8s, pve, docker, m365 []byte
	// tenantID is the m365_tenant_id foreign key (nil for every other type)
	tenantID *uuid.UUID
}

// jobTypeColumns normalises the job type and serialises the configuration of that
// type; the other configuration columns are written as empty objects
func (d *DB) jobTypeColumns(job *BackupJob) (jobColumns, error) {
	jobType, ok := NormalizeJobType(job.JobType)
	if !ok {
		return jobColumns{}, fmt.Errorf("unknown job type %q", job.JobType)
	}
	job.JobType = jobType
	empty := []byte("{}")
	cols := jobColumns{jobType: jobType, db: empty, k8s: empty, pve: empty, docker: empty, m365: empty}
	marshal := func(what string, v any) ([]byte, error) {
		raw, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize %s configuration: %w", what, err)
		}
		return raw, nil
	}
	var err error
	switch {
	case jobType == JobTypeDatabase && job.DBConfig != nil:
		sealed := job.DBConfig.Clone()
		sealed.Password = d.seal(sealed.Password)
		cols.db, err = marshal("database", sealed)
	case jobType == JobTypeKubernetes && job.K8sConfig != nil:
		cols.k8s, err = marshal("kubernetes", job.K8sConfig)
	case jobType == JobTypePVE && job.PVEConfig != nil:
		cols.pve, err = marshal("Proxmox VE", job.PVEConfig)
	case jobType == JobTypeDocker && job.DockerConfig != nil:
		cols.docker, err = marshal("Docker", job.DockerConfig)
	case jobType == JobTypeM365 && job.M365Config != nil:
		cols.m365, err = marshal("Microsoft 365", job.M365Config)
		if job.M365Config.TenantID != uuid.Nil {
			id := job.M365Config.TenantID
			cols.tenantID = &id
		}
	}
	return cols, err
}

// parseM365Config decodes the m365_config column for Microsoft 365 jobs
func parseM365Config(jobType string, raw []byte) *m365.Spec {
	if jobType != JobTypeM365 {
		return nil
	}
	spec := &m365.Spec{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, spec)
	}
	return spec
}

// parseDockerConfig decodes the docker_config column for Docker host jobs
func parseDockerConfig(jobType string, raw []byte) *dockerbackup.Spec {
	if jobType != JobTypeDocker {
		return nil
	}
	spec := &dockerbackup.Spec{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, spec)
	}
	return spec
}

// parsePVEConfig decodes the pve_config column for Proxmox VE jobs
func parsePVEConfig(jobType string, raw []byte) *pvebackup.Spec {
	if jobType != JobTypePVE {
		return nil
	}
	spec := &pvebackup.Spec{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, spec)
	}
	return spec
}

// parseK8sConfig decodes the k8s_config column for kubernetes jobs
func parseK8sConfig(jobType string, raw []byte) *k8sbackup.Spec {
	if jobType != JobTypeKubernetes || len(raw) == 0 {
		return nil
	}
	var spec k8sbackup.Spec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return nil
	}
	return &spec
}

// parseDBConfig decodes the db_config column and opens the sealed password; an empty
// object yields nil
func (d *DB) parseDBConfig(raw []byte) (*dbbackup.Spec, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var spec dbbackup.Spec
	if err := json.Unmarshal(raw, &spec); err != nil || spec.Engine == "" {
		return nil, nil
	}
	var err error
	if spec.Password, err = d.open(spec.Password); err != nil {
		return nil, fmt.Errorf("database job password: %w", err)
	}
	return &spec, nil
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
	details := run.Details
	if len(details) == 0 {
		details = json.RawMessage("{}")
	}
	query := `
		UPDATE backup_runs
		SET status = $1, start_time = $2, end_time = $3, bytes_scanned = $4,
		    bytes_uploaded = $5, dedup_ratio = $6, chunk_count = $7,
		    error_message = $8, pbs_snapshot_id = $9, log_tail = $10, details = $11,
		    key_fingerprint = $13
		WHERE id = $12
	`
	_, err := d.Pool.Exec(ctx, query,
		run.Status, run.StartTime, run.EndTime, run.BytesScanned,
		run.BytesUploaded, run.DedupRatio, run.ChunkCount,
		run.ErrorMessage, run.PBSSnapshotID, run.LogTail, []byte(details), run.ID,
		run.KeyFingerprint,
	)
	return err
}

// LatestRunByJob returns the newest run of every job that has one
func (d *DB) LatestRunByJob(ctx context.Context) (map[uuid.UUID]*JobLastRun, error) {
	rows, err := d.Pool.Query(ctx, `
		SELECT DISTINCT ON (job_id) job_id, id, status, COALESCE(end_time, start_time, created_at)
		FROM backup_runs ORDER BY job_id, created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[uuid.UUID]*JobLastRun{}
	for rows.Next() {
		var jobID uuid.UUID
		var lr JobLastRun
		if err := rows.Scan(&jobID, &lr.RunID, &lr.Status, &lr.At); err != nil {
			return nil, err
		}
		out[jobID] = &lr
	}
	return out, rows.Err()
}

// ListRuns lists the newest runs whose job is within scope. Runs have no labels of
// their own: a run is visible exactly when its job is.
func (d *DB) ListRuns(ctx context.Context, limit int, scope Scope) ([]*BackupRun, error) {
	return d.listRuns(ctx, nil, limit, scope)
}

// ListRunsByAgent is ListRuns restricted to one agent (the agent status page)
func (d *DB) ListRunsByAgent(ctx context.Context, agentID uuid.UUID, limit int, scope Scope) ([]*BackupRun, error) {
	return d.listRuns(ctx, &agentID, limit, scope)
}

func (d *DB) listRuns(ctx context.Context, agentID *uuid.UUID, limit int, scope Scope) ([]*BackupRun, error) {
	if limit <= 0 {
		limit = 50
	}
	where, args := scope.SQL("j.labels", []any{limit, agentID})
	rows, err := d.Pool.Query(ctx, `
		SELECT r.id, r.job_id, r.agent_id, r.target_id, r.workflow_id, r.run_id, r.status,
		       r.start_time, r.end_time, r.bytes_scanned, r.bytes_uploaded, r.dedup_ratio,
		       r.chunk_count, r.error_message, r.pbs_snapshot_id, r.log_tail, r.created_at,
		       j.name as job_name, a.hostname as agent_name
		FROM backup_runs r
		JOIN backup_jobs j ON r.job_id = j.id
		JOIN agents a ON r.agent_id = a.id
		WHERE ($2::uuid IS NULL OR r.agent_id = $2) AND `+where+`
		ORDER BY r.created_at DESC
		LIMIT $1`, args...)
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

// SetAgentInventoryDetail stores the on-demand full inventory
func (d *DB) SetAgentInventoryDetail(ctx context.Context, id uuid.UUID, detail []byte) error {
	tag, err := d.Pool.Exec(ctx, `UPDATE agents SET inventory_detail = $2, inventory_detail_at = NOW(), updated_at = NOW() WHERE id = $1`, id, detail)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// enginesOrEmpty keeps the NOT NULL text[] column happy: a nil slice would be sent as NULL
func enginesOrEmpty(e []string) []string {
	if e == nil {
		return []string{}
	}
	return e
}
