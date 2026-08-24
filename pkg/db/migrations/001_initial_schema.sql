-- 001_initial_schema.sql
-- FallBCK Initial Database Schema

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Agents Table
CREATE TABLE IF NOT EXISTS agents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    hostname VARCHAR(255) NOT NULL,
    ip_address VARCHAR(64) NOT NULL DEFAULT '',
    os VARCHAR(64) NOT NULL DEFAULT '',
    arch VARCHAR(64) NOT NULL DEFAULT '',
    version VARCHAR(64) NOT NULL DEFAULT '',
    task_queue VARCHAR(255) NOT NULL UNIQUE,
    status VARCHAR(32) NOT NULL DEFAULT 'offline', -- 'online', 'offline', 'busy', 'error'
    last_seen_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Enrollment Tokens for Agent Onboarding
CREATE TABLE IF NOT EXISTS enrollment_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    max_uses INT NOT NULL DEFAULT 1,
    uses_count INT NOT NULL DEFAULT 0,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Backup Targets (Proxmox Backup Server, etc.)
CREATE TABLE IF NOT EXISTS backup_targets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    target_type VARCHAR(64) NOT NULL DEFAULT 'pbs', -- 'pbs', 's3', etc.
    endpoint VARCHAR(512) NOT NULL,                 -- e.g. https://pbs.example.com:8007
    datastore VARCHAR(255) NOT NULL,                -- e.g. datastore1
    namespace VARCHAR(255) NOT NULL DEFAULT '',
    auth_token_encrypted TEXT NOT NULL,             -- PBS API Token (PBSAPIToken=user@pbs!token=...)
    fingerprint VARCHAR(255) NOT NULL DEFAULT '',   -- SHA256 TLS cert fingerprint
    tls_verify BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Backup Jobs
CREATE TABLE IF NOT EXISTS backup_jobs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    target_id UUID NOT NULL REFERENCES backup_targets(id) ON DELETE RESTRICT,
    schedule_cron VARCHAR(128) NOT NULL DEFAULT '', -- Cron expression, empty if manual
    backup_paths JSONB NOT NULL DEFAULT '[]'::jsonb, -- e.g. ["/var/data", "/home"]
    exclude_paths JSONB NOT NULL DEFAULT '[]'::jsonb,
    retention_policy JSONB NOT NULL DEFAULT '{"keep_last": 7, "keep_daily": 7, "keep_weekly": 4, "keep_monthly": 12}'::jsonb,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Backup Runs / History
CREATE TABLE IF NOT EXISTS backup_runs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    job_id UUID NOT NULL REFERENCES backup_jobs(id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    target_id UUID NOT NULL REFERENCES backup_targets(id) ON DELETE CASCADE,
    workflow_id VARCHAR(255) NOT NULL,
    run_id VARCHAR(255) NOT NULL DEFAULT '',
    status VARCHAR(32) NOT NULL DEFAULT 'pending', -- 'pending', 'running', 'completed', 'failed', 'cancelled'
    start_time TIMESTAMP WITH TIME ZONE,
    end_time TIMESTAMP WITH TIME ZONE,
    bytes_scanned BIGINT NOT NULL DEFAULT 0,
    bytes_uploaded BIGINT NOT NULL DEFAULT 0,
    dedup_ratio NUMERIC(5,2) NOT NULL DEFAULT 1.00,
    chunk_count INT NOT NULL DEFAULT 0,
    error_message TEXT NOT NULL DEFAULT '',
    pbs_snapshot_id VARCHAR(255) NOT NULL DEFAULT '', -- e.g. host/agent-123/2026-08-24T14:00:00Z
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Indices for performance
CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status);
CREATE INDEX IF NOT EXISTS idx_backup_jobs_agent_id ON backup_jobs(agent_id);
CREATE INDEX IF NOT EXISTS idx_backup_runs_job_id ON backup_runs(job_id);
CREATE INDEX IF NOT EXISTS idx_backup_runs_status ON backup_runs(status);
CREATE INDEX IF NOT EXISTS idx_backup_runs_created_at ON backup_runs(created_at DESC);
