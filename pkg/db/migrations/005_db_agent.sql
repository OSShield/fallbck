-- Agent types and database backup jobs
ALTER TABLE agents ADD COLUMN IF NOT EXISTS agent_type VARCHAR(32) NOT NULL DEFAULT 'filesystem';
ALTER TABLE backup_jobs ADD COLUMN IF NOT EXISTS job_type VARCHAR(32) NOT NULL DEFAULT 'filesystem';
ALTER TABLE backup_jobs ADD COLUMN IF NOT EXISTS db_config JSONB NOT NULL DEFAULT '{}'::jsonb;
