-- Docker host backup jobs (job_type docker on a filesystem agent) and the agent's
-- self-reported Docker-host flag (from enrollment and heartbeats)
ALTER TABLE backup_jobs ADD COLUMN IF NOT EXISTS docker_config JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS docker_host BOOLEAN NOT NULL DEFAULT false;
