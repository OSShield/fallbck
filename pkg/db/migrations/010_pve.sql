-- Proxmox VE host backup jobs (job_type pve on a filesystem agent) and the agent's
-- self-reported PVE-host flag (from enrollment and heartbeats)
ALTER TABLE backup_jobs ADD COLUMN IF NOT EXISTS pve_config JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS pve_host BOOLEAN NOT NULL DEFAULT false;
