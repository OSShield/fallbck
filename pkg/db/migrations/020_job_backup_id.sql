-- Per-job PBS backup group, chosen by the server instead of derived from the hostname
-- the agent reports. Backfilled with the rule earlier versions applied at run time
-- (agent hostname, plus -docker / -pve) so existing snapshot chains carry on.
-- Database and Microsoft 365 jobs keep the backup_id inside their own config.
ALTER TABLE backup_jobs ADD COLUMN IF NOT EXISTS backup_id TEXT NOT NULL DEFAULT '';
UPDATE backup_jobs j
SET backup_id = a.hostname || CASE j.job_type WHEN 'docker' THEN '-docker' WHEN 'pve' THEN '-pve' ELSE '' END
FROM agents a
WHERE a.id = j.agent_id AND j.backup_id = '' AND j.job_type IN ('filesystem', 'docker', 'pve', 'kubernetes');
