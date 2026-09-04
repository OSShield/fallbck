-- Remote debug-logging toggle per agent, and the agent log tail on failed runs
ALTER TABLE agents ADD COLUMN IF NOT EXISTS debug_logging BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE backup_runs ADD COLUMN IF NOT EXISTS log_tail TEXT NOT NULL DEFAULT '';
