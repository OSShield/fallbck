-- Result of the periodic check of each target's PBS API token against
-- GET /access/permissions (status, findings, checked_at). NULL: not checked yet.
ALTER TABLE backup_targets ADD COLUMN IF NOT EXISTS token_check JSONB NULL;
