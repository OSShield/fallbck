-- Live per-run progress (phase + per-item statuses) polled by the run detail page
ALTER TABLE backup_runs ADD COLUMN IF NOT EXISTS progress JSONB NOT NULL DEFAULT '{}'::jsonb;
