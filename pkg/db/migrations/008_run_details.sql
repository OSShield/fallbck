-- Per-run detailed results (type-specific: archives / databases / PVCs) for the run detail page
ALTER TABLE backup_runs ADD COLUMN IF NOT EXISTS details JSONB NOT NULL DEFAULT '{}'::jsonb;
