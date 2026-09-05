-- Kubernetes backup jobs
ALTER TABLE backup_jobs ADD COLUMN IF NOT EXISTS k8s_config JSONB NOT NULL DEFAULT '{}'::jsonb;
