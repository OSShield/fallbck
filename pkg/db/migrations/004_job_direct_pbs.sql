-- 004: per-job choice of transport to PBS (server tunnel vs. agent direct)
ALTER TABLE backup_jobs
    ADD COLUMN IF NOT EXISTS direct_pbs BOOLEAN NOT NULL DEFAULT FALSE;
