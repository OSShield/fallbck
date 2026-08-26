-- 003: pxar archive format per backup target
ALTER TABLE backup_targets
    ADD COLUMN IF NOT EXISTS pxar_format VARCHAR(8) NOT NULL DEFAULT 'v1';
