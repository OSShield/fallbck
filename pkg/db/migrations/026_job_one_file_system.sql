-- Filesystem jobs can stay on the filesystem of each backup path and leave other
-- mounts out, like proxmox-backup-client without --all-file-systems. Off for existing
-- jobs, so their snapshots keep the same contents.
ALTER TABLE backup_jobs ADD COLUMN IF NOT EXISTS one_file_system BOOLEAN NOT NULL DEFAULT FALSE;
