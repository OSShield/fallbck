-- Remotes (S3, Azure Blob, SFTP, SMB and WebDAV storage FallBCK backs up through
-- rclone) and the remote job type. config holds the backend's settings; the
-- credential is one JSON document sealed with the server master key ('' when the
-- remote keeps it on the agents). A remote cannot be deleted while jobs reference it.
CREATE TABLE IF NOT EXISTS remotes (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    backend TEXT NOT NULL,
    auth_method TEXT NOT NULL DEFAULT 'stored',
    config JSONB NOT NULL DEFAULT '{}',
    secrets_sealed TEXT NOT NULL DEFAULT '',
    labels JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_remotes_labels ON remotes USING GIN (labels jsonb_path_ops);
ALTER TABLE backup_jobs ADD COLUMN IF NOT EXISTS remote_config JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE backup_jobs ADD COLUMN IF NOT EXISTS remote_id UUID NULL REFERENCES remotes(id) ON DELETE RESTRICT;
