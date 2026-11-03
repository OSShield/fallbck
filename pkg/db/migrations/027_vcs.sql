-- VCS connections (a GitLab instance or a git host with the token FallBCK reads it
-- with) and the vcs job type. The token is sealed with the server master key; a
-- connection cannot be deleted while jobs reference it.
CREATE TABLE IF NOT EXISTS vcs_connections (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    provider TEXT NOT NULL,
    base_url TEXT NOT NULL,
    token_sealed TEXT NOT NULL DEFAULT '',
    token_expires TIMESTAMP WITH TIME ZONE NULL,
    ca_pem TEXT NOT NULL DEFAULT '',
    labels JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_vcs_connections_labels ON vcs_connections USING GIN (labels jsonb_path_ops);
ALTER TABLE backup_jobs ADD COLUMN IF NOT EXISTS vcs_config JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE backup_jobs ADD COLUMN IF NOT EXISTS vcs_connection_id UUID NULL REFERENCES vcs_connections(id) ON DELETE RESTRICT;

-- Filesystem agents report the git they found (VCS jobs need 2.31 or newer) and
-- whether git-lfs is installed
ALTER TABLE agents ADD COLUMN IF NOT EXISTS git_version TEXT NOT NULL DEFAULT '';
ALTER TABLE agents ADD COLUMN IF NOT EXISTS git_lfs BOOLEAN NOT NULL DEFAULT false;
