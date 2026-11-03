-- GitHub accounts (tokens FallBCK lists and mirrors repositories with) and the github
-- job type. The token is sealed with the server master key; an account cannot be
-- deleted while jobs reference it.
CREATE TABLE IF NOT EXISTS github_accounts (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    api_url TEXT NOT NULL DEFAULT 'https://api.github.com',
    token_sealed TEXT NOT NULL DEFAULT '',
    token_expires TIMESTAMP WITH TIME ZONE NULL,
    labels JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_github_accounts_labels ON github_accounts USING GIN (labels jsonb_path_ops);
ALTER TABLE backup_jobs ADD COLUMN IF NOT EXISTS github_config JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE backup_jobs ADD COLUMN IF NOT EXISTS github_account_id UUID NULL REFERENCES github_accounts(id) ON DELETE RESTRICT;
