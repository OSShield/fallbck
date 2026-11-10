-- VCS connections can authenticate as a GitHub App installation instead of with a
-- token: the server mints short-lived installation tokens with the App's private key,
-- sealed like the token. Existing connections keep authenticating with their token.
ALTER TABLE vcs_connections ADD COLUMN IF NOT EXISTS auth_type TEXT NOT NULL DEFAULT 'token';
ALTER TABLE vcs_connections ADD COLUMN IF NOT EXISTS app_id BIGINT NOT NULL DEFAULT 0;
ALTER TABLE vcs_connections ADD COLUMN IF NOT EXISTS installation_id BIGINT NOT NULL DEFAULT 0;
ALTER TABLE vcs_connections ADD COLUMN IF NOT EXISTS app_key_sealed TEXT NOT NULL DEFAULT '';
