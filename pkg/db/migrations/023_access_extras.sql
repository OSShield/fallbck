-- Set-based selectors: bindings and API keys store the canonical string form
-- ("env in (prod, stage), team=web") instead of a label object. Existing equality
-- selectors become key=value pairs sorted by key in byte order, which is the form the
-- server prints, so uniqueness keeps working.
CREATE FUNCTION pg_temp.fallbck_selector(j jsonb) RETURNS text LANGUAGE sql IMMUTABLE AS $$
    SELECT coalesce(string_agg(key || '=' || value, ', ' ORDER BY key COLLATE "C"), '') FROM jsonb_each_text(j)
$$;

ALTER TABLE role_bindings
    ALTER COLUMN selector DROP DEFAULT,
    ALTER COLUMN selector TYPE TEXT USING pg_temp.fallbck_selector(selector),
    ALTER COLUMN selector SET DEFAULT '';
ALTER TABLE api_keys
    ALTER COLUMN selector DROP DEFAULT,
    ALTER COLUMN selector TYPE TEXT USING pg_temp.fallbck_selector(selector),
    ALTER COLUMN selector SET DEFAULT '';

-- claim bindings: subject is "<claim>=<value>", e.g. roles=Backup.Admin
ALTER TABLE role_bindings DROP CONSTRAINT role_bindings_kind_check;
ALTER TABLE role_bindings ADD CONSTRAINT role_bindings_kind_check CHECK (kind IN ('user', 'group', 'claim'));

-- What sign-ins have shown: verified emails (lowercased), group names and claim values,
-- with when they were last seen. Feeds the Access page suggestions and stale-binding flags.
CREATE TABLE IF NOT EXISTS idp_subjects (
    kind TEXT NOT NULL CHECK (kind IN ('user', 'group', 'claim')),
    value TEXT NOT NULL,
    last_seen TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    PRIMARY KEY (kind, value)
);

-- Retention: DELETE is allowed only inside a transaction that set fallbck.audit_prune
-- (the server's prune, after exporting the rows). UPDATE stays refused.
CREATE OR REPLACE FUNCTION audit_log_append_only() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' AND current_setting('fallbck.audit_prune', true) = 'on' THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'audit_log is append-only';
END;
$$ LANGUAGE plpgsql;
