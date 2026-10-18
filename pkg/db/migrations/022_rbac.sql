-- Role-based access control. Roles are named permission sets; bindings grant a role to
-- a user (verified OIDC email) or group (groups claim value) on a label selector.
-- Built-in roles get their permissions from the server at every start (pkg/auth/perms.go);
-- the rows are created here so api_keys.role can reference them.
CREATE TABLE IF NOT EXISTS roles (
    name TEXT PRIMARY KEY,
    builtin BOOLEAN NOT NULL DEFAULT FALSE,
    description TEXT NOT NULL DEFAULT '',
    permissions TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
INSERT INTO roles (name, builtin) VALUES ('admin', TRUE), ('operator', TRUE), ('viewer', TRUE)
ON CONFLICT (name) DO NOTHING;

CREATE TABLE IF NOT EXISTS role_bindings (
    id UUID PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('user', 'group')),
    subject TEXT NOT NULL,
    role TEXT NOT NULL REFERENCES roles(name) ON DELETE RESTRICT ON UPDATE CASCADE,
    selector JSONB NOT NULL DEFAULT '{}',
    created_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE (kind, subject, role, selector)
);
CREATE INDEX IF NOT EXISTS idx_role_bindings_subject ON role_bindings (kind, lower(subject));

ALTER TABLE agents ADD COLUMN IF NOT EXISTS labels JSONB NOT NULL DEFAULT '{}';
ALTER TABLE backup_targets ADD COLUMN IF NOT EXISTS labels JSONB NOT NULL DEFAULT '{}';
ALTER TABLE backup_jobs ADD COLUMN IF NOT EXISTS labels JSONB NOT NULL DEFAULT '{}';
ALTER TABLE m365_tenants ADD COLUMN IF NOT EXISTS labels JSONB NOT NULL DEFAULT '{}';
ALTER TABLE key_rings ADD COLUMN IF NOT EXISTS labels JSONB NOT NULL DEFAULT '{}';
ALTER TABLE enrollment_tokens ADD COLUMN IF NOT EXISTS labels JSONB NOT NULL DEFAULT '{}';
CREATE INDEX IF NOT EXISTS idx_agents_labels ON agents USING GIN (labels jsonb_path_ops);
CREATE INDEX IF NOT EXISTS idx_backup_targets_labels ON backup_targets USING GIN (labels jsonb_path_ops);
CREATE INDEX IF NOT EXISTS idx_backup_jobs_labels ON backup_jobs USING GIN (labels jsonb_path_ops);
CREATE INDEX IF NOT EXISTS idx_m365_tenants_labels ON m365_tenants USING GIN (labels jsonb_path_ops);
CREATE INDEX IF NOT EXISTS idx_key_rings_labels ON key_rings USING GIN (labels jsonb_path_ops);
CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_labels ON enrollment_tokens USING GIN (labels jsonb_path_ops);

-- Existing keys keep full access: admin on everything
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'admin' REFERENCES roles(name) ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS selector JSONB NOT NULL DEFAULT '{}';

-- Append-only: a trigger refuses UPDATE and DELETE for every role, the table owner
-- included. Prune by hand with ALTER TABLE audit_log DISABLE TRIGGER audit_log_append_only.
CREATE TABLE IF NOT EXISTS audit_log (
    id BIGSERIAL PRIMARY KEY,
    at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    actor_kind TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_kind TEXT NOT NULL DEFAULT '',
    resource_id TEXT NOT NULL DEFAULT '',
    resource_name TEXT NOT NULL DEFAULT '',
    labels JSONB NOT NULL DEFAULT '{}',
    source_ip TEXT NOT NULL DEFAULT '',
    details JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_audit_log_at ON audit_log (at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_labels ON audit_log USING GIN (labels jsonb_path_ops);

CREATE OR REPLACE FUNCTION audit_log_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only';
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS audit_log_append_only ON audit_log;
CREATE TRIGGER audit_log_append_only BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_append_only();
