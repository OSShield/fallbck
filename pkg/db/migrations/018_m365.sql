-- Microsoft 365 tenants (Entra app registrations FallBCK reads a tenant with) and the
-- m365 job type. The client secret and the certificate's private key are sealed with
-- the server master key; a tenant cannot be deleted while jobs reference it.
CREATE TABLE IF NOT EXISTS m365_tenants (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    tenant_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    auth_method TEXT NOT NULL DEFAULT 'secret',
    secret_sealed TEXT NOT NULL DEFAULT '',
    certificate_pem TEXT NOT NULL DEFAULT '',
    key_sealed TEXT NOT NULL DEFAULT '',
    secret_expires TIMESTAMP WITH TIME ZONE NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL
);
ALTER TABLE backup_jobs ADD COLUMN IF NOT EXISTS m365_config JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE backup_jobs ADD COLUMN IF NOT EXISTS m365_tenant_id UUID NULL REFERENCES m365_tenants(id) ON DELETE RESTRICT;
