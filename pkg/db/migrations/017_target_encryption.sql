-- Per-target client-side encryption: the key(s) of a target, sealed with the server
-- master key; rotation retires a key but keeps it (old snapshots need it). The run
-- records which key wrote its snapshot.
CREATE TABLE IF NOT EXISTS target_keys (
    id UUID PRIMARY KEY,
    target_id UUID NOT NULL REFERENCES backup_targets(id) ON DELETE CASCADE,
    key_sealed TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    retired_at TIMESTAMP WITH TIME ZONE NULL,
    created_by TEXT NOT NULL DEFAULT '',
    UNIQUE (target_id, fingerprint)
);
ALTER TABLE backup_targets ADD COLUMN IF NOT EXISTS encryption_mode TEXT NOT NULL DEFAULT 'none';
ALTER TABLE backup_targets ADD COLUMN IF NOT EXISTS encryption_key_id UUID NULL REFERENCES target_keys(id) ON DELETE SET NULL;
ALTER TABLE backup_targets ADD COLUMN IF NOT EXISTS master_public_key TEXT NOT NULL DEFAULT '';
ALTER TABLE backup_runs ADD COLUMN IF NOT EXISTS key_fingerprint TEXT NOT NULL DEFAULT '';
