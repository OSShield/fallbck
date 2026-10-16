-- Encryption keys move from the target to a key ring that several targets can share.
-- PBS deduplicates per datastore and an encrypted chunk's digest depends on the key, so
-- targets that should deduplicate against each other (many namespaces of one datastore)
-- have to encrypt with the same key. Every target that had a key or a master public key
-- gets a ring of its own, so nothing changes until an operator attaches targets to one ring.
-- Needs PostgreSQL 13+ (gen_random_uuid).
CREATE TABLE IF NOT EXISTS key_rings (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    active_key_id UUID NULL,
    master_public_key TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_by TEXT NOT NULL DEFAULT '',
    migrated_target_id UUID NULL
);

INSERT INTO key_rings (id, name, active_key_id, master_public_key, created_at, updated_at, migrated_target_id)
SELECT gen_random_uuid(),
       CASE WHEN rn = 1 THEN name ELSE name || ' (' || left(id::text, 8) || ')' END,
       encryption_key_id, master_public_key, created_at, NOW(), id
FROM (
    SELECT t.id, t.name, t.encryption_key_id, t.master_public_key, t.created_at,
           row_number() OVER (PARTITION BY t.name ORDER BY t.created_at, t.id) AS rn
    FROM backup_targets t
    WHERE t.encryption_key_id IS NOT NULL OR t.master_public_key <> ''
       OR EXISTS (SELECT 1 FROM target_keys k WHERE k.target_id = t.id)
) s;

ALTER TABLE target_keys ADD COLUMN IF NOT EXISTS ring_id UUID NULL REFERENCES key_rings(id) ON DELETE CASCADE;
UPDATE target_keys k SET ring_id = r.id FROM key_rings r WHERE r.migrated_target_id = k.target_id;
ALTER TABLE target_keys ALTER COLUMN ring_id SET NOT NULL;
ALTER TABLE target_keys DROP COLUMN target_id;
ALTER TABLE target_keys ADD CONSTRAINT target_keys_ring_fingerprint_key UNIQUE (ring_id, fingerprint);
ALTER TABLE key_rings ADD CONSTRAINT key_rings_active_key_fkey FOREIGN KEY (active_key_id) REFERENCES target_keys(id) ON DELETE SET NULL;

ALTER TABLE backup_targets ADD COLUMN IF NOT EXISTS key_ring_id UUID NULL REFERENCES key_rings(id) ON DELETE RESTRICT;
UPDATE backup_targets t SET key_ring_id = r.id FROM key_rings r WHERE r.migrated_target_id = t.id;
ALTER TABLE backup_targets DROP COLUMN encryption_key_id;
ALTER TABLE backup_targets DROP COLUMN master_public_key;
ALTER TABLE key_rings DROP COLUMN migrated_target_id;
CREATE INDEX IF NOT EXISTS idx_backup_targets_key_ring ON backup_targets(key_ring_id);
