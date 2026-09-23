-- Agent inventory: the compact summary an agent attaches to a heartbeat every few
-- minutes (profiles, tools, spool space, resource counts), and the full detail the
-- status page fetches on demand
ALTER TABLE agents ADD COLUMN IF NOT EXISTS inventory JSONB NULL;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS inventory_at TIMESTAMP WITH TIME ZONE NULL;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS inventory_detail JSONB NULL;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS inventory_detail_at TIMESTAMP WITH TIME ZONE NULL;
