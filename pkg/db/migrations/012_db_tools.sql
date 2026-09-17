-- Combined agent: a filesystem agent that finds database client tools on its host
-- reports db_tools and may run database jobs (enrollment and heartbeats)
ALTER TABLE agents ADD COLUMN IF NOT EXISTS db_tools BOOLEAN NOT NULL DEFAULT false;
