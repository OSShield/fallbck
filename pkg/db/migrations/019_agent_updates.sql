-- Agent self-update: auto_update is the per-agent opt-in, self_update the capability
-- the agent reports (Linux, binary writable, not a container), update_requested_at a
-- manual "update now" from the web UI, update_error the agent's last failure
ALTER TABLE agents ADD COLUMN IF NOT EXISTS auto_update BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS self_update BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS update_requested_at TIMESTAMP WITH TIME ZONE NULL;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS update_error TEXT NOT NULL DEFAULT '';
