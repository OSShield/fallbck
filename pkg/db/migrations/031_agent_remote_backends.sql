-- Filesystem agents report the remote backends (rclone) they can back up. Agents
-- that predate remote jobs report none and can't run them.
ALTER TABLE agents ADD COLUMN IF NOT EXISTS remote_backends TEXT[] NOT NULL DEFAULT '{}';
