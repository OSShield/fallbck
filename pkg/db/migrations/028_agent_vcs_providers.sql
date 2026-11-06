-- Filesystem agents report the VCS providers they can list projects of. Agents that
-- predate the list report nothing and only run git-provider jobs.
ALTER TABLE agents ADD COLUMN IF NOT EXISTS vcs_providers TEXT[] NOT NULL DEFAULT '{}';
