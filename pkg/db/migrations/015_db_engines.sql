-- Which database engines an agent can back up: postgres / mysql / mongodb when their
-- client tools are installed, mssql always (built-in driver). Replaces the yes/no
-- db_tools as the gate for database jobs; db_tools stays as "any engine".
ALTER TABLE agents ADD COLUMN IF NOT EXISTS db_engines TEXT[] NOT NULL DEFAULT '{}';
