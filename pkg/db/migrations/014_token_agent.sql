-- Onboarding: remember which agent consumed an enrollment token, so the guided
-- installation can wait for exactly that agent (and the Tokens page can show it)
ALTER TABLE enrollment_tokens ADD COLUMN IF NOT EXISTS agent_id UUID NULL REFERENCES agents(id) ON DELETE SET NULL;
