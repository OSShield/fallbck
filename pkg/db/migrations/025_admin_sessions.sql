-- Server-side record of every admin browser session. The session cookie carries the
-- row's id; a session is valid only while its row exists, is not revoked and has not
-- expired, so signing out, or an administrator revoking it, ends it on the server.
CREATE TABLE IF NOT EXISTS admin_sessions (
    id UUID PRIMARY KEY,
    subject TEXT NOT NULL,
    email TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL DEFAULT '',
    source_ip TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked_at TIMESTAMP WITH TIME ZONE NULL,
    revoked_by TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_email ON admin_sessions (lower(email)) WHERE revoked_at IS NULL;
