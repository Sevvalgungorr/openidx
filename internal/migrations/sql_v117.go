package migrations

// Migration v117 — moderated privileged sessions (PAM C3).
//
// Teleport-style "moderated sessions": a session flagged require_moderator does
// not start until a second, authorized user (the moderator) joins to watch it
// live — the SOX/PCI four-eyes control for privileged access. This differs from
// require_approval (which is decided BEFORE the session and then consumed):
// moderation is a LIVE presence requirement for the duration of the session.
//
// Two additive changes:
//
//  1. guacamole_connections.require_moderator — per-connection flag. Defaults
//     false so existing connections are unchanged.
//
//  2. guacamole_moderation_sessions — the moderation state machine. When a user
//     connects to a require_moderator connection we insert a 'pending' row; the
//     connect is blocked until a moderator claims it (→ 'active'), after which
//     the session proceeds and the moderator holds a read-only share to watch /
//     terminate. Ends 'ended' on session close or 'expired' if no moderator
//     joins within the wait window.
var moderatedSessionsUp = `-- Migration 117: moderated privileged sessions.

ALTER TABLE guacamole_connections
    ADD COLUMN IF NOT EXISTS require_moderator BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS guacamole_moderation_sessions (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id         UUID NOT NULL,
    connection_id  UUID NOT NULL,
    requester_id   UUID NOT NULL,
    reason         TEXT,
    status         VARCHAR(16) NOT NULL DEFAULT 'pending', -- pending|active|ended|expired|denied
    moderator_id   UUID,
    active_conn_id TEXT,          -- Guacamole active-connection UUID once the session starts
    joined_at      TIMESTAMPTZ,   -- when the moderator claimed it
    ended_at       TIMESTAMPTZ,
    expires_at     TIMESTAMPTZ,   -- wait-window deadline for a moderator to join
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- The requester poll + moderator queue both filter by (connection, status);
-- pending lookups are the hot path.
CREATE INDEX IF NOT EXISTS idx_guac_moderation_pending
    ON guacamole_moderation_sessions (connection_id, status)
    WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS idx_guac_moderation_org_status
    ON guacamole_moderation_sessions (org_id, status);

ALTER TABLE guacamole_moderation_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE guacamole_moderation_sessions FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS guac_moderation_isolation ON guacamole_moderation_sessions;
CREATE POLICY guac_moderation_isolation ON guacamole_moderation_sessions
    USING (
        current_setting('app.bypass_rls', true) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', true) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid
    );
`

var moderatedSessionsDown = `-- Rollback 117: drop moderated sessions.
DROP TABLE IF EXISTS guacamole_moderation_sessions;
ALTER TABLE guacamole_connections DROP COLUMN IF EXISTS require_moderator;
`
