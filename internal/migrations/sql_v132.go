package migrations

// Migration v132 — enrollment_sessions: the unified self-service onboarding
// primitive.
//
// A session is created from an MFA-verified console session ("Add a device")
// and surfaced to the user as a short code + QR + deep-link. On redemption it
// maps onto the EXISTING single-use agent_enrollment_tokens flow (correlated by
// token_hash), so HandleEnroll → issueAgentCredentials → ensureAgentZitiIdentity
// is unchanged. The session carries the creating user + org + a server-verified
// mfa_verified flag, which drives risk-based device auto-trust at enroll time.
//
// Like agent_enrollment_tokens / enrolled_agents, this is a GLOBAL agent-
// infrastructure table (no RLS): the public /agent/enroll path (which has no
// tenant JWT) looks a session up by its high-entropy token_hash, exactly as it
// already does for agent_enrollment_tokens. Tenant isolation for the
// authenticated status/list reads is enforced in-query by created_by_user_id.
var enrollmentSessionsUp = `-- Migration 132: enrollment_sessions (unified onboarding).
CREATE TABLE IF NOT EXISTS enrollment_sessions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    short_code          TEXT NOT NULL UNIQUE,
    token_hash          TEXT NOT NULL,
    created_by_user_id  UUID NOT NULL,
    org_id              UUID NOT NULL,
    mfa_verified        BOOLEAN NOT NULL DEFAULT false,
    status              TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending','enrolled','expired','canceled')),
    agent_id            TEXT,
    device_id           TEXT,
    known_device_id     UUID,
    trusted             BOOLEAN NOT NULL DEFAULT false,
    expires_at          TIMESTAMPTZ NOT NULL,
    enrolled_at         TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_enrollment_sessions_token_hash ON enrollment_sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_enrollment_sessions_creator ON enrollment_sessions(created_by_user_id);
`

var enrollmentSessionsDown = `-- Rollback migration 132.
DROP TABLE IF EXISTS enrollment_sessions;
`
