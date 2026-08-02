package migrations

// Migration v123 — throttling for TOTP verification.
//
// VerifyTOTP had no attempt limit of any kind. A TOTP code is six digits, so
// the whole keyspace is a million values, and the live verifier accepts a ±1
// step skew — three codes valid at any moment, roughly 3 in 10^6 per guess. An
// attacker who can call the verify endpoint without bound expects a hit in the
// low hundreds of thousands of requests, which is minutes of traffic. The
// second factor is only a factor if guessing it is expensive.
//
// Throttling state lives here rather than in Redis on purpose. Redis in this
// deployment is optional and treated as a cache: `s.redis` is nil-checked
// throughout the identity service, and the counter in internal/mfa (which this
// replaces) simply stopped counting when Redis was unavailable. A brute-force
// control that silently disappears during an outage is not a control — an
// attacker who can cause or wait out a Redis blip gets unlimited attempts back.
// Postgres is mandatory for this service, so the counter is durable and shares
// the transactional guarantees the credential itself already relies on.
//
// The columns mirror the account-lockout fields on `users` (failed_login_count,
// last_failed_login_at, locked_until) deliberately: same shape, same semantics,
// same atomic-increment-in-SQL treatment, so there is one lockout pattern in
// this codebase rather than two that drift.
//
// Additive and defaulted, so rows written before this migration behave as
// "no failures yet" and keep verifying.

const totpThrottleUp = `
ALTER TABLE mfa_totp ADD COLUMN IF NOT EXISTS failed_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE mfa_totp ADD COLUMN IF NOT EXISTS last_failed_at  TIMESTAMP WITH TIME ZONE;
ALTER TABLE mfa_totp ADD COLUMN IF NOT EXISTS locked_until    TIMESTAMP WITH TIME ZONE;

-- Only locked rows are ever scanned by the lockout check, and they are a tiny
-- minority, so the index is partial.
CREATE INDEX IF NOT EXISTS idx_mfa_totp_locked_until
    ON mfa_totp (locked_until)
    WHERE locked_until IS NOT NULL;
`

const totpThrottleDown = `
DROP INDEX IF EXISTS idx_mfa_totp_locked_until;
ALTER TABLE mfa_totp DROP COLUMN IF EXISTS locked_until;
ALTER TABLE mfa_totp DROP COLUMN IF EXISTS last_failed_at;
ALTER TABLE mfa_totp DROP COLUMN IF EXISTS failed_attempts;
`
