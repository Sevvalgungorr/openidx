package migrations

// Migration v122 — refresh-token reuse detection (RFC 6819 §5.2.2.3 / OAuth 2.1 §6.1).
//
// Rotation already worked: the refresh grant issues a new refresh token and
// invalidates the old one. But it invalidated by hard DELETE, which throws away
// the only evidence that matters. After a DELETE a replayed token is simply
// absent, indistinguishable from a typo or an expired token — and, critically,
// whoever holds the *newest* token keeps working. So in the theft case the
// server sees one `invalid_grant`, shrugs, and the attacker (or the victim,
// whichever refreshed second) carries on with a valid session. Nothing is
// revoked and nothing is recorded.
//
// Reuse detection needs two facts the old schema could not express:
//
//   - family_id groups every token descended from one authorization. Rotation
//     carries it forward, so revoking a family kills the whole chain no matter
//     how many times it has rotated.
//   - used_at tombstones a rotated token instead of deleting it. A presented
//     token that exists but is already used is proof that two parties hold the
//     same secret: exactly one of them is legitimate and the server cannot tell
//     which, so per the RFC both lose — the family is revoked and the user
//     re-authenticates.
//
// Both columns are nullable and backfilled, so tokens issued before this
// migration keep working: a NULL family_id simply means "a family of one", and
// a NULL used_at means "not yet rotated", which is the pre-migration behavior.
//
// The partial index is on (family_id) WHERE family_id IS NOT NULL because
// family revocation is the only query that touches it and it must be fast on
// the security path. Tombstones are cleaned up by the existing expiry sweep —
// they carry the original expires_at, so they age out on their own rather than
// growing without bound.

var refreshTokenReuseUp = `-- Migration 122: refresh-token reuse detection.
ALTER TABLE oauth_refresh_tokens ADD COLUMN IF NOT EXISTS family_id UUID;
ALTER TABLE oauth_refresh_tokens ADD COLUMN IF NOT EXISTS used_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE oauth_refresh_tokens ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMP WITH TIME ZONE;

-- Existing tokens become single-member families so they rotate normally from
-- here on rather than being treated as replays.
UPDATE oauth_refresh_tokens SET family_id = gen_random_uuid() WHERE family_id IS NULL;

CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_family
    ON oauth_refresh_tokens (family_id) WHERE family_id IS NOT NULL;

-- Reuse detection reads by token and then revokes by family; both are hot on
-- the security path.
CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_expires_at
    ON oauth_refresh_tokens (expires_at);`

var refreshTokenReuseDown = `-- Rollback 122.
DROP INDEX IF EXISTS idx_oauth_refresh_tokens_expires_at;
DROP INDEX IF EXISTS idx_oauth_refresh_tokens_family;
ALTER TABLE oauth_refresh_tokens DROP COLUMN IF EXISTS revoked_at;
ALTER TABLE oauth_refresh_tokens DROP COLUMN IF EXISTS used_at;
ALTER TABLE oauth_refresh_tokens DROP COLUMN IF EXISTS family_id;`
