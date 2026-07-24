package migrations

// Migration v105 — PAM checkout controls: break-glass, dual-control, exclusivity.
//
// PAM reveal/connect was single-gated (allow_reveal + a per-entry `reveal`
// grant). Three privileged-access controls that regulators (DORA RTS Art 21,
// ISO 27001 A.8.2) and buyers expect were missing:
//
//   - dual_control_required — a "two-person rule": revealing/checking out the
//     secret needs a SECOND admin to authorize the specific checkout before it
//     proceeds. The authorizer must not be the requester.
//   - exclusive_checkout — only one principal may hold the secret at a time; a
//     concurrent checkout by anyone else is refused until the holder checks in
//     (or the lease expires).
//   - break_glass_enabled — a loudly-audited emergency path that bypasses the
//     dual-control wait and the exclusivity hold, for an outage where the second
//     approver is unreachable. Every use raises a high-severity audit event.
//
// Two ledgers back these:
//   - pam_checkout_authorizations — the dual-control second-person ledger.
//   - pam_active_checkouts        — the live "who holds this secret now" ledger
//     that exclusivity checks and break-glass write.
//
// Both are org-scoped under the v37 FORCE-RLS belt. Additive/idempotent; plain
// statements only (the runner's splitSQL cannot handle DO $$ blocks).
var pamCheckoutControlsUp = `-- Migration 105: PAM checkout controls (break-glass, dual-control, exclusivity).

ALTER TABLE pam_entries ADD COLUMN IF NOT EXISTS dual_control_required BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE pam_entries ADD COLUMN IF NOT EXISTS exclusive_checkout    BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE pam_entries ADD COLUMN IF NOT EXISTS break_glass_enabled   BOOLEAN NOT NULL DEFAULT false;

-- Dual-control second-person ledger. A reveal/checkout on a dual-control entry
-- creates a 'pending' row; a second admin approves it (authorizer_id <> requester_id,
-- enforced in the handler), after which the requester's retry consumes it.
CREATE TABLE IF NOT EXISTS pam_checkout_authorizations (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id            UUID NOT NULL,
    entry_id          UUID NOT NULL REFERENCES pam_entries(id) ON DELETE CASCADE,
    requester_id      UUID NOT NULL,
    action            VARCHAR(16) NOT NULL DEFAULT 'reveal',
    reason            TEXT,
    status            VARCHAR(16) NOT NULL DEFAULT 'pending',
    authorizer_id     UUID,
    authorizer_reason TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    decided_at        TIMESTAMPTZ,
    expires_at        TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '30 minutes')
);
CREATE INDEX IF NOT EXISTS idx_pam_checkout_auth_pending
    ON pam_checkout_authorizations(org_id, entry_id, requester_id, status);

-- Live checkout ledger: an 'active' row means the secret is currently held.
-- exclusivity refuses a new checkout while an active row by a different
-- principal exists; break-glass writes a row with break_glass = true.
CREATE TABLE IF NOT EXISTS pam_active_checkouts (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID NOT NULL,
    entry_id     UUID NOT NULL REFERENCES pam_entries(id) ON DELETE CASCADE,
    principal_id UUID NOT NULL,
    action       VARCHAR(16) NOT NULL DEFAULT 'reveal',
    reason       TEXT,
    break_glass  BOOLEAN NOT NULL DEFAULT false,
    status       VARCHAR(16) NOT NULL DEFAULT 'active',
    leased_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at   TIMESTAMPTZ,
    released_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_pam_active_checkouts_live
    ON pam_active_checkouts(org_id, entry_id, status);
`

var pamCheckoutControlsDown = `-- Rollback 105: drop the checkout-control ledgers and columns.
DROP TABLE IF EXISTS pam_active_checkouts;
DROP TABLE IF EXISTS pam_checkout_authorizations;
ALTER TABLE pam_entries DROP COLUMN IF EXISTS break_glass_enabled;
ALTER TABLE pam_entries DROP COLUMN IF EXISTS exclusive_checkout;
ALTER TABLE pam_entries DROP COLUMN IF EXISTS dual_control_required;
`
