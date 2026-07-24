package migrations

// Migration v107 — privileged-account discovery register.
//
// A PAM/IGA program has to answer "which accounts are privileged, and which of
// those are actually managed?" before it can protect anything. OpenIDX knew
// about roles and groups but never swept the identity store to surface the
// privileged population: standing (non-expiring) admin grants, privileged group
// membership, service/shared-account naming patterns, and dormant privileged
// accounts (the classic audit finding). This is the discovery substrate that
// feeds onboarding into PAM/JIT.
//
// privileged_accounts_discovered is the register a periodic scan reconciles. One
// row per (org, user); the scan refreshes last_seen_at and auto-resolves a
// previously-flagged account that is no longer privileged. 'onboarded' (brought
// under management) and 'ignored' (accepted) are sticky.
//
// Org-scoped under the v37 FORCE-RLS belt. Additive/idempotent; plain statements.
var privilegedAccountsUp = `-- Migration 107: privileged-account discovery register.

CREATE TABLE IF NOT EXISTS privileged_accounts_discovered (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id             UUID NOT NULL,
    user_id            UUID NOT NULL,
    username           VARCHAR(255),
    email              VARCHAR(255),
    privilege_sources  TEXT[] NOT NULL DEFAULT '{}',
    standing_privilege BOOLEAN NOT NULL DEFAULT false,
    is_service_account BOOLEAN NOT NULL DEFAULT false,
    dormant            BOOLEAN NOT NULL DEFAULT false,
    last_login_at      TIMESTAMPTZ,
    status             VARCHAR(24) NOT NULL DEFAULT 'new',
    notes              TEXT,
    first_seen_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_priv_accounts_status
    ON privileged_accounts_discovered(org_id, status);
`

var privilegedAccountsDown = `-- Rollback 107: drop the privileged-account discovery register.
DROP TABLE IF EXISTS privileged_accounts_discovered;
`
