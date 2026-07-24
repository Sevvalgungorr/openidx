package migrations

// Migration v106 — detective segregation-of-duties (SoD) violations.
//
// SoD enforcement was purely PREVENTIVE: evaluateSoDPolicy blocks a NEW request
// that would give a user a conflicting role. Nothing scanned the EXISTING state
// for toxic combinations that predate the policy or accumulated out-of-band
// (direct DB grants, imports, membership drift). SOX/ISAE audits and DORA
// access-review duties expect a DETECTIVE control: a periodic sweep that finds
// who currently holds a conflicting combination and tracks each violation to
// closure.
//
// sod_violations is the violation register the sweep upserts into. One row per
// (policy, user) conflicting combination; a re-sweep refreshes last_detected_at
// and reopens a 'resolved' row whose conflict is back, while an 'open'/'ack'
// violation whose conflict is gone is auto-resolved. 'waived' (accepted risk)
// is sticky — the sweep never reopens or auto-resolves it.
//
// Org-scoped under the v37 FORCE-RLS belt. Additive/idempotent; plain statements.
var sodViolationsUp = `-- Migration 106: detective SoD violation register.

CREATE TABLE IF NOT EXISTS sod_violations (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id            UUID NOT NULL,
    policy_id         UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    policy_name       VARCHAR(255),
    user_id           UUID NOT NULL,
    conflicting_roles TEXT[] NOT NULL DEFAULT '{}',
    status            VARCHAR(16) NOT NULL DEFAULT 'open',
    detail            TEXT,
    first_detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_detected_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at       TIMESTAMPTZ,
    resolved_by       UUID,
    notes             TEXT,
    UNIQUE (org_id, policy_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_sod_violations_open
    ON sod_violations(org_id, status);
CREATE INDEX IF NOT EXISTS idx_sod_violations_user
    ON sod_violations(org_id, user_id);
`

var sodViolationsDown = `-- Rollback 106: drop the detective SoD violation register.
DROP TABLE IF EXISTS sod_violations;
`
