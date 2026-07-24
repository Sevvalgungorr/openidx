package migrations

// Migration v110 — Ziti AI network intelligence (behavioral baselines + anomaly ledger).
//
// The AI layer over the Ziti overlay: learn how each Ziti identity normally
// uses the network, flag deviations, and support an admin quarantine response.
//
//   - ziti_identity_activity  the learned behavioral baseline: one row per
//     (identity, service) pair with a cumulative session count, an hour-of-day
//     histogram, and first/last-seen stamps. service_id = ” rows track overlay
//     logins (api-sessions) rather than service dials.
//   - ziti_ai_anomalies       the detection ledger: every deviation from
//     baseline (new service access, off-hours activity, dormant identity
//     reactivation, session spike) tracked open → acknowledged/resolved.
//   - ziti_ai_quarantine      pre-quarantine role attributes, saved so an
//     unquarantine can restore the identity exactly as it was.
//
// Ziti identities are controller-scoped (not org rows), matching the other
// ziti_* tables. Additive/idempotent; plain statements.
var zitiAIInsightsUp = `-- Migration 110: Ziti AI network intelligence.

CREATE TABLE IF NOT EXISTS ziti_identity_activity (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id    VARCHAR(255) NOT NULL,
    identity_name  VARCHAR(255),
    service_id     VARCHAR(255) NOT NULL DEFAULT '',
    service_name   VARCHAR(255),
    session_count  BIGINT NOT NULL DEFAULT 0,
    hour_histogram JSONB NOT NULL DEFAULT '{}',
    first_seen     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (identity_id, service_id)
);
CREATE INDEX IF NOT EXISTS idx_ziti_activity_identity ON ziti_identity_activity(identity_id);

CREATE TABLE IF NOT EXISTS ziti_ai_anomalies (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id   VARCHAR(255) NOT NULL,
    identity_name VARCHAR(255),
    anomaly_type  VARCHAR(64) NOT NULL,
    severity      VARCHAR(16) NOT NULL DEFAULT 'medium',
    score         DOUBLE PRECISION NOT NULL DEFAULT 0,
    details       JSONB NOT NULL DEFAULT '{}',
    status        VARCHAR(16) NOT NULL DEFAULT 'open',
    detected_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_ziti_ai_anomalies_status ON ziti_ai_anomalies(status, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_ziti_ai_anomalies_identity ON ziti_ai_anomalies(identity_id);

CREATE TABLE IF NOT EXISTS ziti_ai_quarantine (
    identity_id      VARCHAR(255) PRIMARY KEY,
    identity_name    VARCHAR(255),
    saved_attributes JSONB NOT NULL DEFAULT '[]',
    reason           TEXT,
    quarantined_by   VARCHAR(255),
    quarantined_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
`

var zitiAIInsightsDown = `-- Rollback 110: drop the Ziti AI intelligence tables.
DROP TABLE IF EXISTS ziti_ai_quarantine;
DROP TABLE IF EXISTS ziti_ai_anomalies;
DROP TABLE IF EXISTS ziti_identity_activity;
`
