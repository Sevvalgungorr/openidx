package migrations

// Migration v114 — audit_webhook_subscriptions.
//
// internal/audit (the event-streamer's outbound webhooks, route
// /api/v1/audit/webhooks) and internal/webhooks (the admin webhook feature)
// both used a table literally named webhook_subscriptions, but with
// incompatible schemas. The admin webhooks migration (sql.go) won and created
// the table as (name, url, secret, events, status, created_by, ...). The audit
// streamer expected a different shape entirely — enabled (bool), filters
// (jsonb), last_delivery, failure_count — so every audit-webhook query failed
// at runtime with SQLSTATE 42703 and audit webhooks never worked.
//
// Rather than force the two features onto one schema, give the audit streamer
// its own table. This migration creates audit_webhook_subscriptions with the
// exact columns internal/audit/stream.go reads and writes; the audit code is
// updated to target it. Additive/idempotent; the admin webhook_subscriptions
// table is left untouched.
var auditWebhookSubscriptionsUp = `-- Migration 114: audit_webhook_subscriptions.

CREATE TABLE IF NOT EXISTS audit_webhook_subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    url TEXT NOT NULL,
    secret VARCHAR(255),
    enabled BOOLEAN NOT NULL DEFAULT true,
    filters JSONB,
    last_delivery TIMESTAMP WITH TIME ZONE,
    failure_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    org_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000010'
);

CREATE INDEX IF NOT EXISTS idx_audit_webhook_subs_org
    ON audit_webhook_subscriptions(org_id);
CREATE INDEX IF NOT EXISTS idx_audit_webhook_subs_enabled
    ON audit_webhook_subscriptions(org_id) WHERE enabled = true;
`

var auditWebhookSubscriptionsDown = `-- Rollback 114: drop the audit webhook table.
DROP TABLE IF EXISTS audit_webhook_subscriptions;
`
