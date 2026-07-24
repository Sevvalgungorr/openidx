package migrations

// Migration v108 — entitlement warehouse + orphan detection.
//
// Entitlements lived in four disconnected tables (user_roles, group_memberships,
// pam_entry_grants, vault_access_grants). There was no single "who has access to
// what" view an auditor could query, and no way to surface orphaned
// entitlements — grants whose owning account is disabled or gone (the top SOX/
// ISO 27001 access-review finding, and exactly what attackers reuse).
//
// entitlement_warehouse is a denormalized snapshot the rebuild sweep repopulates
// (full delete + insert per org) by unioning every entitlement source into one
// row-per-(user, entitlement) shape, stamping each with whether it is time-bound
// and whether it is orphaned (owner disabled or missing). One queryable surface
// for access certification and orphan cleanup.
//
// Org-scoped under the v37 FORCE-RLS belt. Additive/idempotent; plain statements.
var entitlementWarehouseUp = `-- Migration 108: entitlement warehouse + orphan detection.

CREATE TABLE IF NOT EXISTS entitlement_warehouse (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id           UUID NOT NULL,
    user_id          UUID NOT NULL,
    username         VARCHAR(255),
    entitlement_type VARCHAR(32) NOT NULL,
    entitlement_id   VARCHAR(255) NOT NULL,
    entitlement_name VARCHAR(255),
    source           VARCHAR(64) NOT NULL,
    actions          TEXT[] NOT NULL DEFAULT '{}',
    time_bound       BOOLEAN NOT NULL DEFAULT false,
    expires_at       TIMESTAMPTZ,
    orphaned         BOOLEAN NOT NULL DEFAULT false,
    orphan_reason    VARCHAR(32),
    snapshot_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_entitlement_wh_user     ON entitlement_warehouse(org_id, user_id);
CREATE INDEX IF NOT EXISTS idx_entitlement_wh_orphaned ON entitlement_warehouse(org_id, orphaned);
CREATE INDEX IF NOT EXISTS idx_entitlement_wh_type     ON entitlement_warehouse(org_id, entitlement_type);
`

var entitlementWarehouseDown = `-- Rollback 108: drop the entitlement warehouse.
DROP TABLE IF EXISTS entitlement_warehouse;
`
