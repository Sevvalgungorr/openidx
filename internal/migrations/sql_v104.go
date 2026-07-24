package migrations

// Migration v104 — per-org group-name uniqueness (Wave A2).
//
// The overlay's multi-tenancy (MSP channel) is blocked by a data-model bug: the
// groups table carried a GLOBAL unique constraint on name (groups_name_key), so
// two tenants literally could not both have an "Engineering" or "Admins" group.
// That defeats per-org overlay scoping before it starts — attributes derived
// from group names (see ZitiPerOrgAttributes) assume each org owns its own
// namespace of group names.
//
// This migration drops the global-unique constraint and replaces it with a
// composite UNIQUE (org_id, name): names must be unique WITHIN an org, and two
// orgs may reuse the same name freely. org_id is NOT NULL with a DEFAULT on this
// table, so the composite key is always well-defined (no NULL-collation gap).
//
// Idempotent: DROP ... IF EXISTS on both the legacy and composite constraints
// makes a re-run a clean no-op before the composite is re-added. The migrator
// splits on ';', so this avoids DO/dollar-quoted blocks entirely.
var groupsPerOrgNameUp = `-- Migration 104: per-org group-name uniqueness (Wave A2).

-- Drop the legacy GLOBAL unique constraint on groups.name if present.
ALTER TABLE groups DROP CONSTRAINT IF EXISTS groups_name_key;

-- Drop the composite too (idempotent re-run) then add it fresh.
ALTER TABLE groups DROP CONSTRAINT IF EXISTS groups_org_id_name_key;
ALTER TABLE groups ADD CONSTRAINT groups_org_id_name_key UNIQUE (org_id, name);
`

var groupsPerOrgNameDown = `-- Rollback 104: drop the composite constraint.
-- The global-unique constraint is NOT restored: once two orgs share a group
-- name (the whole point of this migration) restoring it would fail, so the
-- rollback simply removes the per-org constraint and leaves names unconstrained.
ALTER TABLE groups DROP CONSTRAINT IF EXISTS groups_org_id_name_key;
`
