package migrations

// Migration v113 — roles.updated_at.
//
// CreateRole and UpdateRole (internal/identity/service.go) both write
// roles.updated_at:
//
//	INSERT INTO roles (id, name, description, is_composite, created_at, updated_at, org_id)
//	    VALUES ($1, $2, $3, $4, $5, $5, $6)
//	UPDATE roles SET name = $2, description = $3, is_composite = $4, updated_at = $5 ...
//
// but the roles table (seeded in v10) only ever had created_at, so every role
// create/update failed with `column "updated_at" of relation "roles" does not
// exist` (SQLSTATE 42703) and the Roles admin page could not create or edit a
// role. The sibling entities (users, groups) all carry updated_at; roles was the
// odd one out.
//
// This adds the column (additive, idempotent) and backfills existing rows from
// created_at so ordering/consumers see a sane initial value.
var rolesUpdatedAtUp = `-- Migration 113: roles.updated_at.

ALTER TABLE roles ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ;
UPDATE roles SET updated_at = created_at WHERE updated_at IS NULL;
`

var rolesUpdatedAtDown = `-- Rollback 113: drop the roles.updated_at column.
ALTER TABLE roles DROP COLUMN IF EXISTS updated_at;
`
