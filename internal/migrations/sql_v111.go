package migrations

// Migration v111 — mobile posture: platform-scoped posture checks.
//
// The agent config endpoint (internal/access/agent_api.go, HandleConfig) filters
// posture checks to the reporting agent's platform:
//
//	WHERE enabled = true
//	  AND (platforms IS NULL OR platforms ? $1 OR platforms ? 'any')
//
// It expects a JSONB `platforms` array on posture_checks (a check tagged
// ["android"] only runs on Android agents; NULL/["any"] runs everywhere). That
// column was referenced in code but never created by a migration, so mobile
// agents hit `ERROR: column "platforms" does not exist (SQLSTATE 42703)` and got
// NO posture checks — breaking mobile device-posture entirely.
//
// This adds the column (additive, idempotent). NULL means "all platforms", which
// preserves existing behavior for every pre-existing check. A GIN index supports
// the `?` containment lookups the config query runs on every agent poll.
var postureCheckPlatformsUp = `-- Migration 111: platform-scoped posture checks.

ALTER TABLE posture_checks ADD COLUMN IF NOT EXISTS platforms JSONB;
CREATE INDEX IF NOT EXISTS idx_posture_checks_platforms ON posture_checks USING GIN (platforms);
`

var postureCheckPlatformsDown = `-- Rollback 111: drop the platform scoping column.
DROP INDEX IF EXISTS idx_posture_checks_platforms;
ALTER TABLE posture_checks DROP COLUMN IF EXISTS platforms;
`
