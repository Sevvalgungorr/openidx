package migrations

// Migration v126 — unique org_id on device_trust_settings.
//
// device_trust_settings is a per-org singleton (one settings row per org), but
// the table only had a PK on id. UpdateDeviceTrustSettings now upserts via
// ON CONFLICT (org_id), which requires a unique constraint on org_id. Without
// it, a fresh install (no settings row) could never persist the admin's
// device-trust configuration — the previous UPDATE ... WHERE id=? affected zero
// rows — so auto-approve-known-IPs and friends silently never took effect,
// leaving clientless (BrowZer) logins stuck behind manual device approval.
//
// Any pre-existing duplicate rows are collapsed to the most-recently-updated one
// before the unique index is created, so the migration is safe on dirty data.
var deviceTrustSettingsUniqueOrgUp = `-- Migration 126: unique org_id on device_trust_settings.

-- Collapse accidental duplicates (keep the newest row per org).
DELETE FROM device_trust_settings a
 USING device_trust_settings b
 WHERE a.org_id IS NOT DISTINCT FROM b.org_id
   AND a.updated_at < b.updated_at;

CREATE UNIQUE INDEX IF NOT EXISTS uq_device_trust_settings_org
    ON device_trust_settings (org_id);
`

var deviceTrustSettingsUniqueOrgDown = `-- Rollback 126.
DROP INDEX IF EXISTS uq_device_trust_settings_org;
`
