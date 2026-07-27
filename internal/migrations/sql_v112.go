package migrations

// Migration v112 — remote_support_sessions.recording_purged_at.
//
// The remote-support recording retention sweeper
// (internal/access/remote_support_retention.go) reads and writes
// remote_support_sessions.recording_purged_at to track which finalized
// recordings have already had their storage blob deleted:
//
//	SELECT ... FROM remote_support_sessions
//	 WHERE recording_finalized_at IS NOT NULL AND recording_purged_at IS NULL ...
//	UPDATE remote_support_sessions SET recording_purged_at = NOW() ...
//
// The sibling recording columns were added in v42/v92, but recording_purged_at
// was never added to this table (only to guacamole_sessions, in v59). So the
// sweeper failed on every run with `column s.recording_purged_at does not exist`
// (SQLSTATE 42703) and expired remote-support recordings were never purged.
//
// This adds the column (additive, idempotent) plus a partial index matching the
// sweeper's "finalized but not purged" predicate.
var remoteSupportPurgedAtUp = `-- Migration 112: remote_support_sessions.recording_purged_at.

ALTER TABLE remote_support_sessions ADD COLUMN IF NOT EXISTS recording_purged_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_remote_support_recordings_unpurged
    ON remote_support_sessions(recording_finalized_at)
    WHERE recording_finalized_at IS NOT NULL AND recording_purged_at IS NULL;
`

var remoteSupportPurgedAtDown = `-- Rollback 112: drop the purge tracking column.
DROP INDEX IF EXISTS idx_remote_support_recordings_unpurged;
ALTER TABLE remote_support_sessions DROP COLUMN IF EXISTS recording_purged_at;
`
