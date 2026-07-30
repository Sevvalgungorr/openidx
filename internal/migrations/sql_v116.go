package migrations

// Migration v116 — guacamole_sessions recording-seal metadata.
//
// PAM Wave A (A1): guacd writes RDP/SSH session recordings straight to disk as
// plaintext (openidx never sees those bytes inline, unlike the WebRTC
// remote-support path which is already encrypted via recording_crypto.go). A
// filesystem compromise therefore leaks a replayable session recording. The
// guac recording sealer worker (internal/access/guac_recording_sealer.go)
// encrypts each finished recording through the same AES-256-GCM keyring after
// the session ends, and records an integrity hash so tampering is detectable.
//
// Columns (all additive, nullable — a NULL recording_sealed_at means the file
// is still plaintext, i.e. the sealer is disabled or has not run yet):
//   - recording_sealed_at : when the sealer encrypted the on-disk file.
//   - recording_sha256    : hex SHA-256 of the ORIGINAL plaintext recording,
//     computed before encryption, so an auditor can prove the decrypted bytes
//     match what guacd wrote.
//   - recording_key_id    : which keyring key id sealed the file (for rotation;
//     mirrors the per-frame key id in the on-disk framing).
var guacRecordingSealUp = `-- Migration 116: guacamole_sessions recording-seal metadata.

ALTER TABLE guacamole_sessions ADD COLUMN IF NOT EXISTS recording_sealed_at TIMESTAMPTZ;
ALTER TABLE guacamole_sessions ADD COLUMN IF NOT EXISTS recording_sha256 TEXT;
ALTER TABLE guacamole_sessions ADD COLUMN IF NOT EXISTS recording_key_id SMALLINT;

-- Partial index so the sealer's sweep (ended sessions with an unsealed
-- recording) stays cheap as the history table grows.
CREATE INDEX IF NOT EXISTS idx_guacamole_sessions_unsealed
    ON guacamole_sessions (ended_at)
    WHERE recording_path IS NOT NULL AND recording_sealed_at IS NULL;
`

var guacRecordingSealDown = `-- Rollback 116: drop the recording-seal metadata.
DROP INDEX IF EXISTS idx_guacamole_sessions_unsealed;
ALTER TABLE guacamole_sessions DROP COLUMN IF EXISTS recording_key_id;
ALTER TABLE guacamole_sessions DROP COLUMN IF EXISTS recording_sha256;
ALTER TABLE guacamole_sessions DROP COLUMN IF EXISTS recording_sealed_at;
`
