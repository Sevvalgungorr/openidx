// Package access — PAM A1: seal (encrypt-at-rest) guacd session recordings.
//
// guacd writes RDP/SSH session recordings straight to disk as plaintext. Unlike
// the WebRTC remote-support path — where openidx sees every MediaRecorder chunk
// inline and encrypts it on write (remote_support_recording.go) — openidx never
// touches guacd's bytes as they are produced. A filesystem compromise (stolen
// disk, leaked backup, world-readable path) therefore yields a replayable
// recording of a privileged session.
//
// This sealer closes that gap. After a guac session has ended AND its plaintext
// transcript has been generated (guaclog needs the cleartext, so sealing must
// come last), the sweep:
//
//  1. streams the plaintext file, computing its SHA-256 as it goes;
//  2. re-encrypts the bytes through the SAME AES-256-GCM keyring + on-disk
//     framing used by the WebRTC store (recording_crypto.go), so playback and
//     key-rotation logic are shared;
//  3. atomically replaces the plaintext file with the sealed one (temp file +
//     rename, so a crash never leaves a half-written recording);
//  4. records recording_sealed_at / recording_sha256 / recording_key_id on the
//     session row and writes a hash-chained audit event.
//
// The whole feature is inert unless an encryption keyring is configured
// (SetGuacRecordingRing with an enabled ring) — back-compat for single-tenant
// deployments that keep recordings plaintext.
//
// Chunking: the file is sealed as a sequence of fixed-size frames (each an
// independent GCM unit under the shared framing) so the decrypting reader that
// already exists can play it back with no special-casing, and so a large
// recording never has to be held fully in memory on the read path.
package access

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"go.uber.org/zap"
)

// guacSealChunkBytes is the plaintext frame size the sealer cuts the recording
// into before encrypting each frame. 1 MiB keeps per-frame memory bounded while
// keeping framing overhead (key id + length + nonce + tag = 33 bytes/frame)
// negligible relative to a multi-megabyte recording.
const guacSealChunkBytes = 1 << 20 // 1 MiB

// sealGuacRecordings encrypts-at-rest every ended guac session recording that
// is still plaintext on disk. Runs on the recording-retention enforcer tick,
// AFTER generateGuacTranscripts, so guaclog has already consumed the cleartext.
//
// No-op unless a keyring is wired and enabled. Cross-org background sweep under
// the bypass-RLS context set by StartRecordingRetentionEnforcer; each write is
// keyed by the session PK and stamped with the row's own org.
func (h *RemoteSupportHandler) sealGuacRecordings(ctx context.Context) {
	if h.guacRecordingRing == nil || !h.guacRecordingRing.Enabled() {
		return // encryption disabled → sealer inert
	}
	if h.db == nil || h.db.Pool == nil {
		return
	}

	//orgscope:ignore background cross-org sweep under bypass-RLS; org_id selected per row and used to scope the write
	rows, err := h.db.Pool.Query(ctx, `
		SELECT id, COALESCE(org_id::text, ''), recording_path
		  FROM guacamole_sessions
		 WHERE status IN ('ended', 'terminated')
		   AND recording_path IS NOT NULL
		   AND recording_path <> ''
		   AND recording_purged_at IS NULL
		   AND recording_sealed_at IS NULL
		 LIMIT 50`)
	if err != nil {
		h.logger.Warn("sealGuacRecordings: query failed", zap.Error(err))
		return
	}
	type job struct {
		id    string
		orgID string
		path  string
	}
	var jobs []job
	for rows.Next() {
		var j job
		if rows.Scan(&j.id, &j.orgID, &j.path) == nil {
			jobs = append(jobs, j)
		}
	}
	rows.Close()

	sealed := 0
	for _, j := range jobs {
		// Guard the path against directory traversal / root-equality the same
		// way the purge sweep does, so a malformed recording_path can never
		// make us read or overwrite something outside the recordings root.
		if !h.guacRecordingPathSafe(j.path) {
			h.logger.Warn("sealGuacRecordings: skipping unsafe recording_path",
				zap.String("session_id", j.id))
			continue
		}
		if _, statErr := os.Stat(j.path); statErr != nil {
			continue // recording not on disk (yet) — leave unsealed for a later tick
		}
		sum, keyID, sealErr := h.sealOneGuacRecording(j.path)
		if sealErr != nil {
			h.logger.Warn("sealGuacRecordings: seal failed",
				zap.String("session_id", j.id), zap.Error(sealErr))
			continue
		}
		//orgscope:ignore background sweep; row identified by PK, org already fixed at insert
		if _, execErr := h.db.Pool.Exec(ctx, `
			UPDATE guacamole_sessions
			   SET recording_sealed_at = NOW(),
			       recording_sha256    = $1,
			       recording_key_id    = $2
			 WHERE id = $3`, sum, int(keyID), j.id); execErr != nil {
			// The bytes are already encrypted on disk; if we can't persist the
			// metadata we log loudly. The row stays unsealed so a later tick
			// retries — but the file is now ciphertext, so retry re-reads it as
			// "plaintext", double-encrypting. To avoid that, treat a metadata
			// write failure as fatal for this file and surface it; operationally
			// this is extremely rare (same pool the SELECT just succeeded on).
			h.logger.Error("sealGuacRecordings: sealed bytes but metadata write FAILED — manual reconciliation needed",
				zap.String("session_id", j.id), zap.Error(execErr))
			continue
		}
		h.auditGuacSeal(ctx, j.id, j.orgID, sum, keyID)
		sealed++
	}
	if sealed > 0 {
		h.logger.Info("sealGuacRecordings: sealed recordings", zap.Int("count", sealed))
	}
}

// sealOneGuacRecording reads the plaintext recording at path, computes its
// SHA-256, and rewrites it in place (atomically) as keyring-encrypted frames.
// Returns the hex digest of the ORIGINAL plaintext and the key id used.
//
// Atomicity: we write the sealed bytes to a sibling temp file and os.Rename it
// over the original only after a successful fsync+close. A crash mid-seal
// leaves the original plaintext intact (and the row still unsealed), so the
// next tick retries cleanly — never a half-encrypted, unplayable file.
func (h *RemoteSupportHandler) sealOneGuacRecording(path string) (string, byte, error) {
	activeID := h.guacRecordingRing.ActiveID()
	master, err := h.guacRecordingRing.masterFor(activeID)
	if err != nil {
		return "", 0, err
	}
	// Session-scope the derived key by the file's stable base name so playback
	// (which derives from the same identifier) matches. We use the recording
	// file path's directory+name; the download path must pass the same id.
	sessionKey := guacRecordingSessionKey(path)
	aead, err := newRecordingAEAD(master, sessionKey)
	if err != nil {
		return "", 0, err
	}

	src, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer src.Close()

	tmp := path + ".sealing"
	dst, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return "", 0, err
	}
	// Best-effort cleanup of the temp file on any error path before rename.
	committed := false
	defer func() {
		if !committed {
			_ = dst.Close()
			_ = os.Remove(tmp)
		}
	}()

	hasher := sha256.New()
	buf := make([]byte, guacSealChunkBytes)
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			plaintext := buf[:n]
			hasher.Write(plaintext)
			frame, ferr := aead.encryptChunk(activeID, plaintext)
			if ferr != nil {
				return "", 0, ferr
			}
			if _, werr := dst.Write(frame); werr != nil {
				return "", 0, werr
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return "", 0, rerr
		}
	}
	if syncErr := dst.Sync(); syncErr != nil {
		return "", 0, syncErr
	}
	if closeErr := dst.Close(); closeErr != nil {
		return "", 0, closeErr
	}
	if renameErr := os.Rename(tmp, path); renameErr != nil {
		return "", 0, renameErr
	}
	committed = true
	return hex.EncodeToString(hasher.Sum(nil)), activeID, nil
}

// guacRecordingSessionKey derives the HKDF session identifier for a guac
// recording file from its path. Stable across seal and playback so the derived
// per-recording key matches. We use the parent dir + base name so two files
// with the same base in different dirs don't share a key.
func guacRecordingSessionKey(path string) string {
	return filepath.Base(filepath.Dir(path)) + "/" + filepath.Base(path)
}

// guacRecordingPathSafe rejects empty paths, the recordings root itself, and
// any path that escapes the configured root — mirroring the purge sweep's
// guard so the sealer never reads or overwrites a file outside the root.
func (h *RemoteSupportHandler) guacRecordingPathSafe(path string) bool {
	if path == "" {
		return false
	}
	root := h.guacRecordingsRoot
	if root == "" {
		// No configured root to validate against: fail safe (don't seal).
		return false
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	if absPath == absRoot {
		return false
	}
	rel, err := filepath.Rel(absRoot, absPath)
	if err != nil {
		return false
	}
	if rel == ".." || len(rel) >= 3 && rel[:3] == ".."+string(filepath.Separator) {
		return false
	}
	return true
}

// auditGuacSeal writes the hash-chained audit event recording the seal event.
// The integrity hash (of the original plaintext) is captured so a later auditor
// can prove a decrypted recording matches what guacd originally wrote.
func (h *RemoteSupportHandler) auditGuacSeal(ctx context.Context, sessionID, orgID, sha256hex string, keyID byte) {
	details := fmt.Sprintf(`{"session_id":%q,"sha256":%q,"key_id":%d}`, sessionID, sha256hex, int(keyID))
	var org any
	if orgID != "" {
		org = orgID
	} else {
		org = nil
	}
	//orgscope:ignore audit_events stamped with the session's own org_id; background sweep has no request org
	if _, err := h.db.Pool.Exec(ctx, `
		INSERT INTO audit_events (id, event_type, category, action, outcome, actor_id, target_type, resource_id, details, created_at, org_id)
		VALUES (gen_random_uuid(), 'pam.recording.sealed', 'privileged_access', 'recording.seal', 'success', 'system', 'guacamole_session', $1, $2, NOW(), $3)`,
		sessionID, details, org); err != nil {
		h.logger.Warn("auditGuacSeal: audit insert failed", zap.Error(err))
	}
}
