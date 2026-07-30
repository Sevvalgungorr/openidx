// Package access — per-tenant retention policy + background purger for
// remote-support recordings.
//
// Effective retention for a session resolves through four layers:
//
//  1. recording_retention_days on the session row (admin per-session override)
//  2. retention_days on recording_retention_policies for the session's org
//  3. RecordingsDefaultRetentionDays config (global default)
//  4. retentionHardFallbackDays (90) — last-ditch so a misconfigured
//     deployment doesn't keep recordings forever.
//
// A retention_days of 0 anywhere in the chain means "infinite retention" —
// useful for compliance regimes that need indefinite hold under a separate
// legal process. The sweeper skips those rows.
package access

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// retentionHardFallbackDays caps the resolution chain when nothing else is
// configured. Picked to match common audit-retention windows and balance
// "operator forgot to set anything" against "infinite blob accumulation".
const retentionHardFallbackDays = 90

// retentionPolicyRow is the wire shape for the per-tenant policy.
type retentionPolicyRow struct {
	OrgID         string    `json:"org_id"`
	RetentionDays int       `json:"retention_days"`
	UpdatedAt     time.Time `json:"updated_at"`
	UpdatedBy     string    `json:"updated_by,omitempty"`
}

// RegisterRetentionAdminRoutes mounts the per-org retention CRUD surface.
// MUST go behind middleware.Auth — the routes resolve org from the
// requester's auth context.
func (h *RemoteSupportHandler) RegisterRetentionAdminRoutes(r *gin.RouterGroup) {
	r.GET("/recording-retention-policy", h.HandleGetRetentionPolicy)
	r.PUT("/recording-retention-policy", h.HandleSetRetentionPolicy)
}

// HandleGetRetentionPolicy returns the retention policy for the caller's
// org, falling back to the configured default when no row exists.
func (h *RemoteSupportHandler) HandleGetRetentionPolicy(c *gin.Context) {
	orgID := getOrgID(c)
	if orgID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "org_id not in auth context"})
		return
	}
	if h.db == nil || h.db.Pool == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	var row retentionPolicyRow
	var updatedBy *string
	err := h.db.Pool.QueryRow(c.Request.Context(), `
        SELECT org_id::text, retention_days, updated_at, updated_by::text
          FROM recording_retention_policies
         WHERE org_id = $1::uuid
    `, orgID).Scan(&row.OrgID, &row.RetentionDays, &row.UpdatedAt, &updatedBy)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// No row yet — surface the default so admins see the effective
			// behavior, not just "unset".
			c.JSON(http.StatusOK, gin.H{
				"org_id":         orgID,
				"retention_days": h.defaultRetentionDays,
				"source":         "default",
			})
			return
		}
		h.logger.Error("HandleGetRetentionPolicy: query failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query failed"})
		return
	}
	if updatedBy != nil {
		row.UpdatedBy = *updatedBy
	}
	c.JSON(http.StatusOK, gin.H{
		"org_id":         row.OrgID,
		"retention_days": row.RetentionDays,
		"updated_at":     row.UpdatedAt,
		"updated_by":     row.UpdatedBy,
		"source":         "policy",
	})
}

// setRetentionPolicyRequest is the body accepted by HandleSetRetentionPolicy.
type setRetentionPolicyRequest struct {
	RetentionDays int `json:"retention_days"`
}

// HandleSetRetentionPolicy upserts the retention policy for the caller's
// org. retention_days = 0 means "infinite" (sweeper skips). Negative
// values are rejected so a typo doesn't accidentally widen retention.
func (h *RemoteSupportHandler) HandleSetRetentionPolicy(c *gin.Context) {
	orgID := getOrgID(c)
	if orgID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "org_id not in auth context"})
		return
	}
	var req setRetentionPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.RetentionDays < 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "retention_days must be >= 0"})
		return
	}
	if h.db == nil || h.db.Pool == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	updatedBy := getUserID(c)
	_, err := h.db.Pool.Exec(c.Request.Context(), `
        INSERT INTO recording_retention_policies (org_id, retention_days, updated_by)
        VALUES ($1::uuid, $2, NULLIF($3,'')::uuid)
        ON CONFLICT (org_id) DO UPDATE
           SET retention_days = EXCLUDED.retention_days,
               updated_at     = NOW(),
               updated_by     = EXCLUDED.updated_by
    `, orgID, req.RetentionDays, updatedBy)
	if err != nil {
		h.logger.Error("HandleSetRetentionPolicy: upsert failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "upsert failed"})
		return
	}
	h.audit(c.Request.Context(), "remote_support.retention_policy_set", orgID, "success",
		"retention_days="+itoa(req.RetentionDays))
	c.JSON(http.StatusOK, gin.H{
		"org_id":         orgID,
		"retention_days": req.RetentionDays,
		"source":         "policy",
	})
}

// resolveEffectiveRetention walks the four-layer fallback to return how
// long a session's recording should be kept. Returns 0 when retention is
// infinite (sweeper skips); otherwise the absolute number of days.
func (h *RemoteSupportHandler) resolveEffectiveRetention(
	ctx context.Context,
	perSession *int,
	orgID string,
) int {
	if perSession != nil && *perSession >= 0 {
		return *perSession
	}
	if orgID != "" && h.db != nil && h.db.Pool != nil {
		var v int
		err := h.db.Pool.QueryRow(ctx,
			`SELECT retention_days FROM recording_retention_policies WHERE org_id = $1::uuid`,
			orgID,
		).Scan(&v)
		if err == nil {
			return v
		}
	}
	if h.defaultRetentionDays > 0 {
		return h.defaultRetentionDays
	}
	return retentionHardFallbackDays
}

// StartRecordingRetentionEnforcer launches a background goroutine that
// sweeps the sessions table for recordings past their effective retention
// and purges them via the configured recordingStore. Called from
// service.go after the handler is fully wired.
//
// The sweep:
//
//  1. Selects every finalized, not-yet-purged recording.
//  2. Resolves each session's effective retention through the four-layer
//     chain.
//  3. Deletes the storage blob and stamps recording_purged_at +
//     nulls recording_storage_key / recording_url.
//  4. Audits remote_support.recording_purged per session.
//
// A retention of 0 (infinite) is skipped — those rows stay until something
// upstream changes their policy.
func (h *RemoteSupportHandler) StartRecordingRetentionEnforcer(ctx context.Context, interval time.Duration) {
	ctx = orgctx.WithBypassRLS(ctx)
	if h.recordingStore == nil || h.db == nil || h.db.Pool == nil {
		return
	}
	go func() {
		// Run a first sweep promptly so a freshly-started service catches
		// up immediately on cron-style schedule changes; subsequent sweeps
		// honor the configured interval.
		h.sweepExpiredRecordings(ctx)
		h.sweepExpiredGuacRecordings(ctx)
		h.detectEndedGuacSessions(ctx)
		h.generateGuacTranscripts(ctx)
		h.sealGuacRecordings(ctx)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				h.sweepExpiredRecordings(ctx)
				h.sweepExpiredGuacRecordings(ctx)
				h.detectEndedGuacSessions(ctx)
				h.generateGuacTranscripts(ctx)
				h.sealGuacRecordings(ctx)
			}
		}
	}()
	h.logger.Info("Recording retention enforcer started",
		zap.Duration("interval", interval),
		zap.Int("default_days", h.defaultRetentionDays))
}

type purgeCandidate struct {
	SessionID         string
	OrgID             string
	PerSessionRetDays *int
	FinalizedAt       time.Time
}

func (h *RemoteSupportHandler) sweepExpiredRecordings(ctx context.Context) {
	// Sweeper SKIPS sessions with an active legal hold. The NOT EXISTS
	// subquery rides the partial unique index uq_recording_legal_holds_active
	// so this stays a single index lookup per session.
	rows, err := h.db.Pool.Query(ctx, `
        SELECT s.id,
               COALESCE(s.org_id::text, ''),
               s.recording_retention_days,
               s.recording_finalized_at
          FROM remote_support_sessions s
         WHERE s.recording_finalized_at IS NOT NULL
           AND s.recording_purged_at IS NULL
           AND NOT EXISTS (
               SELECT 1 FROM recording_legal_holds rlh
                WHERE rlh.session_id = s.id AND rlh.released_at IS NULL
           )
    `)
	if err != nil {
		h.logger.Warn("sweepExpiredRecordings: query failed", zap.Error(err))
		return
	}
	defer rows.Close()

	candidates := make([]purgeCandidate, 0, 32)
	for rows.Next() {
		var c purgeCandidate
		if err := rows.Scan(&c.SessionID, &c.OrgID, &c.PerSessionRetDays, &c.FinalizedAt); err != nil {
			h.logger.Warn("sweepExpiredRecordings: scan failed", zap.Error(err))
			continue
		}
		candidates = append(candidates, c)
	}

	now := time.Now().UTC()
	purged := 0
	for _, c := range candidates {
		ret := h.resolveEffectiveRetention(ctx, c.PerSessionRetDays, c.OrgID)
		if ret <= 0 {
			// Infinite retention — skip.
			continue
		}
		ageDays := int(now.Sub(c.FinalizedAt).Hours() / 24)
		if ageDays < ret {
			continue
		}
		if err := h.purgeRecording(ctx, c.SessionID); err != nil {
			h.logger.Warn("purgeRecording failed",
				zap.String("session_id", c.SessionID), zap.Error(err))
			continue
		}
		purged++
	}
	if purged > 0 {
		h.logger.Info("recording sweep complete", zap.Int("purged", purged))
	}
}

func (h *RemoteSupportHandler) purgeRecording(ctx context.Context, sessionID string) error {
	if err := h.recordingStore.Delete(sessionID); err != nil {
		return err
	}
	_, err := h.db.Pool.Exec(ctx, `
        UPDATE remote_support_sessions
           SET recording_purged_at  = NOW(),
               recording_storage_key = NULL,
               recording_url         = NULL
         WHERE id = $1
    `, sessionID)
	if err != nil {
		return err
	}
	h.audit(ctx, "remote_support.recording_purged", sessionID, "enforced", "")
	return nil
}

// sweepExpiredGuacRecordings purges guacamole recording files that have
// exceeded their effective retention period. It is invoked from the same
// ticker/goroutine as sweepExpiredRecordings (StartRecordingRetentionEnforcer)
// under the shared bypass-RLS context.
//
// Retention is resolved through the same two-layer chain used for
// remote-support sessions: per-org recording_retention_policies row →
// global default → hard fallback (90 days). guacamole_sessions has no
// per-session retention-days column, so layer 1 of the four-layer chain
// is skipped (perSession is always nil).
//
// Legal-hold: a guacamole_sessions row with an active hold in
// guacamole_recording_legal_holds (released_at IS NULL) is excluded from the
// candidate query below, so a held recording is never purged. (Guac holds live in
// their own table — separate from remote_support's recording_legal_holds — because
// the FK cascades to guacamole_sessions.)
//
// The recording artifact is a guacd-native filesystem directory at
// recording_path (set by handleGuacamoleConnect). We remove it with
// os.RemoveAll (idempotent) and then stamp recording_purged_at.
func (h *RemoteSupportHandler) sweepExpiredGuacRecordings(ctx context.Context) {
	if h.db == nil || h.db.Pool == nil {
		return
	}

	// Bypass-RLS context is set by the caller (StartRecordingRetentionEnforcer).
	// The query is intentionally cross-org — each row carries its own org_id so
	// we can resolve per-org retention correctly.
	//orgscope:ignore background retention sweep — cross-org by design under bypass-RLS context
	rows, err := h.db.Pool.Query(ctx, `
        SELECT id,
               COALESCE(org_id::text, ''),
               recording_path,
               COALESCE(ended_at, started_at)
          FROM guacamole_sessions
         WHERE recording_path  IS NOT NULL
           AND recording_path  != ''
           AND recording_purged_at IS NULL
           AND status IN ('ended', 'terminated')
           AND NOT EXISTS (
                SELECT 1 FROM guacamole_recording_legal_holds h
                 WHERE h.session_id = guacamole_sessions.id
                   AND h.released_at IS NULL
           )
    `)
	if err != nil {
		h.logger.Warn("sweepExpiredGuacRecordings: query failed", zap.Error(err))
		return
	}
	defer rows.Close()

	type guacCandidate struct {
		SessionID     string
		OrgID         string
		RecordingPath string
		FinalizedAt   time.Time
	}

	candidates := make([]guacCandidate, 0, 16)
	for rows.Next() {
		var c guacCandidate
		if err := rows.Scan(&c.SessionID, &c.OrgID, &c.RecordingPath, &c.FinalizedAt); err != nil {
			h.logger.Warn("sweepExpiredGuacRecordings: scan failed", zap.Error(err))
			continue
		}
		candidates = append(candidates, c)
	}

	now := time.Now().UTC()
	purged := 0
	for _, c := range candidates {
		// No per-session retention override for guacamole_sessions; pass nil.
		ret := h.resolveEffectiveRetention(ctx, nil, c.OrgID)
		if ret <= 0 {
			// Infinite retention — skip.
			continue
		}
		ageDays := int(now.Sub(c.FinalizedAt).Hours() / 24)
		if ageDays < ret {
			continue
		}
		if err := h.purgeGuacRecording(ctx, c.SessionID, c.RecordingPath); err != nil {
			h.logger.Warn("purgeGuacRecording failed",
				zap.String("session_id", c.SessionID), zap.Error(err))
			continue
		}
		purged++
	}
	if purged > 0 {
		h.logger.Info("guacamole recording sweep complete", zap.Int("purged", purged))
	}
}

// detectEndedGuacSessions reconciles the guacamole_sessions table against
// the live active-session list from the Guacamole REST API. Any session row
// whose (guacamole_connection_id, username) pair is absent from the live set
// is stamped status='ended' and audited as guacamole.session_ended_detected.
//
// The function applies a 2-minute grace window (started_at < NOW()-2min) so
// sessions that just started are never prematurely closed before Guacamole
// reports them as active.
//
// Fail-safe: if guacamoleClient is nil or ListActiveSessions returns an error
// we log a warning and return immediately without marking anything ended.
// Marking sessions ended without a definitive live set would be a false
// positive, which is far worse than a missed detection.
//
// Both the enumeration query and the per-session UPDATE are cross-org
// background operations executed under the bypass-RLS context established by
// StartRecordingRetentionEnforcer.
func (h *RemoteSupportHandler) detectEndedGuacSessions(ctx context.Context) {
	// Fail-safe: no client → skip entirely. Never end sessions when we
	// cannot see the live set.
	if h.guacamoleClient == nil {
		return
	}
	if h.db == nil || h.db.Pool == nil {
		return
	}

	active, err := h.guacamoleClient.ListActiveSessions(ctx)
	if err != nil {
		h.logger.Warn("detectEndedGuacSessions: list active sessions failed",
			zap.Error(err))
		return
	}

	// Build a set of live keys: connectionIdentifier + "|" + username.
	// This mirrors the composite key that uniquely identifies an active
	// connection from Guacamole's perspective.
	live := make(map[string]bool, len(active))
	for _, a := range active {
		live[a.ConnectionIdentifier+"|"+a.Username] = true
	}

	// Query active sessions that are old enough to be past the grace window.
	// JOIN guacamole_connections to retrieve the Guacamole-side connection
	// identifier, LEFT JOIN users to resolve the username (COALESCE to '' so
	// sessions without a matched user row still participate in the key check).
	//orgscope:ignore background cross-org sweep reconciling active Guacamole sessions against the live set
	rows, err := h.db.Pool.Query(ctx, `
        SELECT gs.id,
               gc.guacamole_connection_id,
               COALESCE(u.username, '')
          FROM guacamole_sessions gs
          JOIN guacamole_connections gc ON gc.id = gs.connection_id
          LEFT JOIN users u ON u.id = gs.user_id
         WHERE gs.status = 'active'
           AND gs.started_at < NOW() - INTERVAL '2 minutes'
    `)
	if err != nil {
		h.logger.Warn("detectEndedGuacSessions: query active sessions failed",
			zap.Error(err))
		return
	}
	defer rows.Close()

	type candidateRow struct {
		id         string
		guacConnID string
		username   string
	}

	var candidates []candidateRow
	for rows.Next() {
		var c candidateRow
		if err := rows.Scan(&c.id, &c.guacConnID, &c.username); err != nil {
			h.logger.Warn("detectEndedGuacSessions: scan failed", zap.Error(err))
			continue
		}
		candidates = append(candidates, c)
	}
	rows.Close()

	// For each DB-active session not in the live set, mark it ended.
	ended := 0
	for _, c := range candidates {
		if live[c.guacConnID+"|"+c.username] {
			// Still live — leave it alone.
			continue
		}
		//orgscope:ignore background sweep; row identified by PK — org scoping enforced at insert time
		_, execErr := h.db.Pool.Exec(ctx, `
            UPDATE guacamole_sessions
               SET status   = 'ended',
                   ended_at = NOW()
             WHERE id = $1
               AND status = 'active'
        `, c.id)
		if execErr != nil {
			h.logger.Warn("detectEndedGuacSessions: update failed",
				zap.String("session_id", c.id), zap.Error(execErr))
			continue
		}
		h.audit(ctx, "guacamole.session_ended_detected", c.id, "session", "")
		ended++
	}
	if ended > 0 {
		h.logger.Info("detectEndedGuacSessions: marked sessions ended",
			zap.Int("count", ended))
	}
}

// generateGuacTranscripts uses the guaclog CLI tool to produce a plain-text
// transcript for every ended/terminated Guacamole session that has a recording
// on disk but not yet a transcript. The function is invoked from
// StartRecordingRetentionEnforcer (immediate + each tick).
//
// If guaclog is not installed (exec.LookPath returns an error) the function
// returns immediately — missing tooling is never an error; the feature is
// simply inert.
//
// guaclog behaviour: it writes <recording_path>.txt to the filesystem. If
// the file is not present after the run (some versions write to stdout
// instead), we persist the captured CombinedOutput to that path ourselves.
//
// Transcript content is never written to the application log.
func (h *RemoteSupportHandler) generateGuacTranscripts(ctx context.Context) {
	if h.db == nil || h.db.Pool == nil {
		return
	}
	guaclog, lookErr := exec.LookPath("guaclog")
	if lookErr != nil {
		return // guaclog not installed → feature inert, no error
	}

	//orgscope:ignore background cross-org transcript sweep under bypass-RLS context
	rows, err := h.db.Pool.Query(ctx,
		`SELECT id, recording_path
		   FROM guacamole_sessions
		  WHERE status IN ('ended', 'terminated')
		    AND recording_path IS NOT NULL
		    AND recording_path <> ''
		    AND recording_purged_at IS NULL
		    AND transcript_path IS NULL
		  LIMIT 50`)
	if err != nil {
		h.logger.Warn("generateGuacTranscripts: query failed", zap.Error(err))
		return
	}
	defer rows.Close()

	type job struct {
		id   string
		path string
	}
	var jobs []job
	for rows.Next() {
		var j job
		if rows.Scan(&j.id, &j.path) == nil {
			jobs = append(jobs, j)
		}
	}
	rows.Close()

	for _, j := range jobs {
		// Skip if the recording file isn't on disk yet.
		if _, statErr := os.Stat(j.path); statErr != nil {
			continue
		}
		tpath := j.path + ".txt"
		cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		out, runErr := exec.CommandContext(cctx, guaclog, j.path).CombinedOutput()
		cancel()
		if runErr != nil {
			h.logger.Warn("generateGuacTranscripts: guaclog failed",
				zap.String("session_id", j.id),
				zap.Error(runErr))
			continue
		}
		// guaclog writes <path>.txt itself; if it wrote to stdout instead,
		// persist the captured output. NEVER log the content.
		if _, statErr := os.Stat(tpath); statErr != nil {
			if writeErr := os.WriteFile(tpath, out, 0o600); writeErr != nil {
				h.logger.Warn("generateGuacTranscripts: failed to write transcript file",
					zap.String("session_id", j.id),
					zap.String("transcript_path", tpath),
					zap.Error(writeErr))
				continue
			}
		}
		//orgscope:ignore background sweep; row identified by PK
		_, _ = h.db.Pool.Exec(ctx,
			`UPDATE guacamole_sessions
			    SET transcript_path         = $1,
			        transcript_generated_at = NOW()
			  WHERE id = $2`,
			tpath, j.id)
		h.audit(ctx, "guacamole.transcript_generated", j.id, "session", "")
	}
}

// isUnderRoot reports whether p is strictly inside root: both are
// filepath.Clean'd, root must be non-empty, and p must have root+"/" as a
// prefix (so p == root is rejected — callers must never RemoveAll the root
// itself).
func isUnderRoot(p, root string) bool {
	if root == "" || p == "" {
		return false
	}
	cp := filepath.Clean(p)
	cr := filepath.Clean(root)
	// Require a path-separator boundary so "/recordings2" is not "under" "/recordings".
	return strings.HasPrefix(cp, cr+string(filepath.Separator))
}

// purgeGuacRecording removes the guacd-native recording file at recordingPath
// and stamps recording_purged_at on the session row. Idempotent: a missing
// path is not an error (os.RemoveAll is a no-op for non-existent paths on
// Go 1.16+).
//
// Safety guard: the path must be strictly inside the configured recordings
// root (h.guacRecordingsRoot). An empty, root-equal, or escaping path is
// skipped with a Warn rather than deleted, preventing a misconfigured or
// corrupted row from wiping the entire recordings directory.
func (h *RemoteSupportHandler) purgeGuacRecording(ctx context.Context, sessionID, recordingPath string) error {
	if recordingPath != "" {
		root := h.guacRecordingsRoot
		if root == "" || !isUnderRoot(recordingPath, root) {
			h.logger.Warn("purgeGuacRecording: skipping unsafe recording_path",
				zap.String("session_id", sessionID),
				zap.String("recording_path", recordingPath),
				zap.String("recordings_root", root))
		} else {
			if err := os.RemoveAll(recordingPath); err != nil {
				return err
			}
			// Also remove the transcript file (recording_path + ".txt") when
			// it is strictly inside the recordings root. The DB columns
			// (transcript_path, transcript_generated_at) are left intact so
			// the audit history is preserved.
			tpath := recordingPath + ".txt"
			if isUnderRoot(tpath, root) {
				if removeErr := os.Remove(tpath); removeErr != nil && !os.IsNotExist(removeErr) {
					h.logger.Warn("purgeGuacRecording: failed to remove transcript file",
						zap.String("session_id", sessionID),
						zap.String("transcript_path", tpath),
						zap.Error(removeErr))
				}
			}
		}
	}
	//orgscope:ignore bypass-RLS sweep — session row identified by PK; org_id scoping is enforced at insert time
	_, err := h.db.Pool.Exec(ctx, `
        UPDATE guacamole_sessions
           SET recording_purged_at = NOW()
         WHERE id = $1
    `, sessionID)
	if err != nil {
		return err
	}
	h.audit(ctx, "guacamole.recording_purged", sessionID, "enforced", "")
	return nil
}

// getOrgID reads the auth-middleware-set org_id from the gin context.
// Kept next to getUserID (in kiosk_api.go) for callers that want both
// without two helper imports.
func getOrgID(c *gin.Context) string {
	if v, ok := c.Get("org_id"); ok {
		if s, _ := v.(string); s != "" {
			return s
		}
	}
	return ""
}

// itoa is a small dependency-free Itoa for audit details (avoids importing
// strconv from this file when nothing else here needs it).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	buf := make([]byte, 0, 8)
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	if neg {
		buf = append([]byte{'-'}, buf...)
	}
	return string(buf)
}
