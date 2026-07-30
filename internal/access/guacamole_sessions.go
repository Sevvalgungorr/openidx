// Package access — Guacamole pre-session approval-request lifecycle.
//
// Handlers and the gate helper for Task 4 of the PAM M3 session-injection epic
// (plan: docs/superpowers/plans/2026-07-02-pam-m3-session-injection.md).
package access

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	apperrors "github.com/openidx/openidx/internal/common/errors"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// ---- Session-request types ----

// GuacSessionRequest is the API representation of a guacamole_session_requests row.
type GuacSessionRequest struct {
	ID           string     `json:"id"`
	OrgID        string     `json:"org_id"`
	ConnectionID string     `json:"connection_id"`
	RequesterID  string     `json:"requester_id"`
	Reason       string     `json:"reason,omitempty"`
	Status       string     `json:"status"`
	ApproverID   *string    `json:"approver_id,omitempty"`
	DecidedAt    *time.Time `json:"decided_at,omitempty"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

// ---- handleRequestGuacSession ----
// POST /api/v1/access/guacamole/connections/:routeId/request
//
// Resolves the guacamole_connections row via route_id, verifies the connection
// belongs to the requester's org (via proxy_routes JOIN, same pattern as
// handleSetGuacCredential), then inserts a pending guacamole_session_requests
// row. Returns {request_id}.
func (s *Service) handleRequestGuacSession(c *gin.Context) {
	routeID := c.Param("routeId")
	userID := c.GetString("user_id")

	var body struct {
		Reason string `json:"reason"`
	}
	_ = c.ShouldBindJSON(&body) // reason is optional

	ctx := c.Request.Context()

	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	// Resolve the guacamole_connections UUID PK for the route, scoped to this org.
	var connectionID string
	err = s.db.Pool.QueryRow(ctx,
		`SELECT gc.id
		   FROM guacamole_connections gc
		   JOIN proxy_routes pr ON pr.id = gc.route_id
		  WHERE gc.route_id = $1 AND pr.org_id = $2`,
		routeID, org.ID).Scan(&connectionID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "guacamole connection not found for this route"})
			return
		}
		s.logger.Error("handleRequestGuacSession: connection lookup failed",
			zap.String("route_id", routeID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to look up connection"})
		return
	}

	expiresAt := time.Now().Add(time.Hour)

	var requestID string
	err = s.db.Pool.QueryRow(ctx,
		`INSERT INTO guacamole_session_requests
			(org_id, connection_id, requester_id, reason, status, expires_at)
		 VALUES ($1, $2, $3, $4, 'pending', $5)
		 RETURNING id`,
		org.ID, connectionID, userID, body.Reason, expiresAt).Scan(&requestID)
	if err != nil {
		s.logger.Error("handleRequestGuacSession: insert failed",
			zap.String("connection_id", connectionID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create session request"})
		return
	}

	s.logAuditEvent(c, "guacamole.session_requested", requestID, "guacamole_session_request",
		map[string]interface{}{
			"route_id":      routeID,
			"connection_id": connectionID,
			"requester_id":  userID,
			"expires_at":    expiresAt.Format(time.RFC3339),
		})

	c.JSON(http.StatusCreated, gin.H{"request_id": requestID})
}

// ---- handleApproveGuacSession ----
// POST /api/v1/access/guacamole/session-requests/:id/approve (admin)
//
// Sets status='approved', records approver and decision time.
func (s *Service) handleApproveGuacSession(c *gin.Context) {
	s.decideGuacSession(c, "approved", "guacamole.session_approved")
}

// ---- handleDenyGuacSession ----
// POST /api/v1/access/guacamole/session-requests/:id/deny (admin)
//
// Sets status='denied', records approver and decision time.
func (s *Service) handleDenyGuacSession(c *gin.Context) {
	s.decideGuacSession(c, "denied", "guacamole.session_denied")
}

// decideGuacSession is the shared implementation for approve/deny.
func (s *Service) decideGuacSession(c *gin.Context, newStatus, auditAction string) {
	requestID := c.Param("id")
	approverID := c.GetString("user_id")

	ctx := c.Request.Context()

	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	tag, err := s.db.Pool.Exec(ctx,
		`UPDATE guacamole_session_requests
		    SET status      = $1,
		        approver_id = $2,
		        decided_at  = NOW()
		  WHERE id = $3 AND org_id = $4 AND status = 'pending'`,
		newStatus, approverID, requestID, org.ID)
	if err != nil {
		s.logger.Error("decideGuacSession: update failed",
			zap.String("request_id", requestID), zap.String("status", newStatus), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update session request"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "session request not found or not in pending state"})
		return
	}

	s.logAuditEvent(c, auditAction, requestID, "guacamole_session_request",
		map[string]interface{}{
			"request_id":  requestID,
			"approver_id": approverID,
			"new_status":  newStatus,
		})

	c.JSON(http.StatusOK, gin.H{"request_id": requestID, "status": newStatus})
}

// ---- handleListGuacSessionRequests ----
// GET /api/v1/access/guacamole/session-requests (admin)
//
// Lists pending session requests for the org. RLS enforces org scoping via
// the request context's app.org_id setting, so no explicit org_id filter
// is needed — but we add it explicitly for defence in depth.
func (s *Service) handleListGuacSessionRequests(c *gin.Context) {
	ctx := c.Request.Context()

	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	rows, err := s.db.Pool.Query(ctx,
		`SELECT id, org_id, connection_id, requester_id, reason, status,
		        approver_id, decided_at, expires_at, created_at
		   FROM guacamole_session_requests
		  WHERE org_id = $1 AND status = 'pending'
		  ORDER BY created_at DESC`,
		org.ID)
	if err != nil {
		s.logger.Error("handleListGuacSessionRequests: query failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list session requests"})
		return
	}
	defer rows.Close()

	var requests []GuacSessionRequest
	for rows.Next() {
		var r GuacSessionRequest
		if err := rows.Scan(
			&r.ID, &r.OrgID, &r.ConnectionID, &r.RequesterID,
			&r.Reason, &r.Status, &r.ApproverID, &r.DecidedAt,
			&r.ExpiresAt, &r.CreatedAt,
		); err != nil {
			s.logger.Warn("handleListGuacSessionRequests: scan failed", zap.Error(err))
			continue
		}
		requests = append(requests, r)
	}
	if requests == nil {
		requests = []GuacSessionRequest{}
	}

	c.JSON(http.StatusOK, gin.H{"requests": requests})
}

// GuacSessionRow is the API representation of a guacamole_sessions row for the
// admin session-history list. It deliberately exposes only a transcript/recording
// *availability* boolean — never the on-disk recording_path or transcript_path.
type GuacSessionRow struct {
	ID                    string     `json:"id"`
	ConnectionID          string     `json:"connection_id"`
	UserID                *string    `json:"user_id,omitempty"`
	GuacSessionUUID       *string    `json:"guac_session_uuid,omitempty"`
	StartedAt             time.Time  `json:"started_at"`
	EndedAt               *time.Time `json:"ended_at,omitempty"`
	Status                string     `json:"status"`
	TranscriptAvailable   bool       `json:"transcript_available"`
	TranscriptGeneratedAt *time.Time `json:"transcript_generated_at,omitempty"`
	RecordingAvailable    bool       `json:"recording_available"`
	OnLegalHold           bool       `json:"on_legal_hold"`
}

// ---- handleListGuacSessionHistory ----
// GET /api/v1/access/guacamole/session-history (admin)
//
// Lists DB-backed guacamole_sessions rows for the org (most recent first), so the
// console can offer per-session transcript downloads (keyed by row id). RLS enforces
// org scoping via the request context's app.org_id; the explicit org_id filter is
// defence in depth (same pattern as handleListGuacSessionRequests). Returns only
// availability booleans and a legal-hold flag — never the on-disk
// recording_path or transcript_path.
func (s *Service) handleListGuacSessionHistory(c *gin.Context) {
	ctx := c.Request.Context()

	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	rows, err := s.db.Pool.Query(ctx,
		`SELECT id, connection_id, user_id, guac_session_uuid,
		        started_at, ended_at, status,
		        (COALESCE(transcript_path, '') <> '') AS transcript_available,
		        transcript_generated_at,
		        (COALESCE(recording_path, '') <> '') AS recording_available,
		        EXISTS (SELECT 1 FROM guacamole_recording_legal_holds h
		                 WHERE h.session_id = guacamole_sessions.id
		                   AND h.released_at IS NULL) AS on_legal_hold
		   FROM guacamole_sessions
		  WHERE org_id = $1
		  ORDER BY started_at DESC
		  LIMIT 200`,
		org.ID)
	if err != nil {
		s.logger.Error("handleListGuacSessionHistory: query failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list session history"})
		return
	}
	defer rows.Close()

	sessions := []GuacSessionRow{}
	for rows.Next() {
		var r GuacSessionRow
		if err := rows.Scan(
			&r.ID, &r.ConnectionID, &r.UserID, &r.GuacSessionUUID,
			&r.StartedAt, &r.EndedAt, &r.Status,
			&r.TranscriptAvailable, &r.TranscriptGeneratedAt,
			&r.RecordingAvailable, &r.OnLegalHold,
		); err != nil {
			s.logger.Warn("handleListGuacSessionHistory: scan failed", zap.Error(err))
			continue
		}
		sessions = append(sessions, r)
	}
	if err := rows.Err(); err != nil {
		s.logger.Error("handleListGuacSessionHistory: rows iteration failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list session history"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"sessions": sessions})
}

// ---- handleListActiveGuacSessions ----
// GET /api/v1/access/guacamole/sessions (admin)
//
// Returns all currently active Guacamole connections via the Guacamole
// activeConnections API.
func (s *Service) handleListActiveGuacSessions(c *gin.Context) {
	if s.guacamoleClient == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Guacamole is not configured"})
		return
	}

	sessions, err := s.guacamoleClient.ListActiveSessions(c.Request.Context())
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("handleListActiveGuacSessions: failed to list active sessions", err), s.logger)
		return
	}

	// Guacamole only knows the shared broker account — surface the real OpenIDX
	// user who launched each session from our own ledger (best-effort).
	s.annotateGuacSessionUsers(c.Request.Context(), sessions)

	c.JSON(http.StatusOK, gin.H{"sessions": sessions})
}

// annotateGuacSessionUsers fills OpenIDXUser on each active session by matching
// its Guacamole connection identifier to the most recent OpenIDX PAM session
// ledger row (pam_entry_sessions) for that connection. Best-effort: on any DB
// error or RLS-hidden row the session simply keeps the shared broker username.
func (s *Service) annotateGuacSessionUsers(ctx context.Context, sessions []GuacActiveSession) {
	if s.db == nil || s.db.Pool == nil || len(sessions) == 0 {
		return
	}
	seen := make(map[string]struct{})
	ids := make([]string, 0, len(sessions))
	for _, sess := range sessions {
		if sess.ConnectionIdentifier == "" {
			continue
		}
		if _, ok := seen[sess.ConnectionIdentifier]; !ok {
			seen[sess.ConnectionIdentifier] = struct{}{}
			ids = append(ids, sess.ConnectionIdentifier)
		}
	}
	if len(ids) == 0 {
		return
	}

	//orgscope:ignore pam_entry_sessions,users RLS enforces org scope via the request ctx; keys are the global Guacamole connection identifiers of the active sessions
	rows, err := s.db.Pool.Query(ctx, `
		SELECT DISTINCT ON (pes.guac_connection_id)
		       pes.guac_connection_id,
		       COALESCE(NULLIF(TRIM(CONCAT_WS(' ', u.first_name, u.last_name)), ''),
		                u.username, u.email, pes.user_id::text)
		  FROM pam_entry_sessions pes
		  LEFT JOIN users u ON u.id = pes.user_id
		 WHERE pes.guac_connection_id = ANY($1)
		 ORDER BY pes.guac_connection_id, pes.started_at DESC`, ids)
	if err != nil {
		s.logger.Warn("annotateGuacSessionUsers: lookup failed", zap.Error(err))
		return
	}
	defer rows.Close()

	byConn := make(map[string]string)
	for rows.Next() {
		var connID, display string
		if scanErr := rows.Scan(&connID, &display); scanErr == nil && display != "" {
			byConn[connID] = display
		}
	}
	for i := range sessions {
		if display, ok := byConn[sessions[i].ConnectionIdentifier]; ok {
			sessions[i].OpenIDXUser = display
		}
	}
}

// ---- handleTerminateGuacSession ----
// POST /api/v1/access/guacamole/sessions/:id/terminate (admin)
//
// Force-terminates an active Guacamole session by its active-connection UUID.
// Also marks the corresponding guacamole_sessions row as terminated (best-effort).
func (s *Service) handleTerminateGuacSession(c *gin.Context) {
	if s.guacamoleClient == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Guacamole is not configured"})
		return
	}

	activeConnID := c.Param("id")

	var body struct {
		Reason string `json:"reason"`
	}
	_ = c.ShouldBindJSON(&body) // reason is optional

	ctx := c.Request.Context()

	// Capture the per-user owner + connection BEFORE terminating (terminate
	// removes the active connection, after which it can't be resolved) so the
	// READ grant can be revoked. Best-effort; the stale-grant sweep is the backstop.
	var termConnID, termGuacUser string
	if (s.guacamoleClient != nil && s.guacamoleClient.perUserIdentities) ||
		(s.guacamoleZitiClient != nil && s.guacamoleZitiClient.perUserIdentities) {
		if sessions, lerr := s.guacamoleClient.ListActiveSessions(ctx); lerr == nil {
			for _, sess := range sessions {
				if sess.Identifier == activeConnID {
					termConnID = sess.ConnectionIdentifier
					break
				}
			}
			if termConnID != "" {
				_ = s.db.Pool.QueryRow(ctx,
					//orgscope:ignore pam_entry_sessions RLS enforces org scope via the request ctx; the lookup key is the global Guacamole connection identifier
					`SELECT COALESCE(guac_username,'') FROM pam_entry_sessions
					  WHERE guac_connection_id = $1 AND guac_username IS NOT NULL
					  ORDER BY started_at DESC LIMIT 1`, termConnID).Scan(&termGuacUser)
			}
		}
	}

	if err := s.guacamoleClient.TerminateSession(ctx, activeConnID); err != nil {
		s.logger.Error("handleTerminateGuacSession: failed to terminate session",
			zap.String("active_conn_id", activeConnID), zap.Error(err))
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("terminate guac session", err), s.logger)
		return
	}

	if termConnID != "" && termGuacUser != "" {
		for _, b := range []*GuacamoleClient{s.guacamoleClient, s.guacamoleZitiClient} {
			if b != nil && b.perUserIdentities {
				if rerr := b.revokeConnectionRead(ctx, termGuacUser, termConnID); rerr != nil {
					s.logger.Warn("handleTerminateGuacSession: revoke READ failed",
						zap.String("guac_user", termGuacUser), zap.String("conn_id", termConnID), zap.Error(rerr))
				}
			}
		}
	}

	// Best-effort: mark the tracking row as terminated. guacamole_sessions has
	// org_id and RLS is FORCE-enabled, so the UPDATE is automatically org-scoped
	// via the request context's app.org_id setting.
	//orgscope:ignore RLS on guacamole_sessions is enforced via the request context's app.org_id setting
	_, dbErr := s.db.Pool.Exec(ctx,
		`UPDATE guacamole_sessions
		    SET status   = 'terminated',
		        ended_at = NOW()
		  WHERE guac_session_uuid = $1
		    AND status = 'active'`,
		activeConnID)
	if dbErr != nil {
		s.logger.Warn("handleTerminateGuacSession: could not update session tracking row",
			zap.String("active_conn_id", activeConnID), zap.Error(dbErr))
		// Not fatal — continue to audit + respond.
	}

	s.logAuditEvent(c, "guacamole.session_terminated", activeConnID, "guacamole_session",
		map[string]interface{}{
			"active_conn_id": activeConnID,
			"reason":         body.Reason,
		})

	c.JSON(http.StatusOK, gin.H{"message": "session terminated", "active_conn_id": activeConnID})
}

// ---- handleShareGuacSession ----
// POST /api/v1/access/guacamole/sessions/:id/share (admin)
//
// Mints a read-only sharing link for an active Guacamole session by its
// active-connection UUID (:id). Delegates to ShareActiveConnection which
// creates a read-only sharing profile via the Guacamole REST API and returns
// a pre-authenticated share URL. On ErrSharingUnsupported (Guacamole server
// does not implement the sharingProfiles endpoint, e.g. < 1.3) the handler
// responds 501 with a helpful fallback message. Audits guacamole.session_shared.
func (s *Service) handleShareGuacSession(c *gin.Context) {
	if s.guacamoleClient == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Guacamole is not configured"})
		return
	}

	activeConnID := c.Param("id")
	ctx := c.Request.Context()

	gc := s.guacamoleClient
	var shareURL string
	var err error
	if gc.perUserIdentities {
		// Owner-restricted: mint the share key as the session's per-user owner.
		owner, pw, oerr := s.resolveActiveSessionOwner(ctx, gc, activeConnID)
		if oerr != nil {
			s.logger.Warn("handleShareGuacSession: owner resolve failed", zap.Error(oerr))
			c.JSON(http.StatusConflict, gin.H{"error": "cannot resolve session owner for read-only monitor"})
			return
		}
		shareURL, err = gc.ShareActiveConnectionForOwner(ctx, activeConnID, owner, pw)
	} else {
		shareURL, err = gc.ShareActiveConnection(ctx, activeConnID)
	}
	if err != nil {
		if errors.Is(err, ErrSharingUnsupported) {
			c.JSON(http.StatusNotImplemented, gin.H{
				"error": "connection sharing not supported; use GET /guacamole/sessions to list active sessions",
			})
			return
		}
		s.logger.Error("handleShareGuacSession: ShareActiveConnection failed",
			zap.String("active_conn_id", activeConnID), zap.Error(err))
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("share guac session", err), s.logger)
		return
	}

	s.logAuditEvent(c, "guacamole.session_shared", activeConnID, "guacamole_session",
		map[string]interface{}{
			"active_conn_id": activeConnID,
		})

	c.JSON(http.StatusOK, gin.H{"share_url": shareURL})
}

// ---- handleGetGuacTranscript ----
// GET /api/v1/access/guacamole/sessions/:id/transcript (admin)
//
// Streams the plain-text transcript for the given guacamole_sessions row.
// Org-scoped via a guacamole_connections → proxy_routes JOIN (same pattern as
// handleSetGuacCredential). Returns 404 when the session has no transcript or
// the transcript file is absent from disk. Audits guacamole.transcript_downloaded.
func (s *Service) handleGetGuacTranscript(c *gin.Context) {
	sessionID := c.Param("id")

	ctx := c.Request.Context()

	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	var transcriptPath string
	err = s.db.Pool.QueryRow(ctx,
		`SELECT gs.transcript_path
		   FROM guacamole_sessions gs
		   JOIN guacamole_connections gc ON gc.id = gs.connection_id
		   JOIN proxy_routes pr ON pr.id = gc.route_id
		  WHERE gs.id = $1 AND pr.org_id = $2`,
		sessionID, org.ID).Scan(&transcriptPath)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
			return
		}
		s.logger.Error("handleGetGuacTranscript: query failed",
			zap.String("session_id", sessionID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to look up session"})
		return
	}
	if transcriptPath == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "transcript not yet generated for this session"})
		return
	}
	if _, statErr := os.Stat(transcriptPath); statErr != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "transcript file not found on disk"})
		return
	}

	s.logAuditEvent(c, "guacamole.transcript_downloaded", sessionID, "guacamole_session",
		map[string]interface{}{
			"session_id":      sessionID,
			"transcript_path": transcriptPath,
		})

	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.File(transcriptPath)
}

// ---- handleGetGuacRecording ----
// GET /api/v1/access/guacamole/sessions/:id/recording (admin)
//
// Streams the raw guacd session recording for the given guacamole_sessions row.
// When the file was sealed (encrypted at rest) by the recording sealer
// (recording_sealed_at IS NOT NULL), the bytes are transparently decrypted
// through the keyring before streaming; a plaintext (unsealed) recording is
// streamed through unchanged. Org-scoped via the same
// guacamole_connections → proxy_routes JOIN as the transcript handler. Returns
// 404 when the session has no recording or the file is absent from disk.
// Audits guacamole.recording_downloaded.
func (s *Service) handleGetGuacRecording(c *gin.Context) {
	sessionID := c.Param("id")
	ctx := c.Request.Context()

	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	var recordingPath string
	var sealedAt *time.Time
	err = s.db.Pool.QueryRow(ctx,
		`SELECT gs.recording_path, gs.recording_sealed_at
		   FROM guacamole_sessions gs
		   JOIN guacamole_connections gc ON gc.id = gs.connection_id
		   JOIN proxy_routes pr ON pr.id = gc.route_id
		  WHERE gs.id = $1 AND pr.org_id = $2`,
		sessionID, org.ID).Scan(&recordingPath, &sealedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
			return
		}
		s.logger.Error("handleGetGuacRecording: query failed",
			zap.String("session_id", sessionID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to look up session"})
		return
	}
	if recordingPath == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "no recording for this session"})
		return
	}
	f, statErr := os.Open(recordingPath)
	if statErr != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "recording file not found on disk"})
		return
	}
	defer f.Close()

	s.logAuditEvent(c, "guacamole.recording_downloaded", sessionID, "guacamole_session",
		map[string]interface{}{
			"session_id": sessionID,
			"sealed":     sealedAt != nil,
		})

	filename := "openidx-guac-recording-" + sessionID
	c.Header("Content-Disposition", `attachment; filename="`+filename+`"`)
	c.Header("Content-Type", "application/octet-stream")

	// Sealed recordings are decrypted on the fly; the derived per-recording key
	// matches the sealer's (guacRecordingSessionKey of the same path). Plaintext
	// recordings stream through unchanged.
	if sealedAt != nil && s.guacRecordingRing != nil && s.guacRecordingRing.Enabled() {
		reader := newDecryptingReader(f, s.guacRecordingRing, guacRecordingSessionKey(recordingPath))
		if _, cErr := io.Copy(c.Writer, reader); cErr != nil {
			s.logger.Warn("handleGetGuacRecording: decrypt copy failed",
				zap.String("session_id", sessionID), zap.Error(cErr))
		}
		return
	}
	if _, cErr := io.Copy(c.Writer, f); cErr != nil {
		s.logger.Warn("handleGetGuacRecording: copy failed",
			zap.String("session_id", sessionID), zap.Error(cErr))
	}
}

// ---- recordGuacSession ----
// recordGuacSession inserts a guacamole_sessions row for a recorded brokered
// session and returns its id. Called from the connect handler when
// record_session is on.
//
// user_id may be an empty string (no-auth path) — NULLIF coerces it to NULL
// so the UUID cast succeeds.
func (s *Service) recordGuacSession(ctx context.Context, orgID, connectionID, userID, recordingPath string) (string, error) {
	var id string
	err := s.db.Pool.QueryRow(ctx,
		`INSERT INTO guacamole_sessions (org_id, connection_id, user_id, recording_path, status)
		 VALUES ($1,$2,NULLIF($3,'')::uuid,$4,'active') RETURNING id`,
		orgID, connectionID, userID, recordingPath).Scan(&id)
	return id, err
}

// ---- checkAndConsumeApproval ----
// checkAndConsumeApproval atomically consumes the most-recent approved,
// unexpired guacamole_session_requests row for the given connection and
// user. Returns (true, nil) if a row was consumed (access granted),
// (false, nil) if none exists (access denied), or (false, err) on error.
//
// The UPDATE runs under the connect handler's ctx which already carries the
// org_id app-setting → RLS scopes the CTE to the right org without an
// explicit org_id predicate. (Note for T7: the context must originate from
// the request — not a background context — so RLS remains active.)
func (s *Service) checkAndConsumeApproval(ctx context.Context, connectionID, userID string) (bool, error) {
	var id string
	err := s.db.Pool.QueryRow(ctx,
		`UPDATE guacamole_session_requests SET status = 'consumed'
		  WHERE id = (
		        SELECT id FROM guacamole_session_requests
		         WHERE connection_id = $1
		           AND requester_id  = $2
		           AND status        = 'approved'
		           AND (expires_at IS NULL OR expires_at > NOW())
		         ORDER BY created_at DESC
		         LIMIT 1
		  )
		  RETURNING id`,
		connectionID, userID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}
