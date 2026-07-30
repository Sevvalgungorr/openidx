// Package access — PAM C3: moderated privileged sessions.
//
// A "moderated session" (Teleport parlance) is the four-eyes control for
// privileged access: a session flagged require_moderator does not start until a
// second, authorized user (the moderator) has joined to watch it live. This is
// the SOX/PCI control auditors ask for on production database and jump-host
// access.
//
// It is deliberately distinct from the existing require_approval gate:
//
//   - require_approval is decided BEFORE the session (an approver clicks
//     approve; the requester then consumes that grant at connect time).
//   - require_moderator is a LIVE presence requirement: the session is gated at
//     connect time and stays gated until a moderator is present.
//
// State machine (guacamole_moderation_sessions.status):
//
//	pending  — requester asked to start; waiting for a moderator to join.
//	active   — a moderator claimed the request; the requester's connect now
//	           proceeds and the moderator holds a read-only Guacamole share to
//	           watch and can terminate.
//	ended    — session finished (either side ended it).
//	expired  — no moderator joined within the wait window.
//	denied   — a moderator refused.
//
// The interactive video side (the moderator watching the live screen) rides on
// Guacamole's existing read-only sharing profiles (ShareActiveConnection),
// which this wires into once the brokered active-connection id is known. The
// gate itself — the valuable, audit-relevant control — is fully server-side and
// testable via the API without a browser.
package access

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/openidx/openidx/internal/common/orgctx"
	"go.uber.org/zap"
)

// moderationWaitWindow is how long a pending moderation request stays open for a
// moderator to join before it is considered expired.
const moderationWaitWindow = 15 * time.Minute

// checkModerationActive reports whether an active moderation session exists for
// this (connection, requester) — i.e. a moderator has joined and the session
// may proceed. Runs under the connect handler's request ctx so RLS scopes it to
// the org. Returns (true,nil) when a moderator is present.
func (s *Service) checkModerationActive(ctx context.Context, connectionID, requesterID string) (bool, error) {
	var id string
	err := s.db.Pool.QueryRow(ctx,
		`SELECT id FROM guacamole_moderation_sessions
		  WHERE connection_id = $1 AND requester_id = $2 AND status = 'active'
		  ORDER BY joined_at DESC LIMIT 1`,
		connectionID, requesterID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// ---- requester side ----

type moderationRequestBody struct {
	RouteID string `json:"route_id" binding:"required"`
	Reason  string `json:"reason"`
}

// handleRequestModeration — POST /pam/moderation/request (authenticated user).
// Opens (or reuses) a pending moderation request for the caller against the
// connection behind route_id. Idempotent: a still-pending request is returned
// rather than duplicated. The client then polls handleGetModerationStatus and,
// once active, retries the Guacamole connect.
func (s *Service) handleRequestModeration(c *gin.Context) {
	var body moderationRequestBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "route_id is required"})
		return
	}
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}

	var connectionID string
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT id FROM guacamole_connections WHERE route_id = $1`, body.RouteID).
		Scan(&connectionID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "no Guacamole connection for this route"})
		return
	}

	// Reuse a still-valid pending request if present (idempotent).
	var existingID, existingStatus string
	err = s.db.Pool.QueryRow(ctx,
		`SELECT id, status FROM guacamole_moderation_sessions
		  WHERE connection_id = $1 AND requester_id = $2
		    AND status IN ('pending','active')
		    AND (expires_at IS NULL OR expires_at > NOW())
		  ORDER BY created_at DESC LIMIT 1`,
		connectionID, userID).Scan(&existingID, &existingStatus)
	if err == nil {
		c.JSON(http.StatusOK, gin.H{"id": existingID, "status": existingStatus, "reused": true})
		return
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		s.logger.Error("handleRequestModeration: lookup failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to open moderation request"})
		return
	}

	expiresAt := time.Now().Add(moderationWaitWindow)
	var id string
	if err := s.db.Pool.QueryRow(ctx,
		`INSERT INTO guacamole_moderation_sessions
		     (org_id, connection_id, requester_id, reason, status, expires_at)
		 VALUES ($1, $2, $3, NULLIF($4,''), 'pending', $5)
		 RETURNING id`,
		org.ID, connectionID, userID, body.Reason, expiresAt).Scan(&id); err != nil {
		s.logger.Error("handleRequestModeration: insert failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to open moderation request"})
		return
	}
	s.logAuditEvent(c, "pam.moderation.requested", id, "moderation_session", map[string]interface{}{
		"connection_id": connectionID, "requester_id": userID, "reason": body.Reason,
	})
	c.JSON(http.StatusCreated, gin.H{"id": id, "status": "pending", "expires_at": expiresAt})
}

// handleGetModerationStatus — GET /pam/moderation/:id (requester or moderator).
// Returns the current state so the requester can poll until 'active'.
func (s *Service) handleGetModerationStatus(c *gin.Context) {
	id := c.Param("id")
	ctx := c.Request.Context()
	if _, err := orgctx.From(ctx); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	var status string
	var moderatorID, activeConnID *string
	var joinedAt, expiresAt *time.Time
	err := s.db.Pool.QueryRow(ctx,
		`SELECT status, moderator_id::text, active_conn_id, joined_at, expires_at
		   FROM guacamole_moderation_sessions WHERE id = $1`, id).
		Scan(&status, &moderatorID, &activeConnID, &joinedAt, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "moderation session not found"})
		return
	}
	if err != nil {
		s.logger.Error("handleGetModerationStatus: query failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load moderation session"})
		return
	}
	// Lazily mark an over-window pending request as expired so pollers see a
	// terminal state without waiting for a sweeper.
	if status == "pending" && expiresAt != nil && time.Now().After(*expiresAt) {
		//orgscope:ignore RLS scopes by the request ctx org; row identified by PK
		_, _ = s.db.Pool.Exec(ctx,
			`UPDATE guacamole_moderation_sessions SET status='expired', ended_at=NOW()
			  WHERE id=$1 AND status='pending'`, id)
		status = "expired"
	}
	c.JSON(http.StatusOK, gin.H{
		"id": id, "status": status,
		"moderator_id": moderatorID, "active_conn_id": activeConnID,
		"joined_at": joinedAt, "expires_at": expiresAt,
	})
}

// ---- moderator side ----

// handleListPendingModeration — GET /pam/moderation/pending (admin/moderator).
// The moderator queue: every pending, unexpired moderation request in the org.
func (s *Service) handleListPendingModeration(c *gin.Context) {
	ctx := c.Request.Context()
	if _, err := orgctx.From(ctx); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	rows, err := s.db.Pool.Query(ctx,
		`SELECT m.id, m.connection_id, m.requester_id::text, COALESCE(m.reason,''),
		        m.created_at, m.expires_at, COALESCE(gc.hostname,'')
		   FROM guacamole_moderation_sessions m
		   LEFT JOIN guacamole_connections gc ON gc.id = m.connection_id
		  WHERE m.status = 'pending' AND (m.expires_at IS NULL OR m.expires_at > NOW())
		  ORDER BY m.created_at ASC`)
	if err != nil {
		s.logger.Error("handleListPendingModeration: query failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list pending moderation"})
		return
	}
	defer rows.Close()
	type item struct {
		ID           string     `json:"id"`
		ConnectionID string     `json:"connection_id"`
		RequesterID  string     `json:"requester_id"`
		Reason       string     `json:"reason"`
		CreatedAt    time.Time  `json:"created_at"`
		ExpiresAt    *time.Time `json:"expires_at"`
		Connection   string     `json:"connection"`
	}
	var out []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.ID, &it.ConnectionID, &it.RequesterID, &it.Reason,
			&it.CreatedAt, &it.ExpiresAt, &it.Connection); err != nil {
			s.logger.Warn("handleListPendingModeration: scan failed", zap.Error(err))
			continue
		}
		out = append(out, it)
	}
	c.JSON(http.StatusOK, gin.H{"pending": out})
}

// handleJoinModeration — POST /pam/moderation/:id/join (admin/moderator).
// A moderator claims a pending request, transitioning it to 'active' so the
// requester's blocked connect can proceed. Atomic UPDATE…WHERE status='pending'
// so two moderators can't both claim it and a requester can't self-approve.
func (s *Service) handleJoinModeration(c *gin.Context) {
	id := c.Param("id")
	ctx := c.Request.Context()
	if _, err := orgctx.From(ctx); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	moderatorID := c.GetString("user_id")
	if moderatorID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}

	// A moderator must not moderate their own session (four-eyes). Reject when
	// the claimer is the requester.
	var requesterID string
	var claimed string
	err := s.db.Pool.QueryRow(ctx,
		`UPDATE guacamole_moderation_sessions
		    SET status = 'active', moderator_id = $2, joined_at = NOW()
		  WHERE id = $1 AND status = 'pending'
		    AND (expires_at IS NULL OR expires_at > NOW())
		    AND requester_id <> $2
		  RETURNING id, requester_id::text`,
		id, moderatorID).Scan(&claimed, &requesterID)
	if errors.Is(err, pgx.ErrNoRows) {
		// Either already claimed/expired, or the caller is the requester.
		c.JSON(http.StatusConflict, gin.H{"error": "request is not pending, already claimed, expired, or you are the requester"})
		return
	}
	if err != nil {
		s.logger.Error("handleJoinModeration: update failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to join moderation"})
		return
	}
	s.logAuditEvent(c, "pam.moderation.joined", id, "moderation_session", map[string]interface{}{
		"moderator_id": moderatorID, "requester_id": requesterID,
	})
	c.JSON(http.StatusOK, gin.H{"id": id, "status": "active", "moderator_id": moderatorID})
}

// handleEndModeration — POST /pam/moderation/:id/end (requester or moderator).
// Terminates the moderation session. If a Guacamole active-connection is
// associated, best-effort terminates it too so ending moderation ends the
// underlying privileged session (the moderator's kill switch).
func (s *Service) handleEndModeration(c *gin.Context) {
	id := c.Param("id")
	ctx := c.Request.Context()
	if _, err := orgctx.From(ctx); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	actor := c.GetString("user_id")

	var activeConnID *string
	err := s.db.Pool.QueryRow(ctx,
		`UPDATE guacamole_moderation_sessions
		    SET status = 'ended', ended_at = NOW()
		  WHERE id = $1 AND status IN ('pending','active')
		  RETURNING active_conn_id`,
		id).Scan(&activeConnID)
	if errors.Is(err, pgx.ErrNoRows) {
		c.JSON(http.StatusConflict, gin.H{"error": "moderation session is not active"})
		return
	}
	if err != nil {
		s.logger.Error("handleEndModeration: update failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to end moderation"})
		return
	}
	if activeConnID != nil && *activeConnID != "" && s.guacamoleClient != nil {
		if termErr := s.guacamoleClient.TerminateSession(ctx, *activeConnID); termErr != nil {
			s.logger.Warn("handleEndModeration: terminate underlying session failed",
				zap.String("active_conn_id", *activeConnID), zap.Error(termErr))
		}
	}
	s.logAuditEvent(c, "pam.moderation.ended", id, "moderation_session", map[string]interface{}{
		"ended_by": actor,
	})
	c.JSON(http.StatusOK, gin.H{"id": id, "status": "ended"})
}
