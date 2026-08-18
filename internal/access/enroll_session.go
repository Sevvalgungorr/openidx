package access

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// enrollmentSession is a row of the enrollment_sessions table (migration v132):
// the unified onboarding primitive that ties a short code / QR / deep-link to
// the MFA-verified console session that created it.
type enrollmentSession struct {
	ID           string
	CreatedByUID string
	OrgID        string
	MFAVerified  bool
	Status       string
	AgentID      string
	Trusted      bool
}

// amrIndicatesMFA reports whether an OIDC amr claim shows a real second factor
// was used (not just a password). Absent/unknown → false (no auto-trust).
func amrIndicatesMFA(amr []string) bool {
	for _, m := range amr {
		switch strings.ToLower(strings.TrimSpace(m)) {
		case "mfa", "otp", "totp", "webauthn", "hwk", "swk", "sms", "u2f", "pop", "fpt", "face":
			return true
		}
	}
	return false
}

// enrollServerURL is the base URL the agent should target for /agent/enroll,
// embedded in the deep-link. Prefers the configured public origin, else derives
// it from the incoming request.
func (h *AgentAPIHandler) enrollServerURL(c *gin.Context) string {
	if h.zm != nil && h.zm.cfg != nil && strings.TrimSpace(h.zm.cfg.PublicBaseURL) != "" {
		return strings.TrimRight(h.zm.cfg.PublicBaseURL, "/")
	}
	scheme := "https"
	if c.Request.TLS == nil && c.GetHeader("X-Forwarded-Proto") == "" {
		scheme = "http"
	}
	return scheme + "://" + c.Request.Host
}

func (h *AgentAPIHandler) enrollSessionTTL() time.Duration {
	mins := 15
	if h.zm != nil && h.zm.cfg != nil && h.zm.cfg.EnrollSessionTTLMinutes > 0 {
		mins = h.zm.cfg.EnrollSessionTTLMinutes
	}
	return time.Duration(mins) * time.Minute
}

// HandleCreateEnrollSession (POST /agent/enroll/session) starts a unified
// onboarding session for the authenticated user: it mints a normal single-use
// agent_enrollment_token, records an enrollment_sessions row tying that token to
// the user + org + server-verified MFA state, and returns the code + deep-link
// the wizard renders as a QR / copyable code. Redemption flows through the
// unchanged HandleEnroll path.
func (h *AgentAPIHandler) HandleCreateEnrollSession(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}
	orgID := c.GetString("org_id")
	mfaVerified := amrIndicatesMFA(c.GetStringSlice("amr"))

	if h.db == nil || h.db.Pool == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "enrollment sessions require a database"})
		return
	}
	ctx := c.Request.Context()

	// The enrollment token IS the code (high-entropy, single-use). It is carried
	// in the QR / deep-link and used by the agent as its enrollment bearer, so no
	// separate (leaky) short-code→token resolve endpoint is needed.
	token := uuid.New().String()
	tokenHash := sha256Hex(token)
	expiresAt := time.Now().UTC().Add(h.enrollSessionTTL())

	if _, err := h.db.Pool.Exec(ctx, `
		INSERT INTO agent_enrollment_tokens (token_hash, description, created_by, expires_at, reusable)
		VALUES ($1, $2, $3, $4, false)
	`, tokenHash, "enrollment session", userID, expiresAt); err != nil {
		h.logger.Error("HandleCreateEnrollSession: token insert failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to start enrollment session"})
		return
	}

	var sessionID string
	if err := h.db.Pool.QueryRow(ctx, `
		INSERT INTO enrollment_sessions (short_code, token_hash, created_by_user_id, org_id, mfa_verified, status, expires_at)
		VALUES ($1, $2, $3, $4, $5, 'pending', $6)
		RETURNING id
	`, token, tokenHash, userID, orgID, mfaVerified, expiresAt).Scan(&sessionID); err != nil {
		h.logger.Error("HandleCreateEnrollSession: session insert failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to start enrollment session"})
		return
	}

	server := h.enrollServerURL(c)
	deepLink := fmt.Sprintf("openidx://enroll?code=%s&server=%s", token, server)

	h.logAuditEventToDB(ctx, "enroll.session_created", sessionID, "success", "user="+userID)
	c.JSON(http.StatusOK, gin.H{
		"id":         sessionID,
		"code":       token,
		"deep_link":  deepLink,
		"server":     server,
		"expires_at": expiresAt.Format(time.RFC3339),
	})
}

// HandleEnrollSessionStatus (GET /agent/enroll/session/:id/status) lets the
// wizard poll for completion. Scoped in-query to the creating user so one tenant
// cannot read another's session.
func (h *AgentAPIHandler) HandleEnrollSessionStatus(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}
	if h.db == nil || h.db.Pool == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "unavailable"})
		return
	}
	var status, agentID string
	var trusted bool
	err := h.db.Pool.QueryRow(c.Request.Context(), `
		SELECT status, COALESCE(agent_id,''), trusted
		FROM enrollment_sessions
		WHERE id = $1 AND created_by_user_id = $2
	`, c.Param("id"), userID).Scan(&status, &agentID, &trusted)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": status, "agent_id": agentID, "device_trusted": trusted})
}

// HandleCancelEnrollSession (DELETE /agent/enroll/session/:id) cancels a pending
// session and revokes its underlying token.
func (h *AgentAPIHandler) HandleCancelEnrollSession(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}
	if h.db == nil || h.db.Pool == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "unavailable"})
		return
	}
	ctx := c.Request.Context()
	var tokenHash string
	err := h.db.Pool.QueryRow(ctx, `
		UPDATE enrollment_sessions SET status = 'canceled'
		WHERE id = $1 AND created_by_user_id = $2 AND status = 'pending'
		RETURNING token_hash
	`, c.Param("id"), userID).Scan(&tokenHash)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found or not cancelable"})
		return
	}
	_, _ = h.db.Pool.Exec(ctx, `UPDATE agent_enrollment_tokens SET revoked = true WHERE token_hash = $1`, tokenHash)
	c.JSON(http.StatusOK, gin.H{"status": "canceled"})
}

// lookupEnrollmentSession returns the pending, unexpired enrollment session for
// a token hash, or nil. Read by the public /agent/enroll path (no tenant JWT);
// enrollment_sessions is a global table like agent_enrollment_tokens, so no RLS
// bypass is needed for this high-entropy-keyed read.
func (h *AgentAPIHandler) lookupEnrollmentSession(ctx context.Context, tokenHash string) *enrollmentSession {
	if h.db == nil || h.db.Pool == nil {
		return nil
	}
	var s enrollmentSession
	err := h.db.Pool.QueryRow(ctx, `
		SELECT id, created_by_user_id, org_id, mfa_verified, status
		FROM enrollment_sessions
		WHERE token_hash = $1 AND status = 'pending' AND expires_at > NOW()
	`, tokenHash).Scan(&s.ID, &s.CreatedByUID, &s.OrgID, &s.MFAVerified, &s.Status)
	if err != nil {
		return nil
	}
	return &s
}

// markEnrollmentSessionEnrolled records the outcome of a redeemed session.
func (h *AgentAPIHandler) markEnrollmentSessionEnrolled(ctx context.Context, sessionID, agentID, deviceID string, trusted bool) {
	if h.db == nil || h.db.Pool == nil {
		return
	}
	if _, err := h.db.Pool.Exec(ctx, `
		UPDATE enrollment_sessions
		SET status = 'enrolled', agent_id = $2, device_id = $3, trusted = $4, enrolled_at = NOW()
		WHERE id = $1
	`, sessionID, agentID, deviceID, trusted); err != nil {
		h.logger.Warn("markEnrollmentSessionEnrolled failed",
			zap.String("session_id", sessionID), zap.Error(err))
	}
}
