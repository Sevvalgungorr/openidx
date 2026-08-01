// Package identity - HTTP handlers for advanced MFA features
package identity

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	apperrors "github.com/openidx/openidx/internal/common/errors"
)

// identityCallerIsAdmin reports whether the authenticated caller holds an
// administrative role, for handlers that need their own authorization check
// on top of (or instead of) the route-level gate.
//
// It accepts both spellings of the elevated role deliberately: the shared
// middleware (requireAdminUnlessSelfService) matches "super_admin" while the
// inline checks in this file historically matched "superadmin". Accepting
// either avoids locking a legitimate super admin out of a route that the
// middleware already let through. Unifying the two spellings repo-wide is a
// separate cleanup.
func identityCallerIsAdmin(c *gin.Context) bool {
	for _, role := range c.GetStringSlice("roles") {
		if role == "admin" || role == "superadmin" || role == "super_admin" {
			return true
		}
	}
	return false
}

// ========================================
// Hardware Token Handlers
// ========================================

func (s *Service) handleListHardwareTokens(c *gin.Context) {
	status := c.Query("status")
	assignedTo := c.Query("assigned_to")

	tokens, err := s.ListHardwareTokens(c.Request.Context(), status, assignedTo)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("list hardware tokens", err), s.logger)
		return
	}

	c.JSON(http.StatusOK, gin.H{"tokens": tokens, "total": len(tokens)})
}

func (s *Service) handleCreateHardwareToken(c *gin.Context) {
	adminID := c.GetString("user_id")
	if adminID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var req CreateHardwareTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	token, err := s.CreateHardwareToken(c.Request.Context(), &req, adminID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, token)
}

func (s *Service) handleGetHardwareToken(c *gin.Context) {
	tokenID := c.Param("token_id")

	token, err := s.GetHardwareToken(c.Request.Context(), tokenID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "token not found"})
		return
	}

	c.JSON(http.StatusOK, token)
}

func (s *Service) handleAssignHardwareToken(c *gin.Context) {
	tokenID := c.Param("token_id")
	adminID := c.GetString("user_id")

	var req struct {
		UserID string `json:"user_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := s.AssignHardwareToken(c.Request.Context(), tokenID, req.UserID, adminID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "token assigned successfully"})
}

func (s *Service) handleUnassignHardwareToken(c *gin.Context) {
	tokenID := c.Param("token_id")
	adminID := c.GetString("user_id")

	if err := s.UnassignHardwareToken(c.Request.Context(), tokenID, adminID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "token unassigned successfully"})
}

func (s *Service) handleRevokeHardwareToken(c *gin.Context) {
	tokenID := c.Param("token_id")
	adminID := c.GetString("user_id")

	var req struct {
		Reason string `json:"reason"`
	}
	c.ShouldBindJSON(&req)

	if err := s.RevokeHardwareToken(c.Request.Context(), tokenID, adminID, req.Reason); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "token revoked"})
}

func (s *Service) handleReportTokenLost(c *gin.Context) {
	tokenID := c.Param("token_id")
	userID := c.GetString("user_id")

	if err := s.ReportTokenLost(c.Request.Context(), tokenID, userID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "token reported as lost"})
}

func (s *Service) handleVerifyHardwareToken(c *gin.Context) {
	userID := c.GetString("user_id")

	var req struct {
		OTP string `json:"otp"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	valid, err := s.VerifyHardwareToken(c.Request.Context(), userID, req.OTP, c.ClientIP(), c.GetHeader("User-Agent"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"valid": valid})
}

func (s *Service) handleGetUserHardwareToken(c *gin.Context) {
	userID := c.GetString("user_id")

	token, err := s.GetUserHardwareToken(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "no token assigned"})
		return
	}

	c.JSON(http.StatusOK, token)
}

func (s *Service) handleGetTokenEvents(c *gin.Context) {
	tokenID := c.Param("token_id")

	events, err := s.GetTokenEvents(c.Request.Context(), tokenID, 50)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("get token events", err), s.logger)
		return
	}

	c.JSON(http.StatusOK, gin.H{"events": events})
}

// ========================================
// Phone Call MFA Handlers
// ========================================

func (s *Service) handleEnrollPhoneCall(c *gin.Context) {
	userID := c.GetString("user_id")

	var req struct {
		PhoneNumber string `json:"phone_number"`
		CountryCode string `json:"country_code"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	challenge, err := s.EnrollPhoneCall(c.Request.Context(), userID, req.PhoneNumber, req.CountryCode)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"challenge_id": challenge.ID,
		"status":       challenge.Status,
		"expires_at":   challenge.ExpiresAt,
		"message":      "Verification call initiated",
	})
}

func (s *Service) handleVerifyPhoneCallEnrollment(c *gin.Context) {
	userID := c.GetString("user_id")

	var req struct {
		Code string `json:"code"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := s.VerifyPhoneCallChallenge(c.Request.Context(), userID, req.Code); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Phone call MFA enabled successfully"})
}

func (s *Service) handleGetPhoneCallStatus(c *gin.Context) {
	userID := c.GetString("user_id")

	enrollment, err := s.GetPhoneCallEnrollment(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"enrolled": false})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"enrolled":       true,
		"phone_number":   enrollment.PhoneNumber,
		"verified":       enrollment.Verified,
		"enabled":        enrollment.Enabled,
		"voice_language": enrollment.VoiceLanguage,
	})
}

func (s *Service) handleDeletePhoneCall(c *gin.Context) {
	userID := c.GetString("user_id")

	if err := s.DeletePhoneCallEnrollment(c.Request.Context(), userID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Phone call MFA removed"})
}

func (s *Service) handleRequestCallback(c *gin.Context) {
	userID := c.GetString("user_id")

	challenge, err := s.RequestCallback(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"challenge_id": challenge.ID,
		"status":       challenge.Status,
		"message":      "Please call the verification number",
	})
}

// ========================================
// Device Trust Approval Handlers
// ========================================

func (s *Service) handleListDeviceTrustRequests(c *gin.Context) {
	status := c.Query("status")
	requestedUserID := c.Query("user_id")
	authUserID := c.GetString("user_id")
	authRoles := c.GetStringSlice("roles")

	// SECURITY: IDOR fix - Only allow admin to query arbitrary users' requests
	if requestedUserID != "" && requestedUserID != authUserID {
		isAdmin := false
		for _, role := range authRoles {
			if role == "admin" || role == "superadmin" {
				isAdmin = true
				break
			}
		}
		if !isAdmin {
			c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions to view other users' requests"})
			return
		}
	} else if requestedUserID == "" {
		// Non-admin users can only view their own requests
		isAdmin := false
		for _, role := range authRoles {
			if role == "admin" || role == "superadmin" {
				isAdmin = true
				break
			}
		}
		if !isAdmin {
			requestedUserID = authUserID
		}
	}

	limit := 50
	offset := 0

	requests, total, err := s.ListDeviceTrustRequests(c.Request.Context(), status, requestedUserID, limit, offset)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("list device trust requests", err), s.logger)
		return
	}

	c.JSON(http.StatusOK, gin.H{"requests": requests, "total": total})
}

func (s *Service) handleApproveDeviceTrust(c *gin.Context) {
	requestID := c.Param("request_id")
	adminID := c.GetString("user_id")

	var req struct {
		Notes string `json:"notes"`
	}
	c.ShouldBindJSON(&req)

	if err := s.ApproveDeviceTrustRequest(c.Request.Context(), requestID, adminID, req.Notes); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Device trust approved"})
}

func (s *Service) handleRejectDeviceTrust(c *gin.Context) {
	requestID := c.Param("request_id")
	adminID := c.GetString("user_id")

	var req struct {
		Notes string `json:"notes"`
	}
	c.ShouldBindJSON(&req)

	if err := s.RejectDeviceTrustRequest(c.Request.Context(), requestID, adminID, req.Notes); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Device trust rejected"})
}

func (s *Service) handleBulkApproveDeviceTrust(c *gin.Context) {
	adminID := c.GetString("user_id")

	var req struct {
		RequestIDs []string `json:"request_ids"`
		Notes      string   `json:"notes"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	approved, failed, _ := s.BulkApproveDeviceTrustRequests(c.Request.Context(), req.RequestIDs, adminID, req.Notes)

	c.JSON(http.StatusOK, gin.H{"approved": approved, "failed": failed})
}

func (s *Service) handleBulkRejectDeviceTrust(c *gin.Context) {
	adminID := c.GetString("user_id")

	var req struct {
		RequestIDs []string `json:"request_ids"`
		Notes      string   `json:"notes"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	rejected, failed, _ := s.BulkRejectDeviceTrustRequests(c.Request.Context(), req.RequestIDs, adminID, req.Notes)

	c.JSON(http.StatusOK, gin.H{"rejected": rejected, "failed": failed})
}

func (s *Service) handleGetDeviceTrustSettings(c *gin.Context) {
	settings, err := s.GetDeviceTrustSettings(c.Request.Context())
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("get device trust settings", err), s.logger)
		return
	}

	c.JSON(http.StatusOK, settings)
}

func (s *Service) handleUpdateDeviceTrustSettings(c *gin.Context) {
	var settings DeviceTrustSettings
	if err := c.ShouldBindJSON(&settings); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := s.UpdateDeviceTrustSettings(c.Request.Context(), &settings); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Settings updated"})
}

func (s *Service) handleGetPendingTrustCount(c *gin.Context) {
	count, _ := s.GetPendingRequestCount(c.Request.Context())
	c.JSON(http.StatusOK, gin.H{"count": count})
}

// ========================================
// MFA Bypass Code Handlers
// ========================================

func (s *Service) handleGenerateBypassCode(c *gin.Context) {
	adminID := c.GetString("user_id")

	// SECURITY: a bypass code is a break-glass MFA override for an arbitrary
	// target user (req.UserID), so only an admin may mint one. The route is
	// also excluded from isIdentitySelfService so the shared admin gate
	// applies; this in-handler check is defense in depth, matching the
	// pattern already used by the sibling read handlers below.
	if !identityCallerIsAdmin(c) {
		c.JSON(http.StatusForbidden, gin.H{"error": "admin role required to generate MFA bypass codes"})
		return
	}

	var req GenerateBypassCodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	code, err := s.GenerateMFABypassCode(c.Request.Context(), &req, adminID, c.ClientIP())
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, code)
}

func (s *Service) handleListBypassCodes(c *gin.Context) {
	requestedUserID := c.Query("user_id")
	status := c.Query("status")
	activeOnly := c.Query("active_only") == "true"
	authUserID := c.GetString("user_id")
	authRoles := c.GetStringSlice("roles")

	// SECURITY: IDOR fix - Only allow admin to query arbitrary users' bypass codes
	if requestedUserID != "" && requestedUserID != authUserID {
		isAdmin := false
		for _, role := range authRoles {
			if role == "admin" || role == "superadmin" {
				isAdmin = true
				break
			}
		}
		if !isAdmin {
			c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions to view other users' bypass codes"})
			return
		}
	} else if requestedUserID == "" {
		// Non-admin users can only view their own codes
		isAdmin := false
		for _, role := range authRoles {
			if role == "admin" || role == "superadmin" {
				isAdmin = true
				break
			}
		}
		if !isAdmin {
			requestedUserID = authUserID
		}
	}

	codes, total, err := s.ListBypassCodes(c.Request.Context(), requestedUserID, status, activeOnly, 50, 0)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("list bypass codes", err), s.logger)
		return
	}

	c.JSON(http.StatusOK, gin.H{"codes": codes, "total": total})
}

func (s *Service) handleRevokeBypassCode(c *gin.Context) {
	codeID := c.Param("code_id")
	adminID := c.GetString("user_id")

	if err := s.RevokeBypassCode(c.Request.Context(), codeID, adminID, c.ClientIP()); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Bypass code revoked"})
}

func (s *Service) handleRevokeAllBypassCodes(c *gin.Context) {
	requestedUserID := c.Param("user_id")
	adminID := c.GetString("user_id")
	authRoles := c.GetStringSlice("roles")

	// SECURITY: IDOR fix - Only allow admin to revoke other users' bypass codes
	if requestedUserID != adminID {
		isAdmin := false
		for _, role := range authRoles {
			if role == "admin" || role == "superadmin" {
				isAdmin = true
				break
			}
		}
		if !isAdmin {
			c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions to revoke other users' bypass codes"})
			return
		}
	}

	count, err := s.RevokeAllBypassCodes(c.Request.Context(), requestedUserID, adminID, c.ClientIP())
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"revoked_count": count})
}

func (s *Service) handleVerifyBypassCode(c *gin.Context) {
	userID := c.GetString("user_id")

	var req struct {
		Code string `json:"code"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	valid, err := s.VerifyBypassCode(c.Request.Context(), userID, req.Code, c.ClientIP(), c.GetHeader("User-Agent"))
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("verify bypass code", err), s.logger)
		return
	}

	c.JSON(http.StatusOK, gin.H{"valid": valid})
}

func (s *Service) handleGetBypassAuditLog(c *gin.Context) {
	requestedUserID := c.Query("user_id")
	authUserID := c.GetString("user_id")
	authRoles := c.GetStringSlice("roles")

	// SECURITY: IDOR fix - Only allow admin to query arbitrary users' audit logs
	if requestedUserID != "" && requestedUserID != authUserID {
		isAdmin := false
		for _, role := range authRoles {
			if role == "admin" || role == "superadmin" {
				isAdmin = true
				break
			}
		}
		if !isAdmin {
			c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions to view other users' audit logs"})
			return
		}
	} else if requestedUserID == "" {
		// Non-admin users can only view their own logs
		isAdmin := false
		for _, role := range authRoles {
			if role == "admin" || role == "superadmin" {
				isAdmin = true
				break
			}
		}
		if !isAdmin {
			requestedUserID = authUserID
		}
	}

	entries, err := s.GetBypassAuditLog(c.Request.Context(), requestedUserID, 100, 0)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("get bypass audit log", err), s.logger)
		return
	}

	c.JSON(http.StatusOK, gin.H{"entries": entries})
}

// ========================================
// Passwordless Authentication Handlers
// ========================================

func (s *Service) handleCreateMagicLink(c *gin.Context) {
	var req struct {
		Email       string `json:"email"`
		Purpose     string `json:"purpose"`
		RedirectURL string `json:"redirect_url"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	link, err := s.CreateMagicLink(c.Request.Context(), req.Email, req.Purpose, req.RedirectURL, c.ClientIP(), c.GetHeader("User-Agent"))
	if err != nil {
		// Do not leak whether the account exists — return the same generic
		// response the OAuth passwordless flow uses.
		s.logger.Debug("magic link creation failed (may be an unknown email)", zap.Error(err))
		c.JSON(http.StatusOK, gin.H{"message": "If an account exists with that email, a magic link has been sent."})
		return
	}

	// Deliver the link by email. Previously this handler RETURNED the raw token in
	// the JSON body ("for testing"), which leaks a one-time credential on a routed
	// endpoint. Send it instead and never echo the token. Failures are logged but
	// not surfaced, so we don't reveal account existence.
	base := strings.TrimRight(s.cfg.OAuthIssuer, "/")
	verifyURL := base + "/oauth/magic-link-verify?token=" + url.QueryEscape(link.Token)
	if err := s.SendMagicLinkEmail(c.Request.Context(), req.Email, verifyURL); err != nil {
		s.logger.Error("failed to send magic link email", zap.Error(err))
	}

	c.JSON(http.StatusOK, gin.H{
		"message":    "If an account exists with that email, a magic link has been sent.",
		"expires_at": link.ExpiresAt,
	})
}

func (s *Service) handleVerifyMagicLink(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		var req struct {
			Token string `json:"token"`
		}
		c.ShouldBindJSON(&req)
		token = req.Token
	}

	userID, purpose, err := s.VerifyMagicLink(c.Request.Context(), token, c.ClientIP(), c.GetHeader("User-Agent"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user_id": userID,
		"purpose": purpose,
		"message": "Magic link verified",
	})
}

func (s *Service) handleCreateQRLoginSession(c *gin.Context) {
	browserInfo := map[string]interface{}{
		"user_agent": c.GetHeader("User-Agent"),
	}

	session, err := s.CreateQRLoginSession(c.Request.Context(), c.ClientIP(), browserInfo)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("create q r login session", err), s.logger)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"session_token": session.SessionToken,
		"qr_code_data":  session.QRCodeData,
		"expires_at":    session.ExpiresAt,
	})
}

func (s *Service) handleScanQRLogin(c *gin.Context) {
	userID := c.GetString("user_id")

	var req struct {
		SessionToken string                 `json:"session_token"`
		MobileInfo   map[string]interface{} `json:"mobile_info"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	session, err := s.ScanQRLoginSession(c.Request.Context(), req.SessionToken, userID, req.MobileInfo)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  session.Status,
		"message": "QR code scanned. Please approve on your mobile device.",
	})
}

func (s *Service) handleApproveQRLogin(c *gin.Context) {
	userID := c.GetString("user_id")

	var req struct {
		SessionToken string `json:"session_token"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := s.ApproveQRLoginSession(c.Request.Context(), req.SessionToken, userID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "QR login approved"})
}

func (s *Service) handleRejectQRLogin(c *gin.Context) {
	var req struct {
		SessionToken string `json:"session_token"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := s.RejectQRLoginSession(c.Request.Context(), req.SessionToken); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "QR login rejected"})
}

func (s *Service) handlePollQRLoginSession(c *gin.Context) {
	sessionToken := c.Query("session_token")

	status, userID, err := s.PollQRLoginSession(c.Request.Context(), sessionToken)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  status,
		"user_id": userID,
	})
}

func (s *Service) handleGetPasswordlessPreferences(c *gin.Context) {
	userID := c.GetString("user_id")

	prefs, err := s.GetPasswordlessPreferences(c.Request.Context(), userID)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("get passwordless preferences", err), s.logger)
		return
	}

	c.JSON(http.StatusOK, prefs)
}

func (s *Service) handleUpdatePasswordlessPreferences(c *gin.Context) {
	userID := c.GetString("user_id")

	var prefs PasswordlessPreferences
	if err := c.ShouldBindJSON(&prefs); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := s.UpdatePasswordlessPreferences(c.Request.Context(), userID, &prefs); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Preferences updated"})
}

// ========================================
// Biometric Authentication Handlers
// ========================================

func (s *Service) handleGetBiometricPreferences(c *gin.Context) {
	userID := c.GetString("user_id")

	prefs, err := s.GetBiometricPreferences(c.Request.Context(), userID)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("get biometric preferences", err), s.logger)
		return
	}

	c.JSON(http.StatusOK, prefs)
}

func (s *Service) handleUpdateBiometricPreferences(c *gin.Context) {
	userID := c.GetString("user_id")

	var prefs BiometricPreferences
	if err := c.ShouldBindJSON(&prefs); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := s.UpdateBiometricPreferences(c.Request.Context(), userID, &prefs); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Preferences updated"})
}

func (s *Service) handleEnableBiometricOnly(c *gin.Context) {
	userID := c.GetString("user_id")

	if err := s.EnableBiometricOnly(c.Request.Context(), userID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Biometric-only login enabled"})
}

func (s *Service) handleDisableBiometricOnly(c *gin.Context) {
	userID := c.GetString("user_id")

	if err := s.DisableBiometricOnly(c.Request.Context(), userID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Biometric-only login disabled"})
}

func (s *Service) handleListBiometricPolicies(c *gin.Context) {
	policies, err := s.ListBiometricPolicies(c.Request.Context())
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("list biometric policies", err), s.logger)
		return
	}

	c.JSON(http.StatusOK, gin.H{"policies": policies})
}

func (s *Service) handleCreateBiometricPolicy(c *gin.Context) {
	var policy BiometricPolicy
	if err := c.ShouldBindJSON(&policy); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	created, err := s.CreateBiometricPolicy(c.Request.Context(), &policy)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, created)
}

func (s *Service) handleUpdateBiometricPolicy(c *gin.Context) {
	policyID := c.Param("policy_id")

	var policy BiometricPolicy
	if err := c.ShouldBindJSON(&policy); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	policy.ID = policyID

	if err := s.UpdateBiometricPolicy(c.Request.Context(), &policy); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Policy updated"})
}

func (s *Service) handleDeleteBiometricPolicy(c *gin.Context) {
	policyID := c.Param("policy_id")

	if err := s.DeleteBiometricPolicy(c.Request.Context(), policyID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Policy deleted"})
}

func (s *Service) handleGetPlatformAuthenticators(c *gin.Context) {
	userID := c.GetString("user_id")

	authenticators, err := s.GetUserPlatformAuthenticators(c.Request.Context(), userID)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("get platform authenticators", err), s.logger)
		return
	}

	c.JSON(http.StatusOK, gin.H{"authenticators": authenticators})
}
