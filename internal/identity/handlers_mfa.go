// Package identity - MFA HTTP handlers
package identity

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	apperrors "github.com/openidx/openidx/internal/common/errors"
)

// WebAuthn Handlers

func (s *Service) handleBeginWebAuthnRegistration(c *gin.Context) {
	// CRITICAL: Only get user ID from authenticated context
	// NEVER allow user_id from query/header/request body to prevent IDOR attacks
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}

	options, err := s.BeginWebAuthnRegistration(c.Request.Context(), userID)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("begin web authn registration", err), s.logger)
		return
	}

	c.JSON(http.StatusOK, options)
}

func (s *Service) handleFinishWebAuthnRegistration(c *gin.Context) {
	// CRITICAL: Only get user ID from authenticated context
	// NEVER allow user_id from query/header/request body to prevent IDOR attacks
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}

	// Parse credential name from query or header (these are metadata, not identifiers)
	credentialName := c.Query("name")
	if credentialName == "" {
		credentialName = c.GetHeader("X-Credential-Name")
	}

	// Parse WebAuthn response
	parsedResponse, err := protocol.ParseCredentialCreationResponseBody(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid WebAuthn response: " + err.Error()})
		return
	}

	credential, err := s.FinishWebAuthnRegistration(c.Request.Context(), userID, credentialName, parsedResponse)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("finish web authn registration", err), s.logger)
		return
	}

	c.JSON(http.StatusCreated, credential)
}

func (s *Service) handleBeginWebAuthnAuthentication(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Username == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username is required"})
		return
	}

	options, err := s.BeginWebAuthnAuthentication(c.Request.Context(), req.Username)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("begin web authn authentication", err), s.logger)
		return
	}

	c.JSON(http.StatusOK, options)
}

func (s *Service) handleFinishWebAuthnAuthentication(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
	}

	// Parse username from request
	username := c.Query("username")
	if username == "" {
		if err := c.ShouldBindJSON(&req); err == nil {
			username = req.Username
		}
	}

	if username == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username is required"})
		return
	}

	// Parse WebAuthn response
	parsedResponse, err := protocol.ParseCredentialRequestResponseBody(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid WebAuthn response: " + err.Error()})
		return
	}

	userID, err := s.FinishWebAuthnAuthentication(c.Request.Context(), username, parsedResponse)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	// In production, this would generate a JWT token
	c.JSON(http.StatusOK, gin.H{
		"authenticated": true,
		"user_id":       userID,
		"method":        "webauthn",
	})
}

func (s *Service) handleGetWebAuthnCredentials(c *gin.Context) {
	// CRITICAL: Only get user ID from authenticated context
	// NEVER allow user_id from query/header/request body to prevent IDOR attacks
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}

	credentials, err := s.GetWebAuthnCredentials(c.Request.Context(), userID)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("get web authn credentials", err), s.logger)
		return
	}

	c.JSON(http.StatusOK, credentials)
}

func (s *Service) handleDeleteWebAuthnCredential(c *gin.Context) {
	// CRITICAL: Only get user ID from authenticated context
	// NEVER allow user_id from query/header/request body to prevent IDOR attacks
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}

	credentialID := c.Param("credential_id")

	if credentialID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "credential_id is required"})
		return
	}

	if err := s.DeleteWebAuthnCredential(c.Request.Context(), userID, credentialID); err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("delete web authn credential", err), s.logger)
		return
	}

	c.JSON(http.StatusNoContent, nil)
}

// Push MFA Handlers

func (s *Service) handleRegisterPushDevice(c *gin.Context) {
	// CRITICAL: Only get user ID from authenticated context
	// NEVER allow user_id from query/header/request body to prevent IDOR attacks
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}

	var enrollment PushMFAEnrollment
	if err := c.ShouldBindJSON(&enrollment); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get client IP
	ipAddress := c.ClientIP()

	device, err := s.RegisterPushMFADevice(c.Request.Context(), userID, &enrollment, ipAddress)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("register push device", err), s.logger)
		return
	}

	c.JSON(http.StatusCreated, device)
}

// handleStartPushEnrollment mints a QR enrollment ticket for the authenticated
// user. The console/app renders the returned qr_payload as a QR code that an
// authenticator scans to bind itself as a push device.
// POST /api/v1/identity/mfa/push/enroll/start
func (s *Service) handleStartPushEnrollment(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}

	ticket, err := s.StartPushEnrollment(c.Request.Context(), userID)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("start push enrollment", err), s.logger)
		return
	}
	c.JSON(http.StatusOK, ticket)
}

// handleCompletePushEnrollment binds the presented device using an enrollment
// ticket. This endpoint is authorized by the single-use ticket itself (from the
// scanned QR), so the scanning authenticator does not need a prior login for the
// target account. Org context is still resolved by the tenant middleware and
// must match the ticket's org.
// POST /api/v1/identity/mfa/push/enroll/complete
func (s *Service) handleCompletePushEnrollment(c *gin.Context) {
	var req struct {
		EnrollmentToken string `json:"enrollment_token"`
		PushMFAEnrollment
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.EnrollmentToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "enrollment_token is required"})
		return
	}

	device, err := s.CompletePushEnrollment(c.Request.Context(), req.EnrollmentToken, &req.PushMFAEnrollment, c.ClientIP())
	if err != nil {
		// Invalid/expired ticket or org mismatch is a client error, not a 500.
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, device)
}

func (s *Service) handleGetPushDevices(c *gin.Context) {
	// CRITICAL: Only get user ID from authenticated context
	// NEVER allow user_id from query/header/request body to prevent IDOR attacks
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}

	devices, err := s.GetPushMFADevices(c.Request.Context(), userID)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("get push devices", err), s.logger)
		return
	}

	c.JSON(http.StatusOK, devices)
}

func (s *Service) handleDeletePushDevice(c *gin.Context) {
	// CRITICAL: Only get user ID from authenticated context
	// NEVER allow user_id from query/header/request body to prevent IDOR attacks
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}

	deviceID := c.Param("device_id")

	if deviceID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "device_id is required"})
		return
	}

	if err := s.DeletePushMFADevice(c.Request.Context(), userID, deviceID); err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("delete push device", err), s.logger)
		return
	}

	c.JSON(http.StatusNoContent, nil)
}

func (s *Service) handleCreatePushChallenge(c *gin.Context) {
	var request PushMFAChallengeRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if request.UserID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id is required"})
		return
	}

	// Auto-fill IP and User-Agent if not provided
	if request.IPAddress == "" {
		request.IPAddress = c.ClientIP()
	}
	if request.UserAgent == "" {
		request.UserAgent = c.GetHeader("User-Agent")
	}
	// Requesting application name for the approval screen (additional context).
	// Prefer an explicit app_name; fall back to a caller-supplied header.
	if request.AppName == "" {
		request.AppName = c.GetHeader("X-Requesting-App")
	}

	challenge, err := s.CreatePushMFAChallenge(c.Request.Context(), &request)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("create push challenge", err), s.logger)
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"challenge_id": challenge.ID,
		"expires_at":   challenge.ExpiresAt,
		"status":       challenge.Status,
	})
}

func (s *Service) handleVerifyPushChallenge(c *gin.Context) {
	var response PushMFAChallengeResponse
	if err := c.ShouldBindJSON(&response); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if response.ChallengeID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "challenge_id is required"})
		return
	}

	// The number is required only to APPROVE (number matching). A deny/report
	// does not need it — the user is rejecting a prompt they don't recognize.
	if response.Approved && response.ChallengeCode == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "challenge_code is required"})
		return
	}

	approved, err := s.VerifyPushMFAChallenge(c.Request.Context(), &response)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if !approved {
		c.JSON(http.StatusUnauthorized, gin.H{
			"verified": false,
			"message":  "Challenge denied by user",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"verified": true,
		"method":   "push_mfa",
	})
}

func (s *Service) handleGetPushChallenge(c *gin.Context) {
	challengeID := c.Param("challenge_id")

	if challengeID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "challenge_id is required"})
		return
	}

	challenge, err := s.GetPushMFAChallenge(c.Request.Context(), challengeID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "challenge not found"})
		return
	}

	// A push challenge is a per-user artifact; a caller may only read their own.
	// This route is self-service (authenticated), so block a positive cross-user
	// mismatch — otherwise anyone with a challenge UUID could read its metadata
	// (app, IP, location, timestamps). Kept conditional on a present user_id so
	// it can't break a caller that legitimately reaches this without one.
	if caller := c.GetString("user_id"); caller != "" && caller != challenge.UserID {
		c.JSON(http.StatusNotFound, gin.H{"error": "challenge not found"})
		return
	}

	// Don't expose the challenge code in GET responses (security)
	challenge.ChallengeCode = ""

	// Build a clean "additional context" block for the approval screen so the
	// user can spot an unexpected prompt (anti-MFA-fatigue, MS-Authenticator
	// style): which app, from where, on what, and when.
	appName := ""
	if challenge.SessionInfo != nil {
		if v, ok := challenge.SessionInfo["app_name"].(string); ok {
			appName = v
		}
	}
	browser := ""
	if challenge.UserAgent != "" {
		browser = parseBrowserName(challenge.UserAgent)
	}
	ctxBlock := gin.H{
		"app_name":   appName,
		"location":   challenge.Location,
		"ip_address": challenge.IPAddress,
		"browser":    browser,
		"user_agent": challenge.UserAgent,
		"created_at": challenge.CreatedAt,
		"expires_at": challenge.ExpiresAt,
	}

	c.JSON(http.StatusOK, gin.H{
		"id":         challenge.ID,
		"user_id":    challenge.UserID,
		"device_id":  challenge.DeviceID,
		"status":     challenge.Status,
		"created_at": challenge.CreatedAt,
		"expires_at": challenge.ExpiresAt,
		"ip_address": challenge.IPAddress,
		"user_agent": challenge.UserAgent,
		"location":   challenge.Location,
		"context":    ctxBlock,
	})
}
