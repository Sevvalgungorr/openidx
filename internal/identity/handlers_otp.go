// Package identity - HTTP handlers for SMS and Email OTP MFA
package identity

import (
	"net/http"

	"github.com/gin-gonic/gin"

	apperrors "github.com/openidx/openidx/internal/common/errors"
)

// --- SMS OTP Handlers ---

// handleEnrollSMS starts SMS MFA enrollment
func (s *Service) handleEnrollSMS(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	var req struct {
		PhoneNumber string `json:"phone_number" binding:"required"`
		CountryCode string `json:"country_code"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "phone_number is required"})
		return
	}

	// Default country code to +1 (US) if not provided
	if req.CountryCode == "" {
		req.CountryCode = "+1"
	}

	enrollment, code, err := s.EnrollSMS(c.Request.Context(), userID, req.PhoneNumber, req.CountryCode)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	response := gin.H{
		"id":           enrollment.ID,
		"phone_number": maskPhone(enrollment.PhoneNumber),
		"country_code": enrollment.CountryCode,
		"verified":     enrollment.Verified,
		"message":      "Verification code sent to your phone",
	}

	// CRITICAL: NEVER expose OTP codes in production
	// OTP codes must NEVER be included in API responses in production environments
	// This check enforces production safety regardless of config flag
	if s.cfg.DebugOTPsEnabled() && s.cfg.IsDevelopment() {
		response["code"] = code
	}

	c.JSON(http.StatusOK, response)
}

// handleVerifySMSEnrollment verifies SMS enrollment with OTP code
func (s *Service) handleVerifySMSEnrollment(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	var req struct {
		Code string `json:"code" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "code is required"})
		return
	}

	if err := s.VerifySMSEnrollment(c.Request.Context(), userID, req.Code); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "SMS MFA enrolled successfully",
		"enabled": true,
	})
}

// handleGetSMSStatus returns SMS MFA enrollment status
func (s *Service) handleGetSMSStatus(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	enrollment, err := s.GetSMSEnrollment(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"enrolled": false,
			"verified": false,
			"enabled":  false,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"enrolled":     true,
		"verified":     enrollment.Verified,
		"enabled":      enrollment.Enabled,
		"phone_number": maskPhone(enrollment.PhoneNumber),
		"country_code": enrollment.CountryCode,
		"created_at":   enrollment.CreatedAt,
		"last_used_at": enrollment.LastUsedAt,
	})
}

// handleDeleteSMS removes SMS MFA enrollment
func (s *Service) handleDeleteSMS(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	if err := s.DeleteSMSEnrollment(c.Request.Context(), userID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "SMS MFA removed successfully"})
}

// handleCreateSMSChallenge creates a new SMS OTP challenge for authentication
func (s *Service) handleCreateSMSChallenge(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	challenge, err := s.CreateSMSChallenge(c.Request.Context(), userID, c.ClientIP(), c.GetHeader("User-Agent"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"challenge_id": challenge.ID,
		"method":       "sms",
		"recipient":    maskPhone(challenge.Recipient),
		"expires_at":   challenge.ExpiresAt,
		"message":      "Verification code sent to your phone",
	})
}

// --- Email OTP Handlers ---

// handleEnrollEmailOTP starts Email OTP MFA enrollment
func (s *Service) handleEnrollEmailOTP(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	var req struct {
		Email string `json:"email"`
	}

	c.ShouldBindJSON(&req)

	// If no email provided, use user's email from profile
	email := req.Email
	if email == "" {
		user, err := s.GetUser(c.Request.Context(), userID)
		if err != nil {
			// Typed renderer: logs the real cause server-side (was previously
			// discarded) while returning a safe body. See internal/common/errors.
			apperrors.HandleErrorWithLogger(c, apperrors.Internal("failed to get user", err), s.logger)
			return
		}
		email = GetEmail(*user)
	}

	if email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email address is required"})
		return
	}

	enrollment, code, err := s.EnrollEmailOTP(c.Request.Context(), userID, email)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	response := gin.H{
		"id":            enrollment.ID,
		"email_address": maskEmail(enrollment.EmailAddress),
		"enabled":       enrollment.Enabled,
		"message":       "Verification code sent to your email",
	}

	// CRITICAL: NEVER expose OTP codes in production
	// OTP codes must NEVER be included in API responses in production environments
	// This check enforces production safety regardless of config flag
	if s.cfg.DebugOTPsEnabled() && s.cfg.IsDevelopment() {
		response["code"] = code
	}

	c.JSON(http.StatusOK, response)
}

// handleGetEmailOTPStatus returns Email OTP MFA enrollment status
func (s *Service) handleGetEmailOTPStatus(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	enrollment, err := s.GetEmailOTPEnrollment(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"enrolled": false,
			"enabled":  false,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"enrolled":      true,
		"enabled":       enrollment.Enabled,
		"email_address": maskEmail(enrollment.EmailAddress),
		"created_at":    enrollment.CreatedAt,
		"last_used_at":  enrollment.LastUsedAt,
	})
}

// handleDeleteEmailOTP removes Email OTP MFA enrollment
func (s *Service) handleDeleteEmailOTP(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	if err := s.DeleteEmailOTPEnrollment(c.Request.Context(), userID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Email OTP MFA removed successfully"})
}

// handleCreateEmailOTPChallenge creates a new Email OTP challenge for authentication
func (s *Service) handleCreateEmailOTPChallenge(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	challenge, err := s.CreateEmailOTPChallenge(c.Request.Context(), userID, c.ClientIP(), c.GetHeader("User-Agent"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"challenge_id": challenge.ID,
		"method":       "email",
		"recipient":    maskEmail(challenge.Recipient),
		"expires_at":   challenge.ExpiresAt,
		"message":      "Verification code sent to your email",
	})
}

// handleVerifyEmailOTPEnrollment verifies the code emailed during enrollment,
// completing the enroll → verify handshake the console expects (mirrors the SMS
// verify step). EnrollEmailOTP already stores the row enabled and emails a code;
// without this endpoint the console's "Verify & Enable" POST returned 404 and
// email OTP could never be confirmed.
func (s *Service) handleVerifyEmailOTPEnrollment(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	var req struct {
		Code string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "code is required"})
		return
	}

	if _, err := s.GetEmailOTPEnrollment(c.Request.Context(), userID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email OTP is not enrolled"})
		return
	}

	if err := s.VerifyOTP(c.Request.Context(), userID, "email", req.Code); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Email OTP MFA enrolled successfully",
		"enabled": true,
	})
}

// --- Common OTP Handlers ---

// handleVerifyOTP verifies an OTP code (works for both SMS and Email)
func (s *Service) handleVerifyOTP(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	var req struct {
		Method string `json:"method" binding:"required"` // "sms" or "email"
		Code   string `json:"code" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "method and code are required"})
		return
	}

	if req.Method != "sms" && req.Method != "email" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "method must be 'sms' or 'email'"})
		return
	}

	if err := s.VerifyOTP(c.Request.Context(), userID, req.Method, req.Code); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":  "OTP verified successfully",
		"verified": true,
	})
}

// handleGetMFAMethods returns all enrolled MFA methods for the current user
func (s *Service) handleGetMFAMethods(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	methods, err := s.GetUserMFAMethods(c.Request.Context(), userID)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("failed to get MFA methods", err), s.logger)
		return
	}

	// Count enabled methods
	enabledCount := 0
	for _, enabled := range methods {
		if enabled {
			enabledCount++
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"methods":       methods,
		"enabled_count": enabledCount,
		"mfa_enabled":   enabledCount > 0,
	})
}
