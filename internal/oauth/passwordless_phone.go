package oauth

import (
	"context"
	"encoding/json"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// handlePasswordlessPhoneInit begins a passwordless "phone sign-in": the user
// proves who they are by approving a push on their registered device, with no
// password (Microsoft / Okta phone-sign-in parity).
//
// POST /oauth/passwordless/phone/init  { "username": "...", "login_session": "..." }
//
// Security model — this is a full authentication factor, so it is deliberately
// strict:
//   - The user MUST already have an ENABLED push device. Possession of that
//     device (plus the number-match on approval) is the sole authentication
//     factor; there is no password fallback and no way to enroll a device here.
//   - It only proceeds inside a real pending OAuth request (login_session), the
//     same envelope the password flow uses.
//   - It reuses the exact mfa_session + mfa-push-begin + mfa-verify(push) path
//     the password flow ends with, so the number-matching, single-use challenge,
//     approval check and code issuance are the already-audited code — this
//     endpoint only swaps "verify password" for "verify a push device exists".
//   - To avoid username enumeration, an unknown user or a user without a push
//     device returns the SAME generic response as success would after the push
//     is created is NOT possible; instead we return a uniform error that does
//     not distinguish "no such user" from "no device". (A future step can make
//     this fully constant-time; today it is a single generic message.)
//   - The endpoint is on the strict auth rate-limit tier (see authPaths).
func (s *Service) handlePasswordlessPhoneInit(c *gin.Context) {
	var req struct {
		Username     string `json:"username"`
		LoginSession string `json:"login_session"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "invalid request body"})
		return
	}
	if req.Username == "" || req.LoginSession == "" {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "username and login_session are required"})
		return
	}

	// The pending OAuth request must exist (same envelope as password login).
	paramsJSON, err := s.redis.Client.Get(c.Request.Context(), "login_session:"+req.LoginSession).Result()
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "invalid or expired login session"})
		return
	}
	var oauthParams map[string]string
	if err := json.Unmarshal([]byte(paramsJSON), &oauthParams); err != nil {
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}

	clientIP := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	// genericReject is returned for "unknown user" and "no push device" alike so
	// this endpoint can't be used to enumerate usernames or probe who has
	// passwordless enabled.
	genericReject := func() {
		c.JSON(400, gin.H{
			"error":             "passwordless_unavailable",
			"error_description": "Passwordless phone sign-in isn't available for this account. Use your password.",
		})
	}

	user, err := s.identityService.GetUserByUsername(c.Request.Context(), req.Username)
	if err != nil || user == nil {
		s.logger.Info("passwordless phone init: user not found",
			zap.String("username", req.Username))
		genericReject()
		return
	}

	// Require at least one ENABLED push device — this is the authentication
	// factor. No device -> no passwordless.
	devices, derr := s.identityService.GetPushMFADevices(c.Request.Context(), user.ID)
	if derr != nil {
		s.logger.Warn("passwordless phone init: device lookup failed", zap.Error(derr))
		genericReject()
		return
	}
	hasEnabled := false
	for _, d := range devices {
		if d.Enabled {
			hasEnabled = true
			break
		}
	}
	if !hasEnabled {
		s.logger.Info("passwordless phone init: no enabled push device",
			zap.String("user_id", user.ID))
		genericReject()
		return
	}

	// Build the mfa_session exactly as the password flow does at its MFA gate, so
	// the downstream mfa-push-begin + mfa-verify(push) path is the same audited
	// code. Mark it passwordless so the verify step can require the push method.
	fingerprint := ""
	if s.riskService != nil {
		fingerprint = s.riskService.ComputeDeviceFingerprint(clientIP, userAgent)
	}
	location := ""
	if s.riskService != nil {
		if geo, gerr := s.riskService.GeoIPLookup(c.Request.Context(), clientIP); gerr == nil && geo != nil {
			switch {
			case geo.City != "" && geo.Country != "":
				location = geo.City + ", " + geo.Country
			case geo.Country != "":
				location = geo.Country
			}
		}
	}

	mfaSession := GenerateRandomToken(32)
	mfaData := map[string]string{
		"user_id":             user.ID,
		"fingerprint":         fingerprint,
		"location":            location,
		"passwordless":        "phone",
		"required_mfa_method": "push",
	}
	for k, v := range oauthParams {
		mfaData[k] = v
	}
	mfaDataJSON, _ := json.Marshal(mfaData)
	if err := s.redis.Client.Set(c.Request.Context(), "mfa_session:"+mfaSession, string(mfaDataJSON), 5*time.Minute).Err(); err != nil {
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}

	// The password step is skipped, but the pending OAuth request is now bound to
	// the mfa_session; consume the login_session so it can't be replayed.
	s.redis.Client.Del(c.Request.Context(), "login_session:"+req.LoginSession)

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.logAuditEvent(ctx, "authentication", "security", "passwordless_phone_init", "success",
			user.ID, clientIP, user.ID, "user",
			map[string]interface{}{"username": user.UserName, "user_agent": userAgent})
	}()

	// Front-end now runs the existing push flow: POST /oauth/mfa-push-begin with
	// this mfa_session (shows the number to match), then polls
	// /oauth/mfa-push-status, then POST /oauth/mfa-verify {method:"push"} to get
	// the redirect_url.
	c.JSON(200, gin.H{
		"mfa_required": true,
		"mfa_session":  mfaSession,
		"mfa_methods":  []string{"push"},
		"passwordless": "phone",
	})
}

// requiredMFAMethodFromSession returns the method a session is pinned to (e.g.
// "push" for passwordless phone sign-in), or "" if it accepts any enrolled
// method. Used by mfa-verify to stop a passwordless session being completed with
// a weaker/unintended method.
func requiredMFAMethodFromSession(mfaData map[string]string) string {
	return mfaData["required_mfa_method"]
}
