// Package identity - HTTP handlers for passwordless admin settings
package identity

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// PasswordlessSystemSettings represents the system-wide passwordless authentication settings
type PasswordlessSystemSettings struct {
	MagicLinkEnabled       bool `json:"magic_link_enabled"`
	MagicLinkExpiryMinutes int  `json:"magic_link_expiry_minutes"`
	QRLoginEnabled         bool `json:"qr_login_enabled"`
	QRSessionExpiryMinutes int  `json:"qr_session_expiry_minutes"`
	BiometricOnlyEnabled   bool `json:"biometric_only_enabled"`
	RequireDeviceTrust     bool `json:"require_device_trust"`
	MaxMagicLinksPerHour   int  `json:"max_magic_links_per_hour"`
}

// defaultPasswordlessSettings returns the default passwordless system settings
func defaultPasswordlessSettings() PasswordlessSystemSettings {
	return PasswordlessSystemSettings{
		MagicLinkEnabled:       true,
		MagicLinkExpiryMinutes: 15,
		QRLoginEnabled:         true,
		QRSessionExpiryMinutes: 5,
		BiometricOnlyEnabled:   true,
		RequireDeviceTrust:     false,
		MaxMagicLinksPerHour:   5,
	}
}

// loadPasswordlessSettings loads the current passwordless settings from the database,
// returning defaults if no settings are stored.
func (s *Service) loadPasswordlessSettings(ctx context.Context) (PasswordlessSystemSettings, error) {
	var raw string
	err := s.db.Pool.QueryRow(ctx,
		"SELECT value::text FROM system_settings WHERE key = 'passwordless'",
	).Scan(&raw)
	if err != nil {
		// Not found or any other error — return defaults
		return defaultPasswordlessSettings(), nil
	}

	settings := defaultPasswordlessSettings()
	if err := json.Unmarshal([]byte(raw), &settings); err != nil {
		return defaultPasswordlessSettings(), err
	}
	return settings, nil
}

// savePasswordlessSettings persists the passwordless settings to the database.
func (s *Service) savePasswordlessSettings(ctx context.Context, settings PasswordlessSystemSettings) error {
	data, err := json.Marshal(settings)
	if err != nil {
		return err
	}
	_, err = s.db.Pool.Exec(ctx,
		"INSERT INTO system_settings (key, value) VALUES ('passwordless', $1::jsonb) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
		string(data),
	)
	return err
}

// handleGetPasswordlessSettings returns the current passwordless system settings.
// GET /api/v1/identity/passwordless/settings
func (s *Service) handleGetPasswordlessSettings(c *gin.Context) {
	settings, err := s.loadPasswordlessSettings(c.Request.Context())
	if err != nil {
		s.logger.Error("failed to load passwordless settings", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load passwordless settings"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"settings": settings})
}

// handleUpdatePasswordlessSettings fully replaces the passwordless system settings.
// PUT /api/v1/identity/passwordless/settings
func (s *Service) handleUpdatePasswordlessSettings(c *gin.Context) {
	var settings PasswordlessSystemSettings
	if err := c.ShouldBindJSON(&settings); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := s.savePasswordlessSettings(c.Request.Context(), settings); err != nil {
		s.logger.Error("failed to save passwordless settings", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save passwordless settings"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"settings": settings})
}

// handlePatchPasswordlessSettings partially updates the passwordless system settings.
// Only fields present in the request body are overwritten.
// PATCH /api/v1/identity/passwordless/settings
func (s *Service) handlePatchPasswordlessSettings(c *gin.Context) {
	// Load current settings as the base
	settings, err := s.loadPasswordlessSettings(c.Request.Context())
	if err != nil {
		s.logger.Error("failed to load passwordless settings for patch", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load passwordless settings"})
		return
	}

	// Read raw body and overlay onto the loaded settings.
	// json.Unmarshal only overwrites fields present in the JSON payload,
	// preserving existing values for omitted fields.
	body, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read request body"})
		return
	}
	if err := json.Unmarshal(body, &settings); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := s.savePasswordlessSettings(c.Request.Context(), settings); err != nil {
		s.logger.Error("failed to save patched passwordless settings", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save passwordless settings"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"settings": settings})
}

// handleGetPasswordlessStats returns usage statistics for passwordless authentication.
// GET /api/v1/identity/passwordless/stats
func (s *Service) handleGetPasswordlessStats(c *gin.Context) {
	ctx := c.Request.Context()

	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	// Count today's magic links
	var magicLinksToday int
	err = s.db.Pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM magic_links WHERE created_at >= CURRENT_DATE",
	).Scan(&magicLinksToday)
	if err != nil {
		s.logger.Warn("failed to count magic links", zap.Error(err))
		magicLinksToday = 0
	}

	// Count today's approved QR logins
	var qrLoginsToday int
	err = s.db.Pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM qr_login_sessions WHERE created_at >= CURRENT_DATE AND status = 'approved' AND org_id = $1",
		org.ID,
	).Scan(&qrLoginsToday)
	if err != nil {
		s.logger.Warn("failed to count qr logins", zap.Error(err))
		qrLoginsToday = 0
	}

	// Count biometric-only users (handle table not existing gracefully)
	var biometricOnlyUsers int
	err = s.db.Pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM biometric_preferences WHERE biometric_only_enabled = true",
	).Scan(&biometricOnlyUsers)
	if err != nil {
		s.logger.Warn("failed to count biometric-only users", zap.Error(err))
		biometricOnlyUsers = 0
	}

	// Count total users
	var totalUsers int
	err = s.db.Pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM users WHERE org_id = $1", org.ID,
	).Scan(&totalUsers)
	if err != nil {
		s.logger.Warn("failed to count total users", zap.Error(err))
		totalUsers = 0
	}

	// Calculate adoption rate
	var adoptionRate float64
	if totalUsers > 0 {
		adoptionRate = float64(biometricOnlyUsers) / float64(totalUsers) * 100
	}

	c.JSON(http.StatusOK, gin.H{"stats": gin.H{
		"magic_links_today":    magicLinksToday,
		"qr_logins_today":      qrLoginsToday,
		"biometric_only_users": biometricOnlyUsers,
		"adoption_rate":        adoptionRate,
		"total_users":          totalUsers,
	}})
}

// handleTestMagicLink sends a test magic link to the specified email address.
// POST /api/v1/identity/passwordless/magic-link/test
func (s *Service) handleTestMagicLink(c *gin.Context) {
	var req struct {
		Email string `json:"email"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email is required"})
		return
	}

	ip := c.ClientIP()
	ua := c.GetHeader("User-Agent")

	link, err := s.CreateMagicLink(c.Request.Context(), req.Email, "test", "", ip, ua)
	if err != nil {
		// Don't leak whether the user exists — always return success
		s.logger.Warn("test magic link creation failed", zap.String("email", req.Email), zap.Error(err))
		c.JSON(http.StatusOK, gin.H{"message": "If the email is registered, a test magic link has been sent."})
		return
	}

	// In dev mode, log the token for debugging
	if s.cfg.Environment == "development" || s.cfg.Environment == "dev" || s.cfg.Environment == "" {
		s.logger.Info("test magic link created",
			zap.String("email", req.Email),
			zap.String("token", link.Token),
			zap.String("link_id", link.ID),
		)
	}

	c.JSON(http.StatusOK, gin.H{"message": "If the email is registered, a test magic link has been sent."})
}
