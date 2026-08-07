// Package handlers provides HTTP handlers for system settings management
package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

// registerBrandingValidators wires the custom "httpurl_or_path" validator into
// gin's binding engine exactly once. It accepts an empty string (paired with
// omitempty), an absolute http(s) URL, or a same-origin root-relative path
// ("/assets/logo.png"). The default "url" tag rejects relative paths, which is
// how the platform's own default branding failed to save (QA 10.6).
var registerBrandingValidatorsOnce sync.Once

func registerBrandingValidators() {
	registerBrandingValidatorsOnce.Do(func() {
		v, ok := binding.Validator.Engine().(*validator.Validate)
		if !ok {
			return
		}
		_ = v.RegisterValidation("httpurl_or_path", func(fl validator.FieldLevel) bool {
			s := strings.TrimSpace(fl.Field().String())
			if s == "" {
				return true // omitempty handles the empty case
			}
			// Root-relative same-origin path.
			if strings.HasPrefix(s, "/") {
				return true
			}
			u, err := url.Parse(s)
			if err != nil {
				return false
			}
			return (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
		})
	})
}

// SettingsHandler handles settings-related requests
type SettingsHandler struct {
	logger *zap.Logger
	db     *pgxpool.Pool
}

// NewSettingsHandler creates a new settings handler
func NewSettingsHandler(logger *zap.Logger, db *pgxpool.Pool) *SettingsHandler {
	registerBrandingValidators()
	return &SettingsHandler{
		logger: logger.With(zap.String("handler", "settings")),
		db:     db,
	}
}

// Settings represents system configuration settings
type Settings struct {
	ID        string          `json:"id"`
	UpdatedAt time.Time       `json:"updated_at"`
	UpdatedBy string          `json:"updated_by"`
	General   GeneralSection  `json:"general"`
	Security  SecuritySection `json:"security"`
	Auth      AuthSection     `json:"auth"`
	Branding  BrandingSection `json:"branding"`
}

// GeneralSection contains general system settings
type GeneralSection struct {
	OrganizationName string `json:"organization_name" binding:"required,min=1,max=255"`
	SupportEmail     string `json:"support_email" binding:"required,email"`
	DefaultLanguage  string `json:"default_language" binding:"required"`
	DefaultTimezone  string `json:"default_timezone" binding:"required"`
	SessionTimeout   int    `json:"session_timeout" binding:"required,min=60,max=86400"`
}

// SecuritySection contains security-related settings
type SecuritySection struct {
	PasswordPolicy PasswordPolicySettings `json:"password_policy"`
	MFA            MFASettings            `json:"mfa"`
	Session        SessionSettings        `json:"session"`
}

// PasswordPolicySettings defines password requirements
type PasswordPolicySettings struct {
	MinLength        int      `json:"min_length" binding:"required,min=8,max=128"`
	RequireUppercase bool     `json:"require_uppercase"`
	RequireLowercase bool     `json:"require_lowercase"`
	RequireNumbers   bool     `json:"require_numbers"`
	RequireSpecial   bool     `json:"require_special"`
	ForbiddenWords   []string `json:"forbidden_words"`
	MaxAge           int      `json:"max_age" binding:"min=0"`
	HistoryCount     int      `json:"history_count" binding:"min=0,max=24"`
}

// MFASettings defines multi-factor authentication settings
type MFASettings struct {
	Enabled        bool             `json:"enabled"`
	Required       bool             `json:"required"`
	AllowedMethods []string         `json:"allowed_methods"`
	TOTP           TOTPSettings     `json:"totp"`
	SMS            SMSSettings      `json:"sms"`
	WebAuthn       WebAuthnSettings `json:"webauthn"`
}

// TOTPSettings defines TOTP-specific settings
type TOTPSettings struct {
	Enabled    bool   `json:"enabled"`
	Issuer     string `json:"issuer"`
	Algorithm  string `json:"algorithm"`
	CodeLength int    `json:"code_length"`
	Period     int    `json:"period"`
	Window     int    `json:"window"`
}

// SMSSettings defines SMS-specific settings
type SMSSettings struct {
	Enabled  bool   `json:"enabled"`
	Provider string `json:"provider"`
}

// WebAuthnSettings defines WebAuthn-specific settings
type WebAuthnSettings struct {
	Enabled              bool   `json:"enabled"`
	RelyingPartyID       string `json:"relying_party_id"`
	RelyingPartyName     string `json:"relying_party_name"`
	RelyingPartyOrigin   string `json:"relying_party_origin"`
	AuthenticatorTimeout int    `json:"authenticator_timeout"`
	RequireResidentKey   bool   `json:"require_resident_key"`
	UserVerification     string `json:"user_verification"`
}

// SessionSettings defines session-related settings
type SessionSettings struct {
	IdleTimeoutMinutes     int `json:"idle_timeout_minutes" binding:"min=1,max=1440"`
	AbsoluteTimeoutMinutes int `json:"absolute_timeout_minutes" binding:"min=1,max=43200"`
	MaxConcurrentSessions  int `json:"max_concurrent_sessions" binding:"min=1,max=100"`
	RememberMeDays         int `json:"remember_me_days" binding:"min=0,max=365"`
}

// AuthSection contains authentication settings
type AuthSection struct {
	AllowRegistration  bool          `json:"allow_registration"`
	RequireEmailVerify bool          `json:"require_email_verify"`
	AllowedDomains     []string      `json:"allowed_domains"`
	SocialLoginEnabled bool          `json:"social_login_enabled"`
	SocialProviders    []string      `json:"social_providers"`
	LockoutPolicy      LockoutPolicy `json:"lockout_policy"`
}

// LockoutPolicy defines account lockout settings
type LockoutPolicy struct {
	Enabled           bool `json:"enabled"`
	MaxFailedAttempts int  `json:"max_failed_attempts" binding:"min=1,max=20"`
	LockoutDuration   int  `json:"lockout_duration_minutes" binding:"min=1,max=1440"`
}

// BrandingSection contains branding customization settings
type BrandingSection struct {
	// logo/favicon may be an absolute http(s) URL or a same-origin relative path
	// (the platform's own defaults are "/assets/logo.png"). The stock "url" tag
	// rejects relative paths, which made saving the server's own defaults fail
	// with a 400 (QA 10.6), so use the custom "httpurl_or_path" validator.
	LogoURL          string `json:"logo_url" binding:"omitempty,httpurl_or_path"`
	FaviconURL       string `json:"favicon_url" binding:"omitempty,httpurl_or_path"`
	PrimaryColor     string `json:"primary_color" binding:"required"`
	SecondaryColor   string `json:"secondary_color" binding:"required"`
	LoginPageTitle   string `json:"login_page_title" binding:"required,max=255"`
	LoginPageMessage string `json:"login_page_message" binding:"max=1000"`
	FooterHTML       string `json:"footer_html"`
}

// SettingsRepository defines the interface for settings persistence
type SettingsRepository interface {
	GetSettings(ctx context.Context) (*Settings, error)
	UpdateSettings(ctx context.Context, settings *Settings, updatedBy string) error
	ResetToDefaults(ctx context.Context, resetBy string) (*Settings, error)
}

// GetSettings handles GET /api/v1/settings
// @Summary Get system settings
// @Description Returns current system configuration settings
// @Tags settings
// @Produce json
// @Success 200 {object} Settings
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/v1/settings [get]
func (h *SettingsHandler) GetSettings(c *gin.Context) {
	h.logger.Debug("Fetching system settings")

	ctx := c.Request.Context()

	// Try to get from admin_console_settings first (new migration)
	settings := &Settings{
		ID:        uuid.New().String(),
		UpdatedAt: time.Now(),
		UpdatedBy: "system",
	}

	// Query individual setting categories
	rows, err := h.db.Query(ctx, `
		SELECT key, value, updated_at, updated_by
		FROM admin_console_settings
		ORDER BY key
	`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var key string
			var value json.RawMessage
			var updatedAt time.Time
			var updatedBy *string

			if err := rows.Scan(&key, &value, &updatedAt, &updatedBy); err != nil {
				continue
			}

			// Find the most recent update time
			if updatedAt.After(settings.UpdatedAt) {
				settings.UpdatedAt = updatedAt
			}
			if updatedBy != nil {
				settings.UpdatedBy = *updatedBy
			}

			// Parse value into appropriate section
			switch key {
			case "general":
				var general GeneralSection
				if json.Unmarshal(value, &general) == nil {
					settings.General = general
				}
			case "security":
				var security SecuritySection
				if json.Unmarshal(value, &security) == nil {
					settings.Security = security
				}
			case "authentication":
				var auth AuthSection
				if json.Unmarshal(value, &auth) == nil {
					settings.Auth = auth
				}
			case "branding":
				var branding BrandingSection
				if json.Unmarshal(value, &branding) == nil {
					settings.Branding = branding
				}
			}
		}
	} else {
		h.logger.Warn("Failed to query admin_console_settings, using defaults", zap.Error(err))
	}

	// Fill in any missing sections with defaults
	if settings.General.OrganizationName == "" {
		settings.General = h.getDefaultGeneralSection()
	}
	if settings.Security.PasswordPolicy.MinLength == 0 {
		settings.Security = h.getDefaultSecuritySection()
	}
	if settings.Auth.AllowedDomains == nil {
		settings.Auth = h.getDefaultAuthSection()
	}
	if settings.Branding.PrimaryColor == "" {
		settings.Branding = h.getDefaultBrandingSection()
	}

	c.JSON(http.StatusOK, settings)
}

// UpdateSettings handles PUT /api/v1/settings
// @Summary Update system settings
// @Description Updates system configuration settings
// @Tags settings
// @Accept json
// @Produce json
// @Param settings body Settings true "Settings to update"
// @Success 200 {object} Settings
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/v1/settings [put]
func (h *SettingsHandler) UpdateSettings(c *gin.Context) {
	h.logger.Debug("Updating system settings")

	var settings Settings
	if err := c.ShouldBindJSON(&settings); err != nil {
		h.logger.Warn("Invalid settings payload", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("Invalid settings: %v", err),
		})
		return
	}

	// Validate settings
	if err := h.ValidateSettings(&settings); err != nil {
		h.logger.Warn("Settings validation failed", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("Validation failed: %v", err),
		})
		return
	}

	// Get user ID from context
	userID, _ := c.Get("user_id")
	if userID == nil {
		userID = "unknown"
	}
	userIDStr := userID.(string)
	settings.UpdatedBy = userIDStr
	settings.ID = uuid.New().String()
	settings.UpdatedAt = time.Now()

	ctx := c.Request.Context()

	// Update each section in the database
	updates := []struct {
		key   string
		value interface{}
	}{
		{"general", settings.General},
		{"security", settings.Security},
		{"authentication", settings.Auth},
		{"branding", settings.Branding},
	}

	for _, update := range updates {
		valueBytes, err := json.Marshal(update.value)
		if err != nil {
			h.logger.Error("Failed to marshal settings section", zap.String("key", update.key), zap.Error(err))
			continue
		}

		_, err = h.db.Exec(ctx, `
			INSERT INTO admin_console_settings (key, value, updated_at, updated_by)
			VALUES ($1, $2, NOW(), $3)
			ON CONFLICT (key) DO UPDATE
			SET value = $2, updated_at = NOW(), updated_by = $3
		`, update.key, valueBytes, userIDStr)

		if err != nil {
			h.logger.Error("Failed to update settings section", zap.String("key", update.key), zap.Error(err))
		}
	}

	h.logger.Info("Settings updated", zap.String("updated_by", userIDStr))

	c.JSON(http.StatusOK, settings)
}

// ResetSettings handles POST /api/v1/settings/reset
// @Summary Reset settings to defaults
// @Description Resets all system settings to default values
// @Tags settings
// @Produce json
// @Success 200 {object} Settings
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/v1/settings/reset [post]
func (h *SettingsHandler) ResetSettings(c *gin.Context) {
	h.logger.Debug("Resetting settings to defaults")

	// Get user ID from context
	userID, _ := c.Get("user_id")
	if userID == nil {
		userID = "unknown"
	}
	resetBy := userID.(string)

	settings := h.getDefaultSettings()
	settings.ID = uuid.New().String()
	settings.UpdatedAt = time.Now()
	settings.UpdatedBy = resetBy

	ctx := c.Request.Context()

	// Reset each section to defaults
	defaults := map[string]interface{}{
		"general":        settings.General,
		"security":       settings.Security,
		"authentication": settings.Auth,
		"branding":       settings.Branding,
	}

	for key, value := range defaults {
		valueBytes, err := json.Marshal(value)
		if err != nil {
			h.logger.Error("Failed to marshal default settings", zap.String("key", key), zap.Error(err))
			continue
		}

		_, err = h.db.Exec(ctx, `
			INSERT INTO admin_console_settings (key, value, updated_at, updated_by)
			VALUES ($1, $2, NOW(), $3)
			ON CONFLICT (key) DO UPDATE
			SET value = $2, updated_at = NOW(), updated_by = $3
		`, key, valueBytes, resetBy)

		if err != nil {
			h.logger.Error("Failed to reset settings section", zap.String("key", key), zap.Error(err))
		}
	}

	h.logger.Info("Settings reset to defaults", zap.String("reset_by", resetBy))
	c.JSON(http.StatusOK, settings)
}

// ValidateSettings validates settings configuration
func (h *SettingsHandler) ValidateSettings(settings *Settings) error {
	// Validate general section
	if settings.General.OrganizationName == "" {
		return fmt.Errorf("organization_name is required")
	}
	if settings.General.SupportEmail == "" {
		return fmt.Errorf("support_email is required")
	}

	// Validate security section
	if settings.Security.PasswordPolicy.MinLength < 8 {
		return fmt.Errorf("password min_length must be at least 8")
	}
	if settings.Security.PasswordPolicy.MinLength > 128 {
		return fmt.Errorf("password min_length cannot exceed 128")
	}

	// Validate MFA methods if enabled
	if settings.Security.MFA.Enabled && len(settings.Security.MFA.AllowedMethods) == 0 {
		return fmt.Errorf("at least one MFA method must be specified when MFA is enabled")
	}

	// Validate session settings
	if settings.Security.Session.IdleTimeoutMinutes < 1 {
		return fmt.Errorf("idle timeout must be at least 1 minute")
	}
	if settings.Security.Session.MaxConcurrentSessions < 1 {
		return fmt.Errorf("max concurrent sessions must be at least 1")
	}

	// Validate branding colors (basic hex color validation)
	if !isValidHexColor(settings.Branding.PrimaryColor) {
		return fmt.Errorf("primary_color must be a valid hex color")
	}
	if !isValidHexColor(settings.Branding.SecondaryColor) {
		return fmt.Errorf("secondary_color must be a valid hex color")
	}

	return nil
}

// ValidatePassword validates a password against the current password policy
// @Summary Validate password
// @Description Checks if a password meets the current password policy
// @Tags settings
// @Accept json
// @Produce json
// @Param password body map[string]string true "Password to validate"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Router /api/v1/settings/validate-password [post]
func (h *SettingsHandler) ValidatePassword(c *gin.Context) {
	var req struct {
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "password is required",
		})
		return
	}

	// Get current password policy from database or use defaults
	policy := h.getPasswordPolicy(c.Request.Context())

	result := map[string]interface{}{
		"valid":  true,
		"errors": []string{},
	}

	// Check minimum length
	if len(req.Password) < policy.MinLength {
		result["valid"] = false
		result["errors"] = append(result["errors"].([]string),
			fmt.Sprintf("Password must be at least %d characters", policy.MinLength))
	}

	// Check uppercase requirement
	if policy.RequireUppercase {
		hasUpper := false
		for _, ch := range req.Password {
			if ch >= 'A' && ch <= 'Z' {
				hasUpper = true
				break
			}
		}
		if !hasUpper {
			result["valid"] = false
			result["errors"] = append(result["errors"].([]string), "Password must contain at least one uppercase letter")
		}
	}

	// Check lowercase requirement
	if policy.RequireLowercase {
		hasLower := false
		for _, ch := range req.Password {
			if ch >= 'a' && ch <= 'z' {
				hasLower = true
				break
			}
		}
		if !hasLower {
			result["valid"] = false
			result["errors"] = append(result["errors"].([]string), "Password must contain at least one lowercase letter")
		}
	}

	// Check numbers requirement
	if policy.RequireNumbers {
		hasNumber := false
		for _, ch := range req.Password {
			if ch >= '0' && ch <= '9' {
				hasNumber = true
				break
			}
		}
		if !hasNumber {
			result["valid"] = false
			result["errors"] = append(result["errors"].([]string), "Password must contain at least one number")
		}
	}

	// Check special characters requirement
	if policy.RequireSpecial {
		hasSpecial := false
		specialChars := "!@#$%^&*()_+-=[]{}|;:,.<>?"
		for _, ch := range req.Password {
			for _, sc := range specialChars {
				if ch == sc {
					hasSpecial = true
					break
				}
			}
			if hasSpecial {
				break
			}
		}
		if !hasSpecial {
			result["valid"] = false
			result["errors"] = append(result["errors"].([]string), "Password must contain at least one special character")
		}
	}

	// Check forbidden words
	for _, word := range policy.ForbiddenWords {
		if containsIgnoreCase(req.Password, word) {
			result["valid"] = false
			result["errors"] = append(result["errors"].([]string),
				fmt.Sprintf("Password cannot contain the word: %s", word))
		}
	}

	c.JSON(http.StatusOK, result)
}

// GetSettingsJSON handles GET /api/v1/settings/json
// @Summary Get settings as JSON
// @Description Returns settings in JSON format for export
// @Tags settings
// @Produce json
// @Success 200 {object} Settings
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/v1/settings/json [get]
func (h *SettingsHandler) GetSettingsJSON(c *gin.Context) {
	h.logger.Debug("Exporting settings as JSON")

	// Get current settings
	settings := h.getDefaultSettings()

	// Marshal to pretty JSON
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		h.logger.Error("Failed to marshal settings", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to export settings",
		})
		return
	}

	c.Header("Content-Disposition", "attachment; filename=settings.json")
	c.Data(http.StatusOK, "application/json", data)
}

// getDefaultSettings returns default system settings
func (h *SettingsHandler) getDefaultSettings() Settings {
	now := time.Now()
	return Settings{
		ID:        uuid.New().String(),
		UpdatedAt: now,
		UpdatedBy: "system",
		General: GeneralSection{
			OrganizationName: "OpenIDX",
			SupportEmail:     "support@openidx.io",
			DefaultLanguage:  "en",
			DefaultTimezone:  "UTC",
			SessionTimeout:   3600,
		},
		Security: SecuritySection{
			PasswordPolicy: PasswordPolicySettings{
				MinLength:        12,
				RequireUppercase: true,
				RequireLowercase: true,
				RequireNumbers:   true,
				RequireSpecial:   true,
				ForbiddenWords:   []string{"password", "123456", "qwerty"},
				MaxAge:           90,
				HistoryCount:     5,
			},
			MFA: MFASettings{
				Enabled:        false,
				Required:       false,
				AllowedMethods: []string{"totp", "sms", "webauthn"},
				TOTP: TOTPSettings{
					Enabled:    true,
					Issuer:     "OpenIDX",
					Algorithm:  "SHA256",
					CodeLength: 6,
					Period:     30,
					Window:     1,
				},
				SMS: SMSSettings{
					Enabled:  false,
					Provider: "twilio",
				},
				WebAuthn: WebAuthnSettings{
					Enabled:              false,
					RelyingPartyID:       "openidx.io",
					RelyingPartyName:     "OpenIDX",
					RelyingPartyOrigin:   "https://openidx.io",
					AuthenticatorTimeout: 60,
					RequireResidentKey:   false,
					UserVerification:     "preferred",
				},
			},
			Session: SessionSettings{
				IdleTimeoutMinutes:     30,
				AbsoluteTimeoutMinutes: 480,
				MaxConcurrentSessions:  5,
				RememberMeDays:         30,
			},
		},
		Auth: AuthSection{
			AllowRegistration:  false,
			RequireEmailVerify: true,
			AllowedDomains:     []string{},
			SocialLoginEnabled: false,
			SocialProviders:    []string{"google", "microsoft", "github"},
			LockoutPolicy: LockoutPolicy{
				Enabled:           true,
				MaxFailedAttempts: 5,
				LockoutDuration:   15,
			},
		},
		Branding: BrandingSection{
			LogoURL:          "/assets/logo.png",
			FaviconURL:       "/assets/favicon.ico",
			PrimaryColor:     "#3B82F6",
			SecondaryColor:   "#1E40AF",
			LoginPageTitle:   "Sign in to OpenIDX",
			LoginPageMessage: "Welcome to OpenIDX Identity Platform",
			FooterHTML:       "&copy; 2025 OpenIDX. All rights reserved.",
		},
	}
}

// isValidHexColor checks if a string is a valid hex color
func isValidHexColor(color string) bool {
	if len(color) != 7 {
		return false
	}
	if color[0] != '#' {
		return false
	}
	for _, ch := range color[1:] {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')) {
			return false
		}
	}
	return true
}

// containsIgnoreCase checks if a string contains a substring (case-insensitive)
func containsIgnoreCase(s, substr string) bool {
	s = toLower(s)
	substr = toLower(substr)
	return contains(s, substr)
}

func toLower(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch >= 'A' && ch <= 'Z' {
			result[i] = ch + 32
		} else {
			result[i] = ch
		}
	}
	return string(result)
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && indexOf(s, substr) >= 0
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			if s[i+j] != substr[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// SettingsService is a service-level implementation of SettingsRepository
type SettingsService struct{}

// getPasswordPolicy retrieves the current password policy from the database
func (h *SettingsHandler) getPasswordPolicy(ctx context.Context) PasswordPolicySettings {
	var value json.RawMessage
	err := h.db.QueryRow(ctx, `
		SELECT value FROM admin_console_settings WHERE key = 'security'
	`).Scan(&value)

	if err == nil {
		var security SecuritySection
		if json.Unmarshal(value, &security) == nil {
			return security.PasswordPolicy
		}
	}

	// Return default policy
	return PasswordPolicySettings{
		MinLength:        12,
		RequireUppercase: true,
		RequireLowercase: true,
		RequireNumbers:   true,
		RequireSpecial:   true,
		ForbiddenWords:   []string{"password", "123456", "qwerty"},
		MaxAge:           90,
		HistoryCount:     5,
	}
}

// getDefaultGeneralSection returns default general settings
func (h *SettingsHandler) getDefaultGeneralSection() GeneralSection {
	return GeneralSection{
		OrganizationName: "OpenIDX",
		SupportEmail:     "support@openidx.io",
		DefaultLanguage:  "en",
		DefaultTimezone:  "UTC",
		SessionTimeout:   3600,
	}
}

// getDefaultSecuritySection returns default security settings
func (h *SettingsHandler) getDefaultSecuritySection() SecuritySection {
	return SecuritySection{
		PasswordPolicy: PasswordPolicySettings{
			MinLength:        12,
			RequireUppercase: true,
			RequireLowercase: true,
			RequireNumbers:   true,
			RequireSpecial:   true,
			ForbiddenWords:   []string{"password", "123456", "qwerty"},
			MaxAge:           90,
			HistoryCount:     5,
		},
		MFA: MFASettings{
			Enabled:        false,
			Required:       false,
			AllowedMethods: []string{"totp", "sms", "webauthn"},
			TOTP: TOTPSettings{
				Enabled:    true,
				Issuer:     "OpenIDX",
				Algorithm:  "SHA256",
				CodeLength: 6,
				Period:     30,
				Window:     1,
			},
			SMS: SMSSettings{
				Enabled:  false,
				Provider: "twilio",
			},
			WebAuthn: WebAuthnSettings{
				Enabled:              false,
				RelyingPartyID:       "openidx.io",
				RelyingPartyName:     "OpenIDX",
				RelyingPartyOrigin:   "https://openidx.io",
				AuthenticatorTimeout: 60,
				RequireResidentKey:   false,
				UserVerification:     "preferred",
			},
		},
		Session: SessionSettings{
			IdleTimeoutMinutes:     30,
			AbsoluteTimeoutMinutes: 480,
			MaxConcurrentSessions:  5,
			RememberMeDays:         30,
		},
	}
}

// getDefaultAuthSection returns default authentication settings
func (h *SettingsHandler) getDefaultAuthSection() AuthSection {
	return AuthSection{
		AllowRegistration:  false,
		RequireEmailVerify: true,
		AllowedDomains:     []string{},
		SocialLoginEnabled: false,
		SocialProviders:    []string{"google", "microsoft", "github"},
		LockoutPolicy: LockoutPolicy{
			Enabled:           true,
			MaxFailedAttempts: 5,
			LockoutDuration:   15,
		},
	}
}

// getDefaultBrandingSection returns default branding settings
func (h *SettingsHandler) getDefaultBrandingSection() BrandingSection {
	return BrandingSection{
		LogoURL:          "/assets/logo.png",
		FaviconURL:       "/assets/favicon.ico",
		PrimaryColor:     "#3B82F6",
		SecondaryColor:   "#1E40AF",
		LoginPageTitle:   "Sign in to OpenIDX",
		LoginPageMessage: "Welcome to OpenIDX Identity Platform",
		FooterHTML:       "&copy; 2025 OpenIDX. All rights reserved.",
	}
}
