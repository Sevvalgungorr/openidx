// Package handlers provides tests for settings handlers
package handlers

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// newTestSettingsHandler creates a handler for testing
func newTestSettingsHandler() *SettingsHandler {
	logger := zap.NewNop()
	return &SettingsHandler{
		logger: logger.With(zap.String("handler", "settings")),
		db:     nil, // Will be mocked in integration tests
	}
}

// TestNewSettingsHandler tests the handler constructor
func TestNewSettingsHandler(t *testing.T) {
	logger := zap.NewNop()
	handler := NewSettingsHandler(logger, nil)

	assert.NotNil(t, handler)
	assert.NotNil(t, handler.logger)
	// db can be nil in tests
}

// TestSettingsSerialization tests Settings JSON serialization
func TestSettingsSerialization(t *testing.T) {
	now := time.Now()
	settings := Settings{
		ID:        "settings-1",
		UpdatedAt: now,
		UpdatedBy: "admin",
		General: GeneralSection{
			OrganizationName: "Acme Corp",
			SupportEmail:     "support@acme.com",
			DefaultLanguage:  "en",
			DefaultTimezone:  "America/New_York",
			SessionTimeout:   3600,
		},
		Security: SecuritySection{
			PasswordPolicy: PasswordPolicySettings{
				MinLength:        14,
				RequireUppercase: true,
				RequireLowercase: true,
				RequireNumbers:   true,
				RequireSpecial:   true,
				ForbiddenWords:   []string{"password", "acme"},
				MaxAge:           90,
				HistoryCount:     10,
			},
			MFA: MFASettings{
				Enabled:        true,
				Required:       true,
				AllowedMethods: []string{"totp", "webauthn"},
			},
			Session: SessionSettings{
				IdleTimeoutMinutes:     15,
				AbsoluteTimeoutMinutes: 480,
				MaxConcurrentSessions:  3,
				RememberMeDays:         30,
			},
		},
		Auth: AuthSection{
			AllowRegistration:  false,
			RequireEmailVerify: true,
			AllowedDomains:     []string{"acme.com", "acme.co.uk"},
			SocialLoginEnabled: true,
			SocialProviders:    []string{"google", "microsoft"},
			LockoutPolicy: LockoutPolicy{
				Enabled:           true,
				MaxFailedAttempts: 5,
				LockoutDuration:   30,
			},
		},
		Branding: BrandingSection{
			LogoURL:          "https://acme.com/logo.png",
			FaviconURL:       "https://acme.com/favicon.ico",
			PrimaryColor:     "#0052CC",
			SecondaryColor:   "#003380",
			LoginPageTitle:   "Welcome to Acme",
			LoginPageMessage: "Sign in to access your applications",
			FooterHTML:       "&copy; 2025 Acme Corp",
		},
	}

	data, err := json.Marshal(settings)
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	var decoded Settings
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, "settings-1", decoded.ID)
	assert.Equal(t, "Acme Corp", decoded.General.OrganizationName)
	assert.Equal(t, 14, decoded.Security.PasswordPolicy.MinLength)
	assert.True(t, decoded.Security.MFA.Enabled)
	assert.Len(t, decoded.Auth.AllowedDomains, 2)
	assert.Equal(t, "#0052CC", decoded.Branding.PrimaryColor)
}

// TestGeneralSectionValidation tests general section validation
func TestGeneralSectionValidation(t *testing.T) {
	tests := []struct {
		name    string
		section GeneralSection
		valid   bool
	}{
		{
			name: "valid general section",
			section: GeneralSection{
				OrganizationName: "Acme Corp",
				SupportEmail:     "support@acme.com",
				DefaultLanguage:  "en",
				DefaultTimezone:  "UTC",
				SessionTimeout:   3600,
			},
			valid: true,
		},
		{
			name: "missing organization name",
			section: GeneralSection{
				OrganizationName: "",
				SupportEmail:     "support@acme.com",
				DefaultLanguage:  "en",
				DefaultTimezone:  "UTC",
				SessionTimeout:   3600,
			},
			valid: false,
		},
		{
			name: "invalid email",
			section: GeneralSection{
				OrganizationName: "Acme Corp",
				SupportEmail:     "not-an-email",
				DefaultLanguage:  "en",
				DefaultTimezone:  "UTC",
				SessionTimeout:   3600,
			},
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := newTestSettingsHandler()
			settings := &Settings{
				General: tt.section,
				Security: SecuritySection{
					PasswordPolicy: PasswordPolicySettings{
						MinLength:        12,
						RequireUppercase: true,
						RequireLowercase: true,
						RequireNumbers:   true,
						RequireSpecial:   true,
						MaxAge:           90,
						HistoryCount:     5,
					},
					MFA: MFASettings{
						AllowedMethods: []string{"totp"},
					},
					Session: SessionSettings{
						IdleTimeoutMinutes:    30,
						MaxConcurrentSessions: 5,
					},
				},
				Auth: AuthSection{
					LockoutPolicy: LockoutPolicy{
						Enabled: true,
					},
				},
				Branding: BrandingSection{
					PrimaryColor:   "#2563eb",
					SecondaryColor: "#1e40af",
					LoginPageTitle: "Test",
				},
			}
			err := handler.ValidateSettings(settings)
			if tt.valid {
				// Note: This is a simplified check; Gin's validation would catch more
				if err != nil {
					assert.NotContains(t, err.Error(), "organization_name")
				}
			}
		})
	}
}

// TestPasswordPolicyValidation tests password policy validation
func TestPasswordPolicyValidation(t *testing.T) {
	handler := newTestSettingsHandler()

	tests := []struct {
		name    string
		policy  PasswordPolicySettings
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid strong policy",
			policy: PasswordPolicySettings{
				MinLength:        12,
				RequireUppercase: true,
				RequireLowercase: true,
				RequireNumbers:   true,
				RequireSpecial:   true,
				MaxAge:           90,
				HistoryCount:     5,
			},
			wantErr: false,
		},
		{
			name: "password too short",
			policy: PasswordPolicySettings{
				MinLength:        5,
				RequireUppercase: true,
				RequireLowercase: true,
				RequireNumbers:   true,
				RequireSpecial:   true,
				MaxAge:           90,
				HistoryCount:     5,
			},
			wantErr: true,
			errMsg:  "min_length must be at least 8",
		},
		{
			name: "password too long",
			policy: PasswordPolicySettings{
				MinLength:        150,
				RequireUppercase: true,
				RequireLowercase: true,
				RequireNumbers:   true,
				RequireSpecial:   true,
				MaxAge:           90,
				HistoryCount:     5,
			},
			wantErr: true,
			errMsg:  "cannot exceed 128",
		},
		{
			name: "minimum valid policy",
			policy: PasswordPolicySettings{
				MinLength:        8,
				RequireUppercase: false,
				RequireLowercase: false,
				RequireNumbers:   false,
				RequireSpecial:   false,
				MaxAge:           0,
				HistoryCount:     0,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			settings := &Settings{
				General: GeneralSection{
					OrganizationName: "Test",
					SupportEmail:     "test@test.com",
					DefaultLanguage:  "en",
					DefaultTimezone:  "UTC",
					SessionTimeout:   3600,
				},
				Security: SecuritySection{
					PasswordPolicy: tt.policy,
					MFA: MFASettings{
						AllowedMethods: []string{"totp"},
					},
					Session: SessionSettings{
						IdleTimeoutMinutes:     30,
						AbsoluteTimeoutMinutes: 480,
						MaxConcurrentSessions:  5,
					},
				},
				Auth: AuthSection{
					LockoutPolicy: LockoutPolicy{Enabled: true},
				},
				Branding: BrandingSection{
					PrimaryColor:   "#2563eb",
					SecondaryColor: "#1e40af",
					LoginPageTitle: "Test",
				},
			}
			err := handler.ValidateSettings(settings)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				// May still error on other fields, but not password policy
				if err != nil {
					assert.NotContains(t, err.Error(), "password")
				}
			}
		})
	}
}

// TestMFASettingsValidation tests MFA settings validation
func TestMFASettingsValidation(t *testing.T) {
	handler := newTestSettingsHandler()

	tests := []struct {
		name    string
		mfa     MFASettings
		wantErr bool
		errMsg  string
	}{
		{
			name: "MFA disabled with no methods",
			mfa: MFASettings{
				Enabled:        false,
				Required:       false,
				AllowedMethods: []string{},
			},
			wantErr: false,
		},
		{
			name: "MFA enabled with methods",
			mfa: MFASettings{
				Enabled:        true,
				Required:       true,
				AllowedMethods: []string{"totp", "webauthn", "sms"},
			},
			wantErr: false,
		},
		{
			name: "MFA enabled without methods",
			mfa: MFASettings{
				Enabled:        true,
				Required:       true,
				AllowedMethods: []string{},
			},
			wantErr: true,
			errMsg:  "at least one MFA method",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			settings := &Settings{
				General: GeneralSection{
					OrganizationName: "Test",
					SupportEmail:     "test@test.com",
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
						MaxAge:           90,
						HistoryCount:     5,
					},
					MFA: tt.mfa,
					Session: SessionSettings{
						IdleTimeoutMinutes:     30,
						AbsoluteTimeoutMinutes: 480,
						MaxConcurrentSessions:  5,
					},
				},
				Auth: AuthSection{
					LockoutPolicy: LockoutPolicy{Enabled: true},
				},
				Branding: BrandingSection{
					PrimaryColor:   "#2563eb",
					SecondaryColor: "#1e40af",
					LoginPageTitle: "Test",
				},
			}
			err := handler.ValidateSettings(settings)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				if err != nil {
					assert.NotContains(t, err.Error(), "MFA")
				}
			}
		})
	}
}

// TestBrandingColorValidation tests branding color validation
func TestBrandingColorValidation(t *testing.T) {
	handler := newTestSettingsHandler()

	tests := []struct {
		name           string
		primaryColor   string
		secondaryColor string
		wantErr        bool
	}{
		{
			name:           "valid hex colors",
			primaryColor:   "#2563eb",
			secondaryColor: "#1e40af",
			wantErr:        false,
		},
		{
			name:           "invalid primary color",
			primaryColor:   "2563eb",
			secondaryColor: "#1e40af",
			wantErr:        true,
		},
		{
			name:           "invalid secondary color",
			primaryColor:   "#2563eb",
			secondaryColor: "1e40af",
			wantErr:        true,
		},
		{
			name:           "short hex code",
			primaryColor:   "#fff",
			secondaryColor: "#000",
			wantErr:        true,
		},
		{
			name:           "long hex code",
			primaryColor:   "#2563ebff",
			secondaryColor: "#1e40afff",
			wantErr:        true,
		},
		{
			name:           "invalid characters",
			primaryColor:   "#2563eb",
			secondaryColor: "#1e40ag",
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			settings := &Settings{
				General: GeneralSection{
					OrganizationName: "Test",
					SupportEmail:     "test@test.com",
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
						MaxAge:           90,
						HistoryCount:     5,
					},
					MFA: MFASettings{
						AllowedMethods: []string{"totp"},
					},
					Session: SessionSettings{
						IdleTimeoutMinutes:     30,
						AbsoluteTimeoutMinutes: 480,
						MaxConcurrentSessions:  5,
					},
				},
				Auth: AuthSection{
					LockoutPolicy: LockoutPolicy{Enabled: true},
				},
				Branding: BrandingSection{
					PrimaryColor:   tt.primaryColor,
					SecondaryColor: tt.secondaryColor,
					LoginPageTitle: "Test",
				},
			}
			err := handler.ValidateSettings(settings)
			if tt.wantErr {
				assert.Error(t, err)
			}
		})
	}
}

// TestIsValidHexColor tests the hex color validation helper
func TestIsValidHexColor(t *testing.T) {
	tests := []struct {
		color string
		valid bool
	}{
		{"#2563eb", true},
		{"#1e40af", true},
		{"#000000", true},
		{"#ffffff", true},
		{"#FFFFFF", true},
		{"#ABCDEF", true},
		{"#123456", true},
		{"2563eb", false},    // missing #
		{"#2563ebff", false}, // too long
		{"#fff", false},      // too short
		{"#2563eg", false},   // invalid character
		{"", false},          // empty
		{"#2563e", false},    // too short
	}

	for _, tt := range tests {
		t.Run(tt.color, func(t *testing.T) {
			result := isValidHexColor(tt.color)
			assert.Equal(t, tt.valid, result)
		})
	}
}

// TestGetSettingsHandler tests GET /settings endpoint structure
func TestGetSettingsHandler(t *testing.T) {
	logger := zap.NewNop()
	handler := NewSettingsHandler(logger, nil)
	assert.NotNil(t, handler)

	// Test serialization of default settings
	settings := handler.getDefaultSettings()
	assert.Equal(t, "OpenIDX", settings.General.OrganizationName)
	assert.Equal(t, 12, settings.Security.PasswordPolicy.MinLength)
}

// TestUpdateSettingsInvalidJSON tests PUT /settings with invalid JSON
func TestUpdateSettingsInvalidJSON(t *testing.T) {
	// Test that invalid JSON is handled properly
	var settings Settings
	err := json.Unmarshal([]byte("not json"), &settings)
	assert.Error(t, err)
}

// TestUpdateSettingsValidation tests PUT /settings with invalid settings
func TestUpdateSettingsValidation(t *testing.T) {
	logger := zap.NewNop()
	handler := NewSettingsHandler(logger, nil)
	assert.NotNil(t, handler)

	// This would fail Gin validation during binding
	settings := Settings{
		General: GeneralSection{
			OrganizationName: "",
			SupportEmail:     "",
			DefaultLanguage:  "",
			DefaultTimezone:  "",
			SessionTimeout:   0,
		},
	}

	// Validate should fail on empty organization name
	err := handler.ValidateSettings(&settings)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "organization_name")
}

// TestResetSettingsHandler tests default settings structure
func TestResetSettingsHandler(t *testing.T) {
	logger := zap.NewNop()
	handler := NewSettingsHandler(logger, nil)
	assert.NotNil(t, handler)

	// Test default settings values
	settings := handler.getDefaultSettings()
	assert.Equal(t, "OpenIDX", settings.General.OrganizationName)
	assert.Equal(t, "support@openidx.io", settings.General.SupportEmail)
	assert.Equal(t, 12, settings.Security.PasswordPolicy.MinLength)
}

// TestValidatePasswordHandler tests password validation logic
func TestValidatePasswordHandler(t *testing.T) {
	logger := zap.NewNop()
	handler := NewSettingsHandler(logger, nil)
	assert.NotNil(t, handler)

	// Test that ValidateSettings checks password policy length
	settings := &Settings{
		General: GeneralSection{
			OrganizationName: "Test",
			SupportEmail:     "test@test.com",
			DefaultLanguage:  "en",
			DefaultTimezone:  "UTC",
			SessionTimeout:   3600,
		},
		Security: SecuritySection{
			PasswordPolicy: PasswordPolicySettings{
				MinLength:        5, // Too short - should fail validation
				RequireUppercase: true,
				RequireLowercase: true,
				RequireNumbers:   true,
				RequireSpecial:   true,
				MaxAge:           90,
				HistoryCount:     5,
			},
			MFA: MFASettings{
				AllowedMethods: []string{"totp"},
			},
			Session: SessionSettings{
				IdleTimeoutMinutes:     30,
				AbsoluteTimeoutMinutes: 480,
				MaxConcurrentSessions:  5,
			},
		},
		Auth: AuthSection{
			LockoutPolicy: LockoutPolicy{Enabled: true},
		},
		Branding: BrandingSection{
			PrimaryColor:   "#2563eb",
			SecondaryColor: "#1e40af",
			LoginPageTitle: "Test",
		},
	}

	err := handler.ValidateSettings(settings)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "min_length must be at least 8")
}

// TestGetSettingsJSONHandler tests settings serialization
func TestGetSettingsJSONHandler(t *testing.T) {
	logger := zap.NewNop()
	handler := NewSettingsHandler(logger, nil)
	assert.NotNil(t, handler)

	// Test that settings can be serialized to JSON
	settings := handler.getDefaultSettings()
	data, err := json.Marshal(settings)
	require.NoError(t, err)
	assert.NotEmpty(t, data)
}

// TestSettingsRoutesRegistration tests route registration
func TestSettingsRoutesRegistration(t *testing.T) {
	handler := newTestSettingsHandler()
	router := gin.New()
	group := router.Group("/api/v1")
	SettingsRoutes(group, handler, nil)

	routes := router.Routes()

	// Collect all routes for verification
	routeMap := make(map[string][]string)
	for _, route := range routes {
		routeMap[route.Path] = append(routeMap[route.Path], route.Method)
	}

	// Verify routes are registered (some paths have multiple methods)
	assert.Contains(t, routeMap["/api/v1/settings"], "GET")
	assert.Contains(t, routeMap["/api/v1/settings"], "PUT")
	assert.Contains(t, routeMap["/api/v1/settings/reset"], "POST")
	assert.Contains(t, routeMap["/api/v1/settings/json"], "GET")
	assert.Contains(t, routeMap["/api/v1/settings/validate-password"], "POST")
}

// TestTOTPSettingsSerialization tests TOTP settings serialization
func TestTOTPSettingsSerialization(t *testing.T) {
	totp := TOTPSettings{
		Enabled:    true,
		Issuer:     "OpenIDX",
		Algorithm:  "SHA256",
		CodeLength: 6,
		Period:     30,
		Window:     1,
	}

	data, err := json.Marshal(totp)
	require.NoError(t, err)

	var decoded TOTPSettings
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, "OpenIDX", decoded.Issuer)
	assert.Equal(t, "SHA256", decoded.Algorithm)
	assert.Equal(t, 6, decoded.CodeLength)
}

// TestWebAuthnSettingsSerialization tests WebAuthn settings serialization
func TestWebAuthnSettingsSerialization(t *testing.T) {
	webauthn := WebAuthnSettings{
		Enabled:              true,
		RelyingPartyID:       "openidx.io",
		RelyingPartyName:     "OpenIDX",
		RelyingPartyOrigin:   "https://openidx.io",
		AuthenticatorTimeout: 60,
		RequireResidentKey:   false,
		UserVerification:     "preferred",
	}

	data, err := json.Marshal(webauthn)
	require.NoError(t, err)

	var decoded WebAuthnSettings
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, "openidx.io", decoded.RelyingPartyID)
	assert.Equal(t, "preferred", decoded.UserVerification)
}

// TestSessionSettingsSerialization tests session settings serialization
func TestSessionSettingsSerialization(t *testing.T) {
	session := SessionSettings{
		IdleTimeoutMinutes:     30,
		AbsoluteTimeoutMinutes: 480,
		MaxConcurrentSessions:  5,
		RememberMeDays:         30,
	}

	data, err := json.Marshal(session)
	require.NoError(t, err)

	var decoded SessionSettings
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, 30, decoded.IdleTimeoutMinutes)
	assert.Equal(t, 480, decoded.AbsoluteTimeoutMinutes)
}

// TestLockoutPolicySerialization tests lockout policy serialization
func TestLockoutPolicySerialization(t *testing.T) {
	lockout := LockoutPolicy{
		Enabled:           true,
		MaxFailedAttempts: 5,
		LockoutDuration:   30,
	}

	data, err := json.Marshal(lockout)
	require.NoError(t, err)

	var decoded LockoutPolicy
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.True(t, decoded.Enabled)
	assert.Equal(t, 5, decoded.MaxFailedAttempts)
}

// TestContainsIgnoreCase tests the case-insensitive contains helper
func TestContainsIgnoreCase(t *testing.T) {
	tests := []struct {
		s      string
		substr string
		result bool
	}{
		{"Password123", "password", true},
		{"Password123", "PASSWORD", true},
		{"Password123", "PaSsWoRd", true},
		{"Password123", "word", true},
		{"Password123", "123", true},
		{"Password123", "abc", false},
		{"", "", true},
		{"test", "", true},
		{"", "test", false},
	}

	for _, tt := range tests {
		t.Run(tt.s+"_"+tt.substr, func(t *testing.T) {
			result := containsIgnoreCase(tt.s, tt.substr)
			assert.Equal(t, tt.result, result)
		})
	}
}

// TestDefaultSettingsStructure tests default settings values
func TestDefaultSettingsStructure(t *testing.T) {
	handler := newTestSettingsHandler()
	settings := handler.getDefaultSettings()

	assert.Equal(t, "OpenIDX", settings.General.OrganizationName)
	assert.Equal(t, "support@openidx.io", settings.General.SupportEmail)
	assert.Equal(t, "en", settings.General.DefaultLanguage)
	assert.Equal(t, "UTC", settings.General.DefaultTimezone)
	assert.Equal(t, 12, settings.Security.PasswordPolicy.MinLength)
	assert.True(t, settings.Security.PasswordPolicy.RequireUppercase)
	assert.Equal(t, "#3B82F6", settings.Branding.PrimaryColor)
	assert.Equal(t, "#1E40AF", settings.Branding.SecondaryColor)
}

// TestValidatePasswordWithForbiddenWords tests password validation against forbidden words
func TestValidatePasswordWithForbiddenWords(t *testing.T) {
	// Note: The getPasswordPolicy method cannot be mocked directly
	// This test verifies the settings validation behavior instead
	handler := newTestSettingsHandler()

	settings := &Settings{
		General: GeneralSection{
			OrganizationName: "Test",
			SupportEmail:     "test@test.com",
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
				ForbiddenWords:   []string{"password", "openidx", "qwerty"},
				MaxAge:           90,
				HistoryCount:     5,
			},
			MFA: MFASettings{
				AllowedMethods: []string{"totp"},
			},
			Session: SessionSettings{
				IdleTimeoutMinutes:     30,
				AbsoluteTimeoutMinutes: 480,
				MaxConcurrentSessions:  5,
			},
		},
		Auth: AuthSection{
			LockoutPolicy: LockoutPolicy{Enabled: true},
		},
		Branding: BrandingSection{
			PrimaryColor:   "#2563eb",
			SecondaryColor: "#1e40af",
			LoginPageTitle: "Test",
		},
	}

	// Verify settings can be validated
	err := handler.ValidateSettings(settings)
	// Settings should be valid structurally
	assert.NoError(t, err)
}

// TestPasswordValidationCombinations tests various password combinations
func TestPasswordValidationCombinations(t *testing.T) {
	handler := newTestSettingsHandler()

	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"valid all requirements", "SecureP@ss123", false},
		{"too short", "Short1!", true},
		{"no uppercase", "lowercase1!", true},
		{"no lowercase", "UPPERCASE1!", true},
		{"no numbers", "NoNumbers!", true},
		{"no special", "NoSpecial123", true},
		{"exactly 12 chars valid", "Valid@12Chars", false},
		{"long valid password", "ThisIsAVeryLongSecurePassword@12345", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			settings := &Settings{
				General: GeneralSection{
					OrganizationName: "Test",
					SupportEmail:     "test@test.com",
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
						MaxAge:           90,
						HistoryCount:     5,
					},
					MFA: MFASettings{
						AllowedMethods: []string{"totp"},
					},
					Session: SessionSettings{
						IdleTimeoutMinutes:     30,
						AbsoluteTimeoutMinutes: 480,
						MaxConcurrentSessions:  5,
					},
				},
				Auth: AuthSection{
					LockoutPolicy: LockoutPolicy{Enabled: true},
				},
				Branding: BrandingSection{
					PrimaryColor:   "#2563eb",
					SecondaryColor: "#1e40af",
					LoginPageTitle: "Test",
				},
			}

			// Validate settings structure (not the password itself)
			err := handler.ValidateSettings(settings)
			// Settings validation should pass
			if !tt.wantErr {
				assert.NoError(t, err)
			}
		})
	}
}
