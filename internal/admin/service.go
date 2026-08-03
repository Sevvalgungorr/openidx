// Package admin provides the Admin API for the Admin Console
package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/ai"
	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/sms"
)

// Dashboard contains overview statistics
type Dashboard struct {
	TotalUsers           int                   `json:"total_users"`
	ActiveUsers          int                   `json:"active_users"`
	TotalGroups          int                   `json:"total_groups"`
	TotalApplications    int                   `json:"total_applications"`
	ActiveSessions       int                   `json:"active_sessions"`
	PendingReviews       int                   `json:"pending_reviews"`
	SecurityAlerts       int                   `json:"security_alerts"`
	RecentActivity       []ActivityItem        `json:"recent_activity"`
	AuthStats            AuthStatistics        `json:"auth_stats"`
	SecurityAlertDetails []SecurityAlertDetail `json:"security_alert_details"`
}

// ActivityItem represents recent activity
type ActivityItem struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Message   string    `json:"message"`
	ActorID   string    `json:"actor_id,omitempty"`
	ActorName string    `json:"actor_name,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// AuthStatistics contains authentication statistics
type AuthStatistics struct {
	TotalLogins      int            `json:"total_logins"`
	SuccessfulLogins int            `json:"successful_logins"`
	FailedLogins     int            `json:"failed_logins"`
	MFAUsage         int            `json:"mfa_usage"`
	LoginsByMethod   map[string]int `json:"logins_by_method"`
	LoginsByDay      []DayStats     `json:"logins_by_day"`
}

// DayStats contains statistics for a single day
type DayStats struct {
	Date  string `json:"date"`
	Count int    `json:"count"`
}

// SecurityAlertDetail represents a security alert detail
type SecurityAlertDetail struct {
	Message   string    `json:"message"`
	Count     int       `json:"count"`
	Timestamp time.Time `json:"timestamp"`
}

// Application represents a registered application/client
type Application struct {
	ID           string    `json:"id"`
	ClientID     string    `json:"client_id"`
	Name         string    `json:"name"`
	Description  string    `json:"description,omitempty"`
	Type         string    `json:"type"`
	Protocol     string    `json:"protocol"`
	BaseURL      string    `json:"base_url,omitempty"`
	RedirectURIs []string  `json:"redirect_uris"`
	Enabled      bool      `json:"enabled"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// ApplicationSSOSettings represents SSO settings for an application
type ApplicationSSOSettings struct {
	ID                   string    `json:"id"`
	ApplicationID        string    `json:"application_id"`
	Enabled              bool      `json:"enabled"`
	UseRefreshTokens     bool      `json:"use_refresh_tokens"`
	AccessTokenLifetime  int       `json:"access_token_lifetime"`
	RefreshTokenLifetime int       `json:"refresh_token_lifetime"`
	RequireConsent       bool      `json:"require_consent"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
}

// DirectoryIntegration represents an external directory sync configuration
type DirectoryIntegration struct {
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	Type       string                 `json:"type"` // ldap, azure_ad, google
	Config     map[string]interface{} `json:"config"`
	Enabled    bool                   `json:"enabled"`
	LastSyncAt *time.Time             `json:"last_sync_at,omitempty"`
	SyncStatus string                 `json:"sync_status"`
	CreatedAt  time.Time              `json:"created_at"`
	UpdatedAt  time.Time              `json:"updated_at"`
}

// Settings represents system settings
type Settings struct {
	General        GeneralSettings        `json:"general"`
	Security       SecuritySettings       `json:"security"`
	Authentication AuthenticationSettings `json:"authentication"`
	Branding       BrandingSettings       `json:"branding"`
}

// GeneralSettings contains general system settings
type GeneralSettings struct {
	OrganizationName string `json:"organization_name"`
	SupportEmail     string `json:"support_email"`
	DefaultLanguage  string `json:"default_language"`
	DefaultTimezone  string `json:"default_timezone"`
}

// SecuritySettings contains security-related settings
type SecuritySettings struct {
	PasswordPolicy            PasswordPolicy `json:"password_policy"`
	SessionTimeout            int            `json:"session_timeout"`
	MaxFailedLogins           int            `json:"max_failed_logins"`
	LockoutDuration           int            `json:"lockout_duration"`
	RequireMFA                bool           `json:"require_mfa"`
	AllowedIPRanges           []string       `json:"allowed_ip_ranges,omitempty"`
	BlockedCountries          []string       `json:"blocked_countries,omitempty"`
	IdleTimeout               int            `json:"idle_timeout"`
	AbsoluteTimeout           int            `json:"absolute_timeout"`
	RememberMeDuration        int            `json:"remember_me_duration"`
	ReauthInterval            int            `json:"reauth_interval"`
	BindSessionToIP           bool           `json:"bind_session_to_ip"`
	ForceLogoutOnPwdChange    bool           `json:"force_logout_on_password_change"`
	MaxConcurrentSessions     int            `json:"max_concurrent_sessions"`
	ConcurrentSessionStrategy string         `json:"concurrent_session_strategy"`
}

// PasswordPolicy defines password requirements
type PasswordPolicy struct {
	MinLength        int  `json:"min_length"`
	RequireUppercase bool `json:"require_uppercase"`
	RequireLowercase bool `json:"require_lowercase"`
	RequireNumbers   bool `json:"require_numbers"`
	RequireSpecial   bool `json:"require_special"`
	MaxAge           int  `json:"max_age"`
	History          int  `json:"history"`
}

// AuthenticationSettings contains authentication settings
type AuthenticationSettings struct {
	AllowRegistration  bool     `json:"allow_registration"`
	RequireEmailVerify bool     `json:"require_email_verify"`
	AllowedDomains     []string `json:"allowed_domains,omitempty"`
	SocialProviders    []string `json:"social_providers,omitempty"`
	MFAMethods         []string `json:"mfa_methods"`
}

// BrandingSettings contains branding customization
type BrandingSettings struct {
	LogoURL          string `json:"logo_url,omitempty"`
	FaviconURL       string `json:"favicon_url,omitempty"`
	PrimaryColor     string `json:"primary_color"`
	SecondaryColor   string `json:"secondary_color"`
	CustomCSS        string `json:"custom_css,omitempty"`
	LoginPageTitle   string `json:"login_page_title"`
	LoginPageMessage string `json:"login_page_message,omitempty"`
}

// AdminDelegation represents a delegated admin permission assignment
type AdminDelegation struct {
	ID              string     `json:"id"`
	DelegateID      string     `json:"delegate_id"`
	DelegateName    string     `json:"delegate_name,omitempty"`
	DelegatedBy     string     `json:"delegated_by"`
	DelegatedByName string     `json:"delegated_by_name,omitempty"`
	ScopeType       string     `json:"scope_type"`
	ScopeID         string     `json:"scope_id"`
	ScopeName       string     `json:"scope_name,omitempty"`
	Permissions     []string   `json:"permissions"`
	Enabled         bool       `json:"enabled"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// DirectorySyncer defines the interface for directory sync operations
type DirectorySyncer interface {
	TestConnection(ctx context.Context, dirType string, configBytes []byte) error
	TriggerSync(ctx context.Context, directoryID string, fullSync bool) error
	GetSyncLogs(ctx context.Context, directoryID string, limit int) (interface{}, error)
	GetSyncState(ctx context.Context, directoryID string) (interface{}, error)
	// Diagnose runs live LDAP/AD probes and returns findings + suggested config
	// fixes (nil dirType/config errors are surfaced in the result, not returned).
	Diagnose(ctx context.Context, dirType string, configBytes []byte) (interface{}, error)
}

// Service provides admin operations
// RiskAssessor defines the interface for risk/device management operations
type RiskAssessor interface {
	GetAllDevices(ctx context.Context, limit, offset int) (interface{}, int, error)
	GetUserDevices(ctx context.Context, userID string) (interface{}, error)
	TrustDevice(ctx context.Context, deviceID string) error
	RevokeDevice(ctx context.Context, deviceID string) error
	GetRiskStats(ctx context.Context) (map[string]interface{}, error)
	GetLoginHistory(ctx context.Context, userID string, limit int) (interface{}, error)
}

// APIKeyManager defines the interface for API key operations
type APIKeyManager interface {
	CreateServiceAccount(ctx context.Context, name, description, ownerID string) (interface{}, error)
	ListServiceAccounts(ctx context.Context, limit, offset int) (interface{}, int, error)
	GetServiceAccount(ctx context.Context, id string) (interface{}, error)
	DeleteServiceAccount(ctx context.Context, id string) error
	CreateAPIKey(ctx context.Context, name string, userID, serviceAccountID *string, scopes []string, expiresAt *time.Time) (string, interface{}, error)
	ListAPIKeys(ctx context.Context, ownerID string, ownerType string) (interface{}, error)
	RevokeAPIKey(ctx context.Context, keyID string) error
}

// WebhookManager defines the interface for webhook operations
type WebhookManager interface {
	CreateSubscription(ctx context.Context, name, url, secret string, events []string, createdBy string) (interface{}, error)
	ListSubscriptions(ctx context.Context) (interface{}, error)
	GetSubscription(ctx context.Context, id string) (interface{}, error)
	DeleteSubscription(ctx context.Context, id string) error
	GetDeliveryHistory(ctx context.Context, subscriptionID string, limit int) (interface{}, error)
	RetryDelivery(ctx context.Context, deliveryID string) error
	Publish(ctx context.Context, eventType string, payload interface{}) error
	PingSubscription(ctx context.Context, subscriptionID string) (interface{}, error)
	GetDeliveryStats(ctx context.Context, subscriptionID string) (interface{}, error)
}

// SecurityService defines the interface for security alert and IP threat operations
type SecurityService interface {
	ListSecurityAlerts(ctx context.Context, status, severity, alertType string, limit, offset int) (interface{}, int, error)
	GetSecurityAlert(ctx context.Context, id string) (interface{}, error)
	UpdateAlertStatus(ctx context.Context, id, status, resolvedBy string) error
	ListIPThreats(ctx context.Context, limit, offset int) (interface{}, int, error)
	AddToThreatList(ctx context.Context, ip, threatType, reason string, permanent bool, blockedUntil *time.Time) error
	RemoveFromThreatList(ctx context.Context, id string) error
}

type Service struct {
	db               *database.PostgresDB
	redis            *database.RedisClient
	config           *config.Config
	logger           *zap.Logger
	settings         SettingsRepository
	directoryService DirectorySyncer
	riskService      RiskAssessor
	apiKeyService    APIKeyManager
	webhookService   WebhookManager
	securityService  SecurityService
	aiClient         *ai.Client
}

// requireAdmin checks if the authenticated user has admin or super_admin role.
// Returns true if admin, false (with 403 response) if not.
func requireAdmin(c *gin.Context) bool {
	if roles, exists := c.Get("roles"); exists {
		if roleList, ok := roles.([]string); ok {
			for _, r := range roleList {
				if r == "admin" || r == "super_admin" {
					return true
				}
			}
		}
	}
	c.JSON(http.StatusForbidden, gin.H{"error": "admin access required"})
	return false
}

// NewService creates a new admin service
func NewService(db *database.PostgresDB, redis *database.RedisClient, cfg *config.Config, logger *zap.Logger) *Service {
	return &Service{
		db:       db,
		redis:    redis,
		config:   cfg,
		logger:   logger.With(zap.String("service", "admin")),
		settings: NewPostgresSettingsRepository(db),
		aiClient: ai.NewClient(cfg, logger),
	}
}

// SetDirectoryService sets the directory service for sync operations
func (s *Service) SetDirectoryService(ds DirectorySyncer) {
	s.directoryService = ds
}

// SetRiskService sets the risk service for device/risk management
func (s *Service) SetRiskService(rs RiskAssessor) {
	s.riskService = rs
}

// SetAPIKeyService sets the API key service for service account/key management
func (s *Service) SetAPIKeyService(aks APIKeyManager) {
	s.apiKeyService = aks
}

// SetWebhookService sets the webhook service for webhook management
func (s *Service) SetWebhookService(ws WebhookManager) {
	s.webhookService = ws
}

// SetSecurityService sets the security service for alert and IP threat management
func (s *Service) SetSecurityService(ss SecurityService) {
	s.securityService = ss
}

// GetDashboard returns dashboard statistics
func (s *Service) GetDashboard(ctx context.Context) (*Dashboard, error) {
	s.logger.Debug("Getting dashboard statistics")

	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	var totalUsers, activeUsers, totalGroups, totalApps, activeSessions, pendingReviews, securityAlerts int

	// Get all dashboard counts in a single query
	err = s.db.Pool.QueryRow(ctx, `
		SELECT
			(SELECT COUNT(*) FROM users WHERE org_id = $1),
			(SELECT COUNT(*) FROM users WHERE enabled = true AND org_id = $1),
			(SELECT COUNT(*) FROM groups WHERE org_id = $1),
			(SELECT COUNT(*) FROM applications WHERE org_id = $1),
			(SELECT COUNT(*) FROM sessions WHERE expires_at > NOW() AND org_id = $1),
			(SELECT COUNT(*) FROM access_reviews WHERE status IN ('pending', 'in_progress') AND org_id = $1),
			(SELECT COUNT(*) FROM audit_events WHERE outcome = 'failure' AND event_type = 'authentication' AND timestamp > NOW() - INTERVAL '24 hours' AND org_id = $1)
	`, org.ID).Scan(&totalUsers, &activeUsers, &totalGroups, &totalApps, &activeSessions, &pendingReviews, &securityAlerts)
	if err != nil {
		s.logger.Error("Failed to query dashboard stats", zap.Error(err))
	}

	// Get recent activity from audit events
	var recentActivity []ActivityItem
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, event_type, action, actor_id, timestamp
		FROM audit_events
		WHERE org_id = $1
		ORDER BY timestamp DESC
		LIMIT 5
	`, org.ID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var item ActivityItem
			rows.Scan(&item.ID, &item.Type, &item.Message, &item.ActorID, &item.Timestamp)
			recentActivity = append(recentActivity, item)
		}
	}

	dashboard := &Dashboard{
		TotalUsers:        totalUsers,
		ActiveUsers:       activeUsers,
		TotalGroups:       totalGroups,
		TotalApplications: totalApps,
		ActiveSessions:    activeSessions,
		PendingReviews:    pendingReviews,
		SecurityAlerts:    securityAlerts,
		RecentActivity:    recentActivity,
		AuthStats:         s.getAuthStatistics(ctx),
	}

	// Get top 5 failed auth attempts grouped by actor
	var alertDetails []SecurityAlertDetail
	alertRows, err := s.db.Pool.Query(ctx, `
		SELECT COALESCE(actor_id, 'unknown') as actor, COUNT(*) as cnt, MAX(timestamp) as latest
		FROM audit_events
		WHERE org_id = $1 AND outcome = 'failure' AND event_type = 'authentication'
		AND timestamp > NOW() - INTERVAL '24 hours'
		GROUP BY actor_id
		ORDER BY cnt DESC
		LIMIT 5
	`, org.ID)
	if err == nil {
		defer alertRows.Close()
		for alertRows.Next() {
			var detail SecurityAlertDetail
			var actor string
			alertRows.Scan(&actor, &detail.Count, &detail.Timestamp)
			detail.Message = fmt.Sprintf("Failed login attempts from %s", actor)
			alertDetails = append(alertDetails, detail)
		}
	}
	dashboard.SecurityAlertDetails = alertDetails

	return dashboard, nil
}

// GetUserDashboard returns dashboard statistics scoped to a specific user
func (s *Service) GetUserDashboard(ctx context.Context, userID string) (*Dashboard, error) {
	s.logger.Debug("Getting user dashboard statistics", zap.String("user_id", userID))

	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	var myGroups, myApps, mySessions, myPendingReviews int

	err = s.db.Pool.QueryRow(ctx, `
		SELECT
			(SELECT COUNT(*) FROM group_memberships WHERE user_id = $1 AND org_id = $2),
			(SELECT COUNT(*) FROM user_application_assignments WHERE user_id = $1 AND org_id = $2),
			(SELECT COUNT(*) FROM sessions WHERE user_id = $1 AND expires_at > NOW() AND org_id = $2),
			(SELECT COUNT(*) FROM review_items ri JOIN access_reviews ar ON ri.review_id = ar.id AND ar.org_id = ri.org_id WHERE ri.org_id = $2 AND ri.user_id = $1 AND ar.status IN ('pending', 'in_progress'))
	`, userID, org.ID).Scan(&myGroups, &myApps, &mySessions, &myPendingReviews)
	if err != nil {
		s.logger.Error("Failed to query user dashboard stats", zap.Error(err))
	}

	// Get user's recent activity
	var recentActivity []ActivityItem
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, event_type, action, actor_id, timestamp
		FROM audit_events
		WHERE org_id = $2 AND (actor_id = $1 OR target_id = $1)
		ORDER BY timestamp DESC
		LIMIT 5
	`, userID, org.ID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var item ActivityItem
			rows.Scan(&item.ID, &item.Type, &item.Message, &item.ActorID, &item.Timestamp)
			recentActivity = append(recentActivity, item)
		}
	}

	// Get user's auth stats
	userAuthStats := s.getUserAuthStatistics(ctx, userID)

	dashboard := &Dashboard{
		TotalUsers:        0, // Not relevant for normal user
		ActiveUsers:       0,
		TotalGroups:       myGroups,
		TotalApplications: myApps,
		ActiveSessions:    mySessions,
		PendingReviews:    myPendingReviews,
		SecurityAlerts:    0,
		RecentActivity:    recentActivity,
		AuthStats:         userAuthStats,
	}

	return dashboard, nil
}

// getUserAuthStatistics returns auth stats scoped to a specific user
func (s *Service) getUserAuthStatistics(ctx context.Context, userID string) AuthStatistics {
	stats := AuthStatistics{
		LoginsByMethod: make(map[string]int),
	}

	org, _ := orgctx.From(ctx)

	// Count user's login events
	rows, err := s.db.Pool.Query(ctx, `
		SELECT action, COUNT(*) as cnt
		FROM audit_events
		WHERE org_id = $2 AND event_type = 'authentication' AND actor_id = $1
		AND timestamp > NOW() - INTERVAL '30 days'
		GROUP BY action
	`, userID, org.ID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var action string
			var count int
			rows.Scan(&action, &count)
			stats.LoginsByMethod[action] = count
			stats.TotalLogins += count
			switch action {
			case "login", "login_mfa":
				stats.SuccessfulLogins += count
			case "login_failed":
				stats.FailedLogins += count
			}
		}
	}

	// Logins by day for chart
	dayRows, err := s.db.Pool.Query(ctx, `
		SELECT DATE(timestamp) as day, COUNT(*) as cnt
		FROM audit_events
		WHERE org_id = $2 AND event_type = 'authentication' AND actor_id = $1
		AND timestamp > NOW() - INTERVAL '30 days'
		GROUP BY DATE(timestamp)
		ORDER BY day
	`, userID, org.ID)
	if err == nil {
		defer dayRows.Close()
		for dayRows.Next() {
			var ds DayStats
			dayRows.Scan(&ds.Date, &ds.Count)
			stats.LoginsByDay = append(stats.LoginsByDay, ds)
		}
	}

	return stats
}

// getAuthStatistics queries real authentication statistics from audit_events
func (s *Service) getAuthStatistics(ctx context.Context) AuthStatistics {
	stats := AuthStatistics{
		LoginsByMethod: make(map[string]int),
	}

	org, _ := orgctx.From(ctx)

	if err := s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_events
		WHERE org_id = $1 AND event_type = 'authentication' AND timestamp > NOW() - INTERVAL '30 days'
	`, org.ID).Scan(&stats.TotalLogins); err != nil {
		s.logger.Error("Failed to query total logins", zap.Error(err))
	}

	if err := s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_events
		WHERE org_id = $1 AND event_type = 'authentication' AND outcome = 'success' AND timestamp > NOW() - INTERVAL '30 days'
	`, org.ID).Scan(&stats.SuccessfulLogins); err != nil {
		s.logger.Error("Failed to query successful logins", zap.Error(err))
	}

	if err := s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_events
		WHERE org_id = $1 AND event_type = 'authentication' AND outcome = 'failure' AND timestamp > NOW() - INTERVAL '30 days'
	`, org.ID).Scan(&stats.FailedLogins); err != nil {
		s.logger.Error("Failed to query failed logins", zap.Error(err))
	}

	if err := s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_events
		WHERE org_id = $1 AND event_type = 'mfa_verification' AND outcome = 'success' AND timestamp > NOW() - INTERVAL '30 days'
	`, org.ID).Scan(&stats.MFAUsage); err != nil {
		s.logger.Error("Failed to query MFA usage", zap.Error(err))
	}

	// Logins by method
	methodRows, err := s.db.Pool.Query(ctx, `
		SELECT COALESCE(action, 'unknown'), COUNT(*) FROM audit_events
		WHERE org_id = $1 AND event_type = 'authentication' AND timestamp > NOW() - INTERVAL '30 days'
		GROUP BY action
	`, org.ID)
	if err == nil {
		defer methodRows.Close()
		for methodRows.Next() {
			var method string
			var count int
			methodRows.Scan(&method, &count)
			stats.LoginsByMethod[method] = count
		}
	}

	// Logins by day (last 7 days)
	dayRows, err := s.db.Pool.Query(ctx, `
		SELECT DATE(timestamp)::text, COUNT(*) FROM audit_events
		WHERE org_id = $1 AND event_type = 'authentication' AND timestamp > NOW() - INTERVAL '7 days'
		GROUP BY DATE(timestamp)
		ORDER BY DATE(timestamp)
	`, org.ID)
	if err == nil {
		defer dayRows.Close()
		for dayRows.Next() {
			var ds DayStats
			dayRows.Scan(&ds.Date, &ds.Count)
			stats.LoginsByDay = append(stats.LoginsByDay, ds)
		}
	}

	return stats
}

// GetSettings returns system settings
func (s *Service) GetSettings(ctx context.Context) (*Settings, error) {
	s.logger.Debug("Getting system settings")

	valueBytes, err := s.settings.GetRaw(ctx, "system")
	if err == nil {
		var settings Settings
		if jsonErr := json.Unmarshal(valueBytes, &settings); jsonErr == nil {
			return &settings, nil
		}
		s.logger.Warn("Failed to unmarshal settings from database, using defaults", zap.Error(err))
	}

	// Fall back to defaults
	settings := &Settings{
		General: GeneralSettings{
			OrganizationName: "OpenIDX",
			SupportEmail:     "support@openidx.io",
			DefaultLanguage:  "en",
			DefaultTimezone:  "UTC",
		},
		Security: SecuritySettings{
			PasswordPolicy: PasswordPolicy{
				MinLength:        12,
				RequireUppercase: true,
				RequireLowercase: true,
				RequireNumbers:   true,
				RequireSpecial:   true,
				MaxAge:           90,
				History:          5,
			},
			SessionTimeout:            30,
			MaxFailedLogins:           5,
			LockoutDuration:           15,
			RequireMFA:                false,
			BlockedCountries:          []string{},
			IdleTimeout:               1800,
			AbsoluteTimeout:           86400,
			RememberMeDuration:        2592000,
			ReauthInterval:            0,
			BindSessionToIP:           false,
			ForceLogoutOnPwdChange:    true,
			MaxConcurrentSessions:     0,
			ConcurrentSessionStrategy: "deny_new",
		},
		Authentication: AuthenticationSettings{
			AllowRegistration:  true,
			RequireEmailVerify: true,
			MFAMethods:         []string{"totp", "webauthn", "sms"},
		},
		Branding: BrandingSettings{
			PrimaryColor:   "#2563eb",
			SecondaryColor: "#1e40af",
			LoginPageTitle: "Welcome to OpenIDX",
		},
	}

	return settings, nil
}

// UpdateSettings updates system settings
func (s *Service) UpdateSettings(ctx context.Context, settings *Settings) error {
	s.logger.Info("Updating system settings")

	valueBytes, err := json.Marshal(settings)
	if err != nil {
		return fmt.Errorf("failed to marshal settings: %w", err)
	}

	if err := s.settings.PutRaw(ctx, "system", valueBytes); err != nil {
		return fmt.Errorf("failed to save settings: %w", err)
	}

	return nil
}

// UpdateApplication updates an existing application
func (s *Service) UpdateApplication(ctx context.Context, id string, updates map[string]interface{}) error {
	s.logger.Info("Updating application", zap.String("id", id))

	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	setParts := []string{}
	args := []interface{}{}
	argCount := 1

	if name, ok := updates["name"].(string); ok {
		setParts = append(setParts, "name = $"+fmt.Sprintf("%d", argCount))
		args = append(args, name)
		argCount++
	}

	if description, ok := updates["description"].(string); ok {
		setParts = append(setParts, "description = $"+fmt.Sprintf("%d", argCount))
		args = append(args, description)
		argCount++
	}

	if baseURL, ok := updates["base_url"].(string); ok {
		setParts = append(setParts, "base_url = $"+fmt.Sprintf("%d", argCount))
		args = append(args, baseURL)
		argCount++
	}

	var syncRedirectURIs []string // captured for the backing-OAuth-client sync below
	if redirectURIsRaw, ok := updates["redirect_uris"]; ok {
		// Handle both []string and []interface{} types
		var redirectURIs []string
		if uris, ok := redirectURIsRaw.([]string); ok {
			redirectURIs = uris
		} else if uris, ok := redirectURIsRaw.([]interface{}); ok {
			for _, uri := range uris {
				if uriStr, ok := uri.(string); ok {
					redirectURIs = append(redirectURIs, uriStr)
				}
			}
		}
		if len(redirectURIs) > 0 {
			setParts = append(setParts, "redirect_uris = $"+fmt.Sprintf("%d", argCount))
			args = append(args, redirectURIs)
			argCount++
			syncRedirectURIs = redirectURIs
		}
	}

	if enabled, ok := updates["enabled"].(bool); ok {
		setParts = append(setParts, "enabled = $"+fmt.Sprintf("%d", argCount))
		args = append(args, enabled)
		argCount++
	}

	if len(setParts) == 0 {
		return fmt.Errorf("no valid fields to update")
	}

	setParts = append(setParts, "updated_at = NOW()")
	query := fmt.Sprintf("UPDATE applications SET %s WHERE id = $%d AND org_id = $%d",
		strings.Join(setParts, ", "), argCount, argCount+1)
	args = append(args, id, org.ID)

	_, err = s.db.Pool.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to update application: %w", err)
	}

	// Propagate editable settings to the backing OAuth client. The OAuth flow's
	// source of truth is oauth_clients, so without this a redirect-URI edit on
	// the Applications page would update only the listing copy and never take
	// effect on logins. For a proxy-app tile (client_id="proxy-app-<routeID>")
	// there is no oauth_clients row, so the UPDATE simply matches nothing.
	ocSet := []string{}
	ocArgs := []interface{}{}
	ocN := 1
	if name, ok := updates["name"].(string); ok {
		ocSet = append(ocSet, fmt.Sprintf("name = $%d", ocN))
		ocArgs = append(ocArgs, name)
		ocN++
	}
	if desc, ok := updates["description"].(string); ok {
		ocSet = append(ocSet, fmt.Sprintf("description = $%d", ocN))
		ocArgs = append(ocArgs, desc)
		ocN++
	}
	if len(syncRedirectURIs) > 0 {
		urisJSON, _ := json.Marshal(syncRedirectURIs)
		ocSet = append(ocSet, fmt.Sprintf("redirect_uris = $%d", ocN))
		ocArgs = append(ocArgs, urisJSON)
		ocN++
	}
	if len(ocSet) > 0 {
		var clientID string
		if e := s.db.Pool.QueryRow(ctx,
			"SELECT client_id FROM applications WHERE id = $1 AND org_id = $2", id, org.ID).Scan(&clientID); e == nil {
			ocSet = append(ocSet, "updated_at = NOW()")
			ocArgs = append(ocArgs, clientID)
			//orgscope:ignore client_id resolved via the org-scoped applications lookup on the line above; oauth_clients keyed by globally-unique client_id
			ocQuery := fmt.Sprintf("UPDATE oauth_clients SET %s WHERE client_id = $%d", strings.Join(ocSet, ", "), ocN)
			if _, e := s.db.Pool.Exec(ctx, ocQuery, ocArgs...); e != nil {
				s.logger.Warn("update application: failed to sync backing OAuth client",
					zap.String("client_id", clientID), zap.Error(e))
			}
		}
	}

	return nil
}

// ListApplications returns registered applications with optional pagination
func (s *Service) ListApplications(ctx context.Context, offset, limit int) ([]Application, int, error) {
	s.logger.Debug("Listing applications")

	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, 0, err
	}

	var totalCount int
	if err := s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM applications WHERE org_id = $1", org.ID).Scan(&totalCount); err != nil {
		s.logger.Error("Failed to query application count", zap.Error(err))
	}

	query := `
		SELECT id, client_id, name, COALESCE(description, ''), type, protocol,
		       COALESCE(base_url, ''), redirect_uris, enabled, created_at, updated_at
		FROM applications
		WHERE org_id = $1
		ORDER BY name
	`
	args := []interface{}{org.ID}
	argCount := 2

	if limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argCount)
		args = append(args, limit)
		argCount++
	}
	if offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argCount)
		args = append(args, offset)
	}

	rows, err := s.db.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var apps []Application
	for rows.Next() {
		var app Application
		if err := rows.Scan(
			&app.ID, &app.ClientID, &app.Name, &app.Description, &app.Type,
			&app.Protocol, &app.BaseURL, &app.RedirectURIs, &app.Enabled, &app.CreatedAt, &app.UpdatedAt,
		); err != nil {
			return nil, 0, err
		}
		apps = append(apps, app)
	}

	return apps, totalCount, nil
}

// CreateApplication creates a new application
func (s *Service) CreateApplication(ctx context.Context, app *Application) error {
	s.logger.Info("Creating application", zap.String("name", app.Name))

	if app.ID == "" {
		app.ID = uuid.New().String()
	}
	if app.ClientID == "" {
		app.ClientID = uuid.New().String()
	}
	app.CreatedAt = time.Now()
	app.UpdatedAt = time.Now()

	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO applications (id, client_id, name, description, type, protocol, base_url, redirect_uris, enabled, created_at, updated_at, org_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`, app.ID, app.ClientID, app.Name, app.Description, app.Type, app.Protocol,
		app.BaseURL, app.RedirectURIs, app.Enabled, app.CreatedAt, app.UpdatedAt, org.ID)
	if err != nil {
		return fmt.Errorf("failed to create application: %w", err)
	}

	return nil
}

// GetApplicationSSOSettings gets SSO settings for an application
func (s *Service) GetApplicationSSOSettings(ctx context.Context, applicationID string) (*ApplicationSSOSettings, error) {
	s.logger.Debug("Getting SSO settings", zap.String("application_id", applicationID))

	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	var settings ApplicationSSOSettings
	err = s.db.Pool.QueryRow(ctx, `
		SELECT id, application_id, enabled, use_refresh_tokens, access_token_lifetime,
		       refresh_token_lifetime, require_consent, created_at, updated_at
		FROM application_sso_settings WHERE application_id = $1 AND org_id = $2
	`, applicationID, org.ID).Scan(
		&settings.ID, &settings.ApplicationID, &settings.Enabled, &settings.UseRefreshTokens,
		&settings.AccessTokenLifetime, &settings.RefreshTokenLifetime, &settings.RequireConsent,
		&settings.CreatedAt, &settings.UpdatedAt,
	)

	if err != nil {
		// Return default settings if none exist
		settings = ApplicationSSOSettings{
			ApplicationID:        applicationID,
			Enabled:              true,
			UseRefreshTokens:     true,
			AccessTokenLifetime:  3600,
			RefreshTokenLifetime: 86400,
			RequireConsent:       false,
		}
		return &settings, nil
	}

	return &settings, nil
}

// UpdateApplicationSSOSettings updates SSO settings for an application
func (s *Service) UpdateApplicationSSOSettings(ctx context.Context, settings *ApplicationSSOSettings) error {
	s.logger.Info("Updating SSO settings", zap.String("application_id", settings.ApplicationID))

	settings.UpdatedAt = time.Now()

	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	// Try to update existing settings
	result, err := s.db.Pool.Exec(ctx, `
		UPDATE application_sso_settings SET
			enabled = $2, use_refresh_tokens = $3, access_token_lifetime = $4,
			refresh_token_lifetime = $5, require_consent = $6, updated_at = $7
		WHERE application_id = $1 AND org_id = $8
	`, settings.ApplicationID, settings.Enabled, settings.UseRefreshTokens,
		settings.AccessTokenLifetime, settings.RefreshTokenLifetime, settings.RequireConsent, settings.UpdatedAt, org.ID)

	if err != nil {
		return fmt.Errorf("failed to update SSO settings: %w", err)
	}

	// If no rows were affected, create new settings
	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		settings.ID = uuid.New().String()
		settings.CreatedAt = settings.UpdatedAt

		_, err = s.db.Pool.Exec(ctx, `
			INSERT INTO application_sso_settings (id, application_id, enabled, use_refresh_tokens,
				access_token_lifetime, refresh_token_lifetime, require_consent, created_at, updated_at, org_id)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		`, settings.ID, settings.ApplicationID, settings.Enabled, settings.UseRefreshTokens,
			settings.AccessTokenLifetime, settings.RefreshTokenLifetime, settings.RequireConsent,
			settings.CreatedAt, settings.UpdatedAt, org.ID)

		if err != nil {
			return fmt.Errorf("failed to create SSO settings: %w", err)
		}
	}

	return nil
}

// RegisterRoutes registers admin service routes
func RegisterRoutes(router *gin.RouterGroup, svc *Service) {
	// The application catalog LIST is read by the end-user Access Requests page
	// to choose what to request, so it stays available to any authenticated user.
	router.GET("/applications", svc.handleListApplications)

	// Everything else on the admin surface is admin/super_admin only. Gating the
	// whole group here (rather than relying on the optional OPA layer) keeps the
	// legacy CRUD routes — application writes, directories, service accounts, API
	// keys, webhooks, devices, analytics, sessions, alerts — from being reachable
	// by any authenticated caller when ENABLE_OPA_AUTHZ is disabled.
	admin := router.Group("")
	admin.Use(RequireAdmin())

	// Dashboard and Settings are now handled by internal/admin/handlers package
	// to avoid route registration conflicts

	// SMS Settings (separate from main settings due to credential sensitivity)
	admin.GET("/settings/sms", svc.handleGetSMSSettings)
	admin.PUT("/settings/sms", svc.handleUpdateSMSSettings)
	admin.POST("/settings/sms/test", svc.handleTestSMS)

	// Applications
	admin.POST("/applications", svc.handleCreateApplication)
	admin.GET("/applications/:id", svc.handleGetApplication)
	admin.PUT("/applications/:id", svc.handleUpdateApplication)
	admin.DELETE("/applications/:id", svc.handleDeleteApplication)

	// Application SSO Settings
	admin.GET("/applications/:id/sso-settings", svc.handleGetApplicationSSOSettings)
	admin.PUT("/applications/:id/sso-settings", svc.handleUpdateApplicationSSOSettings)

	// Directory integrations
	admin.GET("/directories", svc.handleListDirectories)
	admin.POST("/directories", svc.handleCreateDirectory)
	admin.GET("/directories/:id", svc.handleGetDirectory)
	admin.PUT("/directories/:id", svc.handleUpdateDirectory)
	admin.DELETE("/directories/:id", svc.handleDeleteDirectory)
	admin.POST("/directories/:id/sync", svc.handleSyncDirectory)
	admin.POST("/directories/:id/test", svc.handleTestConnection)
	// Live LDAP/AD diagnostics with suggested fixes. The :id form diagnoses a
	// saved integration; the wizard (pre-save) form posts {type, config} to
	// /directory-diagnose so it does not collide with the :id wildcard.
	admin.POST("/directories/:id/diagnose", svc.handleDiagnoseDirectory)
	admin.POST("/directory-diagnose", svc.handleDiagnoseDirectory)
	admin.GET("/directories/:id/sync-logs", svc.handleGetSyncLogs)
	admin.GET("/directories/:id/sync-state", svc.handleGetSyncState)

	// MFA configuration
	admin.GET("/mfa/methods", svc.handleListMFAMethods)
	admin.PUT("/mfa/methods", svc.handleUpdateMFAMethods)

	// Device management (conditional access)
	admin.GET("/devices", svc.handleListDevices)
	admin.GET("/users/:id/devices", svc.handleUserDevices)
	admin.POST("/devices/:id/trust", svc.handleTrustDevice)
	admin.DELETE("/devices/:id", svc.handleRevokeDevice)

	// Risk stats and login history
	admin.GET("/risk/stats", svc.handleRiskStats)
	admin.GET("/login-history", svc.handleLoginHistory)

	// Service accounts
	admin.GET("/service-accounts", svc.handleListServiceAccounts)
	admin.POST("/service-accounts", svc.handleCreateServiceAccount)
	admin.GET("/service-accounts/:id", svc.handleGetServiceAccount)
	admin.DELETE("/service-accounts/:id", svc.handleDeleteServiceAccount)

	// API keys
	admin.GET("/service-accounts/:id/api-keys", svc.handleListServiceAccountAPIKeys)
	admin.POST("/service-accounts/:id/api-keys", svc.handleCreateServiceAccountAPIKey)
	admin.POST("/api-keys", svc.handleCreateUserAPIKey)
	admin.GET("/api-keys", svc.handleListUserAPIKeys)
	admin.DELETE("/api-keys/:id", svc.handleRevokeAPIKey)

	// Webhooks
	admin.GET("/webhooks", svc.handleListWebhooks)
	admin.POST("/webhooks", svc.handleCreateWebhook)
	admin.GET("/webhooks/:id", svc.handleGetWebhook)
	admin.DELETE("/webhooks/:id", svc.handleDeleteWebhook)
	admin.GET("/webhooks/:id/deliveries", svc.handleWebhookDeliveries)
	admin.POST("/webhooks/deliveries/:id/retry", svc.handleRetryWebhookDelivery)
	admin.POST("/webhooks/:id/test", svc.handleTestWebhook)
	admin.GET("/webhooks/:id/stats", svc.handleWebhookStats)

	// Invitations
	admin.GET("/invitations", svc.handleListInvitations)
	admin.POST("/invitations", svc.handleCreateInvitation)
	admin.DELETE("/invitations/:id", svc.handleDeleteInvitation)

	// Analytics
	admin.GET("/analytics/logins", svc.handleLoginAnalytics)
	admin.GET("/analytics/risk", svc.handleRiskAnalytics)
	admin.GET("/analytics/users", svc.handleUserAnalytics)
	admin.GET("/analytics/events", svc.handleEventAnalytics)

	// Session management
	admin.GET("/sessions", svc.handleListAllSessions)
	admin.DELETE("/sessions/:id", svc.handleAdminRevokeSession)
	admin.DELETE("/users/:id/sessions", svc.handleAdminRevokeAllUserSessions)

	// Security alerts
	admin.GET("/security-alerts", svc.handleListSecurityAlerts)
	admin.GET("/security-alerts/:id", svc.handleGetSecurityAlert)
	admin.PUT("/security-alerts/:id/status", svc.handleUpdateAlertStatus)

	// IP threat management
	admin.GET("/ip-threats", svc.handleListIPThreats)
	admin.POST("/ip-threats", svc.handleAddIPThreat)
	admin.DELETE("/ip-threats/:id", svc.handleRemoveIPThreat)

	// Service account key rotation
	admin.POST("/service-accounts/:id/rotate-key", svc.handleRotateServiceAccountKey)

	// Compliance posture dashboard
	admin.GET("/compliance-posture", svc.handleGetCompliancePosture)

	// Entitlement catalog
	admin.GET("/entitlements", svc.handleGetEntitlementCatalog)
	admin.GET("/entitlements/stats", svc.handleGetEntitlementStats)
	admin.PUT("/entitlements/:type/:id/metadata", svc.handleUpdateEntitlementMetadata)

	// Admin delegations
	admin.GET("/delegations", svc.handleListDelegations)
	admin.POST("/delegations", svc.handleCreateDelegation)
	admin.GET("/delegations/:id", svc.handleGetDelegation)
	admin.PUT("/delegations/:id", svc.handleUpdateDelegation)
	admin.DELETE("/delegations/:id", svc.handleDeleteDelegation)

	// Developer experience
	admin.GET("/developer/settings", svc.handleGetDeveloperSettings)
	admin.PUT("/developer/settings", svc.handleUpdateDeveloperSettings)
	admin.GET("/developer/api-catalog", svc.handleListAPIEndpoints)
	admin.GET("/developer/code-samples", svc.handleGetCodeSamples)
	admin.POST("/developer/playground/sessions", svc.handleCreatePlaygroundSession)
	admin.POST("/developer/playground/execute", svc.handleExecutePlayground)

	// Admin audit log
	admin.GET("/audit-log", svc.handleGetAdminAuditLog)
	admin.GET("/audit-log/:id", svc.handleGetAdminAuditEntry)
	admin.GET("/settings-history", svc.handleGetSettingsHistory)

	// Enhanced analytics (Phase 12)
	admin.GET("/analytics/auth-dashboard", svc.handleAuthAnalyticsDashboard)
	admin.GET("/analytics/usage", svc.handleUsageAnalytics)
	admin.GET("/analytics/api-usage", svc.handleAPIUsageMetrics)
	admin.GET("/analytics/feature-adoption", svc.handleFeatureAdoption)
	admin.GET("/analytics/risk-timeline", svc.handleRiskScoreTimeline)
	admin.GET("/analytics/activity-heatmap", svc.handleUserActivityHeatmap)

	// System health (Phase 14)
	admin.GET("/system/health", svc.handleSystemHealth)

	// Error catalog (Phase 14)
	admin.GET("/error-catalog", svc.handleListErrorCatalog)
	admin.POST("/error-catalog", svc.handleCreateErrorCatalogEntry)
	admin.PUT("/error-catalog/:code", svc.handleUpdateErrorCatalogEntry)
	admin.DELETE("/error-catalog/:code", svc.handleDeleteErrorCatalogEntry)

	// Phase 15: AI & Intelligence

	// AI Agent Identity Management
	admin.GET("/ai-agents", svc.handleListAIAgents)
	admin.POST("/ai-agents", svc.handleCreateAIAgent)
	admin.GET("/ai-agents/analytics", svc.handleAIAgentAnalytics)
	admin.GET("/ai-agents/:id", svc.handleGetAIAgent)
	admin.PUT("/ai-agents/:id", svc.handleUpdateAIAgent)
	admin.DELETE("/ai-agents/:id", svc.handleDeleteAIAgent)
	admin.POST("/ai-agents/:id/suspend", svc.handleSuspendAIAgent)
	admin.POST("/ai-agents/:id/activate", svc.handleActivateAIAgent)
	admin.POST("/ai-agents/:id/rotate-credentials", svc.handleRotateAIAgentCredentials)
	admin.GET("/ai-agents/:id/activity", svc.handleListAIAgentActivity)
	admin.GET("/ai-agents/:id/permissions", svc.handleListAIAgentPermissions)
	admin.POST("/ai-agents/:id/permissions", svc.handleGrantAIAgentPermission)
	admin.DELETE("/ai-agents/:id/permissions/:permId", svc.handleRevokeAIAgentPermission)

	// Identity Security Posture Management (ISPM)
	admin.GET("/ispm/score", svc.handleGetPostureScore)
	admin.GET("/ispm/findings", svc.handleListPostureFindings)
	admin.GET("/ispm/findings/:id", svc.handleGetPostureFinding)
	admin.POST("/ispm/findings/:id/dismiss", svc.handleDismissPostureFinding)
	admin.POST("/ispm/findings/:id/remediate", svc.handleRemediatePostureFinding)
	admin.GET("/ispm/trends", svc.handleGetPostureTrends)
	admin.GET("/ispm/rules", svc.handleListPostureRules)
	admin.PUT("/ispm/rules/:id", svc.handleUpdatePostureRule)
	admin.POST("/ispm/scan", svc.RunPostureChecks)

	// AI-Powered Access Recommendations
	admin.GET("/recommendations", svc.handleListRecommendations)
	admin.GET("/recommendations/stats", svc.handleRecommendationStats)
	admin.GET("/recommendations/:id", svc.handleGetRecommendation)
	admin.POST("/recommendations/:id/accept", svc.handleAcceptRecommendation)
	admin.POST("/recommendations/:id/dismiss", svc.handleDismissRecommendation)
	admin.POST("/recommendations/:id/apply", svc.handleApplyRecommendation)
	admin.POST("/recommendations/generate", svc.handleGenerateRecommendations)

	// AI Identity Intelligence — cross-pillar fusion (IAM risk + alerts + MFA
	// + devices + breaches + Ziti anomalies) with optional local-LLM narration.
	admin.GET("/ai/intelligence/overview", svc.handleAIIntelligenceOverview)
	admin.GET("/ai/intelligence/users/:id", svc.handleAIIntelligenceUser)
	admin.GET("/ai/intelligence/briefing", svc.handleAIIntelligenceBriefing)
	admin.POST("/ai/intelligence/ask", svc.handleAIIntelligenceAsk)
	admin.GET("/ai/intelligence/status", svc.handleAIIntelligenceStatus)

	// Predictive Analytics
	admin.GET("/analytics/predictions", svc.handlePredictionsSummary)
	admin.GET("/analytics/predictions/login-forecast", svc.handleLoginForecast)
	admin.GET("/analytics/predictions/risk-forecast", svc.handleRiskForecast)
	admin.GET("/analytics/predictions/capacity", svc.handleCapacityForecast)

	// Phase 16: Enterprise Operations

	// Bulk Operations
	admin.POST("/bulk-operations", svc.handleCreateBulkOperation)
	admin.GET("/bulk-operations", svc.handleListBulkOperations)
	admin.GET("/bulk-operations/export/users", svc.handleExportUsersCSV)
	admin.GET("/bulk-operations/:id", svc.handleGetBulkOperation)
	admin.DELETE("/bulk-operations/:id", svc.handleCancelBulkOperation)

	// Email Template Management
	admin.GET("/email-templates", svc.handleListEmailTemplates)
	admin.GET("/email-templates/:id", svc.handleGetEmailTemplate)
	admin.PUT("/email-templates/:id", svc.handleUpdateEmailTemplate)
	admin.POST("/email-templates/:id/preview", svc.handlePreviewEmailTemplate)
	admin.POST("/email-templates/:id/reset", svc.handleResetEmailTemplate)
	admin.GET("/email-branding", svc.handleGetEmailBranding)
	admin.PUT("/email-branding", svc.handleUpdateEmailBranding)

	// De-provisioning / Lifecycle Policies
	admin.GET("/lifecycle-policies", svc.handleListLifecyclePolicies)
	admin.POST("/lifecycle-policies", svc.handleCreateLifecyclePolicy)
	admin.GET("/lifecycle-policies/preview", svc.handlePreviewLifecyclePolicy)
	admin.GET("/lifecycle-policies/:id", svc.handleGetLifecyclePolicy)
	admin.PUT("/lifecycle-policies/:id", svc.handleUpdateLifecyclePolicy)
	admin.DELETE("/lifecycle-policies/:id", svc.handleDeleteLifecyclePolicy)
	admin.POST("/lifecycle-policies/:id/execute", svc.handleExecuteLifecyclePolicy)
	admin.GET("/lifecycle-policies/:id/executions", svc.handleListLifecycleExecutions)

	// Attestation Campaigns
	admin.GET("/attestation-campaigns", svc.handleListAttestationCampaigns)
	admin.POST("/attestation-campaigns", svc.handleCreateAttestationCampaign)
	admin.GET("/attestation-campaigns/:id", svc.handleGetAttestationCampaign)
	admin.PUT("/attestation-campaigns/:id", svc.handleUpdateAttestationCampaign)
	admin.POST("/attestation-campaigns/:id/launch", svc.handleLaunchAttestationCampaign)
	admin.GET("/attestation-campaigns/:id/items", svc.handleListAttestationItems)
	admin.POST("/attestation-campaigns/:id/items/:itemId/decide", svc.handleDecideAttestationItem)
	admin.POST("/attestation-campaigns/:id/items/:itemId/delegate", svc.handleDelegateAttestationItem)
	admin.GET("/attestation-campaigns/:id/progress", svc.handleAttestationProgress)

	// Audit Archival & Retention
	admin.GET("/audit-retention", svc.handleListRetentionPolicies)
	admin.POST("/audit-retention", svc.handleCreateRetentionPolicy)
	admin.PUT("/audit-retention/:id", svc.handleUpdateRetentionPolicy)
	admin.DELETE("/audit-retention/:id", svc.handleDeleteRetentionPolicy)
	admin.POST("/audit-archives", svc.handleCreateAuditArchive)
	admin.GET("/audit-archives", svc.handleListAuditArchives)
	admin.GET("/audit-archives/:id", svc.handleGetAuditArchive)
	admin.POST("/audit-archives/:id/restore", svc.handleRestoreAuditArchive)

	// OAuth signing key rotation (install-wide; consumed by the oauth service)
	admin.GET("/oauth/signing-keys", svc.handleListOAuthSigningKeys)
	admin.POST("/oauth/signing-keys/rotate", svc.handleRotateOAuthSigningKey)

	// Phase 17: Multi-Tenancy, Privacy, Federation & Notifications

	// 17A: Tenant Branding & Management
	admin.POST("/tenants/switch", svc.handleSwitchTenant)
	admin.GET("/tenants/current", svc.handleGetCurrentTenant)
	admin.GET("/tenants/:orgId/branding", svc.handleGetTenantBrandingRecord)
	admin.PUT("/tenants/:orgId/branding", svc.handleUpdateTenantBrandingRecord)
	admin.GET("/tenants/:orgId/settings", svc.handleGetTenantSettings)
	admin.PUT("/tenants/:orgId/settings", svc.handleUpdateTenantSettings)
	admin.GET("/tenants/:orgId/domains", svc.handleListTenantDomains)
	admin.POST("/tenants/:orgId/domains", svc.handleCreateTenantDomain)
	admin.DELETE("/tenants/:orgId/domains/:domainId", svc.handleDeleteTenantDomain)
	admin.POST("/tenants/:orgId/domains/:domainId/verify", svc.handleVerifyTenantDomain)

	// 17B: Privacy & GDPR
	admin.GET("/privacy/dashboard", svc.handlePrivacyDashboard)
	admin.GET("/privacy/consents", svc.handleListConsents)
	admin.GET("/privacy/consents/stats", svc.handleConsentStats)
	admin.GET("/privacy/dsars", svc.handleListDSARs)
	admin.POST("/privacy/dsars", svc.handleCreateDSAR)
	admin.GET("/privacy/dsars/:id", svc.handleGetDSAR)
	admin.PUT("/privacy/dsars/:id", svc.handleUpdateDSAR)
	admin.POST("/privacy/dsars/:id/execute", svc.handleExecuteDSAR)
	admin.GET("/privacy/retention", svc.handleListPrivacyRetention)
	admin.POST("/privacy/retention", svc.handleCreatePrivacyRetention)
	admin.PUT("/privacy/retention/:id", svc.handleUpdatePrivacyRetention)
	admin.DELETE("/privacy/retention/:id", svc.handleDeletePrivacyRetention)
	admin.GET("/privacy/assessments", svc.handleListPrivacyAssessments)
	admin.POST("/privacy/assessments", svc.handleCreatePrivacyAssessment)
	admin.GET("/privacy/assessments/:id", svc.handleGetPrivacyAssessment)
	admin.PUT("/privacy/assessments/:id", svc.handleUpdatePrivacyAssessment)
	admin.DELETE("/privacy/assessments/:id", svc.handleDeletePrivacyAssessment)

	// 17C: Federation & SSO
	admin.GET("/social-providers", svc.handleListSocialProviders)
	admin.POST("/social-providers", svc.handleCreateSocialProvider)
	admin.GET("/social-providers/:id", svc.handleGetSocialProvider)
	admin.PUT("/social-providers/:id", svc.handleUpdateSocialProvider)
	admin.DELETE("/social-providers/:id", svc.handleDeleteSocialProvider)
	admin.GET("/federation/rules", svc.handleListFederationRules)
	admin.POST("/federation/rules", svc.handleCreateFederationRule)
	admin.PUT("/federation/rules/:id", svc.handleUpdateFederationRule)
	admin.DELETE("/federation/rules/:id", svc.handleDeleteFederationRule)
	admin.GET("/users/:id/identity-links", svc.handleListUserIdentityLinks)
	admin.DELETE("/users/:id/identity-links/:linkId", svc.handleDeleteIdentityLink)
	admin.GET("/applications/:id/claims", svc.handleListCustomClaims)
	admin.POST("/applications/:id/claims", svc.handleCreateCustomClaim)
	admin.PUT("/applications/:id/claims/:claimId", svc.handleUpdateCustomClaim)
	admin.DELETE("/applications/:id/claims/:claimId", svc.handleDeleteCustomClaim)

	// 17D: Notification Management
	admin.GET("/notifications/routing-rules", svc.handleListRoutingRules)
	admin.POST("/notifications/routing-rules", svc.handleCreateRoutingRule)
	admin.GET("/notifications/routing-rules/:id", svc.handleGetRoutingRule)
	admin.PUT("/notifications/routing-rules/:id", svc.handleUpdateRoutingRule)
	admin.DELETE("/notifications/routing-rules/:id", svc.handleDeleteRoutingRule)
	admin.GET("/notifications/broadcasts", svc.handleListBroadcasts)
	admin.POST("/notifications/broadcasts", svc.handleCreateBroadcast)
	admin.GET("/notifications/broadcasts/:id", svc.handleGetBroadcast)
	admin.POST("/notifications/broadcasts/:id/send", svc.handleSendBroadcast)
	admin.DELETE("/notifications/broadcasts/:id", svc.handleDeleteBroadcast)
	admin.GET("/notifications/stats", svc.handleNotificationStats)

	// Phase 18: MFA Management & Risk Analytics
	// 18A: MFA Management
	admin.GET("/mfa/enrollment-stats", svc.handleMFAEnrollmentStats)
	admin.GET("/mfa/policies", svc.handleListMFAPolicies)
	admin.POST("/mfa/policies", svc.handleCreateMFAPolicy)
	admin.GET("/mfa/policies/:id", svc.handleGetMFAPolicy)
	admin.PUT("/mfa/policies/:id", svc.handleUpdateMFAPolicy)
	admin.DELETE("/mfa/policies/:id", svc.handleDeleteMFAPolicy)
	admin.GET("/mfa/user-status", svc.handleListUserMFAStatus)
	admin.GET("/mfa/user-status/:id", svc.handleGetUserMFAStatus)

	// 18B: Login Anomaly Analytics
	admin.GET("/risk/anomalies", svc.handleLoginAnomalies)
	admin.GET("/risk/user-profile/:id", svc.handleUserRiskProfile)
	admin.GET("/risk/overview", svc.handleRiskOverview)

	// Phase 19: Advanced Security Features
	// Identity Breach Detection & Response (IBDR)
	admin.POST("/ibdr/detect", svc.handleIBDRDetectBreach)
	admin.GET("/ibdr/incidents", svc.handleIBDRIncidents)
	admin.GET("/ibdr/alerts", svc.handleIBDRAlerts)
	admin.POST("/ibdr/incidents/:id/respond", svc.handleIBDRTriggerResponse)

	// Continuous Authentication
	admin.GET("/continuous-auth/risk", svc.handleContinuousAuthGetRisk)
	admin.POST("/continuous-auth/check", svc.handleContinuousAuthCheck)
	admin.POST("/continuous-auth/update", svc.handleContinuousAuthUpdate)

	// Passwordless Authentication
}

// HTTP Handlers

func (s *Service) handleUpdateSettings(c *gin.Context) {
	var settings Settings
	if err := c.ShouldBindJSON(&settings); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if err := s.UpdateSettings(c.Request.Context(), &settings); err != nil {
		s.logger.Error("failed to update settings", zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(200, settings)
}

func (s *Service) handleGetSMSSettings(c *gin.Context) {
	valueBytes, err := s.settings.GetRaw(c.Request.Context(), "sms_config")

	var settings *sms.DBSMSSettings
	if err == nil {
		settings = &sms.DBSMSSettings{}
		if jsonErr := json.Unmarshal(valueBytes, settings); jsonErr != nil {
			settings = sms.DefaultDBSMSSettings()
		}
	} else {
		settings = sms.DefaultDBSMSSettings()
	}

	sms.MaskCredentials(settings)
	c.JSON(200, settings)
}

func (s *Service) handleUpdateSMSSettings(c *gin.Context) {
	var incoming sms.DBSMSSettings
	if err := c.ShouldBindJSON(&incoming); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// Load existing settings to merge masked credentials
	var existing *sms.DBSMSSettings
	existingBytes, err := s.settings.GetRaw(c.Request.Context(), "sms_config")
	if err == nil {
		existing = &sms.DBSMSSettings{}
		json.Unmarshal(existingBytes, existing)
	}

	sms.MergeCredentials(&incoming, existing)
	sms.ValidateOTPSettings(&incoming)

	valueBytes, err := json.Marshal(&incoming)
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to marshal SMS settings"})
		return
	}

	if err := s.settings.PutRaw(c.Request.Context(), "sms_config", valueBytes); err != nil {
		c.JSON(500, gin.H{"error": "failed to save SMS settings"})
		return
	}

	sms.MaskCredentials(&incoming)
	c.JSON(200, incoming)
}

func (s *Service) handleTestSMS(c *gin.Context) {
	var req struct {
		PhoneNumber string            `json:"phone_number"`
		Settings    sms.DBSMSSettings `json:"settings"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if req.PhoneNumber == "" {
		c.JSON(400, gin.H{"error": "phone_number is required"})
		return
	}

	// Merge masked credentials from DB before testing
	var existing *sms.DBSMSSettings
	existingBytes, err := s.settings.GetRaw(c.Request.Context(), "sms_config")
	if err == nil {
		existing = &sms.DBSMSSettings{}
		json.Unmarshal(existingBytes, existing)
	}
	sms.MergeCredentials(&req.Settings, existing)

	// Force enabled for test
	cfg := req.Settings.ToConfig()
	cfg.Enabled = true

	smsService, err := sms.NewService(cfg, s.logger)
	if err != nil {
		c.JSON(400, gin.H{"error": fmt.Sprintf("failed to create SMS service: %v", err), "success": false})
		return
	}

	prefix := req.Settings.MessagePrefix
	if prefix == "" {
		prefix = "OpenIDX"
	}
	msg := fmt.Sprintf("%s: This is a test message. If you received this, SMS is configured correctly.", prefix)
	if err := smsService.SendMessage(c.Request.Context(), req.PhoneNumber, msg); err != nil {
		c.JSON(400, gin.H{"error": fmt.Sprintf("failed to send test SMS: %v", err), "success": false})
		return
	}

	c.JSON(200, gin.H{"success": true, "message": "Test SMS sent successfully"})
}

func (s *Service) handleListApplications(c *gin.Context) {
	offset := 0
	limit := 0
	if v := c.Query("offset"); v != "" {
		fmt.Sscanf(v, "%d", &offset)
	}
	if offset < 0 {
		offset = 0
	}
	if v := c.Query("limit"); v != "" {
		fmt.Sscanf(v, "%d", &limit)
	}
	if limit < 1 {
		limit = 1
	}
	if limit > 100 {
		limit = 100
	}

	apps, totalCount, err := s.ListApplications(c.Request.Context(), offset, limit)
	if err != nil {
		s.logger.Error("failed to list applications", zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.Header("X-Total-Count", fmt.Sprintf("%d", totalCount))
	c.JSON(200, apps)
}

func (s *Service) handleCreateApplication(c *gin.Context) {
	var app Application
	if err := c.ShouldBindJSON(&app); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if err := s.CreateApplication(c.Request.Context(), &app); err != nil {
		s.logger.Error("failed to create application", zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(201, app)
}

func (s *Service) handleGetApplication(c *gin.Context) {
	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	id := c.Param("id")
	var app Application
	err = s.db.Pool.QueryRow(c.Request.Context(), `
		SELECT id, client_id, name, COALESCE(description, ''), type, protocol,
		       COALESCE(base_url, ''), redirect_uris, enabled, created_at, updated_at
		FROM applications WHERE id = $1 AND org_id = $2
	`, id, org.ID).Scan(
		&app.ID, &app.ClientID, &app.Name, &app.Description, &app.Type,
		&app.Protocol, &app.BaseURL, &app.RedirectURIs, &app.Enabled, &app.CreatedAt, &app.UpdatedAt,
	)
	if err != nil {
		c.JSON(404, gin.H{"error": "Application not found"})
		return
	}
	c.JSON(200, app)
}
func (s *Service) handleUpdateApplication(c *gin.Context) {
	id := c.Param("id")
	var updates map[string]interface{}
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	if err := s.UpdateApplication(c.Request.Context(), id, updates); err != nil {
		s.logger.Error("failed to update application", zap.String("id", id), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(200, gin.H{"message": "Application updated successfully"})
}
func (s *Service) handleDeleteApplication(c *gin.Context) {
	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	id := c.Param("id")
	result, err := s.db.Pool.Exec(c.Request.Context(), "DELETE FROM applications WHERE id = $1 AND org_id = $2", id, org.ID)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to delete application"})
		return
	}
	if result.RowsAffected() == 0 {
		c.JSON(404, gin.H{"error": "Application not found"})
		return
	}
	c.JSON(204, nil)
}

func (s *Service) handleListDirectories(c *gin.Context) {
	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	rows, err := s.db.Pool.Query(c.Request.Context(), `
		SELECT id, name, type, config, enabled, last_sync_at, sync_status, created_at, updated_at
		FROM directory_integrations WHERE org_id = $1 ORDER BY name
	`, org.ID)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to list directories"})
		return
	}
	defer rows.Close()

	var dirs []DirectoryIntegration
	for rows.Next() {
		var d DirectoryIntegration
		var configBytes []byte
		if err := rows.Scan(&d.ID, &d.Name, &d.Type, &configBytes, &d.Enabled, &d.LastSyncAt, &d.SyncStatus, &d.CreatedAt, &d.UpdatedAt); err != nil {
			continue
		}
		if len(configBytes) > 0 {
			if err := json.Unmarshal(configBytes, &d.Config); err != nil {
				s.logger.Warn("Failed to parse directory config", zap.String("id", d.ID), zap.Error(err))
			}
		}
		dirs = append(dirs, d)
	}
	if dirs == nil {
		dirs = []DirectoryIntegration{}
	}
	c.JSON(200, dirs)
}

// validateDirectoryIntegration checks required fields per directory type and
// returns a field->message map (empty when valid). This is the authoritative
// guard: the UI mirrors it, but the API must not persist a directory that can
// never sync (e.g. a blank name, or an LDAP/AD config with no host, no bind, no
// search base, or empty username/email mapping).
func validateDirectoryIntegration(dir DirectoryIntegration) map[string]string {
	errs := map[string]string{}
	cfgStr := func(key string) string {
		if dir.Config == nil {
			return ""
		}
		if v, ok := dir.Config[key].(string); ok {
			return strings.TrimSpace(v)
		}
		return ""
	}
	mappingStr := func(key string) string {
		if dir.Config == nil {
			return ""
		}
		m, ok := dir.Config["attribute_mapping"].(map[string]interface{})
		if !ok {
			return ""
		}
		if v, ok := m[key].(string); ok {
			return strings.TrimSpace(v)
		}
		return ""
	}

	if strings.TrimSpace(dir.Name) == "" {
		errs["name"] = "Name is required."
	}
	if strings.TrimSpace(dir.Type) == "" {
		errs["type"] = "Directory type is required."
		return errs // can't validate config without a type
	}

	switch dir.Type {
	case "ldap", "active_directory":
		if cfgStr("host") == "" {
			errs["config.host"] = "Host is required."
		}
		if cfgStr("bind_dn") == "" {
			errs["config.bind_dn"] = "Bind DN is required (e.g. user@domain for Active Directory)."
		}
		if cfgStr("bind_password") == "" {
			errs["config.bind_password"] = "Bind password is required."
		}
		// A search base is required somewhere: base_dn, or both user+group base DNs.
		if cfgStr("base_dn") == "" && cfgStr("user_base_dn") == "" {
			errs["config.base_dn"] = "Base DN is required (e.g. DC=corp,DC=local). Use \"Diagnose & Auto-Fix\" to detect it."
		}
		if cfgStr("user_filter") == "" {
			errs["config.user_filter"] = "User filter is required."
		}
		if mappingStr("username") == "" {
			errs["config.attribute_mapping.username"] = "Username attribute mapping is required (e.g. sAMAccountName for AD)."
		}
		if mappingStr("email") == "" {
			errs["config.attribute_mapping.email"] = "Email attribute mapping is required (e.g. userPrincipalName for AD)."
		}
	case "azure_ad":
		if cfgStr("tenant_id") == "" {
			errs["config.tenant_id"] = "Tenant ID is required."
		}
		if cfgStr("client_id") == "" {
			errs["config.client_id"] = "Client ID is required."
		}
		if cfgStr("client_secret") == "" {
			errs["config.client_secret"] = "Client secret is required."
		}
	case "hris", "bamboohr":
		if cfgStr("subdomain") == "" && cfgStr("host") == "" {
			errs["config.subdomain"] = "Subdomain (or host) is required."
		}
		if cfgStr("api_key") == "" {
			errs["config.api_key"] = "API key is required."
		}
	}
	return errs
}

func (s *Service) handleCreateDirectory(c *gin.Context) {
	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	var dir DirectoryIntegration
	if err := c.ShouldBindJSON(&dir); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	if verrs := validateDirectoryIntegration(dir); len(verrs) > 0 {
		c.JSON(400, gin.H{"error": "validation failed", "fields": verrs})
		return
	}

	dir.ID = uuid.New().String()
	dir.SyncStatus = "never"
	dir.CreatedAt = time.Now()
	dir.UpdatedAt = time.Now()

	configBytes, _ := json.Marshal(dir.Config)

	_, err = s.db.Pool.Exec(c.Request.Context(), `
		INSERT INTO directory_integrations (id, name, type, config, enabled, sync_status, created_at, updated_at, org_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, dir.ID, dir.Name, dir.Type, configBytes, dir.Enabled, dir.SyncStatus, dir.CreatedAt, dir.UpdatedAt, org.ID)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to create directory integration"})
		return
	}

	c.JSON(201, dir)
}

func (s *Service) handleGetDirectory(c *gin.Context) {
	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	id := c.Param("id")
	var d DirectoryIntegration
	var configBytes []byte
	err = s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT id, name, type, config, enabled, last_sync_at, sync_status, created_at, updated_at
		 FROM directory_integrations WHERE id = $1 AND org_id = $2`, id, org.ID).Scan(
		&d.ID, &d.Name, &d.Type, &configBytes, &d.Enabled, &d.LastSyncAt, &d.SyncStatus, &d.CreatedAt, &d.UpdatedAt)
	if err != nil {
		c.JSON(404, gin.H{"error": "Directory not found"})
		return
	}
	if len(configBytes) > 0 {
		json.Unmarshal(configBytes, &d.Config)
	}
	c.JSON(200, d)
}

func (s *Service) handleUpdateDirectory(c *gin.Context) {
	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	id := c.Param("id")
	var dir DirectoryIntegration
	if err := c.ShouldBindJSON(&dir); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	if verrs := validateDirectoryIntegration(dir); len(verrs) > 0 {
		c.JSON(400, gin.H{"error": "validation failed", "fields": verrs})
		return
	}

	configBytes, _ := json.Marshal(dir.Config)

	result, err := s.db.Pool.Exec(c.Request.Context(), `
		UPDATE directory_integrations SET name = $2, type = $3, config = $4, enabled = $5, updated_at = NOW()
		WHERE id = $1 AND org_id = $6
	`, id, dir.Name, dir.Type, configBytes, dir.Enabled, org.ID)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to update directory"})
		return
	}
	if result.RowsAffected() == 0 {
		c.JSON(404, gin.H{"error": "Directory not found"})
		return
	}
	c.JSON(200, gin.H{"message": "Directory updated"})
}

func (s *Service) handleDeleteDirectory(c *gin.Context) {
	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	id := c.Param("id")
	result, err := s.db.Pool.Exec(c.Request.Context(), `DELETE FROM directory_integrations WHERE id = $1 AND org_id = $2`, id, org.ID)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to delete directory"})
		return
	}
	if result.RowsAffected() == 0 {
		c.JSON(404, gin.H{"error": "Directory not found"})
		return
	}
	c.JSON(200, gin.H{"message": "Directory deleted"})
}

func (s *Service) handleSyncDirectory(c *gin.Context) {
	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	id := c.Param("id")

	// Verify directory exists
	var exists bool
	s.db.Pool.QueryRow(c.Request.Context(), `SELECT EXISTS(SELECT 1 FROM directory_integrations WHERE id = $1 AND org_id = $2)`, id, org.ID).Scan(&exists)
	if !exists {
		c.JSON(404, gin.H{"error": "Directory integration not found"})
		return
	}

	fullSync := c.Query("full") == "true"

	if s.directoryService != nil {
		if err := s.directoryService.TriggerSync(c.Request.Context(), id, fullSync); err != nil {
			s.logger.Error("failed to trigger directory sync", zap.String("id", id), zap.Error(err))
			c.JSON(500, gin.H{"error": "internal server error"})
			return
		}
	} else {
		// Fallback: just mark as syncing if no directory service
		s.db.Pool.Exec(c.Request.Context(), `
			UPDATE directory_integrations SET sync_status = 'syncing', last_sync_at = NOW(), updated_at = NOW()
			WHERE id = $1 AND org_id = $2`, id, org.ID)
	}

	syncType := "incremental"
	if fullSync {
		syncType = "full"
	}

	c.JSON(200, gin.H{"status": "syncing", "sync_type": syncType, "message": "Directory sync initiated"})
}

func (s *Service) handleTestConnection(c *gin.Context) {
	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	id := c.Param("id")

	var dirType string
	var configBytes []byte
	err = s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT type, config FROM directory_integrations WHERE id = $1 AND org_id = $2`, id, org.ID).Scan(&dirType, &configBytes)
	if err != nil {
		c.JSON(404, gin.H{"error": "Directory not found"})
		return
	}

	if s.directoryService != nil {
		if err := s.directoryService.TestConnection(c.Request.Context(), dirType, configBytes); err != nil {
			c.JSON(400, gin.H{"error": err.Error(), "success": false})
			return
		}
	}

	c.JSON(200, gin.H{"success": true, "message": "Connection test successful"})
}

// handleDiagnoseDirectory runs live LDAP/AD diagnostics and returns findings +
// suggested config fixes. It diagnoses either a saved integration (:id) or, when
// a JSON body {type, config} is supplied, an inline config — so the setup wizard
// can diagnose BEFORE the integration is saved.
func (s *Service) handleDiagnoseDirectory(c *gin.Context) {
	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	if s.directoryService == nil {
		c.JSON(503, gin.H{"error": "directory service unavailable"})
		return
	}

	// Inline config from the body takes precedence (wizard, pre-save).
	var body struct {
		Type   string          `json:"type"`
		Config json.RawMessage `json:"config"`
	}
	_ = c.ShouldBindJSON(&body)

	var dirType string
	var configBytes []byte
	if len(body.Config) > 0 {
		dirType = body.Type
		if dirType == "" {
			dirType = "ldap"
		}
		configBytes = body.Config
	} else {
		id := c.Param("id")
		if id == "" {
			c.JSON(400, gin.H{"error": "provide a saved directory id or a {type, config} body"})
			return
		}
		if err := s.db.Pool.QueryRow(c.Request.Context(),
			`SELECT type, config FROM directory_integrations WHERE id = $1 AND org_id = $2`,
			id, org.ID).Scan(&dirType, &configBytes); err != nil {
			c.JSON(404, gin.H{"error": "Directory not found"})
			return
		}
	}

	result, err := s.directoryService.Diagnose(c.Request.Context(), dirType, configBytes)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, result)
}

func (s *Service) handleGetSyncLogs(c *gin.Context) {
	id := c.Param("id")

	if s.directoryService != nil {
		logs, err := s.directoryService.GetSyncLogs(c.Request.Context(), id, 20)
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to get sync logs"})
			return
		}
		c.JSON(200, logs)
		return
	}

	c.JSON(200, []interface{}{})
}

func (s *Service) handleGetSyncState(c *gin.Context) {
	id := c.Param("id")

	if s.directoryService != nil {
		state, err := s.directoryService.GetSyncState(c.Request.Context(), id)
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to get sync state"})
			return
		}
		c.JSON(200, state)
		return
	}

	c.JSON(200, gin.H{"directory_id": id})
}

func (s *Service) handleListMFAMethods(c *gin.Context) {
	valueBytes, err := s.settings.GetRaw(c.Request.Context(), "mfa_methods")
	if err == nil {
		var methods []string
		if json.Unmarshal(valueBytes, &methods) == nil {
			c.JSON(200, methods)
			return
		}
	}
	c.JSON(200, []string{"totp", "webauthn", "sms"})
}

func (s *Service) handleUpdateMFAMethods(c *gin.Context) {
	var methods []string
	if err := c.ShouldBindJSON(&methods); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request body, expected array of strings"})
		return
	}

	valueBytes, err := json.Marshal(methods)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to marshal methods"})
		return
	}

	if err := s.settings.PutRaw(c.Request.Context(), "mfa_methods", valueBytes); err != nil {
		c.JSON(500, gin.H{"error": "Failed to save MFA methods"})
		return
	}

	c.JSON(200, gin.H{"status": "updated", "methods": methods})
}

func (s *Service) handleGetApplicationSSOSettings(c *gin.Context) {
	applicationID := c.Param("id")

	settings, err := s.GetApplicationSSOSettings(c.Request.Context(), applicationID)
	if err != nil {
		s.logger.Error("failed to get SSO settings", zap.String("application_id", applicationID), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(200, settings)
}

func (s *Service) handleUpdateApplicationSSOSettings(c *gin.Context) {
	applicationID := c.Param("id")

	var settings ApplicationSSOSettings
	if err := c.ShouldBindJSON(&settings); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	settings.ApplicationID = applicationID

	if err := s.UpdateApplicationSSOSettings(c.Request.Context(), &settings); err != nil {
		s.logger.Error("failed to update SSO settings", zap.String("application_id", applicationID), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(200, gin.H{"message": "SSO settings updated successfully"})
}

// Device management handlers

func (s *Service) handleListDevices(c *gin.Context) {
	if s.riskService == nil {
		c.JSON(500, gin.H{"error": "risk service not available"})
		return
	}

	limit := 50
	offset := 0
	if l := c.Query("limit"); l != "" {
		fmt.Sscanf(l, "%d", &limit)
	}
	if limit < 1 {
		limit = 1
	}
	if limit > 100 {
		limit = 100
	}
	if o := c.Query("offset"); o != "" {
		fmt.Sscanf(o, "%d", &offset)
	}
	if offset < 0 {
		offset = 0
	}

	devices, total, err := s.riskService.GetAllDevices(c.Request.Context(), limit, offset)
	if err != nil {
		s.logger.Error("failed to list devices", zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(200, gin.H{"devices": devices, "total": total})
}

func (s *Service) handleUserDevices(c *gin.Context) {
	if s.riskService == nil {
		c.JSON(500, gin.H{"error": "risk service not available"})
		return
	}

	userID := c.Param("id")
	devices, err := s.riskService.GetUserDevices(c.Request.Context(), userID)
	if err != nil {
		s.logger.Error("failed to get user devices", zap.String("user_id", userID), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(200, gin.H{"devices": devices})
}

func (s *Service) handleTrustDevice(c *gin.Context) {
	if s.riskService == nil {
		c.JSON(500, gin.H{"error": "risk service not available"})
		return
	}

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	deviceID := c.Param("id")

	// Look up user_id before trusting so frontend can sync Ziti attributes
	var userID string
	_ = s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT user_id FROM known_devices WHERE id = $1 AND org_id = $2`, deviceID, org.ID).Scan(&userID)

	if err := s.riskService.TrustDevice(c.Request.Context(), deviceID); err != nil {
		s.logger.Error("failed to trust device", zap.String("device_id", deviceID), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(200, gin.H{"message": "Device trusted", "user_id": userID})
}

func (s *Service) handleRevokeDevice(c *gin.Context) {
	if s.riskService == nil {
		c.JSON(500, gin.H{"error": "risk service not available"})
		return
	}

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	deviceID := c.Param("id")

	// Look up user_id before revoking so frontend can sync Ziti attributes
	var userID string
	_ = s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT user_id FROM known_devices WHERE id = $1 AND org_id = $2`, deviceID, org.ID).Scan(&userID)

	if err := s.riskService.RevokeDevice(c.Request.Context(), deviceID); err != nil {
		s.logger.Error("failed to revoke device", zap.String("device_id", deviceID), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(200, gin.H{"message": "Device revoked", "user_id": userID})
}

func (s *Service) handleRiskStats(c *gin.Context) {
	if s.riskService == nil {
		c.JSON(500, gin.H{"error": "risk service not available"})
		return
	}

	stats, err := s.riskService.GetRiskStats(c.Request.Context())
	if err != nil {
		s.logger.Error("failed to get risk stats", zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(200, stats)
}

func (s *Service) handleLoginHistory(c *gin.Context) {
	if s.riskService == nil {
		c.JSON(500, gin.H{"error": "risk service not available"})
		return
	}

	userID := c.Query("user_id")
	limit := 50
	if l := c.Query("limit"); l != "" {
		fmt.Sscanf(l, "%d", &limit)
	}
	if limit < 1 {
		limit = 1
	}
	if limit > 100 {
		limit = 100
	}

	history, err := s.riskService.GetLoginHistory(c.Request.Context(), userID, limit)
	if err != nil {
		s.logger.Error("failed to get login history", zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(200, gin.H{"history": history})
}

// Service account handlers

func (s *Service) handleListServiceAccounts(c *gin.Context) {
	if s.apiKeyService == nil {
		c.JSON(500, gin.H{"error": "API key service not available"})
		return
	}

	limit := 50
	offset := 0
	if l := c.Query("limit"); l != "" {
		fmt.Sscanf(l, "%d", &limit)
	}
	if limit < 1 {
		limit = 1
	}
	if limit > 100 {
		limit = 100
	}
	if o := c.Query("offset"); o != "" {
		fmt.Sscanf(o, "%d", &offset)
	}
	if offset < 0 {
		offset = 0
	}

	accounts, total, err := s.apiKeyService.ListServiceAccounts(c.Request.Context(), limit, offset)
	if err != nil {
		s.logger.Error("failed to list service accounts", zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(200, gin.H{"service_accounts": accounts, "total": total})
}

func (s *Service) handleCreateServiceAccount(c *gin.Context) {
	if s.apiKeyService == nil {
		c.JSON(500, gin.H{"error": "API key service not available"})
		return
	}

	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	userID, _ := c.Get("user_id")
	ownerID, _ := userID.(string)

	account, err := s.apiKeyService.CreateServiceAccount(c.Request.Context(), req.Name, req.Description, ownerID)
	if err != nil {
		s.logger.Error("failed to create service account", zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(201, account)
}

func (s *Service) handleGetServiceAccount(c *gin.Context) {
	if s.apiKeyService == nil {
		c.JSON(500, gin.H{"error": "API key service not available"})
		return
	}

	id := c.Param("id")
	account, err := s.apiKeyService.GetServiceAccount(c.Request.Context(), id)
	if err != nil {
		c.JSON(404, gin.H{"error": "Service account not found"})
		return
	}
	c.JSON(200, account)
}

func (s *Service) handleDeleteServiceAccount(c *gin.Context) {
	if s.apiKeyService == nil {
		c.JSON(500, gin.H{"error": "API key service not available"})
		return
	}

	id := c.Param("id")
	if err := s.apiKeyService.DeleteServiceAccount(c.Request.Context(), id); err != nil {
		s.logger.Error("failed to delete service account", zap.String("id", id), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(200, gin.H{"message": "Service account deleted"})
}

// API key handlers

func (s *Service) handleListServiceAccountAPIKeys(c *gin.Context) {
	if s.apiKeyService == nil {
		c.JSON(500, gin.H{"error": "API key service not available"})
		return
	}

	id := c.Param("id")
	keys, err := s.apiKeyService.ListAPIKeys(c.Request.Context(), id, "service_account")
	if err != nil {
		s.logger.Error("failed to list service account API keys", zap.String("id", id), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(200, gin.H{"api_keys": keys})
}

func (s *Service) handleCreateServiceAccountAPIKey(c *gin.Context) {
	if s.apiKeyService == nil {
		c.JSON(500, gin.H{"error": "API key service not available"})
		return
	}

	saID := c.Param("id")
	var req struct {
		Name      string     `json:"name"`
		Scopes    []string   `json:"scopes"`
		ExpiresAt *time.Time `json:"expires_at"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	plainKey, apiKey, err := s.apiKeyService.CreateAPIKey(c.Request.Context(), req.Name, nil, &saID, req.Scopes, req.ExpiresAt)
	if err != nil {
		s.logger.Error("failed to create service account API key", zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(201, gin.H{"key": plainKey, "api_key": apiKey})
}

func (s *Service) handleCreateUserAPIKey(c *gin.Context) {
	if s.apiKeyService == nil {
		c.JSON(500, gin.H{"error": "API key service not available"})
		return
	}

	var req struct {
		Name      string     `json:"name"`
		Scopes    []string   `json:"scopes"`
		ExpiresAt *time.Time `json:"expires_at"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	userID, _ := c.Get("user_id")
	uid, _ := userID.(string)

	plainKey, apiKey, err := s.apiKeyService.CreateAPIKey(c.Request.Context(), req.Name, &uid, nil, req.Scopes, req.ExpiresAt)
	if err != nil {
		s.logger.Error("failed to create user API key", zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(201, gin.H{"key": plainKey, "api_key": apiKey})
}

func (s *Service) handleListUserAPIKeys(c *gin.Context) {
	if s.apiKeyService == nil {
		c.JSON(500, gin.H{"error": "API key service not available"})
		return
	}

	userID, _ := c.Get("user_id")
	uid, _ := userID.(string)
	if uid == "" {
		c.JSON(200, gin.H{"api_keys": []interface{}{}})
		return
	}

	keys, err := s.apiKeyService.ListAPIKeys(c.Request.Context(), uid, "user")
	if err != nil {
		s.logger.Error("failed to list user API keys", zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(200, gin.H{"api_keys": keys})
}

func (s *Service) handleRevokeAPIKey(c *gin.Context) {
	if s.apiKeyService == nil {
		c.JSON(500, gin.H{"error": "API key service not available"})
		return
	}

	id := c.Param("id")
	if err := s.apiKeyService.RevokeAPIKey(c.Request.Context(), id); err != nil {
		s.logger.Error("failed to revoke API key", zap.String("id", id), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(200, gin.H{"message": "API key revoked"})
}

// Webhook handlers

func (s *Service) handleListWebhooks(c *gin.Context) {
	if s.webhookService == nil {
		c.JSON(500, gin.H{"error": "webhook service not available"})
		return
	}

	subs, err := s.webhookService.ListSubscriptions(c.Request.Context())
	if err != nil {
		s.logger.Error("failed to list webhooks", zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(200, gin.H{"webhooks": subs})
}

func (s *Service) handleCreateWebhook(c *gin.Context) {
	if s.webhookService == nil {
		c.JSON(500, gin.H{"error": "webhook service not available"})
		return
	}

	var req struct {
		Name   string   `json:"name"`
		URL    string   `json:"url"`
		Secret string   `json:"secret"`
		Events []string `json:"events"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// Validate required fields
	if req.Name == "" {
		c.JSON(400, gin.H{"error": "webhook name is required"})
		return
	}
	if len(req.Events) == 0 {
		c.JSON(400, gin.H{"error": "at least one event is required"})
		return
	}
	if len(req.Secret) < 16 {
		c.JSON(400, gin.H{"error": "webhook secret must be at least 16 characters"})
		return
	}

	// Validate webhook URL
	parsedURL, err := url.Parse(req.URL)
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		c.JSON(400, gin.H{"error": "invalid webhook URL"})
		return
	}
	if parsedURL.Scheme != "https" {
		c.JSON(400, gin.H{"error": "webhook URL must use HTTPS"})
		return
	}
	// Block internal/private IPs (SSRF prevention)
	host := parsedURL.Hostname()
	if host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "0.0.0.0" ||
		strings.HasPrefix(host, "10.") || strings.HasPrefix(host, "192.168.") || strings.HasPrefix(host, "172.") {
		c.JSON(400, gin.H{"error": "webhook URL must not point to internal addresses"})
		return
	}

	userID, _ := c.Get("user_id")
	createdBy, _ := userID.(string)

	sub, err := s.webhookService.CreateSubscription(c.Request.Context(), req.Name, req.URL, req.Secret, req.Events, createdBy)
	if err != nil {
		s.logger.Error("failed to create webhook", zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(201, sub)
}

func (s *Service) handleGetWebhook(c *gin.Context) {
	if s.webhookService == nil {
		c.JSON(500, gin.H{"error": "webhook service not available"})
		return
	}

	id := c.Param("id")
	sub, err := s.webhookService.GetSubscription(c.Request.Context(), id)
	if err != nil {
		c.JSON(404, gin.H{"error": "Webhook not found"})
		return
	}
	c.JSON(200, sub)
}

func (s *Service) handleDeleteWebhook(c *gin.Context) {
	if s.webhookService == nil {
		c.JSON(500, gin.H{"error": "webhook service not available"})
		return
	}

	id := c.Param("id")
	if err := s.webhookService.DeleteSubscription(c.Request.Context(), id); err != nil {
		s.logger.Error("failed to delete webhook", zap.String("id", id), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(200, gin.H{"message": "Webhook deleted"})
}

func (s *Service) handleWebhookDeliveries(c *gin.Context) {
	if s.webhookService == nil {
		c.JSON(500, gin.H{"error": "webhook service not available"})
		return
	}

	id := c.Param("id")
	limit := 50
	if l := c.Query("limit"); l != "" {
		fmt.Sscanf(l, "%d", &limit)
	}
	if limit < 1 {
		limit = 1
	}
	if limit > 100 {
		limit = 100
	}

	deliveries, err := s.webhookService.GetDeliveryHistory(c.Request.Context(), id, limit)
	if err != nil {
		s.logger.Error("failed to get webhook deliveries", zap.String("id", id), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(200, gin.H{"deliveries": deliveries})
}

func (s *Service) handleRetryWebhookDelivery(c *gin.Context) {
	if s.webhookService == nil {
		c.JSON(500, gin.H{"error": "webhook service not available"})
		return
	}

	id := c.Param("id")
	if err := s.webhookService.RetryDelivery(c.Request.Context(), id); err != nil {
		s.logger.Error("failed to retry webhook delivery", zap.String("id", id), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(200, gin.H{"message": "Delivery retry initiated"})
}

func (s *Service) handleTestWebhook(c *gin.Context) {
	if s.webhookService == nil {
		c.JSON(500, gin.H{"error": "webhook service not available"})
		return
	}

	id := c.Param("id")
	delivery, err := s.webhookService.PingSubscription(c.Request.Context(), id)
	if err != nil {
		s.logger.Error("failed to test webhook", zap.String("id", id), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(200, gin.H{"message": "Test ping sent", "delivery": delivery})
}

func (s *Service) handleWebhookStats(c *gin.Context) {
	if s.webhookService == nil {
		c.JSON(500, gin.H{"error": "webhook service not available"})
		return
	}

	id := c.Param("id")
	stats, err := s.webhookService.GetDeliveryStats(c.Request.Context(), id)
	if err != nil {
		s.logger.Error("failed to get webhook stats", zap.String("id", id), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(200, stats)
}

// Invitation handlers

func (s *Service) handleListInvitations(c *gin.Context) {
	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	rows, err := s.db.Pool.Query(c.Request.Context(), `
		SELECT id, email, roles, groups, token, invited_by, expires_at, created_at
		FROM user_invitations
		WHERE org_id = $1
		ORDER BY created_at DESC
		LIMIT 50
	`, org.ID)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to list invitations"})
		return
	}
	defer rows.Close()

	var invitations []map[string]interface{}
	for rows.Next() {
		var id, email, token, invitedBy string
		var roles, groups []string
		var expiresAt, createdAt time.Time
		if err := rows.Scan(&id, &email, &roles, &groups, &token, &invitedBy, &expiresAt, &createdAt); err != nil {
			continue
		}
		invitations = append(invitations, map[string]interface{}{
			"id":         id,
			"email":      email,
			"roles":      roles,
			"groups":     groups,
			"token":      token,
			"invited_by": invitedBy,
			"expires_at": expiresAt,
			"created_at": createdAt,
		})
	}
	if invitations == nil {
		invitations = []map[string]interface{}{}
	}
	c.JSON(200, gin.H{"invitations": invitations})
}

func (s *Service) handleCreateInvitation(c *gin.Context) {
	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	var req struct {
		Email  string   `json:"email"`
		Roles  []string `json:"roles"`
		Groups []string `json:"groups"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// Validate email address
	if req.Email == "" || !strings.Contains(req.Email, "@") || len(req.Email) > 254 {
		c.JSON(400, gin.H{"error": "invalid email address"})
		return
	}

	id := uuid.New().String()
	token := uuid.New().String()
	userID, _ := c.Get("user_id")
	invitedBy, _ := userID.(string)
	if invitedBy == "" {
		invitedBy = "00000000-0000-0000-0000-000000000001" // default admin user in dev mode
	}
	expiresAt := time.Now().Add(7 * 24 * time.Hour)

	_, err = s.db.Pool.Exec(c.Request.Context(), `
		INSERT INTO user_invitations (id, email, roles, groups, token, invited_by, expires_at, created_at, org_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), $8)
	`, id, req.Email, req.Roles, req.Groups, token, invitedBy, expiresAt, org.ID)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to create invitation"})
		return
	}

	c.JSON(201, gin.H{
		"id":         id,
		"email":      req.Email,
		"roles":      req.Roles,
		"groups":     req.Groups,
		"token":      token,
		"invited_by": invitedBy,
		"expires_at": expiresAt,
	})
}

func (s *Service) handleDeleteInvitation(c *gin.Context) {
	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	id := c.Param("id")
	result, err := s.db.Pool.Exec(c.Request.Context(), `DELETE FROM user_invitations WHERE id = $1 AND org_id = $2`, id, org.ID)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to delete invitation"})
		return
	}
	if result.RowsAffected() == 0 {
		c.JSON(404, gin.H{"error": "Invitation not found"})
		return
	}
	c.JSON(200, gin.H{"message": "Invitation deleted"})
}

// Analytics handlers

func parsePeriod(period string) string {
	switch period {
	case "7d":
		return "7 days"
	case "90d":
		return "90 days"
	default:
		return "30 days"
	}
}

func (s *Service) handleLoginAnalytics(c *gin.Context) {
	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	interval := parsePeriod(c.Query("period"))

	rows, err := s.db.Pool.Query(c.Request.Context(), `
		SELECT date_trunc('day', created_at)::date as date,
		       COUNT(*) FILTER (WHERE success = true) as successful,
		       COUNT(*) FILTER (WHERE success = false) as failed
		FROM login_history
		WHERE org_id = $2 AND created_at > NOW() - $1::interval
		GROUP BY 1 ORDER BY 1
	`, interval, org.ID)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to query login analytics"})
		return
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var date time.Time
		var successful, failed int
		if err := rows.Scan(&date, &successful, &failed); err != nil {
			continue
		}
		results = append(results, map[string]interface{}{
			"date":       date.Format("2006-01-02"),
			"successful": successful,
			"failed":     failed,
		})
	}
	if results == nil {
		results = []map[string]interface{}{}
	}
	c.JSON(200, results)
}

func (s *Service) handleRiskAnalytics(c *gin.Context) {
	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	interval := parsePeriod(c.Query("period"))
	ctx := c.Request.Context()

	// The risk-dashboard page reads {risk: RiskOverview}. It previously received
	// a bare [{level,count}] array, so risk was undefined and the whole page
	// rendered empty. Build the full overview the UI expects.

	// Average risk score + high-risk logins in the last 24h.
	var avgRiskScore float64
	_ = s.db.Pool.QueryRow(ctx,
		`SELECT COALESCE(AVG(risk_score),0) FROM login_history
		 WHERE org_id = $2 AND created_at > NOW() - $1::interval`, interval, org.ID).Scan(&avgRiskScore)

	var highRiskLogins24h int
	_ = s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM login_history
		 WHERE org_id = $1 AND created_at > NOW() - INTERVAL '24 hours' AND risk_score >= 51`, org.ID).Scan(&highRiskLogins24h)

	// Active (unresolved) security alerts.
	var activeAlerts int
	_ = s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM security_alerts
		 WHERE org_id = $1 AND status <> 'resolved'`, org.ID).Scan(&activeAlerts)

	// Risk score distribution into fixed buckets (0-20, 21-40, ...).
	type bucket struct {
		Bucket string `json:"bucket"`
		Min    int    `json:"min"`
		Max    int    `json:"max"`
		Count  int    `json:"count"`
	}
	buckets := []bucket{
		{"0-20", 0, 20, 0}, {"21-40", 21, 40, 0}, {"41-60", 41, 60, 0},
		{"61-80", 61, 80, 0}, {"81-100", 81, 100, 0},
	}
	drows, derr := s.db.Pool.Query(ctx,
		`SELECT LEAST(FLOOR(risk_score/20)::int,4) AS b, COUNT(*)
		   FROM login_history
		  WHERE org_id = $2 AND created_at > NOW() - $1::interval
		  GROUP BY 1`, interval, org.ID)
	if derr == nil {
		defer drows.Close()
		for drows.Next() {
			var b, cnt int
			if drows.Scan(&b, &cnt) == nil && b >= 0 && b < len(buckets) {
				buckets[b].Count = cnt
			}
		}
	}

	// Top risky users by average risk score in the window.
	type riskyUser struct {
		UserID       string  `json:"user_id"`
		Email        string  `json:"email"`
		Username     string  `json:"username"`
		AvgRiskScore float64 `json:"avg_risk_score"`
		LastLogin    string  `json:"last_login"`
		AnomalyCount int     `json:"anomaly_count"`
	}
	topUsers := []riskyUser{}
	urows, uerr := s.db.Pool.Query(ctx,
		`SELECT lh.user_id,
		        COALESCE(u.email,''), COALESCE(u.username,''),
		        AVG(lh.risk_score) AS avg_score,
		        MAX(lh.created_at) AS last_login,
		        COUNT(*) FILTER (WHERE lh.risk_score >= 51) AS anomalies
		   FROM login_history lh
		   LEFT JOIN users u ON u.id = lh.user_id AND u.org_id = lh.org_id
		  WHERE lh.org_id = $2 AND lh.created_at > NOW() - $1::interval
		  GROUP BY lh.user_id, u.email, u.username
		  ORDER BY avg_score DESC
		  LIMIT 10`, interval, org.ID)
	if uerr == nil {
		defer urows.Close()
		for urows.Next() {
			var ru riskyUser
			var last time.Time
			if urows.Scan(&ru.UserID, &ru.Email, &ru.Username, &ru.AvgRiskScore, &last, &ru.AnomalyCount) == nil {
				ru.LastLogin = last.Format(time.RFC3339)
				topUsers = append(topUsers, ru)
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{"risk": gin.H{
		"avg_risk_score":           avgRiskScore,
		"high_risk_logins_24h":     highRiskLogins24h,
		"active_alerts":            activeAlerts,
		"impossible_travel_events": 0, // not tracked yet
		"risk_distribution":        buckets,
		"top_risky_users":          topUsers,
	}})
}

func (s *Service) handleUserAnalytics(c *gin.Context) {
	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	interval := parsePeriod(c.Query("period"))

	// User growth over time
	rows, err := s.db.Pool.Query(c.Request.Context(), `
		SELECT date_trunc('day', created_at)::date as date, COUNT(*) as count
		FROM users WHERE org_id = $2 AND created_at > NOW() - $1::interval
		GROUP BY 1 ORDER BY 1
	`, interval, org.ID)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to query user analytics"})
		return
	}
	defer rows.Close()

	var growth []map[string]interface{}
	for rows.Next() {
		var date time.Time
		var count int
		if err := rows.Scan(&date, &count); err != nil {
			continue
		}
		growth = append(growth, map[string]interface{}{
			"date":  date.Format("2006-01-02"),
			"count": count,
		})
	}
	if growth == nil {
		growth = []map[string]interface{}{}
	}

	// Total and active users
	var total, active int
	s.db.Pool.QueryRow(c.Request.Context(), "SELECT COUNT(*) FROM users WHERE org_id = $1", org.ID).Scan(&total)
	s.db.Pool.QueryRow(c.Request.Context(), "SELECT COUNT(*) FROM users WHERE enabled = true AND org_id = $1", org.ID).Scan(&active)

	c.JSON(200, gin.H{
		"growth": growth,
		"total":  total,
		"active": active,
	})
}

func (s *Service) handleEventAnalytics(c *gin.Context) {
	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	interval := parsePeriod(c.Query("period"))

	rows, err := s.db.Pool.Query(c.Request.Context(), `
		SELECT event_type, COUNT(*) as count
		FROM audit_events WHERE org_id = $2 AND timestamp > NOW() - $1::interval
		GROUP BY 1 ORDER BY 2 DESC LIMIT 10
	`, interval, org.ID)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to query event analytics"})
		return
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var eventType string
		var count int
		if err := rows.Scan(&eventType, &count); err != nil {
			continue
		}
		results = append(results, map[string]interface{}{
			"event_type": eventType,
			"count":      count,
		})
	}
	if results == nil {
		results = []map[string]interface{}{}
	}
	c.JSON(200, results)
}

// ==========================================
// Compliance Posture Dashboard
// ==========================================

// CompliancePosture represents the overall compliance health score
type CompliancePosture struct {
	MFAAdoptionRate        float64 `json:"mfa_adoption_rate"`
	PasswordComplianceRate float64 `json:"password_compliance_rate"`
	OpenReviewsCount       int     `json:"open_reviews_count"`
	OverdueReviewsCount    int     `json:"overdue_reviews_count"`
	DormantAccountsCount   int     `json:"dormant_accounts_count"`
	DisabledAccountsCount  int     `json:"disabled_accounts_count"`
	ActiveCampaignsCount   int     `json:"active_campaigns_count"`
	CampaignCompletionRate float64 `json:"campaign_completion_rate"`
	PolicyViolationsCount  int     `json:"policy_violations_count"`
	OverallScore           int     `json:"overall_score"`
}

// GetCompliancePosture returns the aggregated compliance health score
func (s *Service) GetCompliancePosture(ctx context.Context) (*CompliancePosture, error) {
	posture := &CompliancePosture{}

	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	// MFA adoption: % of enabled users with at least one MFA method enrolled,
	// derived from the real enrollment tables via mfaStatusColumns. The old
	// query counted a mfa_enrollments table no migration creates; its single
	// QueryRow error (Warn-swallowed) also zeroed total_enabled, which dragged
	// the password compliance rate below to 0% with it.
	var totalEnabled, mfaEnrolled int
	err = s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*),
		       COUNT(*) FILTER (WHERE totp_enabled OR sms_enabled OR email_otp_enabled OR push_enabled OR webauthn_enabled)
		FROM (SELECT `+mfaStatusColumns+`
		      FROM users u WHERE u.enabled = true AND u.org_id = $1) m
	`, org.ID).Scan(&totalEnabled, &mfaEnrolled)
	if err != nil {
		s.logger.Warn("Failed to query MFA adoption", zap.Error(err))
	}
	if totalEnabled > 0 {
		posture.MFAAdoptionRate = float64(mfaEnrolled) / float64(totalEnabled) * 100
	}

	// Password compliance: % of users whose password hasn't expired (max_age = 90 days default)
	var passwordCompliant int
	err = s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM users
		WHERE enabled = true AND org_id = $1 AND (password_changed_at IS NULL OR password_changed_at > NOW() - INTERVAL '90 days')
	`, org.ID).Scan(&passwordCompliant)
	if err != nil {
		s.logger.Warn("Failed to query password compliance", zap.Error(err))
	}
	if totalEnabled > 0 {
		posture.PasswordComplianceRate = float64(passwordCompliant) / float64(totalEnabled) * 100
	}

	// Open and overdue access reviews
	err = s.db.Pool.QueryRow(ctx, `
		SELECT
			(SELECT COUNT(*) FROM access_reviews WHERE status IN ('pending', 'in_progress') AND org_id = $1),
			(SELECT COUNT(*) FROM access_reviews WHERE status IN ('pending', 'in_progress') AND end_date < NOW() AND org_id = $1)
	`, org.ID).Scan(&posture.OpenReviewsCount, &posture.OverdueReviewsCount)
	if err != nil {
		s.logger.Warn("Failed to query review counts", zap.Error(err))
	}

	// Dormant accounts: users who haven't logged in for 90+ days
	err = s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM users
		WHERE enabled = true AND org_id = $1 AND (last_login IS NULL OR last_login < NOW() - INTERVAL '90 days')
	`, org.ID).Scan(&posture.DormantAccountsCount)
	if err != nil {
		s.logger.Warn("Failed to query dormant accounts", zap.Error(err))
	}

	// Disabled accounts
	err = s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM users WHERE enabled = false AND org_id = $1
	`, org.ID).Scan(&posture.DisabledAccountsCount)
	if err != nil {
		s.logger.Warn("Failed to query disabled accounts", zap.Error(err))
	}

	// Active certification campaigns
	err = s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM certification_campaigns WHERE status = 'active'
	`).Scan(&posture.ActiveCampaignsCount)
	if err != nil {
		s.logger.Warn("Failed to query active campaigns", zap.Error(err))
	}

	// Campaign completion rate (avg % across active campaign runs)
	var avgCompletion *float64
	err = s.db.Pool.QueryRow(ctx, `
		SELECT AVG(
			CASE WHEN total_items > 0 THEN (reviewed_items::float / total_items * 100)
			ELSE 0 END
		) FROM campaign_runs
		WHERE status = 'in_progress'
	`).Scan(&avgCompletion)
	if err != nil {
		s.logger.Warn("Failed to query campaign completion", zap.Error(err))
	}
	if avgCompletion != nil {
		posture.CampaignCompletionRate = *avgCompletion
	}

	// Policy violations: failed policy evaluations in last 30 days
	err = s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_events
		WHERE org_id = $1 AND event_type = 'policy_evaluation' AND outcome = 'failure'
		AND timestamp > NOW() - INTERVAL '30 days'
	`, org.ID).Scan(&posture.PolicyViolationsCount)
	if err != nil {
		s.logger.Warn("Failed to query policy violations", zap.Error(err))
	}

	// Compute overall score (weighted composite 0-100)
	score := 0.0
	score += posture.MFAAdoptionRate * 0.25
	score += posture.PasswordComplianceRate * 0.20
	if posture.OverdueReviewsCount == 0 {
		score += 15
	}
	if posture.DormantAccountsCount == 0 {
		score += 10
	} else if posture.DormantAccountsCount < 5 {
		score += 5
	}
	if posture.PolicyViolationsCount == 0 {
		score += 15
	} else if posture.PolicyViolationsCount < 10 {
		score += 7
	}
	if posture.ActiveCampaignsCount > 0 {
		score += 10
	}
	score += posture.CampaignCompletionRate * 0.05

	if score > 100 {
		score = 100
	}
	posture.OverallScore = int(score)

	return posture, nil
}

func (s *Service) handleGetCompliancePosture(c *gin.Context) {
	posture, err := s.GetCompliancePosture(c.Request.Context())
	if err != nil {
		s.logger.Error("failed to get compliance posture", zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(200, posture)
}

// ==========================================
// Entitlement Catalog
// ==========================================

// EntitlementEntry represents a single entitlement in the catalog
type EntitlementEntry struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	Type           string     `json:"type"`
	Description    string     `json:"description"`
	MemberCount    int        `json:"member_count"`
	RiskLevel      string     `json:"risk_level"`
	OwnerID        *string    `json:"owner_id,omitempty"`
	Tags           []string   `json:"tags"`
	ReviewRequired bool       `json:"review_required"`
	LastReviewedAt *time.Time `json:"last_reviewed_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

// EntitlementStats summarizes the entitlement catalog
type EntitlementStats struct {
	TotalEntitlements int            `json:"total_entitlements"`
	ByType            map[string]int `json:"by_type"`
	ByRiskLevel       map[string]int `json:"by_risk_level"`
	OrphanCount       int            `json:"orphan_count"`
}

// GetEntitlementCatalog returns a unified view of all entitlements
func (s *Service) GetEntitlementCatalog(ctx context.Context, offset, limit int, entType, riskLevel, search string) ([]EntitlementEntry, int, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, 0, err
	}

	query := `
		WITH catalog AS (
			SELECT r.id, r.name, 'role' as type, COALESCE(r.description, '') as description,
				(SELECT COUNT(*) FROM user_roles WHERE role_id = r.id AND org_id = $1) as member_count,
				r.created_at
			FROM roles r
			WHERE r.org_id = $1
			UNION ALL
			SELECT g.id, g.name, 'group' as type, COALESCE(g.description, '') as description,
				(SELECT COUNT(*) FROM group_memberships WHERE group_id = g.id AND org_id = $1) as member_count,
				g.created_at
			FROM groups g
			WHERE g.org_id = $1
			UNION ALL
			SELECT a.id, a.name, 'application' as type, COALESCE(a.description, '') as description,
				(SELECT COUNT(*) FROM user_application_assignments WHERE application_id = a.id AND org_id = $1) as member_count,
				a.created_at
			FROM applications a
			WHERE a.org_id = $1
		)
		SELECT c.id, c.name, c.type, c.description, c.member_count, c.created_at,
			COALESCE(em.risk_level, 'low') as risk_level,
			em.owner_id,
			COALESCE(em.tags, '[]'::jsonb) as tags,
			COALESCE(em.review_required, false) as review_required,
			em.last_reviewed_at
		FROM catalog c
		LEFT JOIN entitlement_metadata em ON em.entitlement_id = c.id AND em.entitlement_type = c.type
	`

	conditions := []string{}
	args := []interface{}{org.ID}
	argCount := 2

	if entType != "" {
		conditions = append(conditions, fmt.Sprintf("c.type = $%d", argCount))
		args = append(args, entType)
		argCount++
	}
	if riskLevel != "" {
		conditions = append(conditions, fmt.Sprintf("COALESCE(em.risk_level, 'low') = $%d", argCount))
		args = append(args, riskLevel)
		argCount++
	}
	if search != "" {
		conditions = append(conditions, fmt.Sprintf("(LOWER(c.name) LIKE $%d OR LOWER(c.description) LIKE $%d)", argCount, argCount))
		args = append(args, "%"+strings.ToLower(search)+"%")
		argCount++
	}

	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}

	countQuery := "SELECT COUNT(*) FROM (" + query + ") sub"
	var total int
	if err := s.db.Pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count entitlements: %w", err)
	}

	query += " ORDER BY c.type, c.name"
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argCount)
		args = append(args, limit)
		argCount++
	}
	if offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argCount)
		args = append(args, offset)
	}

	rows, err := s.db.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query entitlements: %w", err)
	}
	defer rows.Close()

	var entries []EntitlementEntry
	for rows.Next() {
		var e EntitlementEntry
		var tagsJSON []byte
		if err := rows.Scan(&e.ID, &e.Name, &e.Type, &e.Description, &e.MemberCount,
			&e.CreatedAt, &e.RiskLevel, &e.OwnerID, &tagsJSON, &e.ReviewRequired, &e.LastReviewedAt); err != nil {
			s.logger.Warn("Failed to scan entitlement row", zap.Error(err))
			continue
		}
		if len(tagsJSON) > 0 {
			json.Unmarshal(tagsJSON, &e.Tags)
		}
		if e.Tags == nil {
			e.Tags = []string{}
		}
		entries = append(entries, e)
	}
	if entries == nil {
		entries = []EntitlementEntry{}
	}

	return entries, total, nil
}

// GetEntitlementStats returns summary statistics for the catalog
func (s *Service) GetEntitlementStats(ctx context.Context) (*EntitlementStats, error) {
	stats := &EntitlementStats{
		ByType:      make(map[string]int),
		ByRiskLevel: make(map[string]int),
	}

	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	var roleCount, groupCount, appCount int
	s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM roles WHERE org_id = $1", org.ID).Scan(&roleCount)
	s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM groups WHERE org_id = $1", org.ID).Scan(&groupCount)
	s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM applications WHERE org_id = $1", org.ID).Scan(&appCount)

	stats.ByType["role"] = roleCount
	stats.ByType["group"] = groupCount
	stats.ByType["application"] = appCount
	stats.TotalEntitlements = roleCount + groupCount + appCount

	riskRows, err := s.db.Pool.Query(ctx, `
		SELECT risk_level, COUNT(*) FROM entitlement_metadata GROUP BY risk_level
	`)
	if err == nil {
		defer riskRows.Close()
		for riskRows.Next() {
			var level string
			var count int
			riskRows.Scan(&level, &count)
			stats.ByRiskLevel[level] = count
		}
	}
	metadataCount := 0
	for _, c := range stats.ByRiskLevel {
		metadataCount += c
	}
	stats.ByRiskLevel["low"] += stats.TotalEntitlements - metadataCount

	var orphanCount int
	s.db.Pool.QueryRow(ctx, `
		SELECT
			(SELECT COUNT(*) FROM roles r WHERE r.org_id = $1 AND NOT EXISTS (SELECT 1 FROM user_roles WHERE role_id = r.id AND org_id = $1)) +
			(SELECT COUNT(*) FROM groups g WHERE g.org_id = $1 AND NOT EXISTS (SELECT 1 FROM group_memberships WHERE group_id = g.id AND org_id = $1))
	`, org.ID).Scan(&orphanCount)
	stats.OrphanCount = orphanCount

	return stats, nil
}

// UpdateEntitlementMetadata updates risk level, owner, tags for an entitlement
func (s *Service) UpdateEntitlementMetadata(ctx context.Context, entType, entID string, metadata map[string]interface{}) error {
	riskLevel, _ := metadata["risk_level"].(string)
	if riskLevel == "" {
		riskLevel = "low"
	}
	ownerID, _ := metadata["owner_id"].(string)
	description, _ := metadata["description"].(string)
	reviewRequired, _ := metadata["review_required"].(bool)

	var tags []byte
	if tagsRaw, ok := metadata["tags"]; ok {
		tags, _ = json.Marshal(tagsRaw)
	} else {
		tags = []byte("[]")
	}

	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO entitlement_metadata (entitlement_type, entitlement_id, risk_level, owner_id, description, tags, review_required, updated_at)
		VALUES ($1, $2, $3, NULLIF($4, ''), $5, $6, $7, NOW())
		ON CONFLICT (entitlement_type, entitlement_id) DO UPDATE SET
			risk_level = $3, owner_id = NULLIF($4, ''), description = $5, tags = $6, review_required = $7, updated_at = NOW()
	`, entType, entID, riskLevel, ownerID, description, tags, reviewRequired)
	if err != nil {
		return fmt.Errorf("failed to update entitlement metadata: %w", err)
	}
	return nil
}

func (s *Service) handleGetEntitlementCatalog(c *gin.Context) {
	offset := 0
	limit := 50
	if v := c.Query("offset"); v != "" {
		fmt.Sscanf(v, "%d", &offset)
	}
	if offset < 0 {
		offset = 0
	}
	if v := c.Query("limit"); v != "" {
		fmt.Sscanf(v, "%d", &limit)
	}
	if limit < 1 {
		limit = 1
	}
	if limit > 100 {
		limit = 100
	}

	entries, total, err := s.GetEntitlementCatalog(c.Request.Context(), offset, limit,
		c.Query("type"), c.Query("risk_level"), c.Query("search"))
	if err != nil {
		s.logger.Error("failed to get entitlement catalog", zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.Header("X-Total-Count", fmt.Sprintf("%d", total))
	c.JSON(200, entries)
}

func (s *Service) handleGetEntitlementStats(c *gin.Context) {
	stats, err := s.GetEntitlementStats(c.Request.Context())
	if err != nil {
		s.logger.Error("failed to get entitlement stats", zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(200, stats)
}

func (s *Service) handleUpdateEntitlementMetadata(c *gin.Context) {
	entType := c.Param("type")
	entID := c.Param("id")

	var metadata map[string]interface{}
	if err := c.ShouldBindJSON(&metadata); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	if err := s.UpdateEntitlementMetadata(c.Request.Context(), entType, entID, metadata); err != nil {
		s.logger.Error("failed to update entitlement metadata", zap.String("type", entType), zap.String("id", entID), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(200, gin.H{"message": "Entitlement metadata updated"})
}

// ── Admin Delegation service methods ──────────────────────────────────────────

// CreateDelegation creates a new admin delegation
func (s *Service) CreateDelegation(ctx context.Context, d *AdminDelegation) error {
	s.logger.Info("Creating admin delegation", zap.String("delegate_id", d.DelegateID), zap.String("scope_type", d.ScopeType))

	d.ID = uuid.New().String()
	d.CreatedAt = time.Now()
	d.UpdatedAt = time.Now()

	permJSON, err := json.Marshal(d.Permissions)
	if err != nil {
		return fmt.Errorf("failed to marshal permissions: %w", err)
	}

	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO admin_delegations (id, delegate_id, delegated_by, scope_type, scope_id, permissions, enabled, expires_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`, d.ID, d.DelegateID, d.DelegatedBy, d.ScopeType, d.ScopeID, permJSON, d.Enabled, d.ExpiresAt, d.CreatedAt, d.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to create delegation: %w", err)
	}

	return nil
}

// ListDelegations returns admin delegations with pagination
func (s *Service) ListDelegations(ctx context.Context, offset, limit int, scopeType string) ([]AdminDelegation, int, error) {
	s.logger.Debug("Listing admin delegations")

	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, 0, err
	}

	countQuery := "SELECT COUNT(*) FROM admin_delegations"
	dataQuery := `
		SELECT ad.id, ad.delegate_id,
			COALESCE(u1.first_name || ' ' || u1.last_name, u1.username, '') as delegate_name,
			ad.delegated_by,
			COALESCE(u2.first_name || ' ' || u2.last_name, u2.username, '') as delegated_by_name,
			ad.scope_type, ad.scope_id,
			CASE ad.scope_type
				WHEN 'group' THEN (SELECT name FROM groups WHERE id = ad.scope_id AND org_id = $1)
				WHEN 'role' THEN (SELECT name FROM roles WHERE id = ad.scope_id AND org_id = $1)
				WHEN 'application' THEN (SELECT name FROM applications WHERE id = ad.scope_id AND org_id = $1)
				WHEN 'organization' THEN (SELECT name FROM organizations WHERE id = ad.scope_id)
				ELSE ''
			END as scope_name,
			ad.permissions, ad.enabled, ad.expires_at, ad.created_at, ad.updated_at
		FROM admin_delegations ad
		LEFT JOIN users u1 ON u1.id = ad.delegate_id AND u1.org_id = $1
		LEFT JOIN users u2 ON u2.id = ad.delegated_by AND u2.org_id = $1
	`

	// org.ID is referenced as $1 in dataQuery (scoped JOINs/subqueries); the
	// countQuery touches only the unscoped admin_delegations table, so it uses
	// its own arg slice without org.ID and its own placeholder numbering.
	conditions := []string{}
	args := []interface{}{org.ID}
	argCount := 2
	countConditions := []string{}
	countArgs := []interface{}{}
	countArgCount := 1

	if scopeType != "" {
		conditions = append(conditions, fmt.Sprintf("ad.scope_type = $%d", argCount))
		args = append(args, scopeType)
		argCount++
		countConditions = append(countConditions, fmt.Sprintf("ad.scope_type = $%d", countArgCount))
		countArgs = append(countArgs, scopeType)
		// scope_type is the only filter on the count query, so countArgCount is
		// not advanced further (the count query has no LIMIT/OFFSET).
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = " WHERE " + strings.Join(conditions, " AND ")
	}
	countWhereClause := ""
	if len(countConditions) > 0 {
		countWhereClause = " WHERE " + strings.Join(countConditions, " AND ")
	}

	var total int
	if err := s.db.Pool.QueryRow(ctx, countQuery+countWhereClause, countArgs...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count delegations: %w", err)
	}

	dataQuery += whereClause + " ORDER BY ad.created_at DESC"
	if limit > 0 {
		dataQuery += fmt.Sprintf(" LIMIT $%d", argCount)
		args = append(args, limit)
		argCount++
	}
	if offset > 0 {
		dataQuery += fmt.Sprintf(" OFFSET $%d", argCount)
		args = append(args, offset)
	}

	rows, err := s.db.Pool.Query(ctx, dataQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query delegations: %w", err)
	}
	defer rows.Close()

	var delegations []AdminDelegation
	for rows.Next() {
		var d AdminDelegation
		var permJSON []byte
		var scopeName *string
		if err := rows.Scan(&d.ID, &d.DelegateID, &d.DelegateName, &d.DelegatedBy, &d.DelegatedByName,
			&d.ScopeType, &d.ScopeID, &scopeName, &permJSON, &d.Enabled, &d.ExpiresAt, &d.CreatedAt, &d.UpdatedAt); err != nil {
			s.logger.Warn("Failed to scan delegation row", zap.Error(err))
			continue
		}
		if scopeName != nil {
			d.ScopeName = *scopeName
		}
		if len(permJSON) > 0 {
			json.Unmarshal(permJSON, &d.Permissions)
		}
		if d.Permissions == nil {
			d.Permissions = []string{}
		}
		delegations = append(delegations, d)
	}
	if delegations == nil {
		delegations = []AdminDelegation{}
	}

	return delegations, total, nil
}

// GetDelegation returns a single admin delegation by ID
func (s *Service) GetDelegation(ctx context.Context, id string) (*AdminDelegation, error) {
	s.logger.Debug("Getting admin delegation", zap.String("id", id))

	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	var d AdminDelegation
	var permJSON []byte
	var scopeName *string
	err = s.db.Pool.QueryRow(ctx, `
		SELECT ad.id, ad.delegate_id,
			COALESCE(u1.first_name || ' ' || u1.last_name, u1.username, '') as delegate_name,
			ad.delegated_by,
			COALESCE(u2.first_name || ' ' || u2.last_name, u2.username, '') as delegated_by_name,
			ad.scope_type, ad.scope_id,
			CASE ad.scope_type
				WHEN 'group' THEN (SELECT name FROM groups WHERE id = ad.scope_id AND org_id = $2)
				WHEN 'role' THEN (SELECT name FROM roles WHERE id = ad.scope_id AND org_id = $2)
				WHEN 'application' THEN (SELECT name FROM applications WHERE id = ad.scope_id AND org_id = $2)
				WHEN 'organization' THEN (SELECT name FROM organizations WHERE id = ad.scope_id)
				ELSE ''
			END as scope_name,
			ad.permissions, ad.enabled, ad.expires_at, ad.created_at, ad.updated_at
		FROM admin_delegations ad
		LEFT JOIN users u1 ON u1.id = ad.delegate_id AND u1.org_id = $2
		LEFT JOIN users u2 ON u2.id = ad.delegated_by AND u2.org_id = $2
		WHERE ad.id = $1
	`, id, org.ID).Scan(&d.ID, &d.DelegateID, &d.DelegateName, &d.DelegatedBy, &d.DelegatedByName,
		&d.ScopeType, &d.ScopeID, &scopeName, &permJSON, &d.Enabled, &d.ExpiresAt, &d.CreatedAt, &d.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("delegation not found: %w", err)
	}
	if scopeName != nil {
		d.ScopeName = *scopeName
	}
	if len(permJSON) > 0 {
		json.Unmarshal(permJSON, &d.Permissions)
	}
	if d.Permissions == nil {
		d.Permissions = []string{}
	}

	return &d, nil
}

// UpdateDelegation updates mutable fields on an admin delegation
func (s *Service) UpdateDelegation(ctx context.Context, id string, updates map[string]interface{}) error {
	s.logger.Info("Updating admin delegation", zap.String("id", id))

	setParts := []string{}
	args := []interface{}{}
	argCount := 1

	if scopeType, ok := updates["scope_type"].(string); ok {
		setParts = append(setParts, fmt.Sprintf("scope_type = $%d", argCount))
		args = append(args, scopeType)
		argCount++
	}
	if scopeID, ok := updates["scope_id"].(string); ok {
		setParts = append(setParts, fmt.Sprintf("scope_id = $%d", argCount))
		args = append(args, scopeID)
		argCount++
	}
	if permsRaw, ok := updates["permissions"]; ok {
		var perms []string
		if permsList, ok := permsRaw.([]string); ok {
			perms = permsList
		} else if permsList, ok := permsRaw.([]interface{}); ok {
			for _, p := range permsList {
				if ps, ok := p.(string); ok {
					perms = append(perms, ps)
				}
			}
		}
		permJSON, _ := json.Marshal(perms)
		setParts = append(setParts, fmt.Sprintf("permissions = $%d", argCount))
		args = append(args, permJSON)
		argCount++
	}
	if enabled, ok := updates["enabled"].(bool); ok {
		setParts = append(setParts, fmt.Sprintf("enabled = $%d", argCount))
		args = append(args, enabled)
		argCount++
	}
	if expiresAtStr, ok := updates["expires_at"].(string); ok {
		if expiresAtStr == "" {
			setParts = append(setParts, fmt.Sprintf("expires_at = $%d", argCount))
			args = append(args, nil)
			argCount++
		} else if t, err := time.Parse(time.RFC3339, expiresAtStr); err == nil {
			setParts = append(setParts, fmt.Sprintf("expires_at = $%d", argCount))
			args = append(args, t)
			argCount++
		}
	}

	if len(setParts) == 0 {
		return fmt.Errorf("no valid fields to update")
	}

	setParts = append(setParts, "updated_at = NOW()")
	query := fmt.Sprintf("UPDATE admin_delegations SET %s WHERE id = $%d",
		strings.Join(setParts, ", "), argCount)
	args = append(args, id)

	result, err := s.db.Pool.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to update delegation: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("delegation not found")
	}

	return nil
}

// DeleteDelegation removes an admin delegation by ID
func (s *Service) DeleteDelegation(ctx context.Context, id string) error {
	s.logger.Info("Deleting admin delegation", zap.String("id", id))

	result, err := s.db.Pool.Exec(ctx, "DELETE FROM admin_delegations WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("failed to delete delegation: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("delegation not found")
	}

	return nil
}

// ── Admin Delegation HTTP handlers ────────────────────────────────────────────

func (s *Service) handleListDelegations(c *gin.Context) {
	offset := 0
	limit := 20
	if v := c.Query("offset"); v != "" {
		fmt.Sscanf(v, "%d", &offset)
	}
	if offset < 0 {
		offset = 0
	}
	if v := c.Query("limit"); v != "" {
		fmt.Sscanf(v, "%d", &limit)
	}
	if limit < 1 {
		limit = 1
	}
	if limit > 100 {
		limit = 100
	}
	scopeType := c.Query("scope_type")

	delegations, total, err := s.ListDelegations(c.Request.Context(), offset, limit, scopeType)
	if err != nil {
		s.logger.Error("failed to list delegations", zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.Header("X-Total-Count", fmt.Sprintf("%d", total))
	c.JSON(200, delegations)
}

func (s *Service) handleCreateDelegation(c *gin.Context) {
	var d AdminDelegation
	if err := c.ShouldBindJSON(&d); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if d.DelegateID == "" || d.ScopeType == "" || d.ScopeID == "" {
		c.JSON(400, gin.H{"error": "delegate_id, scope_type, and scope_id are required"})
		return
	}
	// Set delegated_by from the authenticated user if available
	if userID, exists := c.Get("user_id"); exists {
		if uid, ok := userID.(string); ok && d.DelegatedBy == "" {
			d.DelegatedBy = uid
		}
	}
	if d.DelegatedBy == "" {
		c.JSON(400, gin.H{"error": "delegated_by is required"})
		return
	}
	if d.Permissions == nil {
		d.Permissions = []string{}
	}

	if err := s.CreateDelegation(c.Request.Context(), &d); err != nil {
		s.logger.Error("failed to create delegation", zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(201, d)
}

func (s *Service) handleGetDelegation(c *gin.Context) {
	id := c.Param("id")
	d, err := s.GetDelegation(c.Request.Context(), id)
	if err != nil {
		c.JSON(404, gin.H{"error": "Delegation not found"})
		return
	}
	c.JSON(200, d)
}

func (s *Service) handleUpdateDelegation(c *gin.Context) {
	id := c.Param("id")
	var updates map[string]interface{}
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	if err := s.UpdateDelegation(c.Request.Context(), id, updates); err != nil {
		if strings.Contains(err.Error(), "not found") {
			c.JSON(404, gin.H{"error": "Delegation not found"})
			return
		}
		s.logger.Error("failed to update delegation", zap.String("id", id), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(200, gin.H{"message": "Delegation updated successfully"})
}

func (s *Service) handleDeleteDelegation(c *gin.Context) {
	id := c.Param("id")
	if err := s.DeleteDelegation(c.Request.Context(), id); err != nil {
		if strings.Contains(err.Error(), "not found") {
			c.JSON(404, gin.H{"error": "Delegation not found"})
			return
		}
		c.JSON(500, gin.H{"error": "Failed to delete delegation"})
		return
	}
	c.JSON(204, nil)
}
