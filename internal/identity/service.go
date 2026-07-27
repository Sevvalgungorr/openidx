// Package identity provides identity management functionality
package identity

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/secretcrypt"
	"github.com/openidx/openidx/internal/risk"
)

// Use the min function from pushmfa.go

// ctxKey is an unexported type for context keys in this package.
type ctxKey int

const (
	// ctxKeyActorID is the context key for the actor (authenticated user) performing the operation.
	ctxKeyActorID ctxKey = iota
)

// ContextWithActorID returns a new context that carries the given actor ID.
func ContextWithActorID(ctx context.Context, actorID string) context.Context {
	return context.WithValue(ctx, ctxKeyActorID, actorID)
}

// actorIDFromContext extracts the actor ID from context, returning "system" if not set.
func actorIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKeyActorID).(string); ok && v != "" {
		return v
	}
	return "system"
}

// Session represents an active user session
type Session struct {
	ID         string    `json:"id"`
	UserID     string    `json:"user_id"`
	ClientID   string    `json:"client_id"`
	IPAddress  string    `json:"ip_address"`
	UserAgent  string    `json:"user_agent"`
	StartedAt  time.Time `json:"started_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// MFATOTP represents TOTP MFA settings for a user
type MFATOTP struct {
	ID         string     `json:"id"`
	UserID     string     `json:"user_id"`
	Secret     string     `json:"-"` // Never expose in JSON
	Enabled    bool       `json:"enabled"`
	EnrolledAt *time.Time `json:"enrolled_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

// MFABackupCode represents a backup code for MFA
type MFABackupCode struct {
	ID        string     `json:"id"`
	UserID    string     `json:"user_id"`
	CodeHash  string     `json:"-"` // Never expose in JSON
	Used      bool       `json:"used"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// MFAPolicy represents an MFA enforcement policy
type MFAPolicy struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name"`
	Description      string                 `json:"description"`
	Enabled          bool                   `json:"enabled"`
	Priority         int                    `json:"priority"`
	Conditions       map[string]interface{} `json:"conditions"`
	RequiredMethods  []string               `json:"required_methods"`
	GracePeriodHours int                    `json:"grace_period_hours"`
	CreatedAt        time.Time              `json:"created_at"`
	UpdatedAt        time.Time              `json:"updated_at"`
}

// TOTPEnrollment represents the enrollment process
type TOTPEnrollment struct {
	Secret    string `json:"secret"`
	QRCodeURL string `json:"qr_code_url"`
	ManualKey string `json:"manual_key"`
}

// TOTPVerification represents a TOTP verification request
type TOTPVerification struct {
	Code string `json:"code"`
}

// GroupMember represents a user's membership in a group
type GroupMember struct {
	UserID    string    `json:"user_id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`
	JoinedAt  time.Time `json:"joined_at"`
}

// Role represents a role in the system
type Role struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	IsComposite bool      `json:"is_composite"`
	CreatedAt   time.Time `json:"created_at"`
}

// UserRoleAssignment represents a role assignment with time-bound metadata
type UserRoleAssignment struct {
	Role       Role       `json:"role"`
	AssignedBy string     `json:"assigned_by"`
	AssignedAt time.Time  `json:"assigned_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}

// DirectoryAuthenticator is an interface for LDAP/AD auth and password operations
type DirectoryAuthenticator interface {
	AuthenticateUser(ctx context.Context, directoryID, username, password string) error
	ChangePassword(ctx context.Context, directoryID, username, oldPassword, newPassword string) error
	ResetPassword(ctx context.Context, directoryID, username, newPassword string) error
}

// Service provides identity management operations
type Service struct {
	db                *database.PostgresDB
	redis             *database.RedisClient
	cfg               *config.Config
	logger            *zap.Logger
	webauthnSessions  sync.Map // In-memory storage for WebAuthn sessions (use Redis in production)
	directoryService  DirectoryAuthenticator
	emailService      EmailSender
	webhookService    WebhookPublisher
	anomalyDetector   AnomalyDetector
	smsProvider       SMSProvider       // SMS OTP provider
	smsProviderMu     sync.RWMutex      // Protects smsProvider for runtime hot-swap
	phoneCallProvider PhoneCallProvider // Phone call MFA provider
	risk              RiskService       // Risk evaluation service

	// JWKS public key cache
	jwksCacheMu     sync.RWMutex
	jwksCachedKey   *rsa.PublicKey
	jwksCacheExpiry time.Time

	// idpCipher encrypts identity_providers.client_secret at rest. Best-effort:
	// a passthrough (noop) when no usable ENCRYPTION_KEY is configured.
	idpCipher *secretcrypt.Cipher

	// users is the user data-access port (Repository pattern — see
	// user_repository.go). New/refactored user reads route through this so SQL
	// lives in one place and read-mostly queries use the read replica. The
	// legacy inline db.Pool user queries are being migrated here incrementally.
	users UserRepository

	// groups is the group data-access port (see group_repository.go), the second
	// aggregate migrated to the Repository pattern.
	groups GroupRepository

	// sessions is the session data-access port (see session_repository.go), the
	// third aggregate. Reads that tolerate lag use the replica; IsValid reads the
	// primary (security-critical read-after-write).
	sessions SessionRepository
}

// NewService creates a new identity service
func NewService(db *database.PostgresDB, redis *database.RedisClient, cfg *config.Config, logger *zap.Logger) *Service {
	log := logger.With(zap.String("service", "identity"))
	encKey := ""
	if cfg != nil {
		encKey = cfg.EncryptionKey
	}
	idpCipher, err := secretcrypt.New(encKey)
	if err != nil {
		log.Warn("IdP client secrets will NOT be encrypted at rest; set a 32-byte ENCRYPTION_KEY to enable", zap.Error(err))
		idpCipher = secretcrypt.NewNoop()
	}
	return &Service{
		db:        db,
		redis:     redis,
		cfg:       cfg,
		logger:    log,
		idpCipher: idpCipher,
		users:     NewPostgresUserRepository(db),
		groups:    NewPostgresGroupRepository(db),
		sessions:  NewPostgresSessionRepository(db),
	}
}

// SetDirectoryService sets the directory service for LDAP auth pass-through
func (s *Service) SetDirectoryService(ds DirectoryAuthenticator) {
	s.directoryService = ds
}

// EmailSender defines the interface for sending emails
type EmailSender interface {
	SendVerificationEmail(ctx context.Context, to, userName, token, baseURL string) error
	SendInvitationEmail(ctx context.Context, to, inviterName, token, baseURL string) error
	SendPasswordResetEmail(ctx context.Context, to, userName, token, baseURL string) error
	SendWelcomeEmail(ctx context.Context, to, userName string) error
	SendAsync(ctx context.Context, to, subject, templateName string, data map[string]interface{}) error
}

// WebhookPublisher defines the interface for publishing webhook events
type WebhookPublisher interface {
	Publish(ctx context.Context, eventType string, payload interface{}) error
}

// AnomalyDetector defines the interface for anomaly detection during login
type AnomalyDetector interface {
	RunAnomalyCheck(ctx context.Context, userID, ip, userAgent string, lat, lon float64) interface{}
	CheckIPThreatList(ctx context.Context, ip string) (bool, string)
}

// SMSProvider defines the interface for sending SMS messages
type SMSProvider interface {
	SendOTP(ctx context.Context, phoneNumber, code string) error
	SendMessage(ctx context.Context, phoneNumber, message string) error
}

// SetEmailService sets the email service
func (s *Service) SetEmailService(es EmailSender) {
	s.emailService = es
}

// SetWebhookService sets the webhook service
func (s *Service) SetWebhookService(ws WebhookPublisher) {
	s.webhookService = ws
}

// SetAnomalyDetector sets the anomaly detection service
func (s *Service) SetAnomalyDetector(ad AnomalyDetector) {
	s.anomalyDetector = ad
}

// SetSMSProvider sets the SMS provider for OTP delivery (thread-safe for runtime hot-swap)
func (s *Service) SetSMSProvider(sp SMSProvider) {
	s.smsProviderMu.Lock()
	defer s.smsProviderMu.Unlock()
	s.smsProvider = sp
}

// getSMSProvider returns the current SMS provider (thread-safe)
func (s *Service) getSMSProvider() SMSProvider {
	s.smsProviderMu.RLock()
	defer s.smsProviderMu.RUnlock()
	return s.smsProvider
}

// SetPhoneCallProvider sets the phone call provider for voice MFA
func (s *Service) SetPhoneCallProvider(pcp PhoneCallProvider) {
	s.phoneCallProvider = pcp
}

// RiskService defines the interface for risk evaluation
type RiskService interface {
	ListRiskPolicies(ctx context.Context, enabledOnly bool) ([]risk.RiskPolicy, error)
	GetRiskPolicy(ctx context.Context, policyID string) (*risk.RiskPolicy, error)
	CreateRiskPolicy(ctx context.Context, req risk.CreateRiskPolicyRequest) (*risk.RiskPolicy, error)
	UpdateRiskPolicy(ctx context.Context, policyID string, req risk.CreateRiskPolicyRequest) (*risk.RiskPolicy, error)
	DeleteRiskPolicy(ctx context.Context, policyID string) error
	ToggleRiskPolicy(ctx context.Context, policyID string, enabled bool) error
	GeoIPLookup(ctx context.Context, ip string) (*risk.GeoResult, error)
	ComputeDeviceFingerprint(ipAddress, userAgent string) string
	RegisterDevice(ctx context.Context, userID, fingerprint, ipAddress, userAgent, location string) (string, bool, error)
	IsDeviceTrusted(ctx context.Context, userID, fingerprint string) bool
	GetRecentFailedAttempts(ctx context.Context, userID string) int
	EvaluateRiskPolicies(ctx context.Context, loginCtx risk.EvaluateLoginContext) (*risk.PolicyEvaluationResult, error)
	GetRiskStats(ctx context.Context) (map[string]interface{}, error)
	GetLoginHistory(ctx context.Context, userID string, limit int) ([]risk.LoginRecord, error)
}

// SetRiskService sets the risk service
func (s *Service) SetRiskService(rs RiskService) {
	s.risk = rs
}

// openIDXAuthMiddleware validates OpenIDX OAuth JWT tokens
func (s *Service) openIDXAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "missing authorization header",
			})
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid authorization header format",
			})
			return
		}

		tokenString := parts[1]

		// Parse JWT token with signature validation
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Validate signing method
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				s.logger.Warn("Unexpected signing method", zap.Any("method", token.Header["alg"]))
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			// Fetch the public key from OAuth service (cached with 5-min TTL)
			key, err := s.getOAuthPublicKey()
			if err != nil {
				s.logger.Error("Failed to get OAuth public key", zap.Error(err))
				return nil, err
			}
			return key, nil
		})

		if err != nil {
			s.logger.Warn("JWT parsing failed", zap.Error(err), zap.String("token_prefix", tokenString[:min(50, len(tokenString))]))
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid token",
			})
			return
		}

		// Validate token
		if token == nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid token",
			})
			return
		}

		// Extract claims
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid token claims",
			})
			return
		}

		// Validate expiration
		if exp, ok := claims["exp"].(float64); ok {
			if time.Now().Unix() > int64(exp) {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error": "token expired",
				})
				return
			}
		}

		// Validate issuer
		if iss, ok := claims["iss"].(string); ok {
			expectedIssuer := s.cfg.OAuthIssuer
			if expectedIssuer == "" {
				expectedIssuer = "http://localhost:8006"
			}
			if iss != expectedIssuer {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error": "invalid token issuer",
				})
				return
			}
		}

		// Set user context from token claims
		if sub, ok := claims["sub"].(string); ok {
			c.Set("user_id", sub)
		}
		if email, ok := claims["email"].(string); ok {
			c.Set("email", email)
		}
		if name, ok := claims["name"].(string); ok {
			c.Set("name", name)
		}

		// Extract roles
		if rolesRaw, ok := claims["roles"].([]interface{}); ok {
			var roles []string
			for _, r := range rolesRaw {
				if role, ok := r.(string); ok {
					roles = append(roles, role)
				}
			}
			c.Set("roles", roles)
		}

		c.Next()
	}
}

// isIdentitySelfService reports whether an /api/v1/identity request path is a
// caller-scoped self-service operation (operating on the authenticated user's
// own account), as opposed to an administrative one that acts on other users
// or system-wide resources. Matching is precise to avoid e.g. "/users/me"
// accidentally matching "/users/members".
func isIdentitySelfService(path string) bool {
	rest := strings.TrimPrefix(path, "/api/v1/identity")
	switch {
	case rest == "/users/me" || strings.HasPrefix(rest, "/users/me/"):
		return true // profile, password, PATs, consents, privacy, identity-links
	case strings.HasPrefix(rest, "/mfa/"):
		return true // the caller's own MFA enrollment/verification
	case rest == "/trusted-browsers" || strings.HasPrefix(rest, "/trusted-browsers/"):
		return true
	case rest == "/risk-assessment", rest == "/resend-verification":
		return true
	}
	return false
}

// requireAdminUnlessSelfService enforces authorization on the identity API.
// Self-service paths are allowed for any authenticated user; everything else
// (user/role/group/provider management, etc.) requires an admin role. This is
// deny-by-default: any path not explicitly recognized as self-service needs
// admin, so new administrative routes are protected automatically.
//
// Must run after openIDXAuthMiddleware (which sets "roles" from the token).
func (s *Service) requireAdminUnlessSelfService() gin.HandlerFunc {
	return func(c *gin.Context) {
		if isIdentitySelfService(c.Request.URL.Path) {
			c.Next()
			return
		}
		rolesRaw, _ := c.Get("roles")
		roles, _ := rolesRaw.([]string)
		for _, r := range roles {
			if r == "admin" || r == "super_admin" {
				c.Next()
				return
			}
		}
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"error": "admin role required for this operation",
		})
	}
}

// getOAuthPublicKey returns the OAuth service's RSA public key, using a cache with 5-minute TTL
func (s *Service) getOAuthPublicKey() (*rsa.PublicKey, error) {
	// Check cache first (read lock)
	s.jwksCacheMu.RLock()
	if s.jwksCachedKey != nil && time.Now().Before(s.jwksCacheExpiry) {
		key := s.jwksCachedKey
		s.jwksCacheMu.RUnlock()
		return key, nil
	}
	s.jwksCacheMu.RUnlock()

	// Cache miss or expired - fetch and update (write lock)
	s.jwksCacheMu.Lock()
	defer s.jwksCacheMu.Unlock()

	// Double-check after acquiring write lock
	if s.jwksCachedKey != nil && time.Now().Before(s.jwksCacheExpiry) {
		return s.jwksCachedKey, nil
	}

	jwksURL := s.cfg.OAuthJWKSURL
	if jwksURL == "" {
		jwksURL = "http://localhost:8006/.well-known/jwks.json"
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	var jwks struct {
		Keys []struct {
			Kty string `json:"kty"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS: %w", err)
	}

	// Find the first RSA signing key
	for _, key := range jwks.Keys {
		if key.Kty == "RSA" && key.Use == "sig" {
			pubKey, err := parseRSAPublicKey(key.N, key.E)
			if err != nil {
				return nil, err
			}
			s.jwksCachedKey = pubKey
			s.jwksCacheExpiry = time.Now().Add(5 * time.Minute)
			s.logger.Info("JWKS public key cached", zap.String("jwks_url", jwksURL))
			return pubKey, nil
		}
	}

	return nil, fmt.Errorf("no valid RSA signing key found")
}

// parseRSAPublicKey parses RSA public key from base64url encoded n and e
func parseRSAPublicKey(nStr, eStr string) (*rsa.PublicKey, error) {
	// Remove padding for base64url encoding
	nClean := strings.TrimRight(nStr, "=")
	eClean := strings.TrimRight(eStr, "=")

	// Decode n (modulus)
	nBytes, err := base64.RawURLEncoding.DecodeString(nClean)
	if err != nil {
		return nil, fmt.Errorf("failed to decode n: %w", err)
	}
	n := new(big.Int).SetBytes(nBytes)

	// Decode e (exponent)
	eBytes, err := base64.RawURLEncoding.DecodeString(eClean)
	if err != nil {
		return nil, fmt.Errorf("failed to decode e: %w", err)
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}

// GetUser retrieves a user by ID
func (s *Service) GetUser(ctx context.Context, userID string) (*User, error) {
	s.logger.Debug("Getting user", zap.String("user_id", userID))

	// Delegates to the user repository (Repository pattern — see
	// user_repository.go). The repo owns the SQL, scopes to the caller's tenant
	// (a cross-tenant id reads as not-found, not 403), and serves the read from
	// the replica pool when one is configured. The repo returns the sentinel
	// ErrUserNotFound on a miss; existing callers already treat any error here as
	// "user not found", so the contract is preserved.
	return s.users.GetByID(ctx, userID)
}

// ListUsers retrieves users with pagination
func (s *Service) ListUsers(ctx context.Context, offset, limit int, search ...string) ([]User, int, error) {
	s.logger.Debug("Listing users", zap.Int("offset", offset), zap.Int("limit", limit))

	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, 0, err
	}

	searchQuery := ""
	if len(search) > 0 {
		searchQuery = search[0]
	}

	var total int
	if searchQuery != "" {
		escaped := strings.NewReplacer("%", "\\%", "_", "\\_").Replace(searchQuery)
		searchPattern := "%" + escaped + "%"
		err = s.db.Pool.QueryRow(ctx, `
			SELECT COUNT(*) FROM users
			WHERE (username ILIKE $1 ESCAPE '\\' OR email ILIKE $1 ESCAPE '\\' OR first_name ILIKE $1 ESCAPE '\\' OR last_name ILIKE $1 ESCAPE '\\')
			  AND org_id = $2
		`, searchPattern, org.ID).Scan(&total)
		if err != nil {
			return nil, 0, err
		}
	} else {
		err = s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM users WHERE org_id = $1", org.ID).Scan(&total)
		if err != nil {
			return nil, 0, err
		}
	}

	var rows interface {
		Next() bool
		Scan(...interface{}) error
		Close()
	}
	if searchQuery != "" {
		escaped := strings.NewReplacer("%", "\\%", "_", "\\_").Replace(searchQuery)
		searchPattern := "%" + escaped + "%"
		rows, err = s.db.Pool.Query(ctx, `
			SELECT id, username, email, first_name, last_name, enabled, email_verified,
			       created_at, updated_at, last_login_at, password_changed_at,
			       password_must_change, failed_login_count, last_failed_login_at, locked_until
			FROM users
			WHERE (username ILIKE $1 ESCAPE '\\' OR email ILIKE $1 ESCAPE '\\' OR first_name ILIKE $1 ESCAPE '\\' OR last_name ILIKE $1 ESCAPE '\\')
			  AND org_id = $2
			ORDER BY created_at DESC
			OFFSET $3 LIMIT $4
		`, searchPattern, org.ID, offset, limit)
	} else {
		rows, err = s.db.Pool.Query(ctx, `
			SELECT id, username, email, first_name, last_name, enabled, email_verified,
			       created_at, updated_at, last_login_at, password_changed_at,
			       password_must_change, failed_login_count, last_failed_login_at, locked_until
			FROM users
			WHERE org_id = $1
			ORDER BY created_at DESC
			OFFSET $2 LIMIT $3
		`, org.ID, offset, limit)
	}
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var dbUser UserDB
		if err := rows.Scan(
			&dbUser.ID, &dbUser.Username, &dbUser.Email, &dbUser.FirstName, &dbUser.LastName,
			&dbUser.Enabled, &dbUser.EmailVerified, &dbUser.CreatedAt, &dbUser.UpdatedAt, &dbUser.LastLoginAt,
			&dbUser.PasswordChangedAt, &dbUser.PasswordMustChange, &dbUser.FailedLoginCount,
			&dbUser.LastFailedLoginAt, &dbUser.LockedUntil,
		); err != nil {
			return nil, 0, err
		}
		// Convert to SCIM User model
		user := dbUser.ToUser()
		users = append(users, user)
	}

	return users, total, nil
}

// CreateUser creates a new user
func (s *Service) CreateUser(ctx context.Context, user *User) error {
	s.logger.Info("Creating user", zap.String("username", user.UserName))

	// Persistence lives in the repository (primary pool). The service keeps the
	// domain side effects: audit logging on success. Repo writes the generated
	// id + timestamps back onto `user`.
	if err := s.users.Create(ctx, user); err != nil {
		return err
	}

	actorID := actorIDFromContext(ctx)
	s.logAuditEvent(ctx, "identity", "user_management", "user.created", "success",
		actorID, user.ID, "user", map[string]interface{}{
			"username": user.UserName,
			"email":    GetEmail(*user),
		})
	return nil
}

// UpdateUser updates an existing user
func (s *Service) UpdateUser(ctx context.Context, user *User) error {
	s.logger.Info("Updating user", zap.String("user_id", user.ID))

	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	// Persistence in the repository (primary pool); domain side effects stay
	// here. A missing row returns ErrUserNotFound (repo), which we translate to
	// the legacy "user not found" contract existing callers expect.
	if err := s.users.Update(ctx, user); err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return fmt.Errorf("user not found")
		}
		return err
	}

	// A user set to disabled must lose live access, not just be blocked from new
	// password logins. deprovisionUser is idempotent, so running it whenever the
	// resulting state is disabled (without needing the prior value) is safe.
	if !user.Enabled {
		s.deprovisionUser(ctx, user.ID, org.ID, false)
	}
	return nil
}

// revokedSessionTTL is how long a revoked-session marker lives in Redis. It
// must outlast the longest refresh-token lifetime so a disabled user's
// in-flight refresh tokens keep failing the oauth-service's revoked-session
// check until they expire on their own.
const revokedSessionTTL = 30 * 24 * time.Hour

// scrubLogValue strips CR/LF from a value before it is placed in a log field,
// so a caller-supplied identifier can't forge extra log lines (defense in depth
// on top of the JSON encoder, and it clears CodeQL's log-injection sink).
func scrubLogValue(s string) string {
	return strings.NewReplacer("\n", "", "\r", "").Replace(s)
}

// deprovisionUser revokes everything that keeps a user's access alive after
// they are disabled or deleted: active sessions (marked revoked + a Redis
// `revoked_session:<id>` marker the oauth-service honors on every refresh
// grant), active API keys, and live PAM state (active vault checkouts, direct
// user vault grants, JIT role elevations). hardDelete removes the child rows
// outright (user is gone); otherwise they are marked revoked and kept for
// audit. Best-effort and idempotent — a failure to revoke one class is logged,
// not fatal, so the caller's primary mutation still completes. OAuth
// access/refresh tokens are additionally neutralized by the oauth-service's
// user-active check on the refresh grant. Ziti network identities and live
// Guacamole transports are torn down by the access-service's deprovision and
// lifecycle sweeps (only it holds those clients), within one 30s tick.
func (s *Service) deprovisionUser(ctx context.Context, userID, orgID string, hardDelete bool) {
	// One scoped logger with the (scrubbed) user id, so the per-step warnings
	// below never re-embed caller-supplied input directly.
	log := s.logger.With(zap.String("user_id", scrubLogValue(userID)))

	// No database configured (unit tests, or a service without a pool): there is
	// nothing to revoke. deprovision is best-effort, so skip rather than
	// nil-panic. Redis-side revocation below is likewise guarded.
	if s.db == nil || s.db.Pool == nil {
		return
	}

	// Collect the user's live session IDs so we can publish revocation markers
	// that the oauth-service checks (it has its own Redis view; the marker is
	// the cross-service signal).
	rows, err := s.db.Pool.Query(ctx,
		`SELECT id FROM sessions WHERE user_id = $1 AND org_id = $2`, userID, orgID)
	if err != nil {
		log.Warn("deprovision: list sessions failed", zap.Error(err))
	} else {
		var sessionIDs []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err == nil {
				sessionIDs = append(sessionIDs, id)
			}
		}
		rows.Close()
		if s.redis != nil {
			for _, id := range sessionIDs {
				if err := s.redis.Client.Set(ctx, "revoked_session:"+id, "1", revokedSessionTTL).Err(); err != nil {
					log.Warn("deprovision: publish revoked-session marker failed", zap.Error(err))
				}
			}
		}
	}

	// PAM: live privileged access must die with the account, in both the soft
	// and hard paths. Checkouts and direct user grants have no FK to users
	// (principal_id is a bare UUID), so they would otherwise survive even a
	// hard delete. Role-mediated vault grants are left intact — they belong to
	// the role, and the user's role assignments are what get removed. The live
	// Guacamole transport is severed by the access-service lifecycle sweep
	// (only it holds the Guacamole client); these row updates are what stop
	// any further reveal/checkout immediately.
	if _, err := s.db.Pool.Exec(ctx,
		`UPDATE vault_checkouts SET status = 'revoked', returned_at = NOW()
		 WHERE principal_id = $1 AND org_id = $2 AND status = 'active'`,
		userID, orgID); err != nil {
		log.Warn("deprovision: revoke vault checkouts failed", zap.Error(err))
	}
	if _, err := s.db.Pool.Exec(ctx,
		`UPDATE vault_access_grants SET expires_at = NOW()
		 WHERE principal_type = 'user' AND principal_id = $1 AND org_id = $2
		   AND (expires_at IS NULL OR expires_at > NOW())`,
		userID, orgID); err != nil {
		log.Warn("deprovision: expire vault grants failed", zap.Error(err))
	}
	if _, err := s.db.Pool.Exec(ctx,
		`UPDATE jit_grants SET status = 'revoked', revoked_at = NOW(), updated_at = NOW()
		 WHERE user_id = $1 AND org_id = $2 AND status = 'active'`,
		userID, orgID); err != nil {
		log.Warn("deprovision: revoke jit grants failed", zap.Error(err))
	}

	if hardDelete {
		if _, err := s.db.Pool.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1 AND org_id = $2`, userID, orgID); err != nil {
			log.Warn("deprovision: delete sessions failed", zap.Error(err))
		}
		//orgscope:ignore user_sessions is keyed by globally-unique user_id (no org_id column); deleting a deprovisioned user's rows
		if _, err := s.db.Pool.Exec(ctx, `DELETE FROM user_sessions WHERE user_id = $1`, userID); err != nil {
			log.Warn("deprovision: delete user_sessions failed", zap.Error(err))
		}
		if _, err := s.db.Pool.Exec(ctx, `DELETE FROM api_keys WHERE user_id = $1 AND org_id = $2`, userID, orgID); err != nil {
			log.Warn("deprovision: delete api_keys failed", zap.Error(err))
		}
		return
	}

	if _, err := s.db.Pool.Exec(ctx,
		`UPDATE sessions SET revoked = true, revoked_at = NOW()
		 WHERE user_id = $1 AND org_id = $2 AND (revoked IS NULL OR revoked = false)`,
		userID, orgID); err != nil {
		log.Warn("deprovision: revoke sessions failed", zap.Error(err))
	}
	if _, err := s.db.Pool.Exec(ctx,
		`UPDATE api_keys SET status = 'revoked' WHERE user_id = $1 AND org_id = $2 AND status = 'active'`,
		userID, orgID); err != nil {
		log.Warn("deprovision: revoke api_keys failed", zap.Error(err))
	}
}

// DeleteUser deletes a user
func (s *Service) DeleteUser(ctx context.Context, userID string) error {
	s.logger.Info("Deleting user", zap.String("user_id", userID))

	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	// Log audit event before deletion so the record exists even if delete succeeds
	actorID := actorIDFromContext(ctx)
	s.logAuditEvent(ctx, "identity", "user_management", "user.deleted", "success",
		actorID, userID, "user", nil)

	// Revoke sessions + API keys and publish session-revocation markers BEFORE
	// removing the user row, so a concurrent refresh grant can't slip through
	// against a still-present user.
	s.deprovisionUser(ctx, userID, org.ID, true)

	// Row removal lives in the repository (primary pool). Ordering + side
	// effects (audit above, deprovision above) stay here. Missing row maps to
	// the legacy "user not found" contract.
	if err := s.users.Delete(ctx, userID); err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return fmt.Errorf("user not found")
		}
		return err
	}
	return nil
}

// CreateIdentityProvider creates a new identity provider
func (s *Service) CreateIdentityProvider(ctx context.Context, idp *IdentityProvider) error {
	s.logger.Info("Creating identity provider", zap.String("name", idp.Name))

	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	idp.ID = uuid.New()
	now := time.Now()
	idp.CreatedAt = now
	idp.UpdatedAt = now

	encSecret, err := s.idpCipher.Encrypt(idp.ClientSecret)
	if err != nil {
		return fmt.Errorf("encrypt idp client_secret: %w", err)
	}

	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO identity_providers (id, name, provider_type, issuer_url, client_id, client_secret, scopes, enabled, created_at, updated_at, org_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`, idp.ID, idp.Name, idp.ProviderType, idp.IssuerURL, idp.ClientID, encSecret, idp.Scopes, idp.Enabled, idp.CreatedAt, idp.UpdatedAt, org.ID)

	return err
}

// GetIdentityProvider retrieves an identity provider by ID
func (s *Service) GetIdentityProvider(ctx context.Context, idpID string) (*IdentityProvider, error) {
	s.logger.Debug("Getting identity provider", zap.String("idp_id", idpID))

	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	var idp IdentityProvider
	err = s.db.Pool.QueryRow(ctx, `
		SELECT id, name, provider_type, issuer_url, client_id, client_secret, scopes, enabled, created_at, updated_at
		FROM identity_providers WHERE id = $1 AND org_id = $2
	`, idpID, org.ID).Scan(
		&idp.ID, &idp.Name, &idp.ProviderType, &idp.IssuerURL, &idp.ClientID, &idp.ClientSecret, &idp.Scopes, &idp.Enabled, &idp.CreatedAt, &idp.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if idp.ClientSecret, err = s.idpCipher.Decrypt(idp.ClientSecret); err != nil {
		return nil, fmt.Errorf("decrypt idp client_secret: %w", err)
	}

	return &idp, nil
}

// ListIdentityProviders retrieves identity providers with pagination
func (s *Service) ListIdentityProviders(ctx context.Context, offset, limit int) ([]IdentityProvider, int, error) {
	s.logger.Debug("Listing identity providers", zap.Int("offset", offset), zap.Int("limit", limit))

	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, 0, err
	}

	var total int
	err = s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM identity_providers WHERE org_id = $1", org.ID).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, name, provider_type, issuer_url, client_id, client_secret, scopes, enabled, created_at, updated_at
		FROM identity_providers
		WHERE org_id = $1
		ORDER BY name
		OFFSET $2 LIMIT $3
	`, org.ID, offset, limit)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	idps := make([]IdentityProvider, 0)
	for rows.Next() {
		var idp IdentityProvider
		if err := rows.Scan(
			&idp.ID, &idp.Name, &idp.ProviderType, &idp.IssuerURL, &idp.ClientID, &idp.ClientSecret, &idp.Scopes, &idp.Enabled, &idp.CreatedAt, &idp.UpdatedAt,
		); err != nil {
			return nil, 0, err
		}
		if idp.ClientSecret, err = s.idpCipher.Decrypt(idp.ClientSecret); err != nil {
			return nil, 0, fmt.Errorf("decrypt idp client_secret: %w", err)
		}
		idps = append(idps, idp)
	}

	return idps, total, nil
}

// UpdateIdentityProvider updates an existing identity provider
func (s *Service) UpdateIdentityProvider(ctx context.Context, idp *IdentityProvider) error {
	s.logger.Info("Updating identity provider", zap.String("idp_id", idp.ID.String()))

	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	idp.UpdatedAt = time.Now()

	encSecret, err := s.idpCipher.Encrypt(idp.ClientSecret)
	if err != nil {
		return fmt.Errorf("encrypt idp client_secret: %w", err)
	}

	_, err = s.db.Pool.Exec(ctx, `
		UPDATE identity_providers
		SET name = $2, provider_type = $3, issuer_url = $4, client_id = $5, client_secret = $6, scopes = $7, enabled = $8, updated_at = $9
		WHERE id = $1 AND org_id = $10
	`, idp.ID, idp.Name, idp.ProviderType, idp.IssuerURL, idp.ClientID, encSecret, idp.Scopes, idp.Enabled, idp.UpdatedAt, org.ID)

	return err
}

// DeleteIdentityProvider deletes an identity provider
func (s *Service) DeleteIdentityProvider(ctx context.Context, idpID string) error {
	s.logger.Info("Deleting identity provider", zap.String("idp_id", idpID))

	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	_, err = s.db.Pool.Exec(ctx, "DELETE FROM identity_providers WHERE id = $1 AND org_id = $2", idpID, org.ID)
	return err
}

// GetUserSessions retrieves active sessions for a user
func (s *Service) GetUserSessions(ctx context.Context, userID string) ([]Session, error) {
	s.logger.Debug("Getting sessions for user", zap.String("user_id", userID))
	// Delegates to the session repository (replica read, lag-tolerant).
	return s.sessions.ListByUser(ctx, userID)
}

// TerminateSession terminates a specific session
func (s *Service) TerminateSession(ctx context.Context, sessionID string) error {
	s.logger.Info("Terminating session", zap.String("session_id", sessionID))
	return s.sessions.Terminate(ctx, sessionID)
}

// ListGroups retrieves groups with pagination
func (s *Service) ListGroups(ctx context.Context, offset, limit int, search ...string) ([]Group, int, error) {
	s.logger.Debug("Listing groups", zap.Int("offset", offset), zap.Int("limit", limit))

	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, 0, err
	}

	searchQuery := ""
	if len(search) > 0 {
		searchQuery = search[0]
	}

	var total int
	if searchQuery != "" {
		searchPattern := "%" + searchQuery + "%"
		err = s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM groups WHERE (name ILIKE $1 OR description ILIKE $1) AND org_id = $2", searchPattern, org.ID).Scan(&total)
		if err != nil {
			return nil, 0, err
		}
	} else {
		err = s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM groups WHERE org_id = $1", org.ID).Scan(&total)
		if err != nil {
			return nil, 0, err
		}
	}

	var rows interface {
		Next() bool
		Scan(...interface{}) error
		Close()
	}
	if searchQuery != "" {
		searchPattern := "%" + searchQuery + "%"
		rows, err = s.db.Pool.Query(ctx, `
			SELECT g.id, g.name, g.description, g.parent_id, g.allow_self_join, g.require_approval, g.max_members, g.created_at, g.updated_at,
			       COALESCE((SELECT COUNT(*) FROM group_memberships gm WHERE gm.group_id = g.id AND gm.org_id = $1), 0) as member_count
			FROM groups g
			WHERE (g.name ILIKE $2 OR g.description ILIKE $2) AND g.org_id = $1
			ORDER BY g.name
			OFFSET $3 LIMIT $4
		`, org.ID, searchPattern, offset, limit)
	} else {
		rows, err = s.db.Pool.Query(ctx, `
			SELECT g.id, g.name, g.description, g.parent_id, g.allow_self_join, g.require_approval, g.max_members, g.created_at, g.updated_at,
			       COALESCE((SELECT COUNT(*) FROM group_memberships gm WHERE gm.group_id = g.id AND gm.org_id = $1), 0) as member_count
			FROM groups g
			WHERE g.org_id = $1
			ORDER BY g.name
			OFFSET $2 LIMIT $3
		`, org.ID, offset, limit)
	}
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var groups []Group
	for rows.Next() {
		var dbGroup GroupDB
		if err := rows.Scan(
			&dbGroup.ID, &dbGroup.DisplayName, &dbGroup.Description, &dbGroup.ParentID, &dbGroup.AllowSelfJoin, &dbGroup.RequireApproval, &dbGroup.MaxMembers, &dbGroup.CreatedAt, &dbGroup.UpdatedAt, &dbGroup.MemberCount,
		); err != nil {
			return nil, 0, err
		}
		groups = append(groups, dbGroup.ToGroup())
	}

	return groups, total, nil
}

// GetGroup retrieves a group by ID
func (s *Service) GetGroup(ctx context.Context, groupID string) (*Group, error) {
	s.logger.Debug("Getting group", zap.String("group_id", groupID))
	// Delegates to the group repository (see group_repository.go): tenant-scoped
	// read on the replica, returns ErrGroupNotFound on a miss.
	return s.groups.GetByID(ctx, groupID)
}

// GetGroupMembers retrieves members of a group
func (s *Service) GetGroupMembers(ctx context.Context, groupID string) ([]GroupMember, error) {
	s.logger.Debug("Getting group members", zap.String("group_id", groupID))

	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	rows, err := s.db.Pool.Query(ctx, `
		SELECT u.id, u.username, u.email, u.first_name, u.last_name, gm.joined_at
		FROM users u
		JOIN group_memberships gm ON u.id = gm.user_id
		WHERE gm.group_id = $1 AND gm.org_id = $2
		ORDER BY gm.joined_at
	`, groupID, org.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var members []GroupMember
	for rows.Next() {
		var m GroupMember
		if err := rows.Scan(&m.UserID, &m.Username, &m.Email, &m.FirstName, &m.LastName, &m.JoinedAt); err != nil {
			return nil, err
		}
		members = append(members, m)
	}

	return members, nil
}

// CreateGroup creates a new group
func (s *Service) CreateGroup(ctx context.Context, group *Group) error {
	s.logger.Info("Creating group", zap.String("name", group.GetName()))
	// Persistence in the repository (primary pool); it writes the generated id +
	// timestamps back onto `group`.
	return s.groups.Create(ctx, group)
}

// UpdateGroup updates an existing group
func (s *Service) UpdateGroup(ctx context.Context, group *Group) error {
	s.logger.Info("Updating group", zap.String("group_id", group.ID))
	return s.groups.Update(ctx, group)
}

// DeleteGroup deletes a group
func (s *Service) DeleteGroup(ctx context.Context, groupID string) error {
	s.logger.Info("Deleting group", zap.String("group_id", groupID))
	// Repo removes memberships then the group row (primary pool).
	return s.groups.Delete(ctx, groupID)
}

// AddGroupMember adds a user to a group
func (s *Service) AddGroupMember(ctx context.Context, groupID, userID string) error {
	s.logger.Info("Adding member to group", zap.String("group_id", groupID), zap.String("user_id", userID))

	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	// Check if group exists (GetGroup scopes to the caller's org, so a
	// group in another org reads as not-found here).
	_, err = s.GetGroup(ctx, groupID)
	if err != nil {
		return fmt.Errorf("group not found: %w", err)
	}

	// Check if user exists
	_, err = s.GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// Use a single atomic query that checks the member limit and inserts in one step,
	// avoiding the TOCTOU race between counting members and inserting.
	result, err := s.db.Pool.Exec(ctx, `
		INSERT INTO group_memberships (group_id, user_id, joined_at, org_id)
		SELECT $1, $2, NOW(), $3
		WHERE NOT EXISTS (SELECT 1 FROM group_memberships WHERE group_id = $1 AND user_id = $2 AND org_id = $3)
		AND (
			SELECT COUNT(*) FROM group_memberships WHERE group_id = $1 AND org_id = $3
		) < COALESCE(
			(SELECT max_members FROM groups WHERE id = $1 AND org_id = $3),
			2147483647
		)
	`, groupID, userID, org.ID)
	if err != nil {
		return fmt.Errorf("failed to add member: %w", err)
	}

	if result.RowsAffected() == 0 {
		// Check why the insert didn't happen: either already a member or limit reached
		var exists bool
		err = s.db.Pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM group_memberships WHERE group_id = $1 AND user_id = $2 AND org_id = $3)", groupID, userID, org.ID).Scan(&exists)
		if err != nil {
			return err
		}
		if exists {
			return fmt.Errorf("user is already a member of this group")
		}
		return fmt.Errorf("group has reached maximum member limit")
	}

	return nil
}

// RemoveGroupMember removes a user from a group
func (s *Service) RemoveGroupMember(ctx context.Context, groupID, userID string) error {
	s.logger.Info("Removing member from group", zap.String("group_id", groupID), zap.String("user_id", userID))

	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	result, err := s.db.Pool.Exec(ctx, `
		DELETE FROM group_memberships WHERE group_id = $1 AND user_id = $2 AND org_id = $3
	`, groupID, userID, org.ID)

	if err != nil {
		return err
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("user is not a member of this group")
	}

	return nil
}

// SearchUsers searches for users by username or email
func (s *Service) SearchUsers(ctx context.Context, query string, limit int) ([]User, error) {
	s.logger.Debug("Searching users", zap.String("query", query))

	if limit <= 0 || limit > 50 {
		limit = 20
	}

	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	searchPattern := "%" + query + "%"
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, username, email, first_name, last_name, enabled, email_verified,
		       created_at, updated_at, last_login_at, password_changed_at,
		       password_must_change, failed_login_count, last_failed_login_at, locked_until
		FROM users
		WHERE (username ILIKE $1 OR email ILIKE $1 OR first_name ILIKE $1 OR last_name ILIKE $1)
		  AND org_id = $2
		ORDER BY username
		LIMIT $3
	`, searchPattern, org.ID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var dbUser UserDB
		if err := rows.Scan(
			&dbUser.ID, &dbUser.Username, &dbUser.Email, &dbUser.FirstName, &dbUser.LastName,
			&dbUser.Enabled, &dbUser.EmailVerified, &dbUser.CreatedAt, &dbUser.UpdatedAt, &dbUser.LastLoginAt,
			&dbUser.PasswordChangedAt, &dbUser.PasswordMustChange, &dbUser.FailedLoginCount,
			&dbUser.LastFailedLoginAt, &dbUser.LockedUntil,
		); err != nil {
			return nil, err
		}
		users = append(users, dbUser.ToUser())
	}

	return users, nil
}

// GetGroupMembersPaginated retrieves members of a group with pagination and search
func (s *Service) GetGroupMembersPaginated(ctx context.Context, groupID string, search string, offset, limit int) ([]GroupMember, int, error) {
	s.logger.Debug("Getting group members paginated", zap.String("group_id", groupID))

	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, 0, err
	}

	// Get total count. Membership rows are scoped by gm.org_id so the
	// count only reflects members within the caller's org.
	var total int
	countQuery := `
		SELECT COUNT(*) FROM users u
		JOIN group_memberships gm ON u.id = gm.user_id
		WHERE gm.group_id = $1 AND gm.org_id = $2
	`
	countArgs := []interface{}{groupID, org.ID}

	if search != "" {
		countQuery += ` AND (u.username ILIKE $3 OR u.email ILIKE $3 OR u.first_name ILIKE $3 OR u.last_name ILIKE $3)`
		countArgs = append(countArgs, "%"+search+"%")
	}

	err = s.db.Pool.QueryRow(ctx, countQuery, countArgs...).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	// Get members
	query := `
		SELECT u.id, u.username, u.email, u.first_name, u.last_name, gm.joined_at
		FROM users u
		JOIN group_memberships gm ON u.id = gm.user_id
		WHERE gm.group_id = $1 AND gm.org_id = $2
	`
	args := []interface{}{groupID, org.ID}

	if search != "" {
		query += ` AND (u.username ILIKE $3 OR u.email ILIKE $3 OR u.first_name ILIKE $3 OR u.last_name ILIKE $3)`
		args = append(args, "%"+search+"%")
		query += ` ORDER BY gm.joined_at DESC OFFSET $4 LIMIT $5`
		args = append(args, offset, limit)
	} else {
		query += ` ORDER BY gm.joined_at DESC OFFSET $3 LIMIT $4`
		args = append(args, offset, limit)
	}

	rows, err := s.db.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var members []GroupMember
	for rows.Next() {
		var m GroupMember
		if err := rows.Scan(&m.UserID, &m.Username, &m.Email, &m.FirstName, &m.LastName, &m.JoinedAt); err != nil {
			return nil, 0, err
		}
		members = append(members, m)
	}

	return members, total, nil
}

// GetSubgroups retrieves subgroups of a parent group
func (s *Service) GetSubgroups(ctx context.Context, parentID string) ([]Group, error) {
	s.logger.Debug("Getting subgroups", zap.String("parent_id", parentID))

	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	rows, err := s.db.Pool.Query(ctx, `
		SELECT g.id, g.name, g.description, g.parent_id, g.allow_self_join, g.require_approval, g.max_members, g.created_at, g.updated_at,
		       COALESCE((SELECT COUNT(*) FROM group_memberships gm WHERE gm.group_id = g.id AND gm.org_id = $2), 0) as member_count
		FROM groups g
		WHERE g.parent_id = $1 AND g.org_id = $2
		ORDER BY g.name
	`, parentID, org.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []Group
	for rows.Next() {
		var dbGroup GroupDB
		if err := rows.Scan(
			&dbGroup.ID, &dbGroup.DisplayName, &dbGroup.Description, &dbGroup.ParentID, &dbGroup.AllowSelfJoin, &dbGroup.RequireApproval, &dbGroup.MaxMembers, &dbGroup.CreatedAt, &dbGroup.UpdatedAt, &dbGroup.MemberCount,
		); err != nil {
			return nil, err
		}
		groups = append(groups, dbGroup.ToGroup())
	}

	return groups, nil
}

// CreateSession creates a new user session
func (s *Service) CreateSession(ctx context.Context, userID, clientID, ipAddress, userAgent string, sessionDuration time.Duration) (*Session, error) {
	s.logger.Info("Creating session", zap.String("user_id", userID), zap.String("client_id", clientID))

	now := time.Now()
	session := &Session{
		UserID:     userID,
		ClientID:   clientID,
		IPAddress:  ipAddress,
		UserAgent:  userAgent,
		StartedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(sessionDuration),
	}
	// Persistence in the repository (primary); it fills in the generated id.
	if err := s.sessions.Create(ctx, session); err != nil {
		return nil, err
	}
	return session, nil
}

// UpdateSessionActivity updates the last seen time for a session
func (s *Service) UpdateSessionActivity(ctx context.Context, sessionID string) error {
	s.logger.Debug("Updating session activity", zap.String("session_id", sessionID))
	// Repo write (primary). Legacy contract: missing/revoked/expired -> error.
	if err := s.sessions.UpdateActivity(ctx, sessionID); err != nil {
		if errors.Is(err, ErrSessionNotFound) {
			return fmt.Errorf("session not found or is revoked/expired")
		}
		return err
	}
	return nil
}

// IsSessionValid checks if a session is not revoked and not expired
func (s *Service) IsSessionValid(ctx context.Context, sessionID string) (bool, error) {
	// Repo reads the PRIMARY here (security-critical read-after-write): a
	// just-revoked session must not read as valid off a lagging replica.
	valid, err := s.sessions.IsValid(ctx, sessionID)
	if errors.Is(err, ErrSessionNotFound) {
		// Preserve the legacy contract: a missing session returned the raw
		// pgx.ErrNoRows-derived error to the caller. Surface a non-nil error so
		// callers still treat it as "not valid".
		return false, err
	}
	return valid, err
}

// CountActiveSessions returns the number of active (non-revoked, non-expired) sessions for a user
func (s *Service) CountActiveSessions(ctx context.Context, userID string) (int, error) {
	return s.sessions.CountActive(ctx, userID)
}

// RevokeUserSessionsOnPasswordChange revokes all sessions and refresh tokens for a user on password change
func (s *Service) RevokeUserSessionsOnPasswordChange(ctx context.Context, userID string) error {
	s.logger.Info("Revoking all sessions on password change", zap.String("user_id", userID))

	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	rows, err := s.db.Pool.Query(ctx, `
		SELECT id FROM sessions
		WHERE user_id = $1 AND org_id = $2 AND (revoked IS NULL OR revoked = false)
	`, userID, org.ID)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var sessionID string
		if err := rows.Scan(&sessionID); err != nil {
			continue
		}
		if _, err := s.db.Pool.Exec(ctx, `UPDATE sessions SET revoked = true, revoked_at = NOW() WHERE id = $1 AND org_id = $2`, sessionID, org.ID); err != nil {
			return fmt.Errorf("failed to revoke session %s: %w", sessionID, err)
		}
		s.redis.Client.Set(ctx, "revoked_session:"+sessionID, "1", 25*time.Hour)
	}

	// Also delete all refresh tokens
	if _, err := s.db.Pool.Exec(ctx, `DELETE FROM oauth_refresh_tokens WHERE user_id = $1 AND org_id = $2`, userID, org.ID); err != nil {
		return fmt.Errorf("failed to delete refresh tokens: %w", err)
	}

	return nil
}

// RecordFailedLogin records a failed login attempt for account lockout
func (s *Service) RecordFailedLogin(ctx context.Context, username string) error {
	s.logger.Info("Recording failed login", zap.String("username", username))

	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	now := time.Now()

	// Get current user state
	var user User
	err = s.db.Pool.QueryRow(ctx, `
		SELECT id, failed_login_count, last_failed_login_at, locked_until
		FROM users WHERE username = $1 AND org_id = $2
	`, username, org.ID).Scan(&user.ID, &user.FailedLoginCount, &user.LastFailedLoginAt, &user.LockedUntil)
	if err != nil {
		return err
	}

	user.FailedLoginCount++
	user.LastFailedLoginAt = &now

	// Read lockout settings from system_settings, with defaults
	maxFailures := 5
	lockoutMinutes := 15
	var settingsValue []byte
	if err := s.db.Pool.QueryRow(ctx, "SELECT value FROM system_settings WHERE key = 'failed_login_lockout_threshold'").Scan(&settingsValue); err == nil {
		var v int
		if json.Unmarshal(settingsValue, &v) == nil && v > 0 {
			maxFailures = v
		}
	}
	if err := s.db.Pool.QueryRow(ctx, "SELECT value FROM system_settings WHERE key = 'failed_login_lockout_duration'").Scan(&settingsValue); err == nil {
		var v int
		if json.Unmarshal(settingsValue, &v) == nil && v > 0 {
			lockoutMinutes = v
		}
	}
	lockoutDuration := time.Duration(lockoutMinutes) * time.Minute

	if user.FailedLoginCount >= maxFailures {
		lockoutUntil := now.Add(lockoutDuration)
		user.LockedUntil = &lockoutUntil
		s.logger.Warn("Account locked due to failed login attempts",
			zap.String("username", username), zap.Int("failures", user.FailedLoginCount))
	}

	// Update user record
	_, err = s.db.Pool.Exec(ctx, `
		UPDATE users
		SET failed_login_count = $2, last_failed_login_at = $3, locked_until = $4
		WHERE username = $1 AND org_id = $5
	`, username, user.FailedLoginCount, user.LastFailedLoginAt, user.LockedUntil, org.ID)

	return err
}

// ClearFailedLogins clears failed login attempts (on successful login)
func (s *Service) ClearFailedLogins(ctx context.Context, username string) error {
	s.logger.Debug("Clearing failed logins", zap.String("username", username))

	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	_, err = s.db.Pool.Exec(ctx, `
		UPDATE users
		SET failed_login_count = 0, last_failed_login_at = NULL, locked_until = NULL
		WHERE username = $1 AND org_id = $2
	`, username, org.ID)

	return err
}

// IsAccountLocked checks if a user account is currently locked
func (s *Service) IsAccountLocked(ctx context.Context, username string) (bool, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return false, err
	}

	var lockedUntil *time.Time
	err = s.db.Pool.QueryRow(ctx, `
		SELECT locked_until FROM users WHERE username = $1 AND org_id = $2
	`, username, org.ID).Scan(&lockedUntil)

	if err != nil {
		return false, err
	}

	if lockedUntil != nil && time.Now().Before(*lockedUntil) {
		return true, nil
	}

	return false, nil
}

// ValidatePasswordPolicy validates a password against policy requirements
func (s *Service) ValidatePasswordPolicy(password string) error {
	// Basic password policy: minimum 8 characters, at least one uppercase, one lowercase, one digit
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters long")
	}

	hasUpper := false
	hasLower := false
	hasDigit := false

	for _, char := range password {
		switch {
		case 'A' <= char && char <= 'Z':
			hasUpper = true
		case 'a' <= char && char <= 'z':
			hasLower = true
		case '0' <= char && char <= '9':
			hasDigit = true
		}
	}

	if !hasUpper {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}
	if !hasLower {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}
	if !hasDigit {
		return fmt.Errorf("password must contain at least one digit")
	}

	return nil
}

// UpdatePassword updates a user's password and enforces policy
func (s *Service) UpdatePassword(ctx context.Context, userID string, newPassword string) error {
	s.logger.Info("Updating password", zap.String("user_id", userID))

	if err := s.ValidatePasswordPolicy(newPassword); err != nil {
		return err
	}

	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	now := time.Now()
	_, err = s.db.Pool.Exec(ctx, `
		UPDATE users
		SET password_hash = $2, password_changed_at = $3, password_must_change = false
		WHERE id = $1 AND org_id = $4
	`, userID, string(hashedPassword), now, org.ID)

	if err == nil {
		actorID := actorIDFromContext(ctx)
		s.logAuditEvent(ctx, "identity", "security", "user.password_changed", "success",
			actorID, userID, "user", nil)
	}

	return err
}

// CheckPasswordExpiry checks if a user's password has expired
func (s *Service) CheckPasswordExpiry(ctx context.Context, userID string) (bool, error) {
	var passwordChangedAt *time.Time
	var mustChange bool

	org, err := orgctx.From(ctx)
	if err != nil {
		return false, err
	}

	err = s.db.Pool.QueryRow(ctx, `
		SELECT password_changed_at, password_must_change FROM users WHERE id = $1 AND org_id = $2
	`, userID, org.ID).Scan(&passwordChangedAt, &mustChange)

	if err != nil {
		return false, err
	}

	// If must_change is set, password has expired
	if mustChange {
		return true, nil
	}

	// Check if password is older than 90 days
	if passwordChangedAt != nil {
		expiryDuration := 90 * 24 * time.Hour // 90 days
		if time.Since(*passwordChangedAt) > expiryDuration {
			return true, nil
		}
	}

	return false, nil
}

// ErrInvalidCredentials is returned when username or password is incorrect
var ErrInvalidCredentials = errors.New("invalid username or password")

// ErrAccountLocked is returned when the user account is locked
var ErrAccountLocked = errors.New("account is locked")

// ErrAccountDisabled is returned when the user account is disabled
var ErrAccountDisabled = errors.New("account is disabled")

// AuthenticateUser verifies username and password credentials
func (s *Service) AuthenticateUser(ctx context.Context, username, password string) (*User, error) {
	s.logger.Info("Authenticating user", zap.String("username", username))

	// The org is resolved (from subdomain/JWT/default) before the
	// request reaches here, so authentication is scoped to the
	// caller's tenant: the same username/email may exist in other
	// orgs, and they must not satisfy a login against this one.
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	var userID, passwordHash string
	var enabled bool
	var lockedUntil *time.Time
	var failedLoginCount int
	var source *string
	var directoryID *string

	// Get user by username or email, within the caller's org
	err = s.db.Pool.QueryRow(ctx, `
		SELECT id, password_hash, enabled, locked_until, failed_login_count, source, directory_id
		FROM users
		WHERE (username = $1 OR email = $1) AND org_id = $2
	`, username, org.ID).Scan(&userID, &passwordHash, &enabled, &lockedUntil, &failedLoginCount, &source, &directoryID)

	if err != nil {
		s.logger.Debug("User not found", zap.String("username", username))
		return nil, ErrInvalidCredentials
	}

	// Check if account is disabled
	if !enabled {
		s.logger.Warn("Login attempt on disabled account", zap.String("username", username))
		return nil, ErrAccountDisabled
	}

	// Check if account is locked
	if lockedUntil != nil && time.Now().Before(*lockedUntil) {
		s.logger.Warn("Login attempt on locked account", zap.String("username", username))
		return nil, ErrAccountLocked
	}

	// Check if user is from a directory — authenticate against directory
	if source != nil && (*source == "ldap" || *source == "active_directory") && directoryID != nil && s.directoryService != nil {
		s.logger.Debug("Authenticating directory user", zap.String("username", username), zap.String("source", *source), zap.String("directory_id", *directoryID))

		if err := s.directoryService.AuthenticateUser(ctx, *directoryID, username, password); err != nil {
			s.recordFailedLogin(ctx, userID, failedLoginCount)
			s.logger.Debug("Directory authentication failed", zap.String("username", username), zap.Error(err))
			return nil, ErrInvalidCredentials
		}
	} else if source != nil && *source == "azure_ad" {
		// Azure AD users must use SSO — cannot authenticate with username/password
		s.logger.Debug("Azure AD user attempted password login", zap.String("username", username))
		return nil, fmt.Errorf("this account uses Azure AD single sign-on")
	} else {
		// Local user — verify password with bcrypt
		if passwordHash == "" {
			s.logger.Debug("User has no password set", zap.String("username", username))
			return nil, ErrInvalidCredentials
		}

		s.logger.Debug("Comparing password", zap.String("username", username))

		err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password))
		if err != nil {
			s.recordFailedLogin(ctx, userID, failedLoginCount)
			s.logger.Debug("Invalid password", zap.String("username", username), zap.Error(err))
			return nil, ErrInvalidCredentials
		}
	}

	// Reset failed login count and update last login
	now := time.Now()
	_, err = s.db.Pool.Exec(ctx, `
		UPDATE users
		SET failed_login_count = 0, last_login_at = $2, locked_until = NULL
		WHERE id = $1 AND org_id = $3
	`, userID, now, org.ID)
	if err != nil {
		s.logger.Error("Failed to update login stats", zap.Error(err))
	}

	// Return full user object
	return s.GetUser(ctx, userID)
}

// recordFailedLogin records a failed login attempt and locks account if necessary
func (s *Service) recordFailedLogin(ctx context.Context, userID string, currentCount int) {
	org, err := orgctx.From(ctx)
	if err != nil {
		s.logger.Error("Failed to record failed login: no org context", zap.Error(err))
		return
	}

	newCount := currentCount + 1
	now := time.Now()

	// Read lockout settings from system_settings
	maxFailures := 5
	lockoutMinutes := 15
	var settingsValue []byte
	if err := s.db.Pool.QueryRow(ctx, "SELECT value FROM system_settings WHERE key = 'failed_login_lockout_threshold'").Scan(&settingsValue); err == nil {
		var v int
		if json.Unmarshal(settingsValue, &v) == nil && v > 0 {
			maxFailures = v
		}
	}
	if err := s.db.Pool.QueryRow(ctx, "SELECT value FROM system_settings WHERE key = 'failed_login_lockout_duration'").Scan(&settingsValue); err == nil {
		var v int
		if json.Unmarshal(settingsValue, &v) == nil && v > 0 {
			lockoutMinutes = v
		}
	}

	var lockedUntil *time.Time
	if newCount >= maxFailures {
		lockTime := now.Add(time.Duration(lockoutMinutes) * time.Minute)
		lockedUntil = &lockTime
		s.logger.Warn("Account locked due to failed attempts", zap.String("user_id", userID))
	}

	_, err = s.db.Pool.Exec(ctx, `
		UPDATE users
		SET failed_login_count = $2, last_failed_login_at = $3, locked_until = $4
		WHERE id = $1 AND org_id = $5
	`, userID, newCount, now, lockedUntil, org.ID)
	if err != nil {
		s.logger.Error("Failed to record failed login", zap.Error(err))
	}
}

// SetPassword sets a new password for a user (hashes and stores)
func (s *Service) SetPassword(ctx context.Context, userID string, password string) error {
	s.logger.Info("Setting password", zap.String("user_id", userID))

	// Validate password policy
	if err := s.ValidatePasswordPolicy(password); err != nil {
		return err
	}

	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	// Hash password
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	now := time.Now()
	_, err = s.db.Pool.Exec(ctx, `
		UPDATE users
		SET password_hash = $2, password_changed_at = $3, password_must_change = false
		WHERE id = $1 AND org_id = $4
	`, userID, string(hash), now, org.ID)

	return err
}

// GenerateTOTPSecret generates a new TOTP secret and QR code for enrollment
func (s *Service) GenerateTOTPSecret(ctx context.Context, userID string) (*TOTPEnrollment, error) {
	s.logger.Info("Generating TOTP secret", zap.String("user_id", userID))

	// Get user information for QR code
	user, err := s.GetUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Generate TOTP key
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "OpenIDX",
		AccountName: user.GetEmail(),
		SecretSize:  32,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate TOTP key: %w", err)
	}

	// Generate QR code URL
	qrURL := key.URL()
	s.logger.Info("Generated TOTP secret for user")

	return &TOTPEnrollment{
		Secret:    key.Secret(),
		QRCodeURL: qrURL,
		ManualKey: key.Secret(),
	}, nil
}

// EnrollTOTP enrolls a user with TOTP MFA after verification
func (s *Service) EnrollTOTP(ctx context.Context, userID, secret, verificationCode string) error {
	s.logger.Info("Enrolling TOTP for user", zap.String("user_id", userID))

	// Verify the code first
	valid := totp.Validate(verificationCode, secret)
	if !valid {
		return fmt.Errorf("invalid TOTP verification code")
	}

	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	now := time.Now()
	totpID := uuid.New().String()

	// Remove any existing TOTP records for this user before inserting
	if _, err := s.db.Pool.Exec(ctx, `DELETE FROM mfa_totp WHERE user_id = $1 AND org_id = $2`, userID, org.ID); err != nil {
		return fmt.Errorf("failed to remove existing TOTP records: %w", err)
	}

	// Insert TOTP record
	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO mfa_totp (id, user_id, secret, enabled, enrolled_at, created_at, updated_at, org_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, totpID, userID, secret, true, now, now, now, org.ID)

	if err != nil {
		return fmt.Errorf("failed to enroll TOTP: %w", err)
	}

	return nil
}

// VerifyTOTP verifies a TOTP code for a user
func (s *Service) VerifyTOTP(ctx context.Context, userID, code string) (bool, error) {
	s.logger.Debug("Verifying TOTP code", zap.String("user_id", userID))

	org, err := orgctx.From(ctx)
	if err != nil {
		return false, err
	}

	// Get user's TOTP secret
	var secret string
	var enabled bool
	err = s.db.Pool.QueryRow(ctx, `
		SELECT secret, enabled FROM mfa_totp WHERE user_id = $1 AND org_id = $2
	`, userID, org.ID).Scan(&secret, &enabled)

	if err != nil {
		return false, fmt.Errorf("failed to get TOTP settings: %w", err)
	}

	if !enabled {
		return false, fmt.Errorf("TOTP not enabled for user")
	}

	// Verify the code
	valid := totp.Validate(code, secret)
	if valid {
		// Update last used timestamp
		now := time.Now()
		_, err = s.db.Pool.Exec(ctx, `
			UPDATE mfa_totp SET last_used_at = $2, updated_at = $2 WHERE user_id = $1 AND org_id = $3
		`, userID, now, org.ID)
		if err != nil {
			s.logger.Warn("Failed to update TOTP last used timestamp", zap.Error(err))
		}
	}

	return valid, nil
}

// DisableTOTP disables TOTP for a user
func (s *Service) DisableTOTP(ctx context.Context, userID string) error {
	s.logger.Info("Disabling TOTP for user", zap.String("user_id", userID))

	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	_, err = s.db.Pool.Exec(ctx, `
		UPDATE mfa_totp SET enabled = false, updated_at = $2 WHERE user_id = $1 AND org_id = $3
	`, userID, time.Now(), org.ID)

	return err
}

// GetTOTPStatus returns the TOTP status for a user
func (s *Service) GetTOTPStatus(ctx context.Context, userID string) (*MFATOTP, error) {
	s.logger.Debug("Getting TOTP status", zap.String("user_id", userID))

	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	var totp MFATOTP
	err = s.db.Pool.QueryRow(ctx, `
		SELECT id, user_id, enabled, enrolled_at, last_used_at, created_at, updated_at
		FROM mfa_totp WHERE user_id = $1 AND org_id = $2
	`, userID, org.ID).Scan(
		&totp.ID, &totp.UserID, &totp.Enabled, &totp.EnrolledAt,
		&totp.LastUsedAt, &totp.CreatedAt, &totp.UpdatedAt,
	)

	if err != nil {
		// Return empty status if no TOTP configured
		return &MFATOTP{UserID: userID, Enabled: false}, nil
	}

	return &totp, nil
}

// GenerateBackupCodes generates backup codes for MFA
func (s *Service) GenerateBackupCodes(ctx context.Context, userID string, count int) ([]string, error) {
	s.logger.Info("Generating backup codes", zap.String("user_id", userID), zap.Int("count", count))

	if count <= 0 || count > 20 {
		count = 10 // Default to 10 codes
	}

	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	var codes []string

	for i := 0; i < count; i++ {
		// Generate random 8-character alphanumeric code
		bytes := make([]byte, 8)
		if _, err := rand.Read(bytes); err != nil {
			return nil, fmt.Errorf("failed to generate random bytes: %w", err)
		}

		code := base32.StdEncoding.EncodeToString(bytes)[:8]
		codes = append(codes, strings.ToUpper(code))

		// Hash the code for storage
		hash := sha256.Sum256([]byte(code))
		codeHash := hex.EncodeToString(hash[:])

		// Store in database
		codeID := uuid.New().String()
		_, err := s.db.Pool.Exec(ctx, `
			INSERT INTO mfa_backup_codes (id, user_id, code_hash, created_at, org_id)
			VALUES ($1, $2, $3, $4, $5)
		`, codeID, userID, codeHash, time.Now(), org.ID)

		if err != nil {
			return nil, fmt.Errorf("failed to store backup code: %w", err)
		}
	}

	return codes, nil
}

// ValidateBackupCode validates a backup code and marks it as used
func (s *Service) ValidateBackupCode(ctx context.Context, userID, code string) (bool, error) {
	s.logger.Info("Validating backup code", zap.String("user_id", userID))

	org, err := orgctx.From(ctx)
	if err != nil {
		return false, err
	}

	// Hash the provided code
	hash := sha256.Sum256([]byte(strings.ToUpper(code)))
	codeHash := hex.EncodeToString(hash[:])

	// Check if code exists and is unused
	var codeID string
	err = s.db.Pool.QueryRow(ctx, `
		SELECT id FROM mfa_backup_codes
		WHERE user_id = $1 AND code_hash = $2 AND used = false AND org_id = $3
	`, userID, codeHash, org.ID).Scan(&codeID)

	if err != nil {
		return false, nil // Code not found or already used
	}

	// Mark code as used
	now := time.Now()
	_, err = s.db.Pool.Exec(ctx, `
		UPDATE mfa_backup_codes SET used = true, used_at = $2 WHERE id = $1 AND org_id = $3
	`, codeID, now, org.ID)

	if err != nil {
		s.logger.Warn("Failed to mark backup code as used", zap.Error(err))
	}

	return true, nil
}

// GetRemainingBackupCodes returns count of unused backup codes
func (s *Service) GetRemainingBackupCodes(ctx context.Context, userID string) (int, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return 0, err
	}

	var count int
	err = s.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM mfa_backup_codes WHERE user_id = $1 AND used = false AND org_id = $2
	`, userID, org.ID).Scan(&count)

	return count, err
}

// GetBackupCodeCount returns count of unused backup codes (alias for GetRemainingBackupCodes)
func (s *Service) GetBackupCodeCount(ctx context.Context, userID string) (int, error) {
	return s.GetRemainingBackupCodes(ctx, userID)
}

// VerifyBackupCode validates a backup code and marks it as used (alias for ValidateBackupCode)
func (s *Service) VerifyBackupCode(ctx context.Context, userID, code string) (bool, error) {
	return s.ValidateBackupCode(ctx, userID, code)
}

// GetPushDevices returns push MFA devices for a user (alias for GetPushMFADevices)
func (s *Service) GetPushDevices(ctx context.Context, userID string) ([]PushMFADevice, error) {
	return s.GetPushMFADevices(ctx, userID)
}

// IsMFARequired checks if MFA is required for a user based on policies
func (s *Service) IsMFARequired(ctx context.Context, userID string, clientIP string) (bool, *MFAPolicy, error) {
	s.logger.Debug("Checking MFA requirements", zap.String("user_id", userID), zap.String("client_ip", clientIP))

	org, err := orgctx.From(ctx)
	if err != nil {
		return false, nil, err
	}

	// Get all active MFA policies ordered by priority
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, name, description, enabled, priority, conditions, required_methods, grace_period_hours,
		       created_at, updated_at
		FROM mfa_policies
		WHERE enabled = true AND org_id = $1
		ORDER BY priority DESC
	`, org.ID)
	if err != nil {
		return false, nil, fmt.Errorf("failed to query MFA policies: %w", err)
	}
	defer rows.Close()

	var policies []MFAPolicy
	for rows.Next() {
		var policy MFAPolicy
		err := rows.Scan(
			&policy.ID, &policy.Name, &policy.Description, &policy.Enabled, &policy.Priority,
			&policy.Conditions, &policy.RequiredMethods, &policy.GracePeriodHours,
			&policy.CreatedAt, &policy.UpdatedAt,
		)
		if err != nil {
			return false, nil, fmt.Errorf("failed to scan policy: %w", err)
		}
		policies = append(policies, policy)
	}

	// Evaluate each policy in priority order
	for _, policy := range policies {
		required, err := s.evaluateMFAPolicy(ctx, userID, clientIP, &policy)
		if err != nil {
			s.logger.Warn("Failed to evaluate MFA policy", zap.String("policy_id", policy.ID), zap.Error(err))
			continue
		}

		if required {
			return true, &policy, nil
		}
	}

	return false, nil, nil
}

// evaluateMFAPolicy evaluates if a specific MFA policy applies to a user
func (s *Service) evaluateMFAPolicy(ctx context.Context, userID, clientIP string, policy *MFAPolicy) (bool, error) {
	// Parse conditions - Conditions is already map[string]interface{} from JSONB
	conditions := policy.Conditions
	if conditions == nil {
		// No conditions means policy applies to all
		return true, nil
	}

	// Check group membership conditions
	if groups, exists := conditions["groups"]; exists {
		if !s.checkUserInGroups(ctx, userID, groups) {
			return false, nil
		}
	}

	// Check IP range conditions
	if ipRanges, exists := conditions["ip_ranges"]; exists {
		if !s.checkIPInRanges(clientIP, ipRanges) {
			return false, nil
		}
	}

	// Check time-based conditions
	if timeWindows, exists := conditions["time_windows"]; exists {
		if !s.checkTimeWindow(timeWindows) {
			return false, nil
		}
	}

	// Check user attributes
	if attributes, exists := conditions["attributes"]; exists {
		if !s.checkUserAttributes(ctx, userID, attributes) {
			return false, nil
		}
	}

	// If we reach here, all conditions are met
	return true, nil
}

// checkUserInGroups checks if user belongs to any of the specified groups
func (s *Service) checkUserInGroups(ctx context.Context, userID string, groups interface{}) bool {
	groupList, ok := groups.([]interface{})
	if !ok {
		return false
	}

	// Get user's group memberships
	userGroups, err := s.getUserGroups(ctx, userID)
	if err != nil {
		s.logger.Warn("Failed to get user groups for MFA policy", zap.Error(err))
		return false
	}

	// Convert to string slice for comparison
	var userGroupNames []string
	for _, group := range userGroups {
		userGroupNames = append(userGroupNames, group.GetName())
	}

	// Check if user is in any required group
	for _, requiredGroup := range groupList {
		groupName, ok := requiredGroup.(string)
		if !ok {
			continue
		}

		for _, userGroup := range userGroupNames {
			if userGroup == groupName {
				return true
			}
		}
	}

	return false
}

// checkIPInRanges checks if IP address falls within any specified ranges
func (s *Service) checkIPInRanges(clientIP string, ipRanges interface{}) bool {
	rangeList, ok := ipRanges.([]interface{})
	if !ok {
		return false
	}

	// Parse client IP
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false
	}

	// Check each IP range
	for _, ipRange := range rangeList {
		rangeStr, ok := ipRange.(string)
		if !ok {
			continue
		}

		// Parse CIDR notation (e.g., "192.168.1.0/24")
		_, network, err := net.ParseCIDR(rangeStr)
		if err != nil {
			s.logger.Warn("Invalid IP range in MFA policy", zap.String("range", rangeStr))
			continue
		}

		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// checkTimeWindow checks if current time falls within specified windows
func (s *Service) checkTimeWindow(timeWindows interface{}) bool {
	windows, ok := timeWindows.([]interface{})
	if !ok {
		return false
	}

	now := time.Now()
	currentDay := now.Weekday()
	currentHour := now.Hour()

	for _, window := range windows {
		windowMap, ok := window.(map[string]interface{})
		if !ok {
			continue
		}

		// Check day of week
		if days, exists := windowMap["days"]; exists {
			dayList, ok := days.([]interface{})
			if ok {
				dayMatches := false
				for _, day := range dayList {
					if dayStr, ok := day.(string); ok {
						if strings.EqualFold(dayStr, currentDay.String()) {
							dayMatches = true
							break
						}
					}
				}
				if !dayMatches {
					continue
				}
			}
		}

		// Check time range
		if startHour, exists := windowMap["start_hour"]; exists {
			if endHour, exists := windowMap["end_hour"]; exists {
				start, ok1 := startHour.(float64)
				end, ok2 := endHour.(float64)
				if ok1 && ok2 {
					if currentHour >= int(start) && currentHour <= int(end) {
						return true
					}
				}
			}
		}
	}

	return false
}

// checkUserAttributes checks if user has specified attributes
func (s *Service) checkUserAttributes(ctx context.Context, userID string, attributes interface{}) bool {
	attrMap, ok := attributes.(map[string]interface{})
	if !ok {
		return false
	}

	user, err := s.GetUser(ctx, userID)
	if err != nil {
		return false
	}

	// Check user attributes (this could be extended to check custom attributes)
	for key, expectedValue := range attrMap {
		switch key {
		case "email_verified":
			if expected, ok := expectedValue.(bool); ok {
				if user.EmailVerified != expected {
					return false
				}
			}
		case "enabled":
			if expected, ok := expectedValue.(bool); ok {
				if user.Enabled != expected {
					return false
				}
			}
			// Add more attribute checks as needed
		}
	}

	return true
}

// getUserGroups retrieves all groups a user belongs to
func (s *Service) getUserGroups(ctx context.Context, userID string) ([]Group, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	rows, err := s.db.Pool.Query(ctx, `
		SELECT g.id, g.name, g.description, g.parent_id, g.created_at, g.updated_at
		FROM groups g
		JOIN group_memberships gm ON g.id = gm.group_id
		WHERE gm.user_id = $1 AND gm.org_id = $2
	`, userID, org.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []Group
	for rows.Next() {
		var dbGroup GroupDB
		err := rows.Scan(&dbGroup.ID, &dbGroup.DisplayName, &dbGroup.Description, &dbGroup.ParentID, &dbGroup.CreatedAt, &dbGroup.UpdatedAt)
		if err != nil {
			return nil, err
		}
		groups = append(groups, dbGroup.ToGroup())
	}

	return groups, nil
}

// ListRoles retrieves all available roles
func (s *Service) ListRoles(ctx context.Context, offset, limit int) ([]Role, int, error) {
	s.logger.Debug("Listing roles", zap.Int("offset", offset), zap.Int("limit", limit))

	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, 0, err
	}

	var total int
	err = s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM roles WHERE org_id = $1", org.ID).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, name, description, is_composite, created_at
		FROM roles
		WHERE org_id = $1
		ORDER BY name
		OFFSET $2 LIMIT $3
	`, org.ID, offset, limit)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var roles []Role
	for rows.Next() {
		var r Role
		err := rows.Scan(&r.ID, &r.Name, &r.Description, &r.IsComposite, &r.CreatedAt)
		if err != nil {
			return nil, 0, err
		}
		roles = append(roles, r)
	}

	return roles, total, nil
}

// GetRole retrieves a role by ID
func (s *Service) GetRole(ctx context.Context, roleID string) (*Role, error) {
	s.logger.Debug("Getting role", zap.String("role_id", roleID))

	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	var role Role
	err = s.db.Pool.QueryRow(ctx, `
		SELECT id, name, description, is_composite, created_at
		FROM roles WHERE id = $1 AND org_id = $2
	`, roleID, org.ID).Scan(&role.ID, &role.Name, &role.Description, &role.IsComposite, &role.CreatedAt)
	if err != nil {
		return nil, err
	}

	return &role, nil
}

// CreateRole creates a new role
func (s *Service) CreateRole(ctx context.Context, role *Role) error {
	s.logger.Info("Creating role", zap.String("name", role.Name))

	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	if role.ID == "" {
		role.ID = uuid.New().String()
	}

	now := time.Now()
	role.CreatedAt = now

	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO roles (id, name, description, is_composite, created_at, updated_at, org_id)
		VALUES ($1, $2, $3, $4, $5, $5, $6)
	`, role.ID, role.Name, role.Description, role.IsComposite, now, org.ID)

	if err == nil {
		actorID := actorIDFromContext(ctx)
		s.logAuditEvent(ctx, "identity", "role_management", "role.created", "success",
			actorID, role.ID, "role", map[string]interface{}{
				"role_name": role.Name,
			})
	}

	return err
}

// UpdateRole updates an existing role
func (s *Service) UpdateRole(ctx context.Context, role *Role) error {
	s.logger.Info("Updating role", zap.String("role_id", role.ID))

	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	result, err := s.db.Pool.Exec(ctx, `
		UPDATE roles
		SET name = $2, description = $3, is_composite = $4, updated_at = $5
		WHERE id = $1 AND org_id = $6
	`, role.ID, role.Name, role.Description, role.IsComposite, time.Now(), org.ID)

	if err != nil {
		return err
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("role not found")
	}

	actorID := actorIDFromContext(ctx)
	s.logAuditEvent(ctx, "identity", "role_management", "role.updated", "success",
		actorID, role.ID, "role", map[string]interface{}{
			"role_name": role.Name,
		})

	return nil
}

// DeleteRole deletes a role
func (s *Service) DeleteRole(ctx context.Context, roleID string) error {
	s.logger.Info("Deleting role", zap.String("role_id", roleID))

	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	// First remove all user-role assignments
	_, err = s.db.Pool.Exec(ctx, "DELETE FROM user_roles WHERE role_id = $1 AND org_id = $2", roleID, org.ID)
	if err != nil {
		return fmt.Errorf("failed to remove role assignments: %w", err)
	}

	// Remove composite role relationships
	_, err = s.db.Pool.Exec(ctx, "DELETE FROM composite_roles WHERE (parent_role_id = $1 OR child_role_id = $1) AND org_id = $2", roleID, org.ID)
	if err != nil {
		return fmt.Errorf("failed to remove composite role relationships: %w", err)
	}

	// Delete the role
	result, err := s.db.Pool.Exec(ctx, "DELETE FROM roles WHERE id = $1 AND org_id = $2", roleID, org.ID)
	if err != nil {
		return err
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("role not found")
	}

	return nil
}

// GetUserRoles retrieves roles assigned to a user
func (s *Service) GetUserRoles(ctx context.Context, userID string) ([]Role, error) {
	s.logger.Debug("Getting user roles", zap.String("user_id", userID))

	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	rows, err := s.db.Pool.Query(ctx, `
		SELECT r.id, r.name, r.description, r.is_composite, r.created_at
		FROM roles r
		JOIN user_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = $1
		AND ur.org_id = $2
		AND (ur.expires_at IS NULL OR ur.expires_at > NOW())
		ORDER BY r.name
	`, userID, org.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roles []Role
	for rows.Next() {
		var r Role
		err := rows.Scan(&r.ID, &r.Name, &r.Description, &r.IsComposite, &r.CreatedAt)
		if err != nil {
			return nil, err
		}
		roles = append(roles, r)
	}

	return roles, nil
}

// GetUserRoleAssignments returns detailed role assignments for a user including expiry info
func (s *Service) GetUserRoleAssignments(ctx context.Context, userID string) ([]UserRoleAssignment, error) {
	s.logger.Debug("Getting user role assignments", zap.String("user_id", userID))

	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	rows, err := s.db.Pool.Query(ctx, `
		SELECT r.id, r.name, r.description, r.is_composite, r.created_at,
		       COALESCE(ur.assigned_by::text, ''), ur.assigned_at, ur.expires_at
		FROM roles r
		JOIN user_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = $1
		AND ur.org_id = $2
		AND (ur.expires_at IS NULL OR ur.expires_at > NOW())
		ORDER BY r.name
	`, userID, org.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var assignments []UserRoleAssignment
	for rows.Next() {
		var a UserRoleAssignment
		err := rows.Scan(
			&a.Role.ID, &a.Role.Name, &a.Role.Description, &a.Role.IsComposite, &a.Role.CreatedAt,
			&a.AssignedBy, &a.AssignedAt, &a.ExpiresAt,
		)
		if err != nil {
			return nil, err
		}
		assignments = append(assignments, a)
	}

	return assignments, nil
}

// PolicyViolation represents a governance policy violation
type PolicyViolation struct {
	PolicyName string `json:"policy_name"`
	PolicyType string `json:"policy_type"`
	Reason     string `json:"reason"`
	Effect     string `json:"effect"`
}

// PolicyViolationError wraps policy violations as an error
type PolicyViolationError struct {
	Violations []PolicyViolation
}

func (e *PolicyViolationError) Error() string {
	if len(e.Violations) == 0 {
		return "policy violation"
	}
	return fmt.Sprintf("policy violation: %s - %s", e.Violations[0].PolicyName, e.Violations[0].Reason)
}

// policyEvaluationDenied builds a fail-closed denial used when CheckPolicies
// cannot evaluate the governance policies (e.g. a DB error). A preventive
// control that cannot run must deny rather than silently allow.
func policyEvaluationDenied(reason string) *PolicyViolationError {
	return &PolicyViolationError{Violations: []PolicyViolation{{
		PolicyName: "governance",
		PolicyType: "evaluation_error",
		Reason:     reason,
		Effect:     "deny",
	}}}
}

// CheckPolicies evaluates all enabled governance policies against the given operation context.
// Returns a PolicyViolationError if any policy denies the action, nil otherwise.
func (s *Service) CheckPolicies(ctx context.Context, userID string, action string, targetRoleIDs []string, clientIP string) error {
	s.logger.Debug("Checking governance policies",
		zap.String("user_id", userID),
		zap.String("action", action),
		zap.Int("target_roles", len(targetRoleIDs)))

	org, err := orgctx.From(ctx)
	if err != nil {
		// Fail closed: without org context we cannot scope (or even run) this
		// preventive control, and the callers only block on a
		// *PolicyViolationError — any other error is ignored and the operation
		// proceeds. Returning a denial is the only value that actually blocks,
		// consistent with the DB-error and roles-lookup paths below. The org
		// guard runs before any DB access, so a nil pool never panics here.
		s.logger.Error("No organization context for governance policy check; failing closed", zap.Error(err))
		return policyEvaluationDenied("unable to evaluate governance policies: no organization context")
	}

	// Query all enabled policies (for this org) with their rules.
	//
	// The policy_rules table stores rule_type + two JSONB columns (conditions,
	// actions), NOT columns named condition/effect/priority. The governance
	// service is the writer: it persists rule.Condition into `conditions`, and
	// {effect, priority} into `actions` (falling back to rule_type for the
	// effect). Selecting the non-existent pr.condition/pr.effect/pr.priority
	// made this query error on every call, and the error path below fails open
	// — so separation-of-duty was never actually enforced. Read the real
	// columns and reshape them into the {condition, effect, priority} the
	// evaluators below expect, mirroring governance.loadPolicyRules.
	rows, err := s.db.Pool.Query(ctx, `
		SELECT p.id, p.name, p.type, p.priority,
		       COALESCE(json_agg(json_build_object(
		           'id', pr.id,
		           'condition', pr.conditions,
		           'effect', COALESCE(NULLIF(pr.actions->>'effect', ''), pr.rule_type),
		           'priority', COALESCE((pr.actions->>'priority')::int, 0)
		       )) FILTER (WHERE pr.id IS NOT NULL), '[]'::json) as rules
		FROM policies p
		LEFT JOIN policy_rules pr ON pr.policy_id = p.id AND pr.org_id = p.org_id
		WHERE p.enabled = true AND p.org_id = $1
		GROUP BY p.id, p.name, p.type, p.priority
		ORDER BY p.priority DESC
	`, org.ID)
	if err != nil {
		// Fail closed: a preventive control that cannot read its policies must not
		// wave the operation through. Blocking a role change on a transient DB
		// error is safer than silently permitting a separation-of-duty violation.
		s.logger.Error("Failed to query governance policies; failing closed", zap.Error(err))
		return policyEvaluationDenied("unable to evaluate governance policies")
	}
	defer rows.Close()

	// Get user's current roles for SoD checks
	var currentRoles []Role
	if action == "assign_role" || action == "update_roles" {
		currentRoles, err = s.GetUserRoles(ctx, userID)
		if err != nil {
			// Fail closed for the same reason: without the user's current roles we
			// cannot tell whether the target roles create a conflict.
			s.logger.Error("Failed to get user roles for policy check; failing closed", zap.Error(err))
			return policyEvaluationDenied("unable to evaluate separation-of-duty policies")
		}
	}

	// Get role names for the target role IDs
	targetRoleNames := make(map[string]string) // id -> name
	if len(targetRoleIDs) > 0 {
		roleRows, err := s.db.Pool.Query(ctx, `
			SELECT id, name FROM roles WHERE id = ANY($1) AND org_id = $2
		`, targetRoleIDs, org.ID)
		if err == nil {
			defer roleRows.Close()
			for roleRows.Next() {
				var id, name string
				if roleRows.Scan(&id, &name) == nil {
					targetRoleNames[id] = name
				}
			}
		}
	}

	var violations []PolicyViolation

	for rows.Next() {
		var policyID, policyName, policyType string
		var priority int
		var rulesJSON []byte

		if err := rows.Scan(&policyID, &policyName, &policyType, &priority, &rulesJSON); err != nil {
			s.logger.Error("Failed to scan policy", zap.Error(err))
			continue
		}

		var rules []struct {
			ID        string                 `json:"id"`
			Condition map[string]interface{} `json:"condition"`
			Effect    string                 `json:"effect"`
			Priority  int                    `json:"priority"`
		}
		if err := json.Unmarshal(rulesJSON, &rules); err != nil {
			s.logger.Error("Failed to parse policy rules", zap.Error(err), zap.String("policy_id", policyID))
			continue
		}

		switch policyType {
		case "separation_of_duty":
			if action != "assign_role" && action != "update_roles" {
				continue
			}
			// Build set of all role names (current + target)
			allRoleNames := make(map[string]bool)
			for _, r := range currentRoles {
				allRoleNames[strings.ToLower(r.Name)] = true
			}
			for _, name := range targetRoleNames {
				allRoleNames[strings.ToLower(name)] = true
			}

			for _, rule := range rules {
				effect := rule.Effect
				if effect == "" {
					effect = "deny"
				}
				// Check conflicting_roles from rule condition
				conflicting, ok := rule.Condition["conflicting_roles"]
				if !ok {
					continue
				}
				conflictList, ok := conflicting.([]interface{})
				if !ok || len(conflictList) < 2 {
					continue
				}
				// Check if all conflicting roles are present
				allPresent := true
				var conflictNames []string
				for _, cr := range conflictList {
					roleName, ok := cr.(string)
					if !ok {
						allPresent = false
						break
					}
					conflictNames = append(conflictNames, roleName)
					if !allRoleNames[strings.ToLower(roleName)] {
						allPresent = false
						break
					}
				}
				if allPresent {
					violations = append(violations, PolicyViolation{
						PolicyName: policyName,
						PolicyType: policyType,
						Reason:     fmt.Sprintf("Separation of duty conflict: roles %s cannot be assigned together", strings.Join(conflictNames, ", ")),
						Effect:     effect,
					})
				}
			}

		case "timebound":
			now := time.Now()
			for _, rule := range rules {
				effect := rule.Effect
				if effect == "" {
					effect = "deny"
				}
				// Check business hours from condition or use defaults
				startHour := 9
				endHour := 18
				if sh, ok := rule.Condition["start_hour"].(float64); ok {
					startHour = int(sh)
				}
				if eh, ok := rule.Condition["end_hour"].(float64); ok {
					endHour = int(eh)
				}
				// Check allowed days (default: Mon-Fri)
				weekday := now.Weekday()
				hour := now.Hour()
				isWeekend := weekday == time.Saturday || weekday == time.Sunday
				outsideHours := hour < startHour || hour >= endHour

				if isWeekend || outsideHours {
					violations = append(violations, PolicyViolation{
						PolicyName: policyName,
						PolicyType: policyType,
						Reason:     fmt.Sprintf("Operation not allowed outside business hours (%d:00-%d:00, Mon-Fri)", startHour, endHour),
						Effect:     effect,
					})
				}
			}

		case "location":
			if clientIP == "" {
				continue
			}
			for _, rule := range rules {
				effect := rule.Effect
				if effect == "" {
					effect = "deny"
				}
				// Get allowed prefixes from condition or use defaults
				allowedPrefixes := []string{"10.", "192.168.", "172.16.", "127.0.0.1"}
				if prefixes, ok := rule.Condition["allowed_prefixes"].([]interface{}); ok {
					allowedPrefixes = nil
					for _, p := range prefixes {
						if ps, ok := p.(string); ok {
							allowedPrefixes = append(allowedPrefixes, ps)
						}
					}
				}
				allowed := false
				for _, prefix := range allowedPrefixes {
					if strings.HasPrefix(clientIP, prefix) {
						allowed = true
						break
					}
				}
				if !allowed {
					violations = append(violations, PolicyViolation{
						PolicyName: policyName,
						PolicyType: policyType,
						Reason:     fmt.Sprintf("Operation not allowed from IP address %s", clientIP),
						Effect:     effect,
					})
				}
			}

		case "risk_based":
			// Risk-based policies evaluate contextual risk factors
			for _, rule := range rules {
				effect := rule.Effect
				if effect == "" {
					effect = "deny"
				}
				threshold := 50
				if t, ok := rule.Condition["risk_threshold"].(float64); ok {
					threshold = int(t)
				}
				// Calculate risk score based on available context
				riskScore := 0
				// External IP adds risk
				if clientIP != "" && !strings.HasPrefix(clientIP, "10.") && !strings.HasPrefix(clientIP, "192.168.") && !strings.HasPrefix(clientIP, "127.") {
					riskScore += 30
				}
				// Multiple role changes add risk
				if len(targetRoleIDs) > 3 {
					riskScore += 20
				}
				if riskScore >= threshold {
					violations = append(violations, PolicyViolation{
						PolicyName: policyName,
						PolicyType: policyType,
						Reason:     fmt.Sprintf("Risk score %d exceeds threshold %d", riskScore, threshold),
						Effect:     effect,
					})
				}
			}
		}
	}

	// Filter for deny violations (require_approval could be handled differently later)
	var denyViolations []PolicyViolation
	for _, v := range violations {
		if v.Effect == "deny" {
			denyViolations = append(denyViolations, v)
		}
	}

	if len(denyViolations) > 0 {
		return &PolicyViolationError{Violations: denyViolations}
	}

	return nil
}

// AssignUserRole assigns a role to a user with an optional expiration time
func (s *Service) AssignUserRole(ctx context.Context, userID, roleID string, assignedBy string, expiresAt *time.Time) error {
	s.logger.Info("Assigning role to user",
		zap.String("user_id", userID), zap.String("role_id", roleID), zap.String("assigned_by", assignedBy))

	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	// Check if role assignment already exists (only non-expired)
	var exists bool
	err = s.db.Pool.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM user_roles WHERE user_id = $1 AND role_id = $2 AND org_id = $3 AND (expires_at IS NULL OR expires_at > NOW()))
	`, userID, roleID, org.ID).Scan(&exists)
	if err != nil {
		return err
	}

	if exists {
		return fmt.Errorf("user already has this role")
	}

	// Insert role assignment
	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO user_roles (user_id, role_id, assigned_by, assigned_at, expires_at, org_id)
		VALUES ($1, $2, $3, NOW(), $4, $5)
	`, userID, roleID, assignedBy, expiresAt, org.ID)

	return err
}

// RemoveUserRole removes a role from a user
func (s *Service) RemoveUserRole(ctx context.Context, userID, roleID string) error {
	s.logger.Info("Removing role from user", zap.String("user_id", userID), zap.String("role_id", roleID))

	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	result, err := s.db.Pool.Exec(ctx, `
		DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2 AND org_id = $3
	`, userID, roleID, org.ID)

	if err != nil {
		return err
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("user does not have this role")
	}

	return nil
}

// UpdateUserRoles replaces all roles for a user
func (s *Service) UpdateUserRoles(ctx context.Context, userID string, roleIDs []string, assignedBy string) error {
	s.logger.Info("Updating user roles", zap.String("user_id", userID), zap.Int("role_count", len(roleIDs)))

	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	// Start transaction
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Remove all existing roles
	_, err = tx.Exec(ctx, "DELETE FROM user_roles WHERE user_id = $1 AND org_id = $2", userID, org.ID)
	if err != nil {
		return err
	}

	// Insert new roles
	for _, roleID := range roleIDs {
		_, err = tx.Exec(ctx, `
			INSERT INTO user_roles (user_id, role_id, assigned_at, org_id)
			VALUES ($1, $2, NOW(), $3)
		`, userID, roleID, org.ID)
		if err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

// RegisterRoutes registers identity service routes
func RegisterRoutes(router *gin.Engine, svc *Service) {
	// Public routes (no auth required)
	public := router.Group("/api/v1/identity")
	{
		public.POST("/users/forgot-password", svc.handleForgotPassword)
		public.POST("/users/reset-password", svc.handleResetPassword)
		public.POST("/verify-email", svc.handleVerifyEmail)
		public.POST("/invitations/:token/accept", svc.handleAcceptInvitation)
		public.GET("/providers", svc.handleListIdentityProviders)
		public.GET("/branding", svc.handleGetLoginBranding)
		public.POST("/federation/discover", svc.handleFederationDiscover)
	}

	identity := router.Group("/api/v1/identity")
	identity.Use(svc.openIDXAuthMiddleware())
	identity.Use(middleware.PermissionResolver(svc.db.Pool, svc.redis.Client))
	// Authorization: self-service paths are open to any authenticated user;
	// all other (administrative) identity routes require an admin role. Without
	// this, the user/role/group management API — including POST /users/:id/roles
	// — was reachable by any authenticated user (privilege escalation).
	identity.Use(svc.requireAdminUnlessSelfService())
	{
		// User Self-Service endpoints (require authentication)
		identity.GET("/users/me", svc.handleGetCurrentUser)
		identity.PUT("/users/me", svc.handleUpdateCurrentUser)
		identity.GET("/users/me/password-info", svc.handleGetPasswordInfo)
		identity.POST("/users/me/change-password", svc.handleChangePassword)
		identity.POST("/users/me/mfa/setup", svc.handleSetupUserMFA)
		identity.POST("/users/me/mfa/enable", svc.handleEnableUserMFA)
		identity.POST("/users/me/mfa/disable", svc.handleDisableUserMFA)
		identity.GET("/users/me/mfa/status", svc.handleGetMyMFAStatus)
		identity.GET("/users/me/sessions", svc.handleGetMySessions)

		// Personal Access Tokens (User self-service)
		identity.GET("/users/me/tokens", svc.handleListUserPATs)
		identity.POST("/users/me/tokens", svc.handleCreateUserPAT)
		identity.DELETE("/users/me/tokens/:id", svc.handleRevokeUserPAT)

		// Consent management (User self-service)
		identity.GET("/users/me/consents", svc.handleListUserConsents)
		identity.DELETE("/users/me/consents/:client_id", svc.handleRevokeUserConsent)

		// Privacy / GDPR self-service (Phase 17B)
		identity.GET("/users/me/privacy/consents", svc.handleGetMyPrivacyConsents)
		identity.POST("/users/me/privacy/consents", svc.handleGrantPrivacyConsent)
		identity.DELETE("/users/me/privacy/consents/:consentType", svc.handleRevokePrivacyConsent)
		identity.POST("/users/me/privacy/dsar", svc.handleSubmitDSAR)
		identity.GET("/users/me/privacy/dsars", svc.handleGetMyDSARs)

		// Identity links self-service (Phase 17C)
		identity.GET("/users/me/identity-links", svc.handleGetMyIdentityLinks)
		identity.DELETE("/users/me/identity-links/:linkId", svc.handleUnlinkMyIdentity)

		// User management
		identity.GET("/users", svc.handleListUsers)
		identity.POST("/users", svc.handleCreateUser)
		identity.GET("/users/search", svc.handleSearchUsers) // Must be before :id route
		identity.GET("/users/export", svc.handleExportUsersCSV)
		identity.POST("/users/import", svc.handleImportUsersCSV)
		identity.GET("/users/:id", svc.handleGetUser)
		identity.PUT("/users/:id", svc.handleUpdateUser)
		identity.DELETE("/users/:id", svc.handleDeleteUser)
		identity.POST("/users/:id/reset-password", svc.handleAdminResetPassword)
		identity.POST("/users/:id/set-password", svc.handleAdminSetPassword)

		// Identity Providers (for SSO) — GET /providers is public (login page needs it)
		identity.POST("/providers", svc.handleCreateIdentityProvider)
		identity.GET("/providers/:id", svc.handleGetIdentityProvider)
		identity.PUT("/providers/:id", svc.handleUpdateIdentityProvider)
		identity.DELETE("/providers/:id", svc.handleDeleteIdentityProvider)

		// Session management
		identity.GET("/users/:id/sessions", svc.handleGetUserSessions)
		identity.DELETE("/sessions/:id", svc.handleTerminateSession)

		// Role management (CRUD)
		identity.GET("/roles", svc.handleListRoles)
		identity.POST("/roles", svc.handleCreateRole)
		identity.GET("/roles/:id", svc.handleGetRole)
		identity.PUT("/roles/:id", svc.handleUpdateRole)
		identity.DELETE("/roles/:id", svc.handleDeleteRole)

		// Permissions
		identity.GET("/permissions", svc.handleListPermissions)
		identity.GET("/roles/:id/permissions", svc.handleGetRolePermissions)
		identity.PUT("/roles/:id/permissions", svc.handleSetRolePermissions)

		// User-Role assignments
		identity.GET("/users/:id/roles", svc.handleGetUserRoles)
		identity.POST("/users/:id/roles", svc.handleAssignUserRole)
		identity.DELETE("/users/:id/roles/:roleId", svc.handleRemoveUserRole)
		identity.PUT("/users/:id/roles", svc.handleUpdateUserRoles)
		identity.GET("/users/:id/role-assignments", svc.handleGetUserRoleAssignments)

		// Group management
		identity.GET("/groups", svc.handleListGroups)
		identity.POST("/groups", svc.handleCreateGroup)
		identity.GET("/groups/:id", svc.handleGetGroup)
		identity.PUT("/groups/:id", svc.handleUpdateGroup)
		identity.DELETE("/groups/:id", svc.handleDeleteGroup)
		identity.GET("/groups/:id/members", svc.handleGetGroupMembers)
		identity.POST("/groups/:id/members", svc.handleAddGroupMember)
		identity.DELETE("/groups/:id/members/:userId", svc.handleRemoveGroupMember)
		identity.GET("/groups/:id/subgroups", svc.handleGetSubgroups)

		// MFA management
		identity.POST("/mfa/totp/setup", svc.handleSetupTOTP)
		identity.POST("/mfa/totp/enroll", svc.handleEnrollTOTP)
		identity.POST("/mfa/totp/verify", svc.handleVerifyTOTP)
		identity.GET("/mfa/totp/status", svc.handleGetTOTPStatus)
		identity.DELETE("/mfa/totp", svc.handleDisableTOTP)
		identity.POST("/mfa/backup/generate", svc.handleGenerateBackupCodes)
		identity.POST("/mfa/backup/verify", svc.handleVerifyBackupCode)
		identity.GET("/mfa/backup/count", svc.handleGetBackupCodeCount)

		// WebAuthn (Passwordless) MFA
		identity.POST("/mfa/webauthn/register/begin", svc.handleBeginWebAuthnRegistration)
		identity.POST("/mfa/webauthn/register/finish", svc.handleFinishWebAuthnRegistration)
		identity.POST("/mfa/webauthn/authenticate/begin", svc.handleBeginWebAuthnAuthentication)
		identity.POST("/mfa/webauthn/authenticate/finish", svc.handleFinishWebAuthnAuthentication)
		identity.GET("/mfa/webauthn/credentials", svc.handleGetWebAuthnCredentials)
		identity.DELETE("/mfa/webauthn/credentials/:credential_id", svc.handleDeleteWebAuthnCredential)

		// Push MFA
		identity.POST("/mfa/push/register", svc.handleRegisterPushDevice)
		// Alias: the admin console posts enrollments to /mfa/push/devices (REST-style,
		// matching the GET/DELETE on the same collection). Same handler + payload as
		// /mfa/push/register, so both work and the console's "Enroll Device" stops 404ing.
		identity.POST("/mfa/push/devices", svc.handleRegisterPushDevice)
		identity.GET("/mfa/push/devices", svc.handleGetPushDevices)
		identity.DELETE("/mfa/push/devices/:device_id", svc.handleDeletePushDevice)
		identity.POST("/mfa/push/challenge", svc.handleCreatePushChallenge)
		identity.POST("/mfa/push/verify", svc.handleVerifyPushChallenge)
		identity.GET("/mfa/push/challenge/:challenge_id", svc.handleGetPushChallenge)

		// SMS OTP MFA
		identity.POST("/mfa/sms/enroll", svc.handleEnrollSMS)
		identity.POST("/mfa/sms/verify", svc.handleVerifySMSEnrollment)
		identity.GET("/mfa/sms/status", svc.handleGetSMSStatus)
		identity.DELETE("/mfa/sms", svc.handleDeleteSMS)
		identity.POST("/mfa/sms/challenge", svc.handleCreateSMSChallenge)

		// Email OTP MFA
		identity.POST("/mfa/email/enroll", svc.handleEnrollEmailOTP)
		identity.GET("/mfa/email/status", svc.handleGetEmailOTPStatus)
		identity.DELETE("/mfa/email", svc.handleDeleteEmailOTP)
		identity.POST("/mfa/email/challenge", svc.handleCreateEmailOTPChallenge)

		// Common OTP verification (works for both SMS and Email)
		identity.POST("/mfa/otp/verify", svc.handleVerifyOTP)

		// Get all enrolled MFA methods for current user
		identity.GET("/mfa/methods", svc.handleGetMFAMethods)

		// Trusted browsers (remember this device)
		identity.POST("/trusted-browsers", svc.handleTrustBrowser)
		identity.GET("/trusted-browsers", svc.handleGetTrustedBrowsers)
		identity.DELETE("/trusted-browsers/:browser_id", svc.handleRevokeTrustedBrowser)
		identity.DELETE("/trusted-browsers", svc.handleRevokeAllTrustedBrowsers)
		identity.GET("/trusted-browsers/check", svc.handleCheckTrustedBrowser)

		// Risk assessment
		identity.GET("/risk-assessment", svc.handleGetRiskAssessment)

		// Email verification
		identity.POST("/resend-verification", svc.handleResendVerification)

		// Invitations
		identity.GET("/invitations", svc.handleListInvitations)
		identity.POST("/invitations", svc.handleCreateInvitation)
		identity.DELETE("/invitations/:id", svc.handleDeleteInvitation)

		// User lifecycle
		identity.POST("/users/:id/offboard", svc.handleOffboardUser)

		// ========================================
		// Advanced MFA Features
		// ========================================

		// Hardware Tokens (Admin)
		identity.GET("/hardware-tokens", svc.handleListHardwareTokens)
		identity.POST("/hardware-tokens", svc.handleCreateHardwareToken)
		identity.GET("/hardware-tokens/:token_id", svc.handleGetHardwareToken)
		identity.POST("/hardware-tokens/:token_id/assign", svc.handleAssignHardwareToken)
		identity.POST("/hardware-tokens/:token_id/unassign", svc.handleUnassignHardwareToken)
		identity.POST("/hardware-tokens/:token_id/revoke", svc.handleRevokeHardwareToken)
		identity.POST("/hardware-tokens/:token_id/report-lost", svc.handleReportTokenLost)
		identity.GET("/hardware-tokens/:token_id/events", svc.handleGetTokenEvents)

		// Hardware Token (User)
		identity.GET("/mfa/hardware-token", svc.handleGetUserHardwareToken)
		identity.POST("/mfa/hardware-token/verify", svc.handleVerifyHardwareToken)

		// Phone Call MFA
		identity.POST("/mfa/phone/enroll", svc.handleEnrollPhoneCall)
		identity.POST("/mfa/phone/verify", svc.handleVerifyPhoneCallEnrollment)
		identity.GET("/mfa/phone/status", svc.handleGetPhoneCallStatus)
		identity.DELETE("/mfa/phone", svc.handleDeletePhoneCall)
		identity.POST("/mfa/phone/callback", svc.handleRequestCallback)

		// Device Trust Approval (Admin)
		identity.GET("/device-trust-requests", svc.handleListDeviceTrustRequests)
		identity.POST("/device-trust-requests/:request_id/approve", svc.handleApproveDeviceTrust)
		identity.POST("/device-trust-requests/:request_id/reject", svc.handleRejectDeviceTrust)
		identity.POST("/device-trust-requests/bulk-approve", svc.handleBulkApproveDeviceTrust)
		identity.POST("/device-trust-requests/bulk-reject", svc.handleBulkRejectDeviceTrust)
		identity.GET("/device-trust-requests/pending-count", svc.handleGetPendingTrustCount)
		identity.GET("/device-trust-settings", svc.handleGetDeviceTrustSettings)
		identity.PUT("/device-trust-settings", svc.handleUpdateDeviceTrustSettings)

		// MFA Bypass Codes (Admin)
		identity.POST("/mfa/bypass-codes", svc.handleGenerateBypassCode)
		identity.GET("/mfa/bypass-codes", svc.handleListBypassCodes)
		identity.DELETE("/mfa/bypass-codes/:code_id", svc.handleRevokeBypassCode)
		identity.DELETE("/users/:id/bypass-codes", svc.handleRevokeAllBypassCodes)
		identity.POST("/mfa/bypass-codes/verify", svc.handleVerifyBypassCode)
		identity.GET("/mfa/bypass-codes/audit", svc.handleGetBypassAuditLog)

		// Passwordless Authentication
		identity.POST("/passwordless/magic-link", svc.handleCreateMagicLink)
		identity.POST("/passwordless/magic-link/verify", svc.handleVerifyMagicLink)
		identity.POST("/passwordless/qr-login", svc.handleCreateQRLoginSession)
		identity.POST("/passwordless/qr-login/scan", svc.handleScanQRLogin)
		identity.POST("/passwordless/qr-login/approve", svc.handleApproveQRLogin)
		identity.POST("/passwordless/qr-login/reject", svc.handleRejectQRLogin)
		identity.GET("/passwordless/qr-login/poll", svc.handlePollQRLoginSession)
		identity.GET("/passwordless/preferences", svc.handleGetPasswordlessPreferences)
		identity.PUT("/passwordless/preferences", svc.handleUpdatePasswordlessPreferences)

		// Passwordless Settings (Admin)
		identity.GET("/passwordless/settings", svc.handleGetPasswordlessSettings)
		identity.PUT("/passwordless/settings", svc.handleUpdatePasswordlessSettings)
		identity.PATCH("/passwordless/settings", svc.handlePatchPasswordlessSettings)
		identity.GET("/passwordless/stats", svc.handleGetPasswordlessStats)
		identity.POST("/passwordless/magic-link/test", svc.handleTestMagicLink)

		// Biometric Authentication
		identity.GET("/biometric/preferences", svc.handleGetBiometricPreferences)
		identity.PUT("/biometric/preferences", svc.handleUpdateBiometricPreferences)
		identity.POST("/biometric/enable-only", svc.handleEnableBiometricOnly)
		identity.POST("/biometric/disable-only", svc.handleDisableBiometricOnly)
		identity.GET("/biometric/authenticators", svc.handleGetPlatformAuthenticators)

		// Biometric Policies (Admin)
		identity.GET("/biometric/policies", svc.handleListBiometricPolicies)
		identity.POST("/biometric/policies", svc.handleCreateBiometricPolicy)
		identity.PUT("/biometric/policies/:policy_id", svc.handleUpdateBiometricPolicy)
		identity.DELETE("/biometric/policies/:policy_id", svc.handleDeleteBiometricPolicy)

		// Risk Policies (Admin)
		identity.GET("/risk/policies", svc.handleListRiskPolicies)
		identity.POST("/risk/policies", svc.handleCreateRiskPolicy)
		identity.GET("/risk/policies/:id", svc.handleGetRiskPolicy)
		identity.PUT("/risk/policies/:id", svc.handleUpdateRiskPolicy)
		identity.DELETE("/risk/policies/:id", svc.handleDeleteRiskPolicy)
		identity.PATCH("/risk/policies/:id/toggle", svc.handleToggleRiskPolicy)
		identity.POST("/risk/evaluate", svc.handleEvaluateRisk)
		identity.GET("/risk/stats", svc.handleGetRiskStats)
		identity.GET("/risk/login-history", svc.handleGetLoginHistory)

		// Login Analytics (Admin)
		identity.GET("/analytics/logins", svc.handleGetLoginAnalytics)

		// Lifecycle workflows
		identity.GET("/lifecycle/workflows", svc.handleListLifecycleWorkflows)
		identity.POST("/lifecycle/workflows", svc.handleCreateLifecycleWorkflow)
		identity.GET("/lifecycle/workflows/:id", svc.handleGetLifecycleWorkflow)
		identity.PUT("/lifecycle/workflows/:id", svc.handleUpdateLifecycleWorkflow)
		identity.DELETE("/lifecycle/workflows/:id", svc.handleDeleteLifecycleWorkflow)
		identity.POST("/lifecycle/workflows/:id/execute", svc.handleExecuteLifecycleWorkflow)
		identity.GET("/lifecycle/executions", svc.handleListLifecycleExecutions)
		identity.GET("/lifecycle/executions/:id", svc.handleGetLifecycleExecution)
	}
}

// HTTP Handlers

func (s *Service) handleListUsers(c *gin.Context) {
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
	search := c.Query("search")

	users, total, err := s.ListUsers(c.Request.Context(), offset, limit, search)
	if err != nil {
		s.logger.Error("failed to list users", zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.Header("X-Total-Count", strconv.Itoa(total))
	c.JSON(200, users)
}

func (s *Service) handleGetUser(c *gin.Context) {
	userID := c.Param("id")

	user, err := s.GetUser(c.Request.Context(), userID)
	if err != nil {
		c.JSON(404, gin.H{"error": "user not found"})
		return
	}

	c.JSON(200, user)
}

func (s *Service) handleCreateUser(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	ctx := ContextWithActorID(c.Request.Context(), c.GetString("user_id"))
	if err := s.CreateUser(ctx, &user); err != nil {
		s.logger.Error("failed to create user", zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	// Send verification email (best-effort)
	if s.emailService != nil {
		token := uuid.New().String()
		org, oerr := orgctx.From(ctx)
		var err error
		if oerr != nil {
			err = oerr
		} else {
			_, err = s.db.Pool.Exec(ctx,
				"INSERT INTO email_verification_tokens (user_id, token, expires_at, org_id) VALUES ($1, $2, NOW() + INTERVAL '24 hours', $3)",
				user.ID, token, org.ID)
		}
		if err == nil {
			baseURL := fmt.Sprintf("http://localhost:%d", s.cfg.Port)
			s.emailService.SendVerificationEmail(c.Request.Context(), user.GetEmail(), user.GetFirstName(), token, baseURL)
		}
	}

	// Publish webhook event (best-effort)
	if s.webhookService != nil {
		s.webhookService.Publish(c.Request.Context(), "user.created", map[string]interface{}{
			"user_id": user.ID, "username": user.GetUsername(), "email": user.GetEmail(),
		})
	}

	c.JSON(201, user)
}

func (s *Service) handleUpdateUser(c *gin.Context) {
	userID := c.Param("id")

	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	user.ID = userID
	if err := s.UpdateUser(c.Request.Context(), &user); err != nil {
		s.logger.Error("failed to update user", zap.String("user_id", userID), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(200, user)
}

func (s *Service) handleDeleteUser(c *gin.Context) {
	userID := c.Param("id")

	ctx := ContextWithActorID(c.Request.Context(), c.GetString("user_id"))
	if err := s.DeleteUser(ctx, userID); err != nil {
		s.logger.Error("failed to delete user", zap.String("user_id", userID), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(204, nil)
}

func (s *Service) handleListIdentityProviders(c *gin.Context) {
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

	idps, total, err := s.ListIdentityProviders(c.Request.Context(), offset, limit)
	if err != nil {
		s.logger.Error("failed to list identity providers", zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.Header("X-Total-Count", strconv.Itoa(total))
	c.JSON(200, idps)
}

func (s *Service) handleGetIdentityProvider(c *gin.Context) {
	idpID := c.Param("id")

	idp, err := s.GetIdentityProvider(c.Request.Context(), idpID)
	if err != nil {
		c.JSON(404, gin.H{"error": "identity provider not found"})
		return
	}

	c.JSON(200, idp)
}

func (s *Service) handleCreateIdentityProvider(c *gin.Context) {
	var idp IdentityProvider
	if err := c.ShouldBindJSON(&idp); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	if err := s.CreateIdentityProvider(c.Request.Context(), &idp); err != nil {
		s.logger.Error("failed to create identity provider", zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(201, idp)
}

func (s *Service) handleUpdateIdentityProvider(c *gin.Context) {
	idpID := c.Param("id")

	var idp IdentityProvider
	if err := c.ShouldBindJSON(&idp); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	parsedID, err := uuid.Parse(idpID)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid identity provider ID format"})
		return
	}
	idp.ID = parsedID
	if err := s.UpdateIdentityProvider(c.Request.Context(), &idp); err != nil {
		s.logger.Error("failed to update identity provider", zap.String("id", idpID), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(200, idp)
}

func (s *Service) handleDeleteIdentityProvider(c *gin.Context) {
	idpID := c.Param("id")

	if err := s.DeleteIdentityProvider(c.Request.Context(), idpID); err != nil {
		s.logger.Error("failed to delete identity provider", zap.String("id", idpID), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(204, nil)
}

func (s *Service) handleGetUserSessions(c *gin.Context) {
	userID := c.Param("id")

	sessions, err := s.GetUserSessions(c.Request.Context(), userID)
	if err != nil {
		s.logger.Error("failed to get user sessions", zap.String("user_id", userID), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(200, sessions)
}

func (s *Service) handleTerminateSession(c *gin.Context) {
	sessionID := c.Param("id")

	if err := s.TerminateSession(c.Request.Context(), sessionID); err != nil {
		s.logger.Error("failed to terminate session", zap.String("session_id", sessionID), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(204, nil)
}

func (s *Service) handleListRoles(c *gin.Context) {
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

	roles, total, err := s.ListRoles(c.Request.Context(), offset, limit)
	if err != nil {
		s.logger.Error("failed to list roles", zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.Header("X-Total-Count", strconv.Itoa(total))
	c.JSON(200, roles)
}

func (s *Service) handleGetRole(c *gin.Context) {
	roleID := c.Param("id")

	role, err := s.GetRole(c.Request.Context(), roleID)
	if err != nil {
		c.JSON(404, gin.H{"error": "role not found"})
		return
	}

	c.JSON(200, role)
}

func (s *Service) handleCreateRole(c *gin.Context) {
	var role Role
	if err := c.ShouldBindJSON(&role); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	ctx := ContextWithActorID(c.Request.Context(), c.GetString("user_id"))
	if err := s.CreateRole(ctx, &role); err != nil {
		s.logger.Error("failed to create role", zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(201, role)
}

func (s *Service) handleUpdateRole(c *gin.Context) {
	roleID := c.Param("id")

	var role Role
	if err := c.ShouldBindJSON(&role); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	role.ID = roleID
	ctx := ContextWithActorID(c.Request.Context(), c.GetString("user_id"))
	if err := s.UpdateRole(ctx, &role); err != nil {
		if err.Error() == "role not found" {
			c.JSON(404, gin.H{"error": "role not found"})
			return
		}
		s.logger.Error("failed to update role", zap.String("role_id", roleID), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(200, role)
}

func (s *Service) handleDeleteRole(c *gin.Context) {
	roleID := c.Param("id")

	if err := s.DeleteRole(c.Request.Context(), roleID); err != nil {
		if err.Error() == "role not found" {
			c.JSON(404, gin.H{"error": "role not found"})
			return
		}
		s.logger.Error("failed to delete role", zap.String("role_id", roleID), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(204, nil)
}

func (s *Service) handleGetUserRoles(c *gin.Context) {
	userID := c.Param("id")

	roles, err := s.GetUserRoles(c.Request.Context(), userID)
	if err != nil {
		s.logger.Error("failed to get user roles", zap.String("user_id", userID), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(200, roles)
}

func (s *Service) handleAssignUserRole(c *gin.Context) {
	userID := c.Param("id")

	var req struct {
		RoleID    string     `json:"role_id" binding:"required"`
		ExpiresAt *time.Time `json:"expires_at"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// Validate expires_at is in the future if provided
	if req.ExpiresAt != nil && req.ExpiresAt.Before(time.Now()) {
		c.JSON(400, gin.H{"error": "expires_at must be in the future"})
		return
	}

	// Get current user ID from context (admin performing the action)
	assignedBy := c.GetString("user_id")
	if assignedBy == "" {
		assignedBy = "" // Allow NULL for unauthenticated requests
	}

	err := s.AssignUserRole(c.Request.Context(), userID, req.RoleID, assignedBy, req.ExpiresAt)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"status": "assigned"})
}

func (s *Service) handleGetUserRoleAssignments(c *gin.Context) {
	userID := c.Param("id")

	assignments, err := s.GetUserRoleAssignments(c.Request.Context(), userID)
	if err != nil {
		s.logger.Error("failed to get user role assignments", zap.String("user_id", userID), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(200, assignments)
}

func (s *Service) handleRemoveUserRole(c *gin.Context) {
	userID := c.Param("id")
	roleID := c.Param("roleId")

	err := s.RemoveUserRole(c.Request.Context(), userID, roleID)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"status": "removed"})
}

func (s *Service) handleUpdateUserRoles(c *gin.Context) {
	userID := c.Param("id")

	var req struct {
		RoleIDs []string `json:"role_ids"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// Get current user ID from context (admin performing the action)
	assignedBy := c.GetString("user_id")
	if assignedBy == "" {
		assignedBy = "00000000-0000-0000-0000-000000000001" // Default admin user
	}

	// Check governance policies before updating roles
	if err := s.CheckPolicies(c.Request.Context(), userID, "update_roles", req.RoleIDs, c.ClientIP()); err != nil {
		if policyErr, ok := err.(*PolicyViolationError); ok {
			c.JSON(403, gin.H{
				"error":      "Policy violation",
				"violations": policyErr.Violations,
			})
			return
		}
	}

	err := s.UpdateUserRoles(c.Request.Context(), userID, req.RoleIDs, assignedBy)
	if err != nil {
		s.logger.Error("failed to update user roles", zap.String("user_id", userID), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(200, gin.H{"status": "updated"})
}

func (s *Service) handleListGroups(c *gin.Context) {
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
	search := c.Query("search")

	groups, total, err := s.ListGroups(c.Request.Context(), offset, limit, search)
	if err != nil {
		s.logger.Error("failed to list groups", zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.Header("X-Total-Count", strconv.Itoa(total))
	c.JSON(200, groups)
}

func (s *Service) handleGetGroup(c *gin.Context) {
	groupID := c.Param("id")

	group, err := s.GetGroup(c.Request.Context(), groupID)
	if err != nil {
		c.JSON(404, gin.H{"error": "group not found"})
		return
	}

	c.JSON(200, group)
}

func (s *Service) handleGetGroupMembers(c *gin.Context) {
	groupID := c.Param("id")

	members, err := s.GetGroupMembers(c.Request.Context(), groupID)
	if err != nil {
		s.logger.Error("failed to get group members", zap.String("group_id", groupID), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(200, members)
}

func (s *Service) handleCreateGroup(c *gin.Context) {
	var group Group
	if err := c.ShouldBindJSON(&group); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	if err := s.CreateGroup(c.Request.Context(), &group); err != nil {
		s.logger.Error("failed to create group", zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(201, group)
}

func (s *Service) handleUpdateGroup(c *gin.Context) {
	groupID := c.Param("id")

	var group Group
	if err := c.ShouldBindJSON(&group); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	group.ID = groupID
	if err := s.UpdateGroup(c.Request.Context(), &group); err != nil {
		s.logger.Error("failed to update group", zap.String("group_id", groupID), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(200, group)
}

func (s *Service) handleDeleteGroup(c *gin.Context) {
	groupID := c.Param("id")

	if err := s.DeleteGroup(c.Request.Context(), groupID); err != nil {
		s.logger.Error("failed to delete group", zap.String("group_id", groupID), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(204, nil)
}

func (s *Service) handleAddGroupMember(c *gin.Context) {
	groupID := c.Param("id")

	var req struct {
		UserID string `json:"user_id" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// Check governance policies (timebound, location) before adding member
	if err := s.CheckPolicies(c.Request.Context(), req.UserID, "add_group_member", nil, c.ClientIP()); err != nil {
		if policyErr, ok := err.(*PolicyViolationError); ok {
			c.JSON(403, gin.H{
				"error":      "Policy violation",
				"violations": policyErr.Violations,
			})
			return
		}
	}

	if err := s.AddGroupMember(c.Request.Context(), groupID, req.UserID); err != nil {
		if strings.Contains(err.Error(), "not found") {
			c.JSON(404, gin.H{"error": err.Error()})
			return
		}
		if strings.Contains(err.Error(), "already a member") || strings.Contains(err.Error(), "maximum member limit") {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
		s.logger.Error("failed to add group member", zap.String("group_id", groupID), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(200, gin.H{"status": "member added"})
}

func (s *Service) handleRemoveGroupMember(c *gin.Context) {
	groupID := c.Param("id")
	userID := c.Param("userId")

	// Check governance policies (timebound, location) before removing member
	if err := s.CheckPolicies(c.Request.Context(), userID, "remove_group_member", nil, c.ClientIP()); err != nil {
		if policyErr, ok := err.(*PolicyViolationError); ok {
			c.JSON(403, gin.H{
				"error":      "Policy violation",
				"violations": policyErr.Violations,
			})
			return
		}
	}

	if err := s.RemoveGroupMember(c.Request.Context(), groupID, userID); err != nil {
		if strings.Contains(err.Error(), "not a member") {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
		s.logger.Error("failed to remove group member", zap.String("group_id", groupID), zap.String("user_id", userID), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(200, gin.H{"status": "member removed"})
}

func (s *Service) handleGetSubgroups(c *gin.Context) {
	parentID := c.Param("id")

	subgroups, err := s.GetSubgroups(c.Request.Context(), parentID)
	if err != nil {
		s.logger.Error("failed to get subgroups", zap.String("parent_id", parentID), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(200, subgroups)
}

func (s *Service) handleSearchUsers(c *gin.Context) {
	query := c.Query("q")
	if query == "" {
		c.JSON(400, gin.H{"error": "search query is required"})
		return
	}

	limitStr := c.DefaultQuery("limit", "20")
	limit, _ := strconv.Atoi(limitStr)
	if limit < 1 {
		limit = 1
	}
	if limit > 100 {
		limit = 100
	}

	users, err := s.SearchUsers(c.Request.Context(), query, limit)
	if err != nil {
		s.logger.Error("failed to search users", zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(200, users)
}

// MFA HTTP Handlers

func (s *Service) handleSetupTOTP(c *gin.Context) {
	userID := c.GetString("user_id") // From JWT middleware
	if userID == "" {
		c.JSON(401, gin.H{"error": "unauthenticated"})
		return
	}

	enrollment, err := s.GenerateTOTPSecret(c.Request.Context(), userID)
	if err != nil {
		s.logger.Error("failed to setup TOTP", zap.String("user_id", userID), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(200, enrollment)
}

func (s *Service) handleEnrollTOTP(c *gin.Context) {
	userID := c.GetString("user_id") // From JWT middleware
	if userID == "" {
		c.JSON(401, gin.H{"error": "unauthenticated"})
		return
	}

	var req struct {
		Secret string `json:"secret" binding:"required"`
		Code   string `json:"code" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	err := s.EnrollTOTP(c.Request.Context(), userID, req.Secret, req.Code)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"status": "enrolled"})
}

func (s *Service) handleVerifyTOTP(c *gin.Context) {
	userID := c.GetString("user_id") // From JWT middleware
	if userID == "" {
		c.JSON(401, gin.H{"error": "unauthenticated"})
		return
	}

	var req TOTPVerification
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	valid, err := s.VerifyTOTP(c.Request.Context(), userID, req.Code)
	if err != nil {
		s.logger.Error("failed to verify TOTP", zap.String("user_id", userID), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(200, gin.H{"valid": valid})
}

func (s *Service) handleGetTOTPStatus(c *gin.Context) {
	userID := c.GetString("user_id") // From JWT middleware
	if userID == "" {
		c.JSON(401, gin.H{"error": "unauthenticated"})
		return
	}

	status, err := s.GetTOTPStatus(c.Request.Context(), userID)
	if err != nil {
		s.logger.Error("failed to get TOTP status", zap.String("user_id", userID), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(200, status)
}

func (s *Service) handleDisableTOTP(c *gin.Context) {
	userID := c.GetString("user_id") // From JWT middleware
	if userID == "" {
		c.JSON(401, gin.H{"error": "unauthenticated"})
		return
	}

	err := s.DisableTOTP(c.Request.Context(), userID)
	if err != nil {
		s.logger.Error("failed to disable TOTP", zap.String("user_id", userID), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(200, gin.H{"status": "disabled"})
}

func (s *Service) handleGenerateBackupCodes(c *gin.Context) {
	userID := c.GetString("user_id") // From JWT middleware
	if userID == "" {
		c.JSON(401, gin.H{"error": "unauthenticated"})
		return
	}

	var req struct {
		Count int `json:"count"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		req.Count = 10 // Default
	}

	codes, err := s.GenerateBackupCodes(c.Request.Context(), userID, req.Count)
	if err != nil {
		s.logger.Error("failed to generate backup codes", zap.String("user_id", userID), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(200, gin.H{"backup_codes": codes})
}

func (s *Service) handleVerifyBackupCode(c *gin.Context) {
	userID := c.GetString("user_id") // From JWT middleware
	if userID == "" {
		c.JSON(401, gin.H{"error": "unauthenticated"})
		return
	}

	var req struct {
		Code string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	valid, err := s.ValidateBackupCode(c.Request.Context(), userID, req.Code)
	if err != nil {
		s.logger.Error("failed to validate backup code", zap.String("user_id", userID), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(200, gin.H{"valid": valid})
}

func (s *Service) handleGetBackupCodeCount(c *gin.Context) {
	userID := c.GetString("user_id") // From JWT middleware
	if userID == "" {
		c.JSON(401, gin.H{"error": "unauthenticated"})
		return
	}

	count, err := s.GetRemainingBackupCodes(c.Request.Context(), userID)
	if err != nil {
		s.logger.Error("failed to get remaining backup codes", zap.String("user_id", userID), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(200, gin.H{"remaining_codes": count})
}

// User Self-Service Handlers

func (s *Service) handleGetCurrentUser(c *gin.Context) {
	userID := c.GetString("user_id") // From JWT middleware
	if userID == "" {
		c.JSON(401, gin.H{"error": "unauthenticated"})
		return
	}

	user, err := s.GetUser(c.Request.Context(), userID)
	if err != nil {
		c.JSON(404, gin.H{"error": "user not found"})
		return
	}

	// Get MFA status
	totpStatus, err := s.GetTOTPStatus(c.Request.Context(), userID)
	if err != nil {
		s.logger.Warn("Failed to get MFA status", zap.Error(err))
	}

	// Build MFA methods list
	mfaMethods := []string{}
	if totpStatus.Enabled {
		mfaMethods = append(mfaMethods, "totp")
	}

	// Return user profile with camelCase fields matching frontend expectations
	c.JSON(200, gin.H{
		"id":            user.ID,
		"username":      user.GetUsername(),
		"email":         user.GetEmail(),
		"firstName":     user.GetFirstName(),
		"lastName":      user.GetLastName(),
		"enabled":       user.Enabled,
		"emailVerified": user.EmailVerified,
		"createdAt":     user.CreatedAt,
		"mfaEnabled":    totpStatus.Enabled,
		"mfaMethods":    mfaMethods,
	})
}

func (s *Service) handleUpdateCurrentUser(c *gin.Context) {
	userID := c.GetString("user_id") // From JWT middleware
	if userID == "" {
		c.JSON(401, gin.H{"error": "unauthenticated"})
		return
	}

	var req struct {
		FirstName string `json:"firstName"`
		LastName  string `json:"lastName"`
		Email     string `json:"email"`
		Enabled   bool   `json:"enabled"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// Get current user
	user, err := s.GetUser(c.Request.Context(), userID)
	if err != nil {
		c.JSON(404, gin.H{"error": "user not found"})
		return
	}

	// Update allowed fields
	user.SetFirstName(req.FirstName)
	user.SetLastName(req.LastName)
	user.SetEmail(req.Email)
	user.Enabled = req.Enabled

	if err := s.UpdateUser(c.Request.Context(), user); err != nil {
		s.logger.Error("failed to update current user", zap.String("user_id", userID), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(200, gin.H{
		"id":            user.ID,
		"username":      user.GetUsername(),
		"email":         user.GetEmail(),
		"firstName":     user.GetFirstName(),
		"lastName":      user.GetLastName(),
		"enabled":       user.Enabled,
		"emailVerified": user.EmailVerified,
		"createdAt":     user.CreatedAt,
	})
}

func (s *Service) handleChangePassword(c *gin.Context) {
	userID := c.GetString("user_id") // From JWT middleware
	if userID == "" {
		c.JSON(401, gin.H{"error": "unauthenticated"})
		return
	}

	var req struct {
		CurrentPassword string `json:"currentPassword" binding:"required"`
		NewPassword     string `json:"newPassword" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()

	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to verify password"})
		return
	}

	// Check if user is from an LDAP directory
	var source *string
	var directoryID *string
	var username string
	var passwordHash string
	err = s.db.Pool.QueryRow(ctx, `
		SELECT username, source, directory_id, password_hash FROM users WHERE id = $1 AND org_id = $2
	`, userID, org.ID).Scan(&username, &source, &directoryID, &passwordHash)

	if err != nil {
		s.logger.Error("Failed to get user info", zap.String("user_id", userID), zap.Error(err))
		c.JSON(500, gin.H{"error": "failed to verify password"})
		return
	}

	if source != nil && *source == "azure_ad" {
		c.JSON(400, gin.H{"error": "Password is managed by Azure Active Directory. Use the Azure AD portal or your organization's self-service password reset."})
		return
	}

	if source != nil && (*source == "ldap" || *source == "active_directory") && directoryID != nil && s.directoryService != nil {
		// LDAP/AD user — change password via directory
		if err := s.directoryService.ChangePassword(ctx, *directoryID, username, req.CurrentPassword, req.NewPassword); err != nil {
			s.logger.Warn("Directory password change failed", zap.String("user_id", userID), zap.Error(err))
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
		// Update password_changed_at in local DB (but NOT the hash — password stays in directory)
		s.db.Pool.Exec(ctx, `UPDATE users SET password_changed_at = NOW(), password_must_change = false WHERE id = $1 AND org_id = $2`, userID, org.ID)
		c.JSON(200, gin.H{"status": "password changed"})
		return
	}

	// Local user — verify current password using bcrypt
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.CurrentPassword)); err != nil {
		c.JSON(400, gin.H{"error": "current password is incorrect"})
		return
	}

	// Set new password
	if err := s.SetPassword(ctx, userID, req.NewPassword); err != nil {
		s.logger.Error("failed to set password", zap.String("user_id", userID), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(200, gin.H{"status": "password changed"})
}

func (s *Service) handleGetPasswordInfo(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(401, gin.H{"error": "unauthenticated"})
		return
	}

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(404, gin.H{"error": "user not found"})
		return
	}

	var source *string
	var passwordChangedAt *time.Time
	var passwordMustChange bool
	err = s.db.Pool.QueryRow(c.Request.Context(), `
		SELECT source, password_changed_at, password_must_change FROM users WHERE id = $1 AND org_id = $2
	`, userID, org.ID).Scan(&source, &passwordChangedAt, &passwordMustChange)
	if err != nil {
		c.JSON(404, gin.H{"error": "user not found"})
		return
	}

	isDirectory := source != nil && (*source == "ldap" || *source == "active_directory" || *source == "azure_ad")
	isLDAP := source != nil && (*source == "ldap" || *source == "active_directory")
	isAzureAD := source != nil && *source == "azure_ad"
	resp := gin.H{
		"is_ldap":              isLDAP,
		"is_directory_managed": isDirectory,
		"is_azure_ad":          isAzureAD,
		"password_must_change": passwordMustChange,
	}
	if source != nil {
		resp["source"] = *source
	} else {
		resp["source"] = "local"
	}
	if passwordChangedAt != nil {
		resp["password_changed_at"] = passwordChangedAt
	}
	c.JSON(200, resp)
}

func (s *Service) handleSetupUserMFA(c *gin.Context) {
	userID := c.GetString("user_id") // From JWT middleware
	if userID == "" {
		c.JSON(401, gin.H{"error": "unauthenticated"})
		return
	}

	enrollment, err := s.GenerateTOTPSecret(c.Request.Context(), userID)
	if err != nil {
		s.logger.Error("failed to setup user MFA", zap.String("user_id", userID), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	// Cache the secret in Redis so handleEnableUserMFA can retrieve it
	cacheKey := fmt.Sprintf("mfa_setup:%s", userID)
	if s.redis != nil {
		s.redis.Client.Set(c.Request.Context(), cacheKey, enrollment.Secret, 10*time.Minute)
	}

	c.JSON(200, gin.H{
		"secret":    enrollment.Secret,
		"qrCodeUrl": enrollment.QRCodeURL,
	})
}

func (s *Service) handleEnableUserMFA(c *gin.Context) {
	userID := c.GetString("user_id") // From JWT middleware
	if userID == "" {
		c.JSON(401, gin.H{"error": "unauthenticated"})
		return
	}

	var req struct {
		Code string `json:"code" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// Retrieve the cached secret from the setup step
	cacheKey := fmt.Sprintf("mfa_setup:%s", userID)
	var secret string
	if s.redis != nil {
		var err error
		secret, err = s.redis.Client.Get(c.Request.Context(), cacheKey).Result()
		if err != nil || secret == "" {
			c.JSON(400, gin.H{"error": "MFA setup expired or not initiated. Please start setup again."})
			return
		}
	} else {
		c.JSON(500, gin.H{"error": "cache unavailable"})
		return
	}

	err := s.EnrollTOTP(c.Request.Context(), userID, secret, req.Code)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid verification code"})
		return
	}

	// Clear the cached secret after successful enrollment
	s.redis.Client.Del(c.Request.Context(), cacheKey)

	// Generate backup codes
	backupCodes, err := s.GenerateBackupCodes(c.Request.Context(), userID, 10)
	if err != nil {
		s.logger.Warn("Failed to generate backup codes", zap.Error(err))
	}

	c.JSON(200, gin.H{
		"status":      "mfa enabled",
		"backupCodes": backupCodes,
	})
}

func (s *Service) handleDisableUserMFA(c *gin.Context) {
	userID := c.GetString("user_id") // From JWT middleware
	if userID == "" {
		c.JSON(401, gin.H{"error": "unauthenticated"})
		return
	}

	err := s.DisableTOTP(c.Request.Context(), userID)
	if err != nil {
		s.logger.Error("failed to disable user MFA", zap.String("user_id", userID), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(200, gin.H{"status": "mfa disabled"})
}

func (s *Service) handleExportUsersCSV(c *gin.Context) {
	users, _, err := s.ListUsers(c.Request.Context(), 0, 10000)
	if err != nil {
		s.logger.Error("failed to export users CSV", zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.Header("Content-Type", "text/csv")
	c.Header("Content-Disposition", "attachment; filename=users.csv")

	writer := csv.NewWriter(c.Writer)
	writer.Write([]string{"username", "email", "first_name", "last_name", "enabled"})

	for _, u := range users {
		enabled := "true"
		if !u.Enabled {
			enabled = "false"
		}
		writer.Write([]string{u.GetUsername(), u.GetEmail(), u.GetFirstName(), u.GetLastName(), enabled})
	}
	writer.Flush()
}

func (s *Service) handleImportUsersCSV(c *gin.Context) {
	file, _, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(400, gin.H{"error": "file is required"})
		return
	}
	defer file.Close()

	reader := csv.NewReader(file)

	// Read header
	header, err := reader.Read()
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid CSV file"})
		return
	}

	// Build column index map
	colIndex := make(map[string]int)
	for i, col := range header {
		colIndex[strings.ToLower(strings.TrimSpace(col))] = i
	}

	var total, created, errCount int
	var importErrors []string

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			errCount++
			importErrors = append(importErrors, fmt.Sprintf("Row %d: invalid CSV row", total+2))
			continue
		}
		total++

		getField := func(name string) string {
			if idx, ok := colIndex[name]; ok && idx < len(record) {
				return strings.TrimSpace(record[idx])
			}
			return ""
		}

		username := getField("username")
		email := getField("email")
		if username == "" || email == "" {
			errCount++
			importErrors = append(importErrors, fmt.Sprintf("Row %d: username and email are required", total+1))
			continue
		}

		user := &User{
			UserName: username,
			Emails:   []Email{{Value: email, Primary: boolPtr(true)}},
			Name:     &Name{GivenName: stringPtr(getField("first_name")), FamilyName: stringPtr(getField("last_name"))},
			Enabled:  getField("enabled") != "false",
		}
		user.SetEmailVerified(false)

		if err := s.CreateUser(c.Request.Context(), user); err != nil {
			errCount++
			importErrors = append(importErrors, fmt.Sprintf("Row %d: %s", total+1, err.Error()))
			continue
		}
		created++
	}

	c.JSON(200, gin.H{
		"total":   total,
		"created": created,
		"errors":  errCount,
		"details": importErrors,
	})
}

func (s *Service) handleForgotPassword(c *gin.Context) {
	var req struct {
		Email string `json:"email"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "email is required"})
		return
	}

	ctx := c.Request.Context()
	// The org is resolved (subdomain/default) before this public
	// endpoint runs, so reset is scoped to the caller's tenant: the
	// same email in another org must not yield a token here.
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(200, gin.H{"message": "If an account with that email exists, a password reset link has been sent."})
		return
	}

	// Opportunistic cleanup of this org's expired/used tokens
	s.db.Pool.Exec(ctx, "DELETE FROM password_reset_tokens WHERE (expires_at < NOW() OR used_at IS NOT NULL) AND org_id = $1", org.ID)

	// Always return success to prevent email enumeration
	// Look up user by email, including source
	var userID string
	var source *string
	err = s.db.Pool.QueryRow(ctx,
		"SELECT id, source FROM users WHERE email = $1 AND enabled = true AND org_id = $2", req.Email, org.ID).Scan(&userID, &source)
	if err != nil {
		// User not found - still return success
		c.JSON(200, gin.H{"message": "If an account with that email exists, a password reset link has been sent."})
		return
	}

	// Directory-managed users cannot use email-based password reset
	if source != nil && (*source == "ldap" || *source == "active_directory" || *source == "azure_ad") {
		note := "This account is managed by Active Directory. Please contact your administrator to reset your password."
		if *source == "azure_ad" {
			note = "This account is managed by Azure Active Directory. Use the Azure AD portal or your organization's self-service password reset."
		}
		c.JSON(200, gin.H{
			"message": "If an account with that email exists, a password reset link has been sent.",
			"note":    note,
		})
		return
	}

	// Generate token
	tokenBytes := make([]byte, 32)
	rand.Read(tokenBytes)
	token := hex.EncodeToString(tokenBytes)

	// Store token with 1 hour expiry
	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO password_reset_tokens (user_id, token, expires_at, org_id)
		VALUES ($1, $2, $3, $4)
	`, userID, token, time.Now().Add(1*time.Hour), org.ID)
	if err != nil {
		s.logger.Error("Failed to create password reset token", zap.Error(err))
		c.JSON(200, gin.H{"message": "If an account with that email exists, a password reset link has been sent."})
		return
	}

	// In dev mode, log the token so it can be used for testing
	s.logger.Info("Password reset token created",
		zap.String("email", req.Email),
		zap.String("token", token),
		zap.String("reset_url", fmt.Sprintf("http://localhost:3000/reset-password?token=%s", token)))

	// Send password reset email
	if s.emailService != nil {
		var firstName string
		s.db.Pool.QueryRow(ctx,
			"SELECT first_name FROM users WHERE id = $1 AND org_id = $2", userID, org.ID).Scan(&firstName)
		baseURL := "http://localhost:3000"
		if err := s.emailService.SendPasswordResetEmail(ctx, req.Email, firstName, token, baseURL); err != nil {
			s.logger.Error("Failed to send password reset email", zap.Error(err))
		}
	}

	c.JSON(200, gin.H{"message": "If an account with that email exists, a password reset link has been sent."})
}

func (s *Service) handleResetPassword(c *gin.Context) {
	var req struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "token and password are required"})
		return
	}

	if violations := s.ValidatePasswordPolicyChecks(req.Password); len(violations) > 0 {
		c.JSON(400, gin.H{"error": "password_policy_violation", "violations": violations})
		return
	}

	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(400, gin.H{"error": "Invalid or expired reset token"})
		return
	}

	// Validate token
	var userID string
	var usedAt *time.Time
	err = s.db.Pool.QueryRow(ctx, `
		SELECT user_id, used_at FROM password_reset_tokens
		WHERE token = $1 AND org_id = $2 AND expires_at > NOW()
	`, req.Token, org.ID).Scan(&userID, &usedAt)
	if err != nil {
		c.JSON(400, gin.H{"error": "Invalid or expired reset token"})
		return
	}
	if usedAt != nil {
		c.JSON(400, gin.H{"error": "This reset token has already been used"})
		return
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), 12)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to process password"})
		return
	}

	// Update password
	_, err = s.db.Pool.Exec(ctx,
		"UPDATE users SET password_hash = $1, password_changed_at = NOW(), updated_at = NOW() WHERE id = $2 AND org_id = $3",
		string(hashedPassword), userID, org.ID)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to update password"})
		return
	}

	// Mark token as used
	s.db.Pool.Exec(ctx,
		"UPDATE password_reset_tokens SET used_at = NOW() WHERE token = $1 AND org_id = $2", req.Token, org.ID)

	c.JSON(200, gin.H{"message": "Password has been reset successfully"})
}

// handleAdminResetPassword allows admins to trigger a password reset email for a user.
// For LDAP users, it resets the password directly in AD and flags password_must_change.
func (s *Service) handleAdminResetPassword(c *gin.Context) {
	userID := c.Param("id")
	ctx := c.Request.Context()

	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(404, gin.H{"error": "User not found"})
		return
	}

	// Get user info including source
	var email, firstName, username string
	var source *string
	var directoryID *string
	err = s.db.Pool.QueryRow(ctx,
		"SELECT email, first_name, username, source, directory_id FROM users WHERE id = $1 AND org_id = $2 AND enabled = true",
		userID, org.ID).Scan(&email, &firstName, &username, &source, &directoryID)
	if err != nil {
		c.JSON(404, gin.H{"error": "User not found"})
		return
	}

	adminID, _ := c.Get("user_id")

	// Directory-managed user — reset password via directory
	if source != nil && (*source == "ldap" || *source == "active_directory" || *source == "azure_ad") && directoryID != nil && s.directoryService != nil {
		var req struct {
			NewPassword string `json:"newPassword"`
		}
		c.ShouldBindJSON(&req)

		if req.NewPassword == "" {
			// Generate a temporary password if not provided
			tokenBytes := make([]byte, 16)
			rand.Read(tokenBytes)
			req.NewPassword = "Tmp!" + hex.EncodeToString(tokenBytes)[:12]
		}

		if err := s.directoryService.ResetPassword(ctx, *directoryID, username, req.NewPassword); err != nil {
			s.logger.Error("Failed to reset directory password",
				zap.String("admin_id", fmt.Sprintf("%v", adminID)),
				zap.String("target_user_id", userID),
				zap.String("source", *source),
				zap.Error(err))
			c.JSON(500, gin.H{"error": "Failed to reset directory password"})
			return
		}

		// Mark password_must_change so user is prompted at next login
		s.db.Pool.Exec(ctx, `UPDATE users SET password_must_change = true, password_changed_at = NOW() WHERE id = $1 AND org_id = $2`, userID, org.ID)

		s.logger.Info("Admin reset directory password",
			zap.String("admin_id", fmt.Sprintf("%v", adminID)),
			zap.String("target_user_id", userID),
			zap.String("source", *source))

		c.JSON(200, gin.H{
			"message": "Directory password has been reset. User must change password at next login.",
			"source":  *source,
		})
		return
	}

	// Local user — existing email reset flow
	tokenBytes := make([]byte, 32)
	rand.Read(tokenBytes)
	token := hex.EncodeToString(tokenBytes)

	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO password_reset_tokens (user_id, token, expires_at, org_id)
		VALUES ($1, $2, $3, $4)
	`, userID, token, time.Now().Add(24*time.Hour), org.ID)
	if err != nil {
		s.logger.Error("Failed to create password reset token", zap.Error(err))
		c.JSON(500, gin.H{"error": "Failed to create reset token"})
		return
	}

	s.logger.Info("Admin triggered password reset",
		zap.String("admin_id", fmt.Sprintf("%v", adminID)),
		zap.String("target_user_id", userID),
		zap.String("target_email", email))

	if s.emailService != nil {
		baseURL := "http://localhost:3000"
		if err := s.emailService.SendPasswordResetEmail(ctx, email, firstName, token, baseURL); err != nil {
			s.logger.Error("Failed to send password reset email", zap.Error(err))
			c.JSON(500, gin.H{"error": "Failed to send reset email"})
			return
		}
	}

	c.JSON(200, gin.H{"message": "Password reset email sent successfully"})
}

// handleAdminSetPassword directly sets a local user's password (admin-only).
// This is the "bypass email-reset" path needed for admin-driven onboarding
// of non-SSO users (and for integration tests that need a working login on a
// freshly-created user). For LDAP/AD/Azure users, callers should keep using
// reset-password — directory-managed passwords are out-of-band by definition.
func (s *Service) handleAdminSetPassword(c *gin.Context) {
	userIDRaw := c.Param("id")
	ctx := c.Request.Context()

	// Validate userID is a UUID before anything else: keeps log statements
	// (which include the userID) free of arbitrary user-controlled bytes,
	// turns malformed paths into 400 instead of 404, and avoids passing
	// adversarial input into SQL parameter binding even though pgx already
	// parameterizes safely.
	userID, uerr := uuid.Parse(userIDRaw)
	if uerr != nil {
		c.JSON(400, gin.H{"error": "user id must be a UUID"})
		return
	}
	userIDStr := userID.String()

	var req struct {
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// Reject empty / clearly too-short passwords up front. SetPassword will
	// also enforce the configured policy.
	if len(req.Password) < 8 {
		c.JSON(400, gin.H{"error": "password must be at least 8 characters"})
		return
	}

	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(404, gin.H{"error": "User not found"})
		return
	}

	// Confirm the user exists and is a local account; directory-managed
	// passwords must be changed via the directory, not here.
	var source *string
	err = s.db.Pool.QueryRow(ctx,
		"SELECT source FROM users WHERE id = $1 AND org_id = $2 AND enabled = true", userIDStr, org.ID,
	).Scan(&source)
	if err != nil {
		c.JSON(404, gin.H{"error": "User not found"})
		return
	}
	if source != nil && (*source == "ldap" || *source == "active_directory" || *source == "azure_ad") {
		c.JSON(400, gin.H{
			"error": "Password for directory-managed users must be set via the directory; use reset-password instead.",
		})
		return
	}

	if err := s.SetPassword(ctx, userIDStr, req.Password); err != nil {
		s.logger.Error("admin set-password failed",
			zap.String("target_user_id", userIDStr),
			zap.Error(err))
		c.JSON(500, gin.H{"error": "failed to set password"})
		return
	}

	if adminID, ok := c.Get("user_id"); ok {
		s.logger.Info("admin set user password directly",
			zap.String("admin_id", fmt.Sprintf("%v", adminID)),
			zap.String("target_user_id", userIDStr))
	}

	c.JSON(200, gin.H{"status": "password set"})
}

// handleGetMySessions returns the calling user's own active sessions. The
// admin-only counterpart (`/users/:id/sessions`) stays admin-only — this
// route is the self-access path that the user portal needs, sourcing the
// user ID from the authenticated JWT rather than the path.
func (s *Service) handleGetMySessions(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(401, gin.H{"error": "authentication required"})
		return
	}
	sessions, err := s.GetUserSessions(c.Request.Context(), userID)
	if err != nil {
		s.logger.Error("failed to get user sessions for self",
			zap.String("user_id", userID), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	// Always emit an empty array (not nil) so client code can iterate
	// unconditionally; matches the shape /api/v1/identity/users/:id/sessions
	// returns for admins.
	if sessions == nil {
		sessions = []Session{}
	}
	c.JSON(200, gin.H{"sessions": sessions})
}

// handleGetMyMFAStatus reports which MFA factors the calling user has
// enrolled. The existing /mfa/methods endpoint returns a method->bool map
// (good for the admin console's enable/disable toggles); /me/mfa/status
// returns the *enabled* method names as an array, which is the shape the
// "is this user MFA-protected?" check actually wants.
func (s *Service) handleGetMyMFAStatus(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(401, gin.H{"error": "authentication required"})
		return
	}
	methodsMap, err := s.GetUserMFAMethods(c.Request.Context(), userID)
	if err != nil {
		s.logger.Error("failed to get MFA methods",
			zap.String("user_id", userID), zap.Error(err))
		c.JSON(500, gin.H{"error": "failed to get MFA methods"})
		return
	}
	enabled := []string{}
	for name, on := range methodsMap {
		if !on {
			continue
		}
		// `backup` (recovery codes) is a fallback mechanism — it's never
		// a *primary* MFA factor on its own. Excluding it from the enabled
		// list matches the "are you MFA-protected?" semantic the caller
		// actually wants: enrolling and then disabling TOTP leaves backup
		// codes lingering in the DB, but that doesn't mean MFA is on.
		if name == "backup" {
			continue
		}
		enabled = append(enabled, name)
	}
	c.JSON(200, gin.H{
		"methods":     enabled,
		"mfa_enabled": len(enabled) > 0,
	})
}

// Permission represents a system permission
type Permission struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Resource    string    `json:"resource"`
	Action      string    `json:"action"`
	CreatedAt   time.Time `json:"created_at"`
}

// ListPermissions returns all available permissions
func (s *Service) ListPermissions(ctx context.Context) ([]Permission, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, name, description, resource, action, created_at
		FROM permissions ORDER BY resource, action
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var perms []Permission
	for rows.Next() {
		var p Permission
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.Resource, &p.Action, &p.CreatedAt); err != nil {
			return nil, err
		}
		perms = append(perms, p)
	}
	return perms, nil
}

// GetRolePermissions returns permissions assigned to a role
func (s *Service) GetRolePermissions(ctx context.Context, roleID string) ([]Permission, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	rows, err := s.db.Pool.Query(ctx, `
		SELECT p.id, p.name, p.description, p.resource, p.action, p.created_at
		FROM permissions p
		JOIN role_permissions rp ON p.id = rp.permission_id
		WHERE rp.role_id = $1 AND rp.org_id = $2
		ORDER BY p.resource, p.action
	`, roleID, org.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var perms []Permission
	for rows.Next() {
		var p Permission
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.Resource, &p.Action, &p.CreatedAt); err != nil {
			return nil, err
		}
		perms = append(perms, p)
	}
	return perms, nil
}

// SetRolePermissions replaces all permissions for a role
func (s *Service) SetRolePermissions(ctx context.Context, roleID string, permissionIDs []string) error {
	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, "DELETE FROM role_permissions WHERE role_id = $1 AND org_id = $2", roleID, org.ID)
	if err != nil {
		return err
	}

	for _, permID := range permissionIDs {
		_, err = tx.Exec(ctx, "INSERT INTO role_permissions (role_id, permission_id, org_id) VALUES ($1, $2, $3)", roleID, permID, org.ID)
		if err != nil {
			return err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return err
	}
	s.invalidatePermissionCache(ctx, roleID)
	return nil
}

// invalidatePermissionCache clears Redis-cached permissions for a role
func (s *Service) invalidatePermissionCache(ctx context.Context, roleID string) {
	if s.redis == nil || s.redis.Client == nil {
		return
	}
	org, err := orgctx.From(ctx)
	if err != nil {
		return
	}
	var roleName string
	_ = s.db.Pool.QueryRow(ctx, "SELECT name FROM roles WHERE id = $1 AND org_id = $2", roleID, org.ID).Scan(&roleName)
	if roleName == "" {
		return
	}
	iter := s.redis.Client.Scan(ctx, 0, "perms:*"+roleName+"*", 100).Iterator()
	for iter.Next(ctx) {
		s.redis.Client.Del(ctx, iter.Val())
	}
}

func (s *Service) handleListPermissions(c *gin.Context) {
	perms, err := s.ListPermissions(c.Request.Context())
	if err != nil {
		s.logger.Error("failed to list permissions", zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(200, perms)
}

func (s *Service) handleGetRolePermissions(c *gin.Context) {
	roleID := c.Param("id")
	perms, err := s.GetRolePermissions(c.Request.Context(), roleID)
	if err != nil {
		s.logger.Error("failed to get role permissions", zap.String("role_id", roleID), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(200, perms)
}

func (s *Service) handleSetRolePermissions(c *gin.Context) {
	roleID := c.Param("id")
	var req struct {
		PermissionIDs []string `json:"permission_ids"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if err := s.SetRolePermissions(c.Request.Context(), roleID, req.PermissionIDs); err != nil {
		s.logger.Error("failed to set role permissions", zap.String("role_id", roleID), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(200, gin.H{"message": "Permissions updated"})
}

// handleVerifyEmail verifies a user's email address
func (s *Service) handleVerifyEmail(c *gin.Context) {
	var req struct {
		Token string `json:"token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid or expired token"})
		return
	}

	var userID string
	err = s.db.Pool.QueryRow(ctx,
		"SELECT user_id FROM email_verification_tokens WHERE token = $1 AND org_id = $2 AND expires_at > NOW() AND used_at IS NULL",
		req.Token, org.ID).Scan(&userID)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid or expired token"})
		return
	}

	_, err = s.db.Pool.Exec(ctx, "UPDATE users SET email_verified = true WHERE id = $1 AND org_id = $2", userID, org.ID)
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to verify email"})
		return
	}

	if _, err := s.db.Pool.Exec(ctx,
		"UPDATE email_verification_tokens SET used_at = NOW() WHERE token = $1 AND org_id = $2", req.Token, org.ID); err != nil {
		s.logger.Error("failed to mark verification token as used", zap.String("token", req.Token), zap.Error(err))
	}

	c.JSON(200, gin.H{"message": "Email verified successfully"})
}

// handleResendVerification resends the verification email
func (s *Service) handleResendVerification(c *gin.Context) {
	userID, _ := c.Get("user_id")

	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(404, gin.H{"error": "user not found"})
		return
	}

	var email, firstName string
	err = s.db.Pool.QueryRow(ctx,
		"SELECT email, first_name FROM users WHERE id = $1 AND org_id = $2", userID, org.ID).Scan(&email, &firstName)
	if err != nil {
		c.JSON(404, gin.H{"error": "user not found"})
		return
	}

	token := uuid.New().String()
	_, err = s.db.Pool.Exec(ctx,
		"INSERT INTO email_verification_tokens (user_id, token, expires_at, org_id) VALUES ($1, $2, NOW() + INTERVAL '24 hours', $3)",
		userID, token, org.ID)
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to create verification token"})
		return
	}

	if s.emailService != nil {
		baseURL := fmt.Sprintf("http://localhost:%d", s.cfg.Port)
		s.emailService.SendVerificationEmail(c.Request.Context(), email, firstName, token, baseURL)
	}

	c.JSON(200, gin.H{"message": "Verification email sent"})
}

// handleListInvitations lists pending invitations
func (s *Service) handleListInvitations(c *gin.Context) {
	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	rows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT id, email, invited_by, roles, groups, token, status, expires_at, accepted_at, created_at
		 FROM user_invitations WHERE org_id = $1 ORDER BY created_at DESC LIMIT 50`, org.ID)
	if err != nil {
		s.logger.Error("failed to list invitations", zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	defer rows.Close()

	type Invitation struct {
		ID         string     `json:"id"`
		Email      string     `json:"email"`
		InvitedBy  string     `json:"invited_by"`
		Roles      []string   `json:"roles"`
		Groups     []string   `json:"groups"`
		Token      string     `json:"token"`
		Status     string     `json:"status"`
		ExpiresAt  time.Time  `json:"expires_at"`
		AcceptedAt *time.Time `json:"accepted_at,omitempty"`
		CreatedAt  time.Time  `json:"created_at"`
	}

	var invitations []Invitation
	for rows.Next() {
		var inv Invitation
		err := rows.Scan(&inv.ID, &inv.Email, &inv.InvitedBy, &inv.Roles, &inv.Groups,
			&inv.Token, &inv.Status, &inv.ExpiresAt, &inv.AcceptedAt, &inv.CreatedAt)
		if err != nil {
			continue
		}
		invitations = append(invitations, inv)
	}
	if invitations == nil {
		invitations = []Invitation{}
	}
	c.JSON(200, gin.H{"invitations": invitations})
}

// handleCreateInvitation creates a new user invitation
func (s *Service) handleCreateInvitation(c *gin.Context) {
	var req struct {
		Email  string   `json:"email" binding:"required"`
		Roles  []string `json:"roles"`
		Groups []string `json:"groups"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	invitedBy, _ := c.Get("user_id")
	token := uuid.New().String()

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	var id string
	err = s.db.Pool.QueryRow(c.Request.Context(),
		`INSERT INTO user_invitations (email, invited_by, roles, groups, token, expires_at, org_id)
		 VALUES ($1, $2, $3, $4, $5, NOW() + INTERVAL '7 days', $6) RETURNING id`,
		req.Email, invitedBy, req.Roles, req.Groups, token, org.ID).Scan(&id)
	if err != nil {
		s.logger.Error("failed to create invitation", zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	// Send invitation email
	if s.emailService != nil {
		inviterName, _ := c.Get("name")
		name, _ := inviterName.(string)
		if name == "" {
			name = "An administrator"
		}
		baseURL := fmt.Sprintf("http://localhost:%d", s.cfg.Port)
		s.emailService.SendInvitationEmail(c.Request.Context(), req.Email, name, token, baseURL)
	}

	c.JSON(201, gin.H{"id": id, "token": token, "email": req.Email})
}

// handleDeleteInvitation revokes an invitation
func (s *Service) handleDeleteInvitation(c *gin.Context) {
	id := c.Param("id")
	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	_, err = s.db.Pool.Exec(c.Request.Context(),
		"DELETE FROM user_invitations WHERE id = $1 AND org_id = $2", id, org.ID)
	if err != nil {
		s.logger.Error("failed to delete invitation", zap.String("id", id), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(200, gin.H{"message": "Invitation revoked"})
}

// handleAcceptInvitation accepts an invitation and creates the user
func (s *Service) handleAcceptInvitation(c *gin.Context) {
	token := c.Param("token")

	var req struct {
		Username  string `json:"username" binding:"required"`
		Password  string `json:"password" binding:"required"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid or expired invitation"})
		return
	}

	// Look up invitation within the caller's org (the invite link is
	// org-specific via the subdomain it was sent for)
	var invID, email string
	var roles, groups []string
	err = s.db.Pool.QueryRow(ctx,
		`SELECT id, email, roles, groups FROM user_invitations
		 WHERE token = $1 AND org_id = $2 AND status = 'pending' AND expires_at > NOW()`,
		token, org.ID).Scan(&invID, &email, &roles, &groups)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid or expired invitation"})
		return
	}

	// Create user (CreateUser scopes to the org carried on ctx)
	user := &User{
		UserName: req.Username,
		Emails:   []Email{{Value: email, Primary: boolPtr(true), Verified: boolPtr(true)}},
		Name:     &Name{GivenName: stringPtr(req.FirstName), FamilyName: stringPtr(req.LastName)},
		Enabled:  true,
	}

	if err := s.CreateUser(ctx, user); err != nil {
		s.logger.Error("failed to create user from invitation", zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	// Set password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err == nil {
		s.db.Pool.Exec(ctx,
			"UPDATE users SET password_hash = $1, password_changed_at = NOW() WHERE id = $2 AND org_id = $3",
			string(hashedPassword), user.ID, org.ID)
	}

	// Assign roles (only roles within the caller's org)
	for _, role := range roles {
		s.db.Pool.Exec(ctx,
			"INSERT INTO user_roles (user_id, role_id, org_id) SELECT $1, id, $3 FROM roles WHERE name = $2 AND org_id = $3 ON CONFLICT DO NOTHING",
			user.ID, role, org.ID)
	}

	// Add to groups (only groups within the caller's org)
	for _, group := range groups {
		s.db.Pool.Exec(ctx,
			"INSERT INTO group_memberships (user_id, group_id, org_id) SELECT $1, id, $3 FROM groups WHERE name = $2 AND org_id = $3 ON CONFLICT DO NOTHING",
			user.ID, group, org.ID)
	}

	// Mark invitation as accepted
	s.db.Pool.Exec(ctx,
		"UPDATE user_invitations SET status = 'accepted', accepted_at = NOW() WHERE id = $1 AND org_id = $2", invID, org.ID)

	// Send welcome email
	if s.emailService != nil {
		s.emailService.SendWelcomeEmail(c.Request.Context(), email, req.FirstName)
	}

	// Publish webhook
	if s.webhookService != nil {
		s.webhookService.Publish(c.Request.Context(), "user.created", map[string]interface{}{
			"user_id": user.ID, "username": user.GetUsername(), "email": email, "source": "invitation",
		})
	}

	c.JSON(201, gin.H{"message": "Account created successfully", "user_id": user.ID})
}

// handleOffboardUser deactivates a user and cleans up their access
func (s *Service) handleOffboardUser(c *gin.Context) {
	userID := c.Param("id")

	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to disable user"})
		return
	}

	// Disable user
	_, err = s.db.Pool.Exec(ctx,
		"UPDATE users SET enabled = false, updated_at = NOW() WHERE id = $1 AND org_id = $2", userID, org.ID)
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to disable user"})
		return
	}

	// Revoke all API keys
	s.db.Pool.Exec(ctx,
		"UPDATE api_keys SET status = 'revoked' WHERE user_id = $1 AND org_id = $2", userID, org.ID)

	// Remove from all groups
	s.db.Pool.Exec(ctx,
		"DELETE FROM group_memberships WHERE user_id = $1 AND org_id = $2", userID, org.ID)

	// Remove all role assignments
	s.db.Pool.Exec(ctx,
		"DELETE FROM user_roles WHERE user_id = $1 AND org_id = $2", userID, org.ID)

	// Terminate all sessions
	s.db.Pool.Exec(ctx,
		"DELETE FROM sessions WHERE user_id = $1 AND org_id = $2", userID, org.ID)

	// Publish webhook
	if s.webhookService != nil {
		s.webhookService.Publish(c.Request.Context(), "user.deleted", map[string]interface{}{
			"user_id": userID, "action": "offboard",
		})
	}

	s.logger.Info("User offboarded", zap.String("user_id", userID))
	c.JSON(200, gin.H{"message": "User offboarded successfully"})
}

// LifecycleWorkflow represents a JML (Joiner/Mover/Leaver) workflow template
type LifecycleWorkflow struct {
	ID               string                   `json:"id"`
	Name             string                   `json:"name"`
	Description      string                   `json:"description"`
	EventType        string                   `json:"event_type"`
	TriggerType      string                   `json:"trigger_type"`
	Actions          []map[string]interface{} `json:"actions"`
	Conditions       map[string]interface{}   `json:"conditions"`
	RequireApproval  bool                     `json:"require_approval"`
	ApprovalPolicyID *string                  `json:"approval_policy_id,omitempty"`
	Enabled          bool                     `json:"enabled"`
	CreatedBy        *string                  `json:"created_by,omitempty"`
	CreatedAt        time.Time                `json:"created_at"`
	UpdatedAt        time.Time                `json:"updated_at"`
}

// LifecycleExecution represents a single execution of a workflow
type LifecycleExecution struct {
	ID               string                   `json:"id"`
	WorkflowID       string                   `json:"workflow_id"`
	UserID           string                   `json:"user_id"`
	TriggeredBy      *string                  `json:"triggered_by,omitempty"`
	TriggerType      string                   `json:"trigger_type"`
	Status           string                   `json:"status"`
	ActionsCompleted []map[string]interface{} `json:"actions_completed"`
	ActionsFailed    []map[string]interface{} `json:"actions_failed"`
	Error            *string                  `json:"error,omitempty"`
	StartedAt        time.Time                `json:"started_at"`
	CompletedAt      *time.Time               `json:"completed_at,omitempty"`
	CreatedAt        time.Time                `json:"created_at"`
}

// CreateLifecycleWorkflow inserts a new lifecycle workflow into the database
func (s *Service) CreateLifecycleWorkflow(ctx context.Context, wf *LifecycleWorkflow) error {
	wf.ID = uuid.New().String()
	wf.CreatedAt = time.Now()
	wf.UpdatedAt = time.Now()

	actionsJSON, err := json.Marshal(wf.Actions)
	if err != nil {
		return fmt.Errorf("failed to marshal actions: %w", err)
	}

	conditionsJSON, err := json.Marshal(wf.Conditions)
	if err != nil {
		return fmt.Errorf("failed to marshal conditions: %w", err)
	}

	_, err = s.db.Pool.Exec(ctx,
		`INSERT INTO lifecycle_workflows (id, name, description, event_type, trigger_type, actions, conditions, require_approval, approval_policy_id, enabled, created_by, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		wf.ID, wf.Name, wf.Description, wf.EventType, wf.TriggerType,
		actionsJSON, conditionsJSON, wf.RequireApproval, wf.ApprovalPolicyID,
		wf.Enabled, wf.CreatedBy, wf.CreatedAt, wf.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create lifecycle workflow: %w", err)
	}
	return nil
}

// ListLifecycleWorkflows returns paginated lifecycle workflows with optional event_type filter
func (s *Service) ListLifecycleWorkflows(ctx context.Context, offset, limit int, eventType string) ([]LifecycleWorkflow, int, error) {
	countQuery := "SELECT COUNT(*) FROM lifecycle_workflows"
	listQuery := `SELECT id, name, description, event_type, trigger_type, actions, conditions,
		require_approval, approval_policy_id, enabled, created_by, created_at, updated_at
		FROM lifecycle_workflows`

	var args []interface{}
	argIdx := 1

	if eventType != "" {
		countQuery += fmt.Sprintf(" WHERE event_type = $%d", argIdx)
		listQuery += fmt.Sprintf(" WHERE event_type = $%d", argIdx)
		args = append(args, eventType)
		argIdx++
	}

	var total int
	err := s.db.Pool.QueryRow(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count lifecycle workflows: %w", err)
	}

	listQuery += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, limit, offset)

	rows, err := s.db.Pool.Query(ctx, listQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list lifecycle workflows: %w", err)
	}
	defer rows.Close()

	var workflows []LifecycleWorkflow
	for rows.Next() {
		var wf LifecycleWorkflow
		var actionsBytes, conditionsBytes []byte

		err := rows.Scan(
			&wf.ID, &wf.Name, &wf.Description, &wf.EventType, &wf.TriggerType,
			&actionsBytes, &conditionsBytes, &wf.RequireApproval, &wf.ApprovalPolicyID,
			&wf.Enabled, &wf.CreatedBy, &wf.CreatedAt, &wf.UpdatedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan lifecycle workflow: %w", err)
		}

		if actionsBytes != nil {
			if err := json.Unmarshal(actionsBytes, &wf.Actions); err != nil {
				return nil, 0, fmt.Errorf("failed to unmarshal actions: %w", err)
			}
		}
		if conditionsBytes != nil {
			if err := json.Unmarshal(conditionsBytes, &wf.Conditions); err != nil {
				return nil, 0, fmt.Errorf("failed to unmarshal conditions: %w", err)
			}
		}

		workflows = append(workflows, wf)
	}

	if workflows == nil {
		workflows = []LifecycleWorkflow{}
	}

	return workflows, total, nil
}

// GetLifecycleWorkflow returns a single lifecycle workflow by ID
func (s *Service) GetLifecycleWorkflow(ctx context.Context, id string) (*LifecycleWorkflow, error) {
	var wf LifecycleWorkflow
	var actionsBytes, conditionsBytes []byte

	err := s.db.Pool.QueryRow(ctx,
		`SELECT id, name, description, event_type, trigger_type, actions, conditions,
			require_approval, approval_policy_id, enabled, created_by, created_at, updated_at
		 FROM lifecycle_workflows WHERE id = $1`, id,
	).Scan(
		&wf.ID, &wf.Name, &wf.Description, &wf.EventType, &wf.TriggerType,
		&actionsBytes, &conditionsBytes, &wf.RequireApproval, &wf.ApprovalPolicyID,
		&wf.Enabled, &wf.CreatedBy, &wf.CreatedAt, &wf.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get lifecycle workflow: %w", err)
	}

	if actionsBytes != nil {
		if err := json.Unmarshal(actionsBytes, &wf.Actions); err != nil {
			return nil, fmt.Errorf("failed to unmarshal actions: %w", err)
		}
	}
	if conditionsBytes != nil {
		if err := json.Unmarshal(conditionsBytes, &wf.Conditions); err != nil {
			return nil, fmt.Errorf("failed to unmarshal conditions: %w", err)
		}
	}

	return &wf, nil
}

// UpdateLifecycleWorkflow updates an existing lifecycle workflow
func (s *Service) UpdateLifecycleWorkflow(ctx context.Context, wf *LifecycleWorkflow) error {
	wf.UpdatedAt = time.Now()

	actionsJSON, err := json.Marshal(wf.Actions)
	if err != nil {
		return fmt.Errorf("failed to marshal actions: %w", err)
	}

	conditionsJSON, err := json.Marshal(wf.Conditions)
	if err != nil {
		return fmt.Errorf("failed to marshal conditions: %w", err)
	}

	result, err := s.db.Pool.Exec(ctx,
		`UPDATE lifecycle_workflows
		 SET name = $1, description = $2, event_type = $3, trigger_type = $4,
			 actions = $5, conditions = $6, require_approval = $7, approval_policy_id = $8,
			 enabled = $9, updated_at = $10
		 WHERE id = $11`,
		wf.Name, wf.Description, wf.EventType, wf.TriggerType,
		actionsJSON, conditionsJSON, wf.RequireApproval, wf.ApprovalPolicyID,
		wf.Enabled, wf.UpdatedAt, wf.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update lifecycle workflow: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("lifecycle workflow not found")
	}

	return nil
}

// DeleteLifecycleWorkflow deletes a lifecycle workflow by ID
func (s *Service) DeleteLifecycleWorkflow(ctx context.Context, id string) error {
	result, err := s.db.Pool.Exec(ctx, "DELETE FROM lifecycle_workflows WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("failed to delete lifecycle workflow: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("lifecycle workflow not found")
	}

	return nil
}

// ExecuteLifecycleWorkflow runs a workflow against a target user
func (s *Service) ExecuteLifecycleWorkflow(ctx context.Context, workflowID, userID, triggeredBy string) (*LifecycleExecution, error) {
	wf, err := s.GetLifecycleWorkflow(ctx, workflowID)
	if err != nil {
		return nil, fmt.Errorf("failed to get workflow: %w", err)
	}

	if !wf.Enabled {
		return nil, fmt.Errorf("workflow is disabled")
	}

	exec := &LifecycleExecution{
		ID:          uuid.New().String(),
		WorkflowID:  workflowID,
		UserID:      userID,
		TriggerType: wf.TriggerType,
		Status:      "in_progress",
		StartedAt:   time.Now(),
		CreatedAt:   time.Now(),
	}
	if triggeredBy != "" {
		exec.TriggeredBy = &triggeredBy
	}

	// Insert the initial execution record
	_, err = s.db.Pool.Exec(ctx,
		`INSERT INTO lifecycle_executions (id, workflow_id, user_id, triggered_by, trigger_type, status, actions_completed, actions_failed, error, started_at, completed_at, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, '[]'::jsonb, '[]'::jsonb, NULL, $7, NULL, $8)`,
		exec.ID, exec.WorkflowID, exec.UserID, exec.TriggeredBy, exec.TriggerType,
		exec.Status, exec.StartedAt, exec.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create execution record: %w", err)
	}

	var completed []map[string]interface{}
	var failed []map[string]interface{}
	var execErr string

	for _, action := range wf.Actions {
		err := s.executeLifecycleAction(ctx, userID, action)
		if err != nil {
			action["error"] = err.Error()
			failed = append(failed, action)
			s.logger.Error("Lifecycle action failed",
				zap.String("workflow_id", workflowID),
				zap.String("user_id", userID),
				zap.Any("action", action),
				zap.Error(err),
			)
		} else {
			completed = append(completed, action)
		}
	}

	if completed == nil {
		completed = []map[string]interface{}{}
	}
	if failed == nil {
		failed = []map[string]interface{}{}
	}

	exec.ActionsCompleted = completed
	exec.ActionsFailed = failed

	if len(failed) > 0 {
		exec.Status = "failed"
		failMsg := fmt.Sprintf("%d of %d actions failed", len(failed), len(wf.Actions))
		exec.Error = &failMsg
		execErr = failMsg
	} else {
		exec.Status = "completed"
	}

	now := time.Now()
	exec.CompletedAt = &now

	completedJSON, _ := json.Marshal(completed)
	failedJSON, _ := json.Marshal(failed)

	var errPtr *string
	if execErr != "" {
		errPtr = &execErr
	}

	_, err = s.db.Pool.Exec(ctx,
		`UPDATE lifecycle_executions
		 SET status = $1, actions_completed = $2, actions_failed = $3, error = $4, completed_at = $5
		 WHERE id = $6`,
		exec.Status, completedJSON, failedJSON, errPtr, exec.CompletedAt, exec.ID,
	)
	if err != nil {
		s.logger.Error("Failed to update execution record", zap.String("execution_id", exec.ID), zap.Error(err))
	}

	return exec, nil
}

// executeLifecycleAction executes a single lifecycle action against a user
func (s *Service) executeLifecycleAction(ctx context.Context, userID string, action map[string]interface{}) error {
	actionType, ok := action["type"].(string)
	if !ok {
		return fmt.Errorf("action missing 'type' field")
	}

	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	switch actionType {
	case "assign_role":
		roleID, ok := action["role_id"].(string)
		if !ok {
			return fmt.Errorf("assign_role action missing 'role_id'")
		}
		_, err := s.db.Pool.Exec(ctx,
			"INSERT INTO user_roles (user_id, role_id, created_at, org_id) VALUES ($1, $2, NOW(), $3) ON CONFLICT DO NOTHING",
			userID, roleID, org.ID)
		return err

	case "remove_role":
		roleID, ok := action["role_id"].(string)
		if !ok {
			return fmt.Errorf("remove_role action missing 'role_id'")
		}
		_, err := s.db.Pool.Exec(ctx,
			"DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2 AND org_id = $3",
			userID, roleID, org.ID)
		return err

	case "assign_group":
		groupID, ok := action["group_id"].(string)
		if !ok {
			return fmt.Errorf("assign_group action missing 'group_id'")
		}
		_, err := s.db.Pool.Exec(ctx,
			"INSERT INTO group_memberships (id, group_id, user_id, created_at, org_id) VALUES (gen_random_uuid(), $1, $2, NOW(), $3) ON CONFLICT DO NOTHING",
			groupID, userID, org.ID)
		return err

	case "remove_group":
		groupID, ok := action["group_id"].(string)
		if !ok {
			return fmt.Errorf("remove_group action missing 'group_id'")
		}
		_, err := s.db.Pool.Exec(ctx,
			"DELETE FROM group_memberships WHERE group_id = $1 AND user_id = $2 AND org_id = $3",
			groupID, userID, org.ID)
		return err

	case "enable_user":
		_, err := s.db.Pool.Exec(ctx,
			"UPDATE users SET enabled = true, updated_at = NOW() WHERE id = $1 AND org_id = $2",
			userID, org.ID)
		return err

	case "disable_user":
		_, err := s.db.Pool.Exec(ctx,
			"UPDATE users SET enabled = false, updated_at = NOW() WHERE id = $1 AND org_id = $2",
			userID, org.ID)
		return err

	case "revoke_sessions":
		_, err := s.db.Pool.Exec(ctx,
			"DELETE FROM sessions WHERE user_id = $1 AND org_id = $2",
			userID, org.ID)
		return err

	default:
		return fmt.Errorf("unsupported action type: %s", actionType)
	}
}

// ListLifecycleExecutions returns paginated lifecycle executions with optional filters
func (s *Service) ListLifecycleExecutions(ctx context.Context, offset, limit int, workflowID, userID string) ([]LifecycleExecution, int, error) {
	countQuery := "SELECT COUNT(*) FROM lifecycle_executions"
	listQuery := `SELECT id, workflow_id, user_id, triggered_by, trigger_type, status,
		actions_completed, actions_failed, error, started_at, completed_at, created_at
		FROM lifecycle_executions`

	var conditions []string
	var args []interface{}
	argIdx := 1

	if workflowID != "" {
		conditions = append(conditions, fmt.Sprintf("workflow_id = $%d", argIdx))
		args = append(args, workflowID)
		argIdx++
	}
	if userID != "" {
		conditions = append(conditions, fmt.Sprintf("user_id = $%d", argIdx))
		args = append(args, userID)
		argIdx++
	}

	if len(conditions) > 0 {
		whereClause := " WHERE " + strings.Join(conditions, " AND ")
		countQuery += whereClause
		listQuery += whereClause
	}

	var total int
	err := s.db.Pool.QueryRow(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count lifecycle executions: %w", err)
	}

	listQuery += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, limit, offset)

	rows, err := s.db.Pool.Query(ctx, listQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list lifecycle executions: %w", err)
	}
	defer rows.Close()

	var executions []LifecycleExecution
	for rows.Next() {
		var ex LifecycleExecution
		var completedBytes, failedBytes []byte

		err := rows.Scan(
			&ex.ID, &ex.WorkflowID, &ex.UserID, &ex.TriggeredBy, &ex.TriggerType,
			&ex.Status, &completedBytes, &failedBytes, &ex.Error,
			&ex.StartedAt, &ex.CompletedAt, &ex.CreatedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan lifecycle execution: %w", err)
		}

		if completedBytes != nil {
			if err := json.Unmarshal(completedBytes, &ex.ActionsCompleted); err != nil {
				return nil, 0, fmt.Errorf("failed to unmarshal actions_completed: %w", err)
			}
		}
		if failedBytes != nil {
			if err := json.Unmarshal(failedBytes, &ex.ActionsFailed); err != nil {
				return nil, 0, fmt.Errorf("failed to unmarshal actions_failed: %w", err)
			}
		}

		executions = append(executions, ex)
	}

	if executions == nil {
		executions = []LifecycleExecution{}
	}

	return executions, total, nil
}

// GetLifecycleExecution returns a single lifecycle execution by ID
func (s *Service) GetLifecycleExecution(ctx context.Context, id string) (*LifecycleExecution, error) {
	var ex LifecycleExecution
	var completedBytes, failedBytes []byte

	err := s.db.Pool.QueryRow(ctx,
		`SELECT id, workflow_id, user_id, triggered_by, trigger_type, status,
			actions_completed, actions_failed, error, started_at, completed_at, created_at
		 FROM lifecycle_executions WHERE id = $1`, id,
	).Scan(
		&ex.ID, &ex.WorkflowID, &ex.UserID, &ex.TriggeredBy, &ex.TriggerType,
		&ex.Status, &completedBytes, &failedBytes, &ex.Error,
		&ex.StartedAt, &ex.CompletedAt, &ex.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get lifecycle execution: %w", err)
	}

	if completedBytes != nil {
		if err := json.Unmarshal(completedBytes, &ex.ActionsCompleted); err != nil {
			return nil, fmt.Errorf("failed to unmarshal actions_completed: %w", err)
		}
	}
	if failedBytes != nil {
		if err := json.Unmarshal(failedBytes, &ex.ActionsFailed); err != nil {
			return nil, fmt.Errorf("failed to unmarshal actions_failed: %w", err)
		}
	}

	return &ex, nil
}

// HTTP Handlers for Lifecycle Workflows

func (s *Service) handleListLifecycleWorkflows(c *gin.Context) {
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
	eventType := c.Query("event_type")

	workflows, total, err := s.ListLifecycleWorkflows(c.Request.Context(), offset, limit, eventType)
	if err != nil {
		s.logger.Error("failed to list lifecycle workflows", zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.Header("X-Total-Count", strconv.Itoa(total))
	c.JSON(200, workflows)
}

func (s *Service) handleCreateLifecycleWorkflow(c *gin.Context) {
	var wf LifecycleWorkflow
	if err := c.ShouldBindJSON(&wf); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request body: " + err.Error()})
		return
	}

	if wf.Name == "" {
		c.JSON(400, gin.H{"error": "name is required"})
		return
	}
	if wf.EventType == "" {
		c.JSON(400, gin.H{"error": "event_type is required"})
		return
	}
	if wf.TriggerType == "" {
		c.JSON(400, gin.H{"error": "trigger_type is required"})
		return
	}

	if userID, exists := c.Get("user_id"); exists {
		uid := userID.(string)
		wf.CreatedBy = &uid
	}

	if err := s.CreateLifecycleWorkflow(c.Request.Context(), &wf); err != nil {
		s.logger.Error("failed to create lifecycle workflow", zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(201, wf)
}

func (s *Service) handleGetLifecycleWorkflow(c *gin.Context) {
	id := c.Param("id")

	wf, err := s.GetLifecycleWorkflow(c.Request.Context(), id)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			c.JSON(404, gin.H{"error": "Workflow not found"})
			return
		}
		s.logger.Error("failed to get lifecycle workflow", zap.String("id", id), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(200, wf)
}

func (s *Service) handleUpdateLifecycleWorkflow(c *gin.Context) {
	id := c.Param("id")

	var wf LifecycleWorkflow
	if err := c.ShouldBindJSON(&wf); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request body: " + err.Error()})
		return
	}

	wf.ID = id

	if err := s.UpdateLifecycleWorkflow(c.Request.Context(), &wf); err != nil {
		if strings.Contains(err.Error(), "not found") {
			c.JSON(404, gin.H{"error": "Workflow not found"})
			return
		}
		s.logger.Error("failed to update lifecycle workflow", zap.String("id", id), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(200, wf)
}

func (s *Service) handleDeleteLifecycleWorkflow(c *gin.Context) {
	id := c.Param("id")

	if err := s.DeleteLifecycleWorkflow(c.Request.Context(), id); err != nil {
		if strings.Contains(err.Error(), "not found") {
			c.JSON(404, gin.H{"error": "Workflow not found"})
			return
		}
		s.logger.Error("failed to delete lifecycle workflow", zap.String("id", id), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(200, gin.H{"message": "Workflow deleted successfully"})
}

func (s *Service) handleExecuteLifecycleWorkflow(c *gin.Context) {
	workflowID := c.Param("id")

	var req struct {
		UserID string `json:"user_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request body: " + err.Error()})
		return
	}

	if req.UserID == "" {
		c.JSON(400, gin.H{"error": "user_id is required"})
		return
	}

	triggeredBy := ""
	if uid, exists := c.Get("user_id"); exists {
		triggeredBy = uid.(string)
	}

	exec, err := s.ExecuteLifecycleWorkflow(c.Request.Context(), workflowID, req.UserID, triggeredBy)
	if err != nil {
		if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "no rows") {
			c.JSON(404, gin.H{"error": "Workflow not found"})
			return
		}
		if strings.Contains(err.Error(), "disabled") {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
		s.logger.Error("failed to execute lifecycle workflow", zap.String("workflow_id", workflowID), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(200, exec)
}

func (s *Service) handleListLifecycleExecutions(c *gin.Context) {
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
	workflowID := c.Query("workflow_id")
	requestedUserID := c.Query("user_id")
	authUserID := c.GetString("user_id")
	authRoles := c.GetStringSlice("roles")

	// SECURITY: IDOR fix - Only allow admin to query arbitrary users' workflow executions
	if requestedUserID != "" && requestedUserID != authUserID {
		isAdmin := false
		for _, role := range authRoles {
			if role == "admin" || role == "superadmin" {
				isAdmin = true
				break
			}
		}
		if !isAdmin {
			c.JSON(403, gin.H{"error": "insufficient permissions to view other users' executions"})
			return
		}
	}

	executions, total, err := s.ListLifecycleExecutions(c.Request.Context(), offset, limit, workflowID, requestedUserID)
	if err != nil {
		s.logger.Error("failed to list lifecycle executions", zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.Header("X-Total-Count", strconv.Itoa(total))
	c.JSON(200, executions)
}

func (s *Service) handleGetLifecycleExecution(c *gin.Context) {
	id := c.Param("id")

	exec, err := s.GetLifecycleExecution(c.Request.Context(), id)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			c.JSON(404, gin.H{"error": "Execution not found"})
			return
		}
		s.logger.Error("failed to get lifecycle execution", zap.String("id", id), zap.Error(err))
		c.JSON(500, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(200, exec)
}

// logAuditEvent writes an audit event to the audit_events table (best-effort, non-blocking).
// It mirrors the pattern used in the OAuth service.
func (s *Service) logAuditEvent(ctx context.Context, eventType, category, action, outcome, actorID, targetID, targetType string, details map[string]interface{}) {
	// Capture the org synchronously from the request context: the
	// write runs on a detached background context (audit is
	// fire-and-forget), so the tenant must be read before we leave the
	// request. Falls back to the default org UUID when none is
	// resolved, matching the milestone's DefaultOrgFallback semantics.
	orgID := "00000000-0000-0000-0000-000000000010"
	if org, err := orgctx.From(ctx); err == nil && org.ID != "" {
		orgID = org.ID
	}
	// No database configured (unit tests, or a service constructed without a
	// pool): audit is best-effort, so skip rather than nil-panic in a goroutine.
	if s.db == nil || s.db.Pool == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		detailsJSON, _ := json.Marshal(details)
		_, err := s.db.Pool.Exec(ctx, `
			INSERT INTO audit_events (id, timestamp, event_type, category, action, outcome,
			                          actor_id, actor_type, actor_ip, target_id, target_type,
			                          resource_id, details, org_id)
			VALUES (gen_random_uuid(), NOW(), $1, $2, $3, $4, $5, 'user', '', $6, $7, $6, $8, $9)
		`, eventType, category, action, outcome, actorID, targetID, targetType, detailsJSON, orgID)
		if err != nil {
			s.logger.Warn("failed to record audit event",
				zap.String("event_type", eventType),
				zap.String("action", action),
				zap.Error(err))
		}
	}()
}
