// Package oauth provides OAuth 2.0 and OpenID Connect provider functionality
package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"html"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	apperrors "github.com/openidx/openidx/internal/common/errors"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"golang.org/x/oauth2"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/resilience"
	"github.com/openidx/openidx/internal/common/secretcrypt"
	"github.com/openidx/openidx/internal/identity"
	"github.com/openidx/openidx/internal/risk"
	"github.com/openidx/openidx/internal/signingkeys"
)

// OAuthClient represents an OAuth 2.0 client application
type OAuthClient struct {
	ID                   string    `json:"id"`
	ClientID             string    `json:"client_id"`
	ClientSecret         string    `json:"client_secret,omitempty"`
	Name                 string    `json:"name"`
	Description          string    `json:"description"`
	Type                 string    `json:"type"` // confidential, public
	RedirectURIs         []string  `json:"redirect_uris"`
	GrantTypes           []string  `json:"grant_types"`
	ResponseTypes        []string  `json:"response_types"`
	Scopes               []string  `json:"scopes"`
	LogoURI              string    `json:"logo_uri,omitempty"`
	PolicyURI            string    `json:"policy_uri,omitempty"`
	TOSUri               string    `json:"tos_uri,omitempty"`
	PKCERequired         bool      `json:"pkce_required"`
	AllowRefreshToken    bool      `json:"allow_refresh_token"`
	AccessTokenLifetime  int       `json:"access_token_lifetime"`  // seconds
	RefreshTokenLifetime int       `json:"refresh_token_lifetime"` // seconds
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
}

// AuthorizationCode represents an OAuth authorization code
type AuthorizationCode struct {
	Code                string    `json:"code"`
	ClientID            string    `json:"client_id"`
	UserID              string    `json:"user_id"`
	RedirectURI         string    `json:"redirect_uri"`
	Scope               string    `json:"scope"`
	State               string    `json:"state,omitempty"`
	Nonce               string    `json:"nonce,omitempty"`
	CodeChallenge       string    `json:"code_challenge,omitempty"`
	CodeChallengeMethod string    `json:"code_challenge_method,omitempty"`
	ExpiresAt           time.Time `json:"expires_at"`
	CreatedAt           time.Time `json:"created_at"`
}

// AccessToken represents an OAuth access token
type AccessToken struct {
	Token     string    `json:"token"`
	ClientID  string    `json:"client_id"`
	UserID    string    `json:"user_id"`
	Scope     string    `json:"scope"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// RefreshToken represents an OAuth refresh token
type RefreshToken struct {
	Token     string    `json:"token"`
	ClientID  string    `json:"client_id"`
	UserID    string    `json:"user_id"`
	Scope     string    `json:"scope"`
	SessionID string    `json:"session_id,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`

	// FamilyID groups every token descended from one authorization. Rotation
	// carries it forward so a whole chain can be revoked at once when a replay
	// proves the secret leaked.
	FamilyID string `json:"family_id,omitempty"`
	// UsedAt is set when this token is rotated away. A non-nil value on a
	// presented token means someone is replaying it — see detectRefreshReuse.
	UsedAt *time.Time `json:"used_at,omitempty"`
}

// TokenResponse represents an OAuth token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// UserInfo represents OIDC UserInfo response
type UserInfo struct {
	Sub               string `json:"sub"`
	Name              string `json:"name,omitempty"`
	GivenName         string `json:"given_name,omitempty"`
	FamilyName        string `json:"family_name,omitempty"`
	Email             string `json:"email,omitempty"`
	EmailVerified     bool   `json:"email_verified,omitempty"`
	Picture           string `json:"picture,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
}

// OIDCDiscovery represents OpenID Connect discovery document
type OIDCDiscovery struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserInfoEndpoint                  string   `json:"userinfo_endpoint"`
	JwksURI                           string   `json:"jwks_uri"`
	RegistrationEndpoint              string   `json:"registration_endpoint,omitempty"`
	DeviceAuthorizationEndpoint       string   `json:"device_authorization_endpoint,omitempty"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	EndSessionEndpoint                string   `json:"end_session_endpoint,omitempty"`
	BackchannelLogoutSupported        bool     `json:"backchannel_logout_supported,omitempty"`
	BackchannelLogoutSessionSupported bool     `json:"backchannel_logout_session_supported,omitempty"`
}

// Service provides OAuth/OIDC operations
type Service struct {
	db               *database.PostgresDB
	redis            *database.RedisClient
	config           *config.Config
	logger           *zap.Logger
	idpCipher        *secretcrypt.Cipher // decrypts identity_providers.client_secret (social login raw read)
	privateKey       *rsa.PrivateKey
	publicKey        *rsa.PublicKey
	keyStore         *signingkeys.Store
	signer           atomic.Pointer[signerSnapshot]
	issuer           string
	tenantBaseDomain string // when set, JWT iss is derived per-tenant (https://<slug>.<base>)
	// dcrInitialAccessToken gates POST /oauth/register (RFC 7591). Empty = open
	// registration (dev/first-run); set to require a bearer initial access token.
	dcrInitialAccessToken string

	// dcrAllowOpenRegistration must be true for UNAUTHENTICATED registration to be
	// accepted when dcrInitialAccessToken is empty. Default false = closed, so a
	// deployment that sets neither value refuses anonymous client registration.
	dcrAllowOpenRegistration bool
	// ssfReceiverConfig trusts an upstream SSF transmitter's issuer + JWKS for
	// inbound SET validation. Empty = only OpenIDX-issued SETs are accepted.
	ssfReceiverConfig SSFReceiverConfig
	identityService   *identity.Service
	riskService       *risk.Service
	webhookService    WebhookPublisher
	authorizeHandler  *AuthorizeHandler
	// redisBreaker fast-fails Redis-backed revocation checks when Redis is
	// unhealthy, so a Redis brownout doesn't make every token op pay the full
	// 3s read timeout (a latency cliff on the verify/introspect hot path). It is
	// shared per-service and distributed via Redis state when available.
	redisBreaker *resilience.CircuitBreaker

	// clients is the OAuth client data-access port (Repository pattern — see
	// client_repository.go). GetByClientID reads the primary (security), List the
	// replica; writes the primary.
	clients OAuthClientStore
}

// WebhookPublisher defines the interface for publishing webhook events
type WebhookPublisher interface {
	Publish(ctx context.Context, eventType string, payload interface{}) error
}

// SetRiskService sets the risk service for conditional access
func (s *Service) SetRiskService(rs *risk.Service) {
	s.riskService = rs
}

// SetWebhookService sets the webhook service for event publishing
func (s *Service) SetWebhookService(ws WebhookPublisher) {
	s.webhookService = ws
}

// AuthorizeHandler returns the authorization handler
func (s *Service) AuthorizeHandler() *AuthorizeHandler {
	return s.authorizeHandler
}

// NewService creates a new OAuth service
func NewService(db *database.PostgresDB, redis *database.RedisClient, cfg *config.Config, logger *zap.Logger, idSvc *identity.Service) (*Service, error) {
	// Try to load RSA key from database, generate if not found
	var privateKey *rsa.PrivateKey
	var storedRaw string

	// Use timeout context for database operations during initialization
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// The OAuth signing key mints every token in the system — a DB read of a
	// plaintext key means full token forgery. Encrypt it at rest with the same
	// AES-256 cipher used for IdP secrets. Reads tolerate both forms so existing
	// plaintext rows keep working (and are re-encrypted in place below).
	keyCipher, kcerr := secretcrypt.New(cfg.EncryptionKey)
	if kcerr != nil {
		logger.Warn("OAuth signing key will be stored WITHOUT encryption at rest (plaintext); set a 32-byte ENCRYPTION_KEY", zap.Error(kcerr))
		keyCipher = secretcrypt.NewNoop()
	}

	err := db.Pool.QueryRow(ctx,
		"SELECT value::text FROM system_settings WHERE key = 'oauth_rsa_private_key'").Scan(&storedRaw)
	storedWasPlaintext := false
	if err == nil && len(storedRaw) > 0 {
		// value is stored as a JSON string, strip quotes
		stored := strings.Trim(storedRaw, "\"")
		var keyPEMStr string
		if secretcrypt.IsEncrypted(stored) {
			// Ciphertext: decrypt to recover the exact PEM (real newlines).
			if dec, derr := keyCipher.Decrypt(stored); derr == nil {
				keyPEMStr = dec
			} else {
				logger.Warn("Failed to decrypt stored RSA key, generating new one", zap.Error(derr))
			}
		} else {
			// Legacy plaintext JSON string: unescape the PEM newlines.
			keyPEMStr = strings.ReplaceAll(stored, "\\n", "\n")
			storedWasPlaintext = true
		}
		if keyPEMStr != "" {
			block, _ := pem.Decode([]byte(keyPEMStr))
			if block != nil {
				privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
				if err != nil {
					logger.Warn("Failed to parse stored RSA key, generating new one", zap.Error(err))
					privateKey = nil
				}
			}
		}
	}

	// The rotatable key set lives in oauth_signing_keys (v79). A legacy
	// system_settings key (loaded above) is imported under its original kid
	// on first boot so outstanding tokens keep verifying; after that the
	// settings row is vestigial and no longer written.
	keyStore := signingkeys.NewStore(db.Pool, cfg.EncryptionKey, logger)
	activeKey, err := keyStore.EnsureActive(ctx, privateKey)
	if err != nil {
		return nil, fmt.Errorf("ensure active signing key: %w", err)
	}
	if privateKey != nil && activeKey.Kid == signingkeys.LegacyKid && storedWasPlaintext {
		logger.Info("Imported legacy plaintext OAuth signing key into oauth_signing_keys (encrypted at rest)")
	}
	privateKey = activeKey.Private
	logger.Info("OAuth signing key loaded", zap.String("kid", activeKey.Kid))

	// Use configured issuer URL or fall back to default
	issuer := cfg.OAuthIssuer
	if issuer == "" {
		issuer = "http://localhost:8006"
	}

	idpCipher, cerr := secretcrypt.New(cfg.EncryptionKey)
	if cerr != nil {
		logger.Warn("IdP client secrets will NOT be decrypted for social login (plaintext at rest); set a 32-byte ENCRYPTION_KEY", zap.Error(cerr))
		idpCipher = secretcrypt.NewNoop()
	}

	svc := &Service{
		db:                       db,
		redis:                    redis,
		config:                   cfg,
		logger:                   logger.With(zap.String("service", "oauth")),
		idpCipher:                idpCipher,
		privateKey:               privateKey,
		publicKey:                &privateKey.PublicKey,
		keyStore:                 keyStore,
		issuer:                   issuer,
		tenantBaseDomain:         cfg.TenantBaseDomain,
		dcrInitialAccessToken:    cfg.DCRInitialAccessToken,
		dcrAllowOpenRegistration: cfg.DCRAllowOpenRegistration,
		ssfReceiverConfig:        SSFReceiverConfig{Issuer: cfg.SSFReceiverIssuer, JWKSURL: cfg.SSFReceiverJWKSURL},
		identityService:          idSvc,
	}

	// Initialize authorize handler
	svc.authorizeHandler = NewAuthorizeHandler(svc, svc.logger)

	// OAuth client data-access repository (Repository pattern — see
	// client_repository.go).
	svc.clients = NewPostgresOAuthClientStore(db)

	// Circuit breaker for Redis-backed revocation checks: after 5 consecutive
	// failures, fast-fail for 5s instead of paying the Redis read timeout on
	// every request during a Redis brownout. State is shared across replicas via
	// Redis when a client is available.
	breakerCfg := resilience.CircuitBreakerConfig{
		Name:         "oauth-redis-revocation",
		Threshold:    5,
		ResetTimeout: 5 * time.Second,
		Logger:       svc.logger,
	}
	if redis != nil {
		breakerCfg.RedisClient = redis.Client
	}
	svc.redisBreaker = resilience.NewCircuitBreaker(breakerCfg)

	// Build the signing snapshot (active key + verification set + JWKS) and
	// keep it fresh so rotations by the admin service take effect without a
	// restart.
	if err := svc.refreshSigner(ctx); err != nil {
		return nil, fmt.Errorf("load signing key set: %w", err)
	}
	go svc.signerRefreshLoop(context.Background(), 5*time.Minute)

	return svc, nil
}

// getBlockedCountries returns the list of blocked country codes from system settings.
// Results are cached in Redis for 5 minutes. Returns nil on any error (fail-open).
func (s *Service) getBlockedCountries(ctx context.Context) []string {
	// Check Redis cache
	cacheKey := "oauth:blocked_countries"
	cached, err := s.redis.Client.Get(ctx, cacheKey).Result()
	if err == nil {
		var countries []string
		if json.Unmarshal([]byte(cached), &countries) == nil {
			return countries
		}
	}

	// Cache miss — query system_settings table
	var valueBytes []byte
	err = s.db.Pool.QueryRow(ctx,
		"SELECT value FROM system_settings WHERE key = 'system'").Scan(&valueBytes)
	if err != nil {
		s.logger.Debug("Failed to load system settings for country block", zap.Error(err))
		return nil
	}

	var settings struct {
		Security struct {
			BlockedCountries []string `json:"blocked_countries"`
		} `json:"security"`
	}
	if err := json.Unmarshal(valueBytes, &settings); err != nil {
		s.logger.Debug("Failed to parse system settings for country block", zap.Error(err))
		return nil
	}

	// Cache for 5 minutes
	if data, err := json.Marshal(settings.Security.BlockedCountries); err == nil {
		s.redis.Client.Set(ctx, cacheKey, string(data), 5*time.Minute)
	}

	return settings.Security.BlockedCountries
}

// checkCountryBlock checks if a login attempt should be blocked based on the client's country.
// Returns a non-nil error if the country is blocked. Fails open on lookup errors.
func (s *Service) checkCountryBlock(ctx context.Context, clientIP, userID, username string) error {
	if s.riskService == nil {
		return nil
	}

	blockedCountries := s.getBlockedCountries(ctx)
	if len(blockedCountries) == 0 {
		return nil
	}

	geo, err := s.riskService.GeoIPLookup(ctx, clientIP)
	if err != nil || geo == nil || geo.CountryCode == "" {
		s.logger.Debug("Geo-IP lookup unavailable, allowing login",
			zap.String("ip", clientIP), zap.Error(err))
		return nil
	}

	for _, blocked := range blockedCountries {
		if strings.EqualFold(blocked, geo.CountryCode) {
			// Log audit event in background with timeout
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				s.logAuditEvent(ctx, "authentication", "security",
					"login_blocked_country", "failure", userID, clientIP, userID, "user",
					map[string]interface{}{
						"username":     username,
						"country_code": geo.CountryCode,
						"country":      geo.Country,
						"city":         geo.City,
						"reason":       "country_blocked",
					})
			}()

			s.logger.Warn("Login blocked: country restriction",
				zap.String("user_id", userID),
				zap.String("username", username),
				zap.String("country_code", geo.CountryCode),
				zap.String("country", geo.Country),
				zap.String("ip", clientIP),
			)

			return fmt.Errorf("access denied from your location")
		}
	}

	return nil
}

// OAuth Client Management

// CreateClient creates a new OAuth client
func (s *Service) CreateClient(ctx context.Context, client *OAuthClient) error {
	s.logger.Info("Creating OAuth client", zap.String("name", client.Name))
	// Persistence in the repository (primary pool) — see client_repository.go.
	return s.clients.Create(ctx, client)
}

// GetClient retrieves an OAuth client by client ID
func (s *Service) GetClient(ctx context.Context, clientID string) (*OAuthClient, error) {
	// Repo reads the PRIMARY here: client validation gates every token grant and
	// checks the secret, so a just-rotated/disabled client must be seen at once.
	return s.clients.GetByClientID(ctx, clientID)
}

// ListClients retrieves all OAuth clients
func (s *Service) ListClients(ctx context.Context, offset, limit int) ([]OAuthClient, int, error) {
	// Repo reads the replica (admin/dashboard, lag-tolerant).
	return s.clients.List(ctx, offset, limit)
}

// UpdateClient updates an OAuth client
func (s *Service) UpdateClient(ctx context.Context, clientID string, client *OAuthClient) error {
	s.logger.Info("Updating OAuth client", zap.String("client_id", clientID))
	return s.clients.Update(ctx, clientID, client)
}

// DeleteClient deletes an OAuth client
func (s *Service) DeleteClient(ctx context.Context, clientID string) error {
	s.logger.Info("Deleting OAuth client", zap.String("client_id", clientID))
	return s.clients.Delete(ctx, clientID)
}

// Authorization Flow

// CreateAuthorizationCode creates an authorization code
func (s *Service) CreateAuthorizationCode(ctx context.Context, code *AuthorizationCode) error {
	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	code.ExpiresAt = time.Now().Add(10 * time.Minute)
	code.CreatedAt = time.Now()

	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO oauth_authorization_codes (
			code, client_id, user_id, redirect_uri, scope, state, nonce,
			code_challenge, code_challenge_method, expires_at, created_at, org_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`, code.Code, code.ClientID, code.UserID, code.RedirectURI, code.Scope,
		code.State, code.Nonce, code.CodeChallenge, code.CodeChallengeMethod,
		code.ExpiresAt, code.CreatedAt, org.ID)

	return err
}

// GetAuthorizationCode retrieves and validates an authorization code
func (s *Service) GetAuthorizationCode(ctx context.Context, code string) (*AuthorizationCode, error) {
	var authCode AuthorizationCode

	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	err = s.db.Pool.QueryRow(ctx, `
		SELECT code, client_id, user_id, redirect_uri, scope, state, nonce,
		       code_challenge, code_challenge_method, expires_at, created_at
		FROM oauth_authorization_codes WHERE code = $1 AND org_id = $2
	`, code, org.ID).Scan(
		&authCode.Code, &authCode.ClientID, &authCode.UserID, &authCode.RedirectURI,
		&authCode.Scope, &authCode.State, &authCode.Nonce, &authCode.CodeChallenge,
		&authCode.CodeChallengeMethod, &authCode.ExpiresAt, &authCode.CreatedAt,
	)

	if err != nil {
		return nil, err
	}

	// Check if expired
	if time.Now().After(authCode.ExpiresAt) {
		return nil, fmt.Errorf("authorization code expired")
	}

	return &authCode, nil
}

// ConsumeAuthorizationCode atomically retrieves and deletes an authorization code (single use).
// This prevents replay attacks by ensuring the code can only be used once.
func (s *Service) ConsumeAuthorizationCode(ctx context.Context, code string) (*AuthorizationCode, error) {
	var authCode AuthorizationCode
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}
	err = s.db.Pool.QueryRow(ctx, `
		DELETE FROM oauth_authorization_codes WHERE code = $1 AND org_id = $2
		RETURNING code, client_id, user_id, redirect_uri, scope, state, nonce,
		          code_challenge, code_challenge_method, expires_at, created_at
	`, code, org.ID).Scan(
		&authCode.Code, &authCode.ClientID, &authCode.UserID, &authCode.RedirectURI,
		&authCode.Scope, &authCode.State, &authCode.Nonce, &authCode.CodeChallenge,
		&authCode.CodeChallengeMethod, &authCode.ExpiresAt, &authCode.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	// Check if expired
	if time.Now().After(authCode.ExpiresAt) {
		return nil, fmt.Errorf("authorization code expired")
	}

	return &authCode, nil
}

// DeleteAuthorizationCode deletes an authorization code (single use)
func (s *Service) DeleteAuthorizationCode(ctx context.Context, code string) error {
	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}
	_, err = s.db.Pool.Exec(ctx, "DELETE FROM oauth_authorization_codes WHERE code = $1 AND org_id = $2", code, org.ID)
	return err
}

// Token Management

// CreateAccessToken creates a new access token
func (s *Service) CreateAccessToken(ctx context.Context, token *AccessToken) error {
	token.CreatedAt = time.Now()

	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO oauth_access_tokens (token, client_id, user_id, scope, expires_at, created_at, org_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, token.Token, token.ClientID, token.UserID, token.Scope, token.ExpiresAt, token.CreatedAt, org.ID)

	return err
}

// CreateRefreshToken creates a new refresh token
func (s *Service) CreateRefreshToken(ctx context.Context, token *RefreshToken) error {
	token.CreatedAt = time.Now()

	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	// Store NULL for empty session_id
	var sessionID interface{}
	if token.SessionID != "" {
		sessionID = token.SessionID
	}

	// A token with no family starts its own: the first token of an
	// authorization, or one issued before migration v122.
	familyID := token.FamilyID
	if familyID == "" {
		familyID = uuid.New().String()
		token.FamilyID = familyID
	}

	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO oauth_refresh_tokens (token, client_id, user_id, scope, session_id, expires_at, created_at, org_id, family_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, token.Token, token.ClientID, token.UserID, token.Scope, sessionID, token.ExpiresAt, token.CreatedAt, org.ID, familyID)

	return err
}

// GetRefreshToken retrieves a refresh token
func (s *Service) GetRefreshToken(ctx context.Context, token string) (*RefreshToken, error) {
	var refreshToken RefreshToken
	var sessionID *string

	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	// A rotated (used_at) token is deliberately still returned: the caller has
	// to see it in order to recognise a replay. Only an explicitly revoked
	// token is filtered out here, because that one carries no new information.
	var familyID *string
	err = s.db.Pool.QueryRow(ctx, `
		SELECT token, client_id, user_id, scope, session_id, expires_at, created_at, family_id, used_at
		FROM oauth_refresh_tokens WHERE token = $1 AND org_id = $2 AND revoked_at IS NULL
	`, token, org.ID).Scan(
		&refreshToken.Token, &refreshToken.ClientID, &refreshToken.UserID,
		&refreshToken.Scope, &sessionID, &refreshToken.ExpiresAt, &refreshToken.CreatedAt,
		&familyID, &refreshToken.UsedAt,
	)

	if err != nil {
		return nil, err
	}

	if sessionID != nil {
		refreshToken.SessionID = *sessionID
	}
	if familyID != nil {
		refreshToken.FamilyID = *familyID
	}

	if time.Now().After(refreshToken.ExpiresAt) {
		return nil, fmt.Errorf("refresh token expired")
	}

	return &refreshToken, nil
}

// RevokeRefreshToken revokes a refresh token
func (s *Service) RevokeRefreshToken(ctx context.Context, token string) error {
	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}
	// Marked, not deleted. A deleted token is indistinguishable from one that
	// never existed, which is precisely what made refresh-token theft invisible
	// before reuse detection: the replay came back as a plain invalid_grant.
	// The row ages out with its own expires_at.
	_, err = s.db.Pool.Exec(ctx,
		"UPDATE oauth_refresh_tokens SET revoked_at = NOW() WHERE token = $1 AND org_id = $2 AND revoked_at IS NULL",
		token, org.ID)
	return err
}

// handleRefreshTokenReuse responds to a proven refresh-token replay: revoke the
// whole family, kill the linked session, and leave a record.
//
// The logging is deliberately loud. Reuse detection is one of the few signals
// that distinguishes "a token leaked" from ordinary client misbehavior, and
// before this existed the event produced a single indistinguishable
// invalid_grant — an operator had no way to know a refresh token had been
// stolen. Errors here are logged rather than returned: the caller has already
// decided to reject the request, and a failure to clean up must not turn into a
// 500 that hides the security event.
func (s *Service) handleRefreshTokenReuse(ctx context.Context, token *RefreshToken, clientID string) {
	revoked := int64(0)
	if token.FamilyID != "" {
		n, err := s.revokeRefreshTokenFamily(ctx, token.FamilyID)
		if err != nil {
			s.logger.Error("refresh reuse: failed to revoke token family",
				zap.String("family_id", token.FamilyID), zap.Error(err))
		}
		revoked = n
	} else {
		// Issued before migration v122, so it has no family. Revoke what we can.
		if err := s.RevokeRefreshToken(ctx, token.Token); err != nil {
			s.logger.Error("refresh reuse: failed to revoke token", zap.Error(err))
		}
	}

	// The session behind the chain is as compromised as the tokens.
	if token.SessionID != "" && s.redis != nil {
		if err := s.redis.Client.Set(ctx,
			"revoked_session:"+token.SessionID, "refresh_reuse", 24*time.Hour).Err(); err != nil {
			s.logger.Error("refresh reuse: failed to revoke session",
				zap.String("session_id", token.SessionID), zap.Error(err))
		}
	}

	s.logger.Warn("SECURITY: refresh token reuse detected — token family revoked",
		zap.String("client_id", sanitizeForLog(clientID)),
		zap.String("user_id", sanitizeForLog(token.UserID)),
		zap.String("family_id", sanitizeForLog(token.FamilyID)),
		zap.String("session_id", sanitizeForLog(token.SessionID)),
		zap.Int64("tokens_revoked", revoked),
		zap.Timep("rotated_at", token.UsedAt))

	if s.webhookService != nil {
		s.webhookService.Publish(ctx, "oauth.refresh_token.reuse_detected", map[string]interface{}{
			"user_id":        token.UserID,
			"client_id":      clientID,
			"family_id":      token.FamilyID,
			"session_id":     token.SessionID,
			"tokens_revoked": revoked,
		})
	}
}

// markRefreshTokenRotated tombstones a token that has just been exchanged for a
// successor, leaving it present but spent.
//
// The UPDATE is conditional on used_at IS NULL and reports whether it matched,
// which makes rotation the point where a race is settled: if two requests
// present the same refresh token concurrently, exactly one wins the update and
// the loser is treated as a replay. Doing the check in SQL rather than in Go
// avoids a read-then-write window an attacker could aim for deliberately.
func (s *Service) markRefreshTokenRotated(ctx context.Context, token string) (bool, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return false, err
	}
	tag, err := s.db.Pool.Exec(ctx,
		"UPDATE oauth_refresh_tokens SET used_at = NOW() WHERE token = $1 AND org_id = $2 AND used_at IS NULL",
		token, org.ID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// revokeRefreshTokenFamily revokes every token descended from one authorization.
//
// This is the response to a proven replay. Revoking only the presented token
// would leave the *other* holder — quite possibly the attacker, since the
// legitimate client is the one that noticed something was wrong — with a
// working chain. RFC 6819 §5.2.2.3 is explicit that the server cannot tell the
// two apart, so both lose and the user re-authenticates.
//
// A token predating migration v122 may have no family; the caller falls back to
// revoking the single token in that case.
func (s *Service) revokeRefreshTokenFamily(ctx context.Context, familyID string) (int64, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return 0, err
	}
	tag, err := s.db.Pool.Exec(ctx,
		"UPDATE oauth_refresh_tokens SET revoked_at = NOW() WHERE family_id = $1 AND org_id = $2 AND revoked_at IS NULL",
		familyID, org.ID)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// accessTokenBlacklistKey returns the Redis key used to mark a given access
// token as revoked. The token is hashed (not stored verbatim) so the key
// stays bounded and we don't keep raw bearer tokens around in Redis.
func accessTokenBlacklistKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return "oauth:revoked_access_token:" + hex.EncodeToString(sum[:])
}

// userTokensRevokedAtKey returns the Redis key recording the most recent
// "revoke everything for this user" timestamp. Any access token whose `iat`
// is older than the value at this key is considered revoked.
func userTokensRevokedAtKey(userID string) string {
	return "oauth:user_tokens_revoked_at:" + userID
}

// MarkAccessTokenRevoked adds an access token to the revocation blacklist.
// `expiresAt` is used as the Redis TTL — once the token would have expired on
// its own, the blacklist entry can be garbage-collected. If Redis is
// unavailable the call returns the underlying error; callers should still
// invalidate any DB-side refresh-token row separately.
func (s *Service) MarkAccessTokenRevoked(ctx context.Context, token string, expiresAt time.Time) error {
	if s.redis == nil || s.redis.Client == nil {
		return fmt.Errorf("redis not configured for token revocation")
	}
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		// Token has already expired — nothing to blacklist; treat as success.
		return nil
	}
	return s.redis.Client.Set(ctx, accessTokenBlacklistKey(token), "1", ttl).Err()
}

// MarkUserTokensRevoked records a per-user "revoke everything issued so far"
// marker. IsAccessTokenRevoked treats any access token with `iat` ≤ this
// timestamp as revoked, which is how /oauth/logout-all invalidates every
// outstanding access token at once without enumerating them.
func (s *Service) MarkUserTokensRevoked(ctx context.Context, userID string) error {
	if s.redis == nil || s.redis.Client == nil {
		return fmt.Errorf("redis not configured for token revocation")
	}
	// 7 days is comfortably longer than the configured access-token lifetime
	// (3600s by default) and bounds memory at one short string per user.
	return s.redis.Client.Set(ctx, userTokensRevokedAtKey(userID),
		strconv.FormatInt(time.Now().Unix(), 10), 7*24*time.Hour).Err()
}

// IsAccessTokenRevoked returns true when either (a) the token's own
// blacklist entry exists, or (b) the user's "revoke everything before
// timestamp T" marker is newer than the token's `iat`. When Redis is
// unavailable it returns the error so the caller can fail closed.
//
// The Redis reads run through a circuit breaker: after repeated Redis failures
// the breaker opens and this returns fast (an error) instead of every request
// paying the Redis read timeout during a brownout. Callers already fail closed
// on error, so opening the breaker is safe — it just makes the failure cheap.
func (s *Service) IsAccessTokenRevoked(ctx context.Context, token string, userID string, issuedAt int64) (bool, error) {
	if s.redis == nil || s.redis.Client == nil {
		return false, fmt.Errorf("redis not configured for token revocation")
	}

	var revoked bool
	err := s.revocationBreakerExec(func() error {
		// Per-token blacklist (set by /oauth/revoke and /oauth/logout).
		if n, err := s.redis.Client.Exists(ctx, accessTokenBlacklistKey(token)).Result(); err != nil {
			return err
		} else if n > 0 {
			revoked = true
			return nil
		}

		// Per-user "revoke everything before now" marker (set by /oauth/logout-all).
		if userID != "" && issuedAt > 0 {
			v, err := s.redis.Client.Get(ctx, userTokensRevokedAtKey(userID)).Result()
			if err != nil && !errors.Is(err, redis.Nil) {
				return err
			}
			if v != "" {
				cutoff, perr := strconv.ParseInt(v, 10, 64)
				// `<=` means "tokens issued in the same wall-clock second as
				// (or before) the logout-all call are revoked." This is the
				// right semantic for /oauth/logout-all: every outstanding
				// access token that existed at the moment the user said
				// "kill everything" should stop working — including ones
				// issued in the very same second. The previous
				// inter-subtest-pollution worry about `handleLogout` bumping
				// the cutoff went away when handleLogout switched to a
				// per-token blacklist for single-session logout (only
				// logout-all bumps the cutoff now).
				if perr == nil && issuedAt <= cutoff {
					revoked = true
				}
			}
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	return revoked, nil
}

// revocationBreakerExec runs a Redis revocation read through the circuit
// breaker when one is configured, otherwise runs it directly. Redis.Nil
// (key-miss) is handled inside fn and never surfaces as a breaker failure.
func (s *Service) revocationBreakerExec(fn func() error) error {
	if s.redisBreaker == nil {
		return fn()
	}
	return s.redisBreaker.ExecuteError(fn)
}

// JWT Token Generation

// issuerForOrg returns the JWT issuer for the given org. In a multi-tenant
// subdomain deployment (tenantBaseDomain set) each tenant gets its own issuer
// (https://<slug>.<base>) so tokens are bound to the tenant that minted them.
// The default org and single-tenant installs (no base domain) keep the global
// issuer, so this is a no-op unless subdomain tenancy is configured.
func (s *Service) issuerForOrg(org orgctx.Org) string {
	if s.tenantBaseDomain != "" && org.Slug != "" && org.Slug != "default" {
		return "https://" + org.Slug + "." + s.tenantBaseDomain
	}
	return s.issuer
}

// GenerateJWT generates a signed JWT access token
func (s *Service) GenerateJWT(ctx context.Context, userID, clientID, scope string, expiresIn int, sessionID ...string) (string, error) {
	now := time.Now()

	org, err := orgctx.From(ctx)
	if err != nil {
		return "", err
	}

	// Get user info for access token
	var email, firstName, lastName string
	if userID != "" {
		_ = s.db.Pool.QueryRow(ctx, `
			SELECT COALESCE(email, ''), COALESCE(first_name, ''), COALESCE(last_name, '')
			FROM users WHERE id = $1 AND org_id = $2
		`, userID, org.ID).Scan(&email, &firstName, &lastName)
	}

	name := firstName
	if lastName != "" {
		name = firstName + " " + lastName
	}

	// Get user roles (excluding expired time-bound assignments)
	roleNames := make([]string, 0)
	if userID != "" {
		rows, err := s.db.Pool.Query(ctx, `
			SELECT r.name
			FROM roles r
			JOIN user_roles ur ON r.id = ur.role_id
			WHERE ur.user_id = $1 AND ur.org_id = $2
			AND (ur.expires_at IS NULL OR ur.expires_at > NOW())
		`, userID, org.ID)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var roleName string
				if err := rows.Scan(&roleName); err == nil {
					roleNames = append(roleNames, roleName)
				}
			}
		}
	}

	// Get user groups
	groupNames := make([]string, 0)
	if userID != "" {
		gRows, err := s.db.Pool.Query(ctx, `
			SELECT g.name FROM groups g
			JOIN group_memberships gm ON g.id = gm.group_id
			WHERE gm.user_id = $1 AND gm.org_id = $2
		`, userID, org.ID)
		if err == nil {
			defer gRows.Close()
			for gRows.Next() {
				var gn string
				if err := gRows.Scan(&gn); err == nil {
					groupNames = append(groupNames, gn)
				}
			}
		}
	}

	// Get effective permissions (resource:action pairs)
	permStrings := make([]string, 0)
	if userID != "" {
		pRows, err := s.db.Pool.Query(ctx, `
			SELECT DISTINCT p.resource || ':' || p.action
			FROM permissions p
			JOIN role_permissions rp ON p.id = rp.permission_id
			JOIN user_roles ur ON ur.role_id = rp.role_id
			WHERE ur.user_id = $1 AND ur.org_id = $2
			AND (ur.expires_at IS NULL OR ur.expires_at > NOW())
		`, userID, org.ID)
		if err == nil {
			defer pRows.Close()
			for pRows.Next() {
				var ps string
				if err := pRows.Scan(&ps); err == nil {
					permStrings = append(permStrings, ps)
				}
			}
		}
	}

	claims := jwt.MapClaims{
		"sub":         userID,
		"aud":         clientID,
		"client_id":   clientID,
		"scope":       scope,
		"iss":         s.issuerForOrg(org),
		"iat":         now.Unix(),
		"exp":         now.Add(time.Duration(expiresIn) * time.Second).Unix(),
		"email":       email,
		"name":        name,
		"roles":       roleNames,
		"groups":      groupNames,
		"permissions": permStrings,
	}

	// Add session ID claim if provided
	if len(sessionID) > 0 && sessionID[0] != "" {
		claims["sid"] = sessionID[0]
	}

	kid, signKey := s.signingKey()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	return token.SignedString(signKey)
}

// GenerateIDToken generates an OIDC ID token
func (s *Service) GenerateIDToken(ctx context.Context, userID, clientID, nonce string, expiresIn int, sessionID ...string) (string, error) {
	now := time.Now()

	org, err := orgctx.From(ctx)
	if err != nil {
		return "", err
	}

	// Get user info
	var email, firstName, lastName string
	_ = s.db.Pool.QueryRow(ctx, `
		SELECT email, first_name, last_name FROM users WHERE id = $1 AND org_id = $2
	`, userID, org.ID).Scan(&email, &firstName, &lastName)

	name := firstName
	if lastName != "" {
		name = firstName + " " + lastName
	}

	// Get user roles (excluding expired time-bound assignments)
	roleNames := make([]string, 0)
	rows, err := s.db.Pool.Query(ctx, `
		SELECT r.name
		FROM roles r
		JOIN user_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = $1 AND ur.org_id = $2
		AND (ur.expires_at IS NULL OR ur.expires_at > NOW())
	`, userID, org.ID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var roleName string
			if err := rows.Scan(&roleName); err == nil {
				roleNames = append(roleNames, roleName)
			}
		}
	}

	// Get user groups
	groupNames := make([]string, 0)
	gRows, gErr := s.db.Pool.Query(ctx, `
		SELECT g.name FROM groups g
		JOIN group_memberships gm ON g.id = gm.group_id
		WHERE gm.user_id = $1 AND gm.org_id = $2
	`, userID, org.ID)
	if gErr == nil {
		defer gRows.Close()
		for gRows.Next() {
			var gn string
			if gRows.Scan(&gn) == nil {
				groupNames = append(groupNames, gn)
			}
		}
	}

	// Get effective permissions
	permStrings := make([]string, 0)
	pRows, pErr := s.db.Pool.Query(ctx, `
		SELECT DISTINCT p.resource || ':' || p.action
		FROM permissions p
		JOIN role_permissions rp ON p.id = rp.permission_id
		JOIN user_roles ur ON ur.role_id = rp.role_id
		WHERE ur.user_id = $1 AND ur.org_id = $2
		AND (ur.expires_at IS NULL OR ur.expires_at > NOW())
	`, userID, org.ID)
	if pErr == nil {
		defer pRows.Close()
		for pRows.Next() {
			var ps string
			if pRows.Scan(&ps) == nil {
				permStrings = append(permStrings, ps)
			}
		}
	}

	claims := jwt.MapClaims{
		// Pairwise when OIDCPairwiseSubjects is on (OIDC Core §8.1); the raw
		// user id otherwise. UserInfo derives the same value so the two agree.
		"sub":         s.subjectFor(userID, clientID),
		"aud":         clientID,
		"iss":         s.issuerForOrg(org),
		"iat":         now.Unix(),
		"exp":         now.Add(time.Duration(expiresIn) * time.Second).Unix(),
		"email":       email,
		"name":        name,
		"given_name":  firstName,
		"family_name": lastName,
		"roles":       roleNames,
		"groups":      groupNames,
		"permissions": permStrings,
	}

	if nonce != "" {
		claims["nonce"] = nonce
	}

	// Add session ID claim if provided
	if len(sessionID) > 0 && sessionID[0] != "" {
		claims["sid"] = sessionID[0]
	}

	kid, signKey := s.signingKey()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	return token.SignedString(signKey)
}

// GetUserInfo retrieves user information for UserInfo endpoint
func (s *Service) GetUserInfo(ctx context.Context, userID string) (*UserInfo, error) {
	var email, firstName, lastName string
	var emailVerified bool

	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	err = s.db.Pool.QueryRow(ctx, `
		SELECT email, first_name, last_name, email_verified
		FROM users WHERE id = $1 AND org_id = $2
	`, userID, org.ID).Scan(&email, &firstName, &lastName, &emailVerified)

	if err != nil {
		return nil, err
	}

	name := firstName
	if lastName != "" {
		name = firstName + " " + lastName
	}

	return &UserInfo{
		Sub:               userID,
		Email:             email,
		EmailVerified:     emailVerified,
		Name:              name,
		GivenName:         firstName,
		FamilyName:        lastName,
		PreferredUsername: email,
	}, nil
}

// Utility Functions

// GenerateRandomToken generates a cryptographically secure random token.
// It uses crypto/rand for security and panics if the CSPRNG fails.
// In a properly configured system, crypto/rand should never fail.
// For code that needs explicit error handling, use GenerateRandomTokenSafe.
func GenerateRandomToken(length int) string {
	token, err := GenerateRandomTokenSafe(length)
	if err != nil {
		// If crypto/rand fails, it's a critical system failure.
		// Panicking is safer than continuing with weak tokens.
		panic("crypto/rand failed: " + err.Error())
	}
	return token
}

// GenerateRandomTokenSafe generates a cryptographically secure random token.
// Returns an error if the CSPRNG fails. Use this function when you need
// explicit error handling instead of panicking on failure.
func GenerateRandomTokenSafe(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("invalid token length: %d", length)
	}
	if length > 4096 {
		return "", fmt.Errorf("token length too large: %d (max 4096)", length)
	}
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to read random bytes: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// VerifyPKCE verifies PKCE code challenge
func VerifyPKCE(codeVerifier, codeChallenge, method string) bool {
	if method == "S256" {
		hash := sha256.Sum256([]byte(codeVerifier))
		computed := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(hash[:])
		return computed == codeChallenge
	}
	// Plain method
	return codeVerifier == codeChallenge
}

// HTTP Handlers

// RegisterRoutes registers OAuth/OIDC routes.
// authMiddleware is optional; when provided it protects the client management API and consent endpoint.
// RegisterRoutes wires the oauth-service HTTP routes.
//
// clientMgmtAuth guards the /api/v1/oauth/clients management API and is
// ALWAYS required — these endpoints create and modify OAuth clients, so they
// must be authenticated in every environment (a nil here is a programmer error
// and intentionally panics at request time rather than silently exposing the
// API). The variadic flowAuth is applied to the interactive OIDC flow
// endpoints (consent, step-up) only when supplied; callers omit it in
// development to keep the local login flow friction-free.
func RegisterRoutes(router *gin.Engine, svc *Service, clientMgmtAuth gin.HandlerFunc, flowAuth ...gin.HandlerFunc) {
	// OIDC Discovery - include OPTIONS for CORS preflight (required for BrowZer and browser-based OIDC clients)
	router.GET("/.well-known/openid-configuration", svc.handleDiscovery)
	router.OPTIONS("/.well-known/openid-configuration", svc.handleDiscovery)
	router.GET("/.well-known/jwks.json", svc.handleJWKS)
	router.OPTIONS("/.well-known/jwks.json", svc.handleJWKS)

	// SSF/CAEP (Shared Signals): transmitter metadata + stream management +
	// receiver push endpoint.
	router.GET("/.well-known/ssf-configuration", svc.handleSSFConfiguration)
	// Stream management is tenant-scoped administration: a stream carries a
	// delivery_endpoint that receives this org's security events (session
	// revoked, credential change), so an unauthenticated caller must never be
	// able to enumerate, create or delete one. Gated with the same middleware
	// as the client-management API.
	ssfAdmin := router.Group("/ssf")
	ssfAdmin.Use(clientMgmtAuth)
	{
		ssfAdmin.GET("/streams", svc.handleListSSFStreams)
		ssfAdmin.POST("/streams", svc.handleCreateSSFStream)
		ssfAdmin.GET("/streams/:id", svc.handleGetSSFStream)
		ssfAdmin.DELETE("/streams/:id", svc.handleDeleteSSFStream)
		ssfAdmin.POST("/streams/:id/verify", svc.handleSSFVerify)
	}
	// Receiver push delivery (RFC 8935) stays public: inbound SETs are
	// authenticated by their signature, not by a session.
	router.POST("/ssf/events", svc.handleSSFReceive)

	oauth := router.Group("/oauth")
	{
		// Authorization endpoint (legacy - using original implementation)
		oauth.GET("/authorize", svc.handleAuthorize)

		// Authorization endpoint v2 (using new AuthorizeHandler with full PKCE support)
		oauth.GET("/authorize/v2", svc.handleAuthorizeV2)

		// Consent endpoint (requires authentication)
		if len(flowAuth) > 0 {
			oauth.POST("/authorize", append(flowAuth, svc.handleAuthorizeConsent)...)
		} else {
			oauth.POST("/authorize", svc.handleAuthorizeConsent)
		}

		// Consent endpoint v2 (using new AuthorizeHandler with full PKCE support)
		if len(flowAuth) > 0 {
			oauth.POST("/authorize/v2", append(flowAuth, svc.handleAuthorizeConsentV2)...)
		} else {
			oauth.POST("/authorize/v2", svc.handleAuthorizeConsentV2)
		}

		// Server-rendered login form callback (for standard OIDC clients)
		oauth.POST("/authorize/callback", svc.handleAuthorizeCallback)

		// Login page (GET) — the target of the /oauth/authorize[/v2] redirect for
		// native/redirect clients; renders the server-side login form.
		oauth.GET("/login", svc.handleLoginPage)

		// Login endpoint for direct authentication (SPA flow)
		oauth.POST("/login", svc.handleLogin)

		// MFA verification endpoint
		oauth.POST("/mfa-verify", svc.handleMFAVerify)

		// WebAuthn MFA begin (returns credential assertion options)
		oauth.POST("/mfa-webauthn-begin", svc.handleMFAWebAuthnBegin)

		// MFA OTP delivery (SMS/Email)
		oauth.POST("/mfa-send-otp", svc.handleMFASendOTP)

		// Push MFA endpoints
		oauth.POST("/mfa-push-begin", svc.handleMFAPushBegin)
		oauth.GET("/mfa-push-status/:challenge_id", svc.handleMFAPushStatus)

		// Step-up MFA endpoints (mid-session re-auth)
		// The handlers read user_id + session_id from the gin context,
		// which the auth middleware populates from the JWT's sub + sid
		// claims. Without the middleware in front, every call sees
		// empty strings and 401s with "valid session required" even
		// for a valid bearer — that was the root cause of issue #124.
		if len(flowAuth) > 0 {
			oauth.POST("/stepup-challenge", append(flowAuth, svc.handleStepUpChallenge)...)
			oauth.POST("/stepup-verify", append(flowAuth, svc.handleStepUpVerify)...)
			oauth.GET("/stepup-status/:id", append(flowAuth, svc.handleStepUpStatus)...)
		} else {
			oauth.POST("/stepup-challenge", svc.handleStepUpChallenge)
			oauth.POST("/stepup-verify", svc.handleStepUpVerify)
			oauth.GET("/stepup-status/:id", svc.handleStepUpStatus)
		}

		// SSO callback endpoint
		oauth.GET("/callback", svc.handleCallback)

		// Token endpoint (with OPTIONS for CORS preflight)
		oauth.POST("/token", svc.handleToken)
		oauth.OPTIONS("/token", svc.handleToken)

		// Device authorization grant (RFC 8628). The device asks here for a code
		// pair; it then polls /token with grant_type=device_code. The two
		// verification routes back the page the user opens on a second device.
		oauth.POST("/device_authorization", svc.handleDeviceAuthorization)
		oauth.OPTIONS("/device_authorization", svc.handleDeviceAuthorization)

		// The verification routes sit behind flowAuth for the same reason the
		// step-up endpoints above do: handleDeviceVerificationDecision reads the
		// subject from the gin context, which only the auth middleware populates
		// from the JWT's sub claim. Registered without it, every approval sees an
		// empty user id and 401s — the exact shape of issue #124. The lookup is
		// guarded too: it is the one endpoint that answers questions about a
		// user_code, and there is no reason for it to answer them to anyone who
		// is not signed in and about to approve.
		if len(flowAuth) > 0 {
			oauth.GET("/device/lookup", append(flowAuth, svc.handleDeviceVerificationLookup)...)
			oauth.POST("/device/decision", append(flowAuth, svc.handleDeviceVerificationDecision)...)
		} else {
			oauth.GET("/device/lookup", svc.handleDeviceVerificationLookup)
			oauth.POST("/device/decision", svc.handleDeviceVerificationDecision)
		}

		// Token introspection & revocation
		// RFC 7662 §2.1 / RFC 7009 §2.1: both endpoints require client
		// authentication. They were previously reachable unauthenticated, so
		// anyone holding a token string could read its metadata or revoke it.
		oauth.POST("/introspect", svc.requireTokenEndpointClientAuth(), svc.handleIntrospect)
		oauth.POST("/revoke", svc.requireTokenEndpointClientAuth(), svc.handleRevoke)

		// Dynamic Client Registration (RFC 7591) + management (RFC 7592).
		oauth.POST("/register", svc.handleRegisterClient)
		oauth.OPTIONS("/register", func(c *gin.Context) { c.AbortWithStatus(204) })
		oauth.GET("/register/:client_id", svc.handleGetRegisteredClient)
		oauth.PUT("/register/:client_id", svc.handleUpdateRegisteredClient)
		oauth.DELETE("/register/:client_id", svc.handleDeleteRegisteredClient)

		// UserInfo endpoint (with OPTIONS for CORS preflight)
		oauth.GET("/userinfo", svc.handleUserInfo)
		oauth.POST("/userinfo", svc.handleUserInfo)
		oauth.OPTIONS("/userinfo", svc.handleUserInfo)

		// Native (mobile) login-session init — mints a login_session from JSON
		// PKCE params so a native client can drive passkey-begin/finish without
		// the browser authorize→login redirect (which RN fetch can't intercept).
		oauth.POST("/native/login-init", svc.handleNativeLoginInit)

		// Passkey-first login (WebAuthn as first factor)
		oauth.POST("/passkey-begin", svc.handlePasskeyBegin)
		oauth.POST("/passkey-finish", svc.handlePasskeyFinish)

		// Consent decision — records or rejects a user's approval of a client and
		// its scopes, then issues the code on approval. The subject comes from the
		// server-side consent stash, so this endpoint is safe unauthenticated.
		oauth.POST("/consent", svc.handleConsentDecision)

		// Magic link login (public, no auth required)
		oauth.POST("/magic-link", svc.handleOAuthMagicLink)
		oauth.GET("/magic-link-verify", svc.handleMagicLinkVerify)

		// QR code login (public, no auth required)
		oauth.POST("/qr-login/create", svc.handleQRLoginCreate)
		oauth.GET("/qr-login/poll", svc.handleQRLoginPoll)

		// Session management endpoints
		oauth.POST("/logout", svc.handleLogout)
		oauth.GET("/logout", svc.handleLogout)
		oauth.POST("/logout-all", svc.handleLogoutAll)
		oauth.POST("/force-login", svc.handleForceLogin)
		oauth.GET("/session-info", svc.handleSessionInfo)
	}

	// Client management API — always authenticated (creates/modifies OAuth
	// clients, so it must never be reachable unauthenticated in any env).
	clients := router.Group("/api/v1/oauth/clients")
	clients.Use(clientMgmtAuth)
	{
		clients.GET("", svc.handleListClients)
		clients.POST("", svc.handleCreateClient)
		clients.GET("/:id", svc.handleGetClient)
		clients.PUT("/:id", svc.handleUpdateClient)
		clients.DELETE("/:id", svc.handleDeleteClient)
		clients.POST("/:id/regenerate-secret", svc.handleRegenerateClientSecret)
	}

	// SAML IdP and Service Provider endpoints (SP management shares the
	// always-on client-management auth; public /saml/idp endpoints stay open).
	svc.RegisterSAMLIdPRoutes(router, clientMgmtAuth)

	// Social login endpoints
	svc.RegisterSocialLoginRoutes(router)
}

// discoverySubjectTypes returns the OIDC subject types the provider actually
// honors: always "public", and "pairwise" only when OIDCPairwiseSubjects is on
// (so discovery never advertises a subject type we don't implement — the
// "advertised = working" rule).
func (s *Service) discoverySubjectTypes() []string {
	if s.config != nil && s.config.OIDCPairwiseSubjects {
		return []string{"public", "pairwise"}
	}
	return []string{"public"}
}

func (s *Service) handleDiscovery(c *gin.Context) {
	// CORS is handled by the APISIX gateway for all routes
	c.Header("Cache-Control", "public, max-age=3600")

	if c.Request.Method == "OPTIONS" {
		c.AbortWithStatus(204)
		return
	}

	// Per-tenant discovery: when subdomain tenancy is configured the issuer and
	// all endpoints are served under the tenant's own host so the document a
	// tenant fetches matches the issuer its tokens carry. Falls back to the
	// global issuer for the default org / single-tenant installs.
	base := s.issuer
	if org, err := orgctx.From(c.Request.Context()); err == nil {
		base = s.issuerForOrg(org)
	}

	discovery := OIDCDiscovery{
		Issuer:                base,
		AuthorizationEndpoint: base + "/oauth/authorize",
		TokenEndpoint:         base + "/oauth/token",
		UserInfoEndpoint:      base + "/oauth/userinfo",
		JwksURI:               base + "/.well-known/jwks.json",
		RegistrationEndpoint:  base + "/oauth/register",
		// RFC 8628 §4: advertising this is how an input-constrained client
		// discovers it can use the device flow instead of giving up on a browser.
		DeviceAuthorizationEndpoint: base + "/oauth/device_authorization",
		ScopesSupported:             []string{"openid", "profile", "email", "offline_access"},
		// Only the authorization code flow is implemented: the authorize path
		// always issues a code (see the response_type it sets on the consent
		// redirect), and no handler produces an implicit or hybrid response.
		// Advertising id_token / token id_token / code id_token sent conforming
		// clients down a flow that silently returns a code instead. Implicit is
		// also removed outright by OAuth 2.1, so narrowing is the right direction.
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token", "client_credentials", grantTypeTokenExchange, grantTypeDeviceCode},
		SubjectTypesSupported:             s.discoverySubjectTypes(),
		IDTokenSigningAlgValuesSupported:  []string{"RS256"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_post", "client_secret_basic"},
		ClaimsSupported:                   []string{"sub", "iss", "aud", "exp", "iat", "email", "email_verified", "name", "given_name", "family_name", "sid"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		EndSessionEndpoint:                base + "/oauth/logout",
		BackchannelLogoutSupported:        true,
		BackchannelLogoutSessionSupported: true,
	}

	c.JSON(200, discovery)
}

func (s *Service) handleJWKS(c *gin.Context) {
	// CORS is handled by the APISIX gateway for all routes.
	// Short max-age so rotated-in keys propagate to verifier caches quickly.
	c.Header("Cache-Control", "public, max-age=300")

	if c.Request.Method == "OPTIONS" {
		c.AbortWithStatus(204)
		return
	}

	// Serve every verification key (active first, then retired keys inside
	// their grace) so consumers keep validating tokens across rotations.
	if snap := s.signer.Load(); snap != nil {
		c.JSON(200, snap.jwks)
		return
	}

	// No snapshot (unit tests construct Service directly): single-key JWKS
	// from the legacy fields (base64url without padding per RFC 7517).
	n := base64.RawURLEncoding.EncodeToString(s.publicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString([]byte{byte(s.publicKey.E >> 16), byte(s.publicKey.E >> 8), byte(s.publicKey.E)})

	jwks := JWKS{
		Keys: []JWK{
			{
				Kty: "RSA",
				Use: "sig",
				Kid: signingkeys.LegacyKid,
				Alg: "RS256",
				N:   n,
				E:   e,
			},
		},
	}

	c.JSON(200, jwks)
}

func (s *Service) handleAuthorize(c *gin.Context) {
	idpHint := c.Query("idp_hint")

	if idpHint != "" {
		// SSO flow with external IdP
		s.handleSSOAuthorize(c, idpHint)
		return
	}

	// Direct OpenIDX login flow
	// Store OAuth parameters in Redis and redirect to login page
	loginSession := GenerateRandomToken(32)
	oauthParams := map[string]string{
		"client_id":             c.Query("client_id"),
		"redirect_uri":          c.Query("redirect_uri"),
		"response_type":         c.Query("response_type"),
		"scope":                 c.Query("scope"),
		"state":                 c.Query("state"),
		"nonce":                 c.Query("nonce"),
		"code_challenge":        c.Query("code_challenge"),
		"code_challenge_method": c.Query("code_challenge_method"),
	}
	// Validate redirect_uri against the registered client.
	//
	// SECURITY: client_id is REQUIRED (RFC 6749 §4.1.1) and is now enforced as
	// such. This block used to be wrapped in `if clientID != ""`, so a request
	// that simply omitted client_id skipped redirect_uri validation entirely
	// and still reached the redirect below — an open redirect from the IdP's
	// own trusted origin (and one that leaked a freshly minted login_session).
	clientID := oauthParams["client_id"]
	if clientID == "" {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "client_id is required"})
		return
	}
	client, err := s.GetClient(c.Request.Context(), clientID)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid_client"})
		return
	}
	validRedirect := false
	for _, uri := range client.RedirectURIs {
		if uri == oauthParams["redirect_uri"] {
			validRedirect = true
			break
		}
	}
	if !validRedirect {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "redirect_uri not registered for client"})
		return
	}

	paramsJSON, _ := json.Marshal(oauthParams)
	s.redis.Client.Set(c.Request.Context(), "login_session:"+loginSession, string(paramsJSON), 10*time.Minute)

	// For public OIDC clients (like BrowZer), serve a server-rendered login page
	// instead of redirecting back to the client with login_session
	if client != nil && client.Type == "public" && c.GetHeader("Accept") != "application/json" {
		s.renderLoginPage(c, loginSession, "")
		return
	}

	// SPA flow: redirect back to the client's login page with the login_session parameter
	redirectURI := oauthParams["redirect_uri"]
	if redirectURI == "" {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "redirect_uri is required"})
		return
	}

	// Parse redirect URI to add login_session parameter
	loginURL, err := url.Parse(redirectURI)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "invalid redirect_uri"})
		return
	}
	query := loginURL.Query()
	query.Set("login_session", loginSession)
	loginURL.RawQuery = query.Encode()

	c.Redirect(302, loginURL.String())
}

// handleAuthorizeV2 handles authorization using the new AuthorizeHandler with full PKCE support
// This handler implements RFC 6749 (Authorization Code Flow) and RFC 7636 (PKCE)
func (s *Service) handleAuthorizeV2(c *gin.Context) {
	s.authorizeHandler.HandleAuthorizeRequest(c)
}

// loginBranding holds the per-tenant branding applied to the server-rendered
// login page. Mirrors the tenant_branding columns the admin Branding page edits.
type loginBranding struct {
	LogoURL            string
	FaviconURL         string
	PrimaryColor       string
	SecondaryColor     string
	BackgroundColor    string
	BackgroundImageURL string
	LoginPageTitle     string
	LoginPageMessage   string
	PortalTitle        string
	CustomCSS          string
	CustomFooter       string
	PoweredByVisible   bool
}

func defaultLoginBranding() loginBranding {
	return loginBranding{
		PrimaryColor:     "#3b82f6",
		SecondaryColor:   "#2563eb",
		BackgroundColor:  "#0f172a",
		LoginPageTitle:   "Sign In",
		PortalTitle:      "OpenIDX Zero Trust Platform",
		PoweredByVisible: true,
	}
}

// loadLoginBranding resolves the request's org (set by the TenantResolver from
// the subdomain / X-Org-Slug / fallback) and loads its branding from
// tenant_branding, falling back to defaults when there is no org or no row.
// tenant_branding is not RLS-scoped, so this unauthenticated read needs no
// bypass; if it ever becomes org-scoped, switch to orgctx.WithBypassRLS here.
func (s *Service) loadLoginBranding(ctx context.Context) loginBranding {
	b := defaultLoginBranding()
	org, err := orgctx.From(ctx)
	if err != nil || s.db == nil || s.db.Pool == nil {
		return b
	}
	var logo, fav, primary, secondary, bg, bgImg, title, msg, portal, css, footer string
	var powered bool
	if qerr := s.db.Pool.QueryRow(ctx,
		`SELECT COALESCE(logo_url,''), COALESCE(favicon_url,''), COALESCE(primary_color,''),
		        COALESCE(secondary_color,''), COALESCE(background_color,''), COALESCE(background_image_url,''),
		        COALESCE(login_page_title,''), COALESCE(login_page_message,''), COALESCE(portal_title,''),
		        COALESCE(custom_css,''), COALESCE(custom_footer,''), COALESCE(powered_by_visible,true)
		 FROM tenant_branding WHERE org_id = $1`, org.ID).Scan(
		&logo, &fav, &primary, &secondary, &bg, &bgImg, &title, &msg, &portal, &css, &footer, &powered); qerr != nil {
		return b
	}
	// Overlay non-empty values over the defaults so an unset column never blanks the page.
	b.LogoURL, b.FaviconURL, b.BackgroundImageURL = logo, fav, bgImg
	b.CustomCSS, b.CustomFooter, b.LoginPageMessage = css, footer, msg
	b.PoweredByVisible = powered
	if primary != "" {
		b.PrimaryColor = primary
	}
	if secondary != "" {
		b.SecondaryColor = secondary
	}
	if bg != "" {
		b.BackgroundColor = bg
	}
	if title != "" {
		b.LoginPageTitle = title
	}
	if portal != "" {
		b.PortalTitle = portal
	}
	return b
}

// handleLoginPage (GET /oauth/login) renders the server-side login form. It is
// the redirect target of /oauth/authorize[/v2] for native/redirect clients
// (e.g. the desktop/mobile PKCE-loopback flow). Validates the login_session
// before rendering so a stale/forged session doesn't reach the form.
func (s *Service) handleLoginPage(c *gin.Context) {
	loginSession := c.Query("login_session")
	if loginSession == "" || !isValidSessionID(loginSession) {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "missing or invalid login_session"})
		return
	}
	if _, err := s.redis.Client.Get(c.Request.Context(), "login_session:"+loginSession).Result(); err != nil {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "login session expired; restart sign-in"})
		return
	}
	s.renderLoginPage(c, loginSession, "")
}

// renderLoginPage serves a minimal HTML login form for standard OIDC clients,
// styled with the requesting tenant's branding.
func (s *Service) renderLoginPage(c *gin.Context, loginSession, errorMsg string) {
	b := s.loadLoginBranding(c.Request.Context())

	errHTML := ""
	if errorMsg != "" {
		errHTML = `<div style="color:#ef4444;background:#fef2f2;border:1px solid #fecaca;padding:12px;border-radius:8px;margin-bottom:16px;font-size:14px">` + html.EscapeString(errorMsg) + `</div>`
	}

	// Colors and custom_css are trusted tenant-admin input (same trust level as
	// the admin Branding page); user-visible text and URL attributes are escaped.
	logoHTML := ""
	if b.LogoURL != "" {
		logoHTML = `<img src="` + html.EscapeString(b.LogoURL) + `" alt="" style="max-height:48px;margin-bottom:16px">`
	}
	faviconHTML := ""
	if b.FaviconURL != "" {
		faviconHTML = `<link rel="icon" href="` + html.EscapeString(b.FaviconURL) + `">`
	}
	bodyBg := b.BackgroundColor
	if b.BackgroundImageURL != "" {
		bodyBg = b.BackgroundColor + ` url('` + html.EscapeString(b.BackgroundImageURL) + `') center/cover no-repeat`
	}
	footerHTML := ""
	if b.CustomFooter != "" {
		footerHTML = `<p class="footer">` + html.EscapeString(b.CustomFooter) + `</p>`
	} else if b.PoweredByVisible {
		footerHTML = `<p class="footer">Powered by OpenIDX</p>`
	}
	msgHTML := ""
	if b.LoginPageMessage != "" {
		msgHTML = `<p class="sub">` + html.EscapeString(b.LoginPageMessage) + `</p>`
	} else {
		msgHTML = `<p class="sub">` + html.EscapeString(b.PortalTitle) + `</p>`
	}

	page := `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>` + html.EscapeString(b.LoginPageTitle) + ` — ` + html.EscapeString(b.PortalTitle) + `</title>` + faviconHTML + `
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:` + bodyBg + `;color:#e2e8f0;display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{background:#1e293b;border:1px solid #334155;border-radius:16px;padding:40px;width:100%;max-width:400px;box-shadow:0 25px 50px rgba(0,0,0,.25);text-align:center}
h1{font-size:24px;font-weight:700;margin-bottom:8px;color:#f8fafc}
.sub{color:#94a3b8;margin-bottom:24px;font-size:14px}
form{text-align:left}
label{display:block;font-size:13px;font-weight:500;color:#94a3b8;margin-bottom:6px}
input{width:100%;padding:10px 14px;background:#0f172a;border:1px solid #334155;border-radius:8px;color:#f8fafc;font-size:15px;outline:none;transition:border .2s}
input:focus{border-color:` + b.PrimaryColor + `}
.field{margin-bottom:16px}
button{width:100%;padding:12px;background:` + b.PrimaryColor + `;color:#fff;border:none;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer;transition:background .2s}
button:hover{background:` + b.SecondaryColor + `}
.footer{margin-top:20px;font-size:12px;color:#64748b}
</style>
<style>` + b.CustomCSS + `</style></head><body>
<div class="card">
` + logoHTML + `
<h1>` + html.EscapeString(b.LoginPageTitle) + `</h1>
` + msgHTML + `
` + errHTML + `
<form method="POST" action="/oauth/authorize/callback">
<input type="hidden" name="login_session" value="` + html.EscapeString(loginSession) + `">
<div class="field"><label>Username</label><input type="text" name="username" required autofocus></div>
<div class="field"><label>Password</label><input type="password" name="password" required></div>
<button type="submit">Sign In</button>
</form>
` + footerHTML + `
</div></body></html>`
	c.Data(200, "text/html; charset=utf-8", []byte(page))
}

// handleAuthorizeCallback handles the server-rendered login form submission for standard OIDC clients
func (s *Service) handleAuthorizeCallback(c *gin.Context) {
	loginSession := c.PostForm("login_session")
	username := c.PostForm("username")
	password := c.PostForm("password")

	if loginSession == "" || username == "" || password == "" {
		s.renderLoginPage(c, loginSession, "All fields are required.")
		return
	}

	// Get OAuth parameters from Redis
	paramsJSON, err := s.redis.Client.Get(c.Request.Context(), "login_session:"+loginSession).Result()
	if err != nil {
		s.renderLoginPage(c, loginSession, "Login session expired. Please try again.")
		return
	}

	var oauthParams map[string]string
	if err := json.Unmarshal([]byte(paramsJSON), &oauthParams); err != nil {
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}

	// Authenticate user
	// The login audit events identity emits are only useful with the caller's
	// IP on them; the raw request context carries neither actor nor address.
	user, err := s.identityService.AuthenticateUser(
		identity.ContextWithActor(c.Request.Context(), "", c.ClientIP()), username, password)
	if err != nil {
		errorMsg := "Invalid username or password."
		if err.Error() == "account is locked" {
			errorMsg = "Account is locked. Please try again later."
		} else if err.Error() == "account is disabled" {
			errorMsg = "Account is disabled. Contact your administrator."
		}
		s.renderLoginPage(c, loginSession, errorMsg)
		return
	}

	// Country-based login blocking
	if err := s.checkCountryBlock(c.Request.Context(), c.ClientIP(), user.ID, username); err != nil {
		s.renderLoginPage(c, loginSession, "Authentication is not available from your location.")
		return
	}

	// Device-trust gate for clientless (BrowZer) access. BrowZer's data path
	// bypasses the proxy's forward-auth device-trust check, and this
	// server-rendered login (POST /oauth/authorize/callback) — not the JSON
	// /oauth/login — is what the BrowZer public client uses, so this is the
	// enforcement point. Mirrors the handleLogin gate (#268). Placed before the
	// login_session is deleted so a blocked user can retry the same session.
	if s.riskService != nil {
		clientIP := c.ClientIP()
		userAgent := c.GetHeader("User-Agent")
		fingerprint := s.riskService.ComputeDeviceFingerprint(clientIP, userAgent)
		// Register the device so an approval has a known_devices row to flip;
		// deviceID is the known_devices UUID (device_trust_requests.device_id is
		// a uuid — passing the fingerprint would fail the insert).
		deviceID, _, _ := s.riskService.RegisterDevice(c.Request.Context(), user.ID, fingerprint, clientIP, userAgent, "")
		deviceTrusted := s.riskService.IsDeviceTrusted(c.Request.Context(), user.ID, fingerprint)
		if s.deviceTrustGateBlocks(oauthParams["client_id"], deviceTrusted) {
			req, derr := s.identityService.CreateDeviceTrustRequest(c.Request.Context(),
				user.ID, deviceID, fingerprint, parseBrowserNameFromUA(userAgent),
				"browser", clientIP, userAgent,
				"clientless (BrowZer) access from an untrusted device")
			if !(derr == nil && req != nil && req.Status == "approved") {
				s.logger.Warn("clientless login blocked: device not trusted",
					zap.String("user_id", user.ID),
					zap.String("client_id", oauthParams["client_id"]))
				s.renderLoginPage(c, loginSession,
					"This device must be approved before clientless access. An approval request has been filed; try again after an administrator approves it.")
				return
			}
			// Auto-approved (e.g. known corporate IP) → fall through and issue the code.
		}
	}

	// Clean up login session
	s.redis.Client.Del(c.Request.Context(), "login_session:"+loginSession)

	// Generate authorization code
	code := GenerateRandomToken(32)
	authCode := &AuthorizationCode{
		Code:                code,
		ClientID:            oauthParams["client_id"],
		UserID:              user.ID,
		RedirectURI:         oauthParams["redirect_uri"],
		Scope:               oauthParams["scope"],
		State:               oauthParams["state"],
		Nonce:               oauthParams["nonce"],
		CodeChallenge:       oauthParams["code_challenge"],
		CodeChallengeMethod: oauthParams["code_challenge_method"],
	}

	if err := s.CreateAuthorizationCode(c.Request.Context(), authCode); err != nil {
		// DB write failure: a transient outage becomes a retryable 503, a real
		// error stays a 500 (see unavailable.go).
		writeServerOrUnavailable(c, err)
		return
	}

	// 302 redirect to client with auth code (standard OIDC flow)
	redirectURL, _ := url.Parse(oauthParams["redirect_uri"])
	query := redirectURL.Query()
	query.Set("code", code)
	if oauthParams["state"] != "" {
		query.Set("state", oauthParams["state"])
	}
	redirectURL.RawQuery = query.Encode()

	c.Redirect(302, redirectURL.String())
}

// handleLogin handles username/password login for direct OpenIDX authentication
// deviceTrustGateBlocks reports whether a login must be blocked for clientless
// device trust: the feature is enabled, the login targets the clientless
// (BrowZer) client, and the device is not trusted. This is the only enforceable
// point for device trust on the BrowZer data path (which bypasses the proxy's
// forward-auth device-trust check). See the design doc.
func (s *Service) deviceTrustGateBlocks(clientID string, deviceTrusted bool) bool {
	return s.config.RequireDeviceTrustForClientless &&
		clientID != "" && clientID == s.config.BrowZerClientID &&
		!deviceTrusted
}

func (s *Service) handleLogin(c *gin.Context) {
	var req struct {
		Username     string `json:"username"`
		Password     string `json:"password"`
		LoginSession string `json:"login_session"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "invalid request body"})
		return
	}

	// Validate login session
	if req.LoginSession == "" {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "login_session is required"})
		return
	}

	// Get OAuth parameters from Redis
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

	// Authenticate user
	clientIP := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	user, err := s.identityService.AuthenticateUser(
		identity.ContextWithActor(c.Request.Context(), "", clientIP), req.Username, req.Password)
	if err != nil {
		// Log failed login audit event in background with timeout
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			s.logAuditEvent(ctx, "authentication", "security", "login_failed", "failure",
				req.Username, clientIP, "", "user",
				map[string]interface{}{"reason": err.Error(), "user_agent": userAgent})
		}()

		// Return appropriate error message
		errorMsg := "Invalid username or password"
		if err.Error() == "account is locked" {
			errorMsg = "Account is locked. Please try again later."
		} else if err.Error() == "account is disabled" {
			errorMsg = "Account is disabled. Please contact your administrator."
		}
		c.JSON(401, gin.H{"error": "invalid_credentials", "error_description": errorMsg})
		return
	}

	// Log successful login audit event in background with timeout
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.logAuditEvent(ctx, "authentication", "security", "login", "success",
			user.ID, clientIP, user.ID, "user",
			map[string]interface{}{"username": user.UserName, "email": user.GetEmail(), "user_agent": userAgent})
	}()

	// Country-based login blocking
	if err := s.checkCountryBlock(c.Request.Context(), clientIP, user.ID, user.UserName); err != nil {
		c.JSON(403, gin.H{
			"error":             "access_denied",
			"error_description": "Authentication is not available from your location.",
		})
		return
	}

	// Risk assessment (conditional access)
	var riskScore int
	var riskFactors []string
	var fingerprint, location string
	var deviceTrusted bool
	authMethods := []string{"password"}

	if s.riskService != nil {
		fingerprint = s.riskService.ComputeDeviceFingerprint(clientIP, userAgent)

		// Geo-IP lookup
		geo, _ := s.riskService.GeoIPLookup(c.Request.Context(), clientIP)
		var lat, lon float64
		if geo != nil {
			location = geo.City + ", " + geo.Country
			lat = geo.Lat
			lon = geo.Lon
		}

		// Register device; deviceID is the known_devices UUID used below for the
		// device-trust request (device_trust_requests.device_id is a uuid).
		deviceID, _, _ := s.riskService.RegisterDevice(c.Request.Context(), user.ID, fingerprint, clientIP, userAgent, location)

		// Check device trust
		deviceTrusted = s.riskService.IsDeviceTrusted(c.Request.Context(), user.ID, fingerprint)

		// Device-trust gate for clientless (BrowZer) access. BrowZer traffic
		// bypasses the proxy's forward-auth device-trust check, so the OIDC login
		// is the only place to enforce it. When enabled, an untrusted device
		// targeting the clientless client is refused a session and a trust request
		// is filed (dedups; auto-approves on known IP / corporate device).
		if s.deviceTrustGateBlocks(oauthParams["client_id"], deviceTrusted) {
			req, derr := s.identityService.CreateDeviceTrustRequest(c.Request.Context(),
				user.ID, deviceID, fingerprint, parseBrowserNameFromUA(userAgent),
				"browser", clientIP, userAgent,
				"clientless (BrowZer) access from an untrusted device")
			if derr == nil && req != nil && req.Status == "approved" {
				// Auto-approved (e.g. known corporate IP) → treat as trusted and
				// let the login proceed.
				deviceTrusted = true
			} else {
				s.logger.Warn("clientless login blocked: device not trusted",
					zap.String("user_id", user.ID),
					zap.String("client_id", oauthParams["client_id"]))
				c.JSON(403, gin.H{
					"error":             "device_not_trusted",
					"error_description": "This device must be approved before clientless access. An approval request has been filed; try again after an administrator approves it.",
				})
				return
			}
		}

		// Calculate risk score
		riskScore, riskFactors = s.riskService.CalculateRiskScore(c.Request.Context(), user.ID, clientIP, userAgent, fingerprint, location, lat, lon)

		// Record login
		s.riskService.RecordLogin(c.Request.Context(), user.ID, clientIP, userAgent, location, lat, lon, fingerprint, true, authMethods, riskScore)

		s.logger.Info("Login risk assessment",
			zap.String("user_id", user.ID),
			zap.Int("risk_score", riskScore),
			zap.Strings("factors", riskFactors),
			zap.Bool("device_trusted", deviceTrusted),
			zap.String("location", location),
		)

		// Publish webhook event for login
		if s.webhookService != nil {
			eventType := "login.success"
			if riskScore >= 70 {
				eventType = "login.high_risk"
			}
			s.webhookService.Publish(c.Request.Context(), eventType, map[string]interface{}{
				"user_id": user.ID, "ip": clientIP, "location": location,
				"risk_score": riskScore, "device_trusted": deviceTrusted,
			})
		}
	}

	// Gather available MFA methods. MFA enforcement must key on ANY enrolled
	// primary factor (TOTP, WebAuthn, push, SMS, email OTP) — not TOTP alone.
	// Previously mfaEnabled was `totpStatus.Enabled`, so a user enrolled solely
	// in WebAuthn/push/SMS/email silently bypassed MFA on password login.
	// Backup and bypass codes are supplemental and never independently force MFA.
	totpStatus, _ := s.identityService.GetTOTPStatus(c.Request.Context(), user.ID)

	var availableMFAMethods []string
	var hasPrimaryFactor bool

	if totpStatus != nil && totpStatus.Enabled {
		availableMFAMethods = append(availableMFAMethods, "totp")
		hasPrimaryFactor = true
	}
	// Check for WebAuthn credentials
	webauthnCreds, _ := s.identityService.GetWebAuthnCredentials(c.Request.Context(), user.ID)
	if len(webauthnCreds) > 0 {
		availableMFAMethods = append(availableMFAMethods, "webauthn")
		hasPrimaryFactor = true
	}
	// Check for push MFA devices
	pushDevices, _ := s.identityService.GetPushDevices(c.Request.Context(), user.ID)
	if len(pushDevices) > 0 {
		availableMFAMethods = append(availableMFAMethods, "push")
		hasPrimaryFactor = true
	}
	// Check for verified SMS OTP enrollment
	if smsEnr, _ := s.identityService.GetSMSEnrollment(c.Request.Context(), user.ID); smsEnr != nil && smsEnr.Verified && smsEnr.Enabled {
		availableMFAMethods = append(availableMFAMethods, "sms")
		hasPrimaryFactor = true
	}
	// Check for email OTP enrollment
	if emailEnr, _ := s.identityService.GetEmailOTPEnrollment(c.Request.Context(), user.ID); emailEnr != nil && emailEnr.Enabled {
		availableMFAMethods = append(availableMFAMethods, "email")
		hasPrimaryFactor = true
	}
	// Check for backup codes (supplemental — only offered alongside a primary factor)
	backupCount, _ := s.identityService.GetBackupCodeCount(c.Request.Context(), user.ID)
	if backupCount > 0 {
		availableMFAMethods = append(availableMFAMethods, "backup")
	}
	// Check for active bypass codes (admin-generated, supplemental)
	hasActiveBypass, _ := s.identityService.HasActiveBypassCode(c.Request.Context(), user.ID)
	if hasActiveBypass {
		availableMFAMethods = append(availableMFAMethods, "bypass")
	}

	mfaEnabled := hasPrimaryFactor

	// Check for trusted browser — skip MFA if browser is trusted
	var browserTrusted bool
	if fingerprint != "" && s.identityService != nil {
		tb, _ := s.identityService.IsTrustedBrowser(c.Request.Context(), user.ID, fingerprint)
		browserTrusted = tb != nil
	}

	// Adaptive risk assessment via identity service (replaces hardcoded threshold)
	var riskAssessment *identity.RiskAssessment
	if s.identityService != nil {
		var geo_lat, geo_lon float64
		if s.riskService != nil {
			geo, _ := s.riskService.GeoIPLookup(c.Request.Context(), clientIP)
			if geo != nil {
				geo_lat = geo.Lat
				geo_lon = geo.Lon
			}
		}
		lc := &identity.LoginContext{
			UserID:         user.ID,
			Username:       user.UserName,
			IPAddress:      clientIP,
			UserAgent:      userAgent,
			Latitude:       geo_lat,
			Longitude:      geo_lon,
			DeviceID:       fingerprint,
			BrowserHash:    fingerprint,
			KnownDevice:    deviceTrusted,
			TrustedBrowser: browserTrusted,
		}
		assessment, assessErr := s.identityService.AssessLoginRisk(c.Request.Context(), lc)
		if assessErr == nil && assessment != nil {
			riskAssessment = assessment
			// Use assessment score/factors if available (more sophisticated than raw risk score)
			riskScore = assessment.Score
			riskFactors = assessment.Factors
		}
	}

	// Determine MFA requirement from risk assessment (or fall back to legacy threshold)
	requireMFA := false
	denyAccess := false
	if riskAssessment != nil {
		requireMFA = riskAssessment.RequiresMFA && mfaEnabled && !browserTrusted
		denyAccess = riskAssessment.DenyAccess
		// Filter available MFA methods by risk-allowed methods
		if requireMFA && len(riskAssessment.AllowedMethods) > 0 {
			allowedSet := make(map[string]bool)
			for _, m := range riskAssessment.AllowedMethods {
				allowedSet[m] = true
			}
			filtered := []string{}
			for _, m := range availableMFAMethods {
				if allowedSet[m] {
					filtered = append(filtered, m)
				}
			}
			if len(filtered) > 0 {
				availableMFAMethods = filtered
			}
		}
	} else {
		// Legacy fallback: hardcoded threshold
		requireMFA = riskScore >= 70 && mfaEnabled && !browserTrusted
		denyAccess = riskScore >= 70 && !mfaEnabled
	}

	// Skip MFA if browser is trusted and risk is not high
	skipMFA := browserTrusted && riskScore < 70

	if mfaEnabled && !skipMFA && (requireMFA || (totpStatus != nil && totpStatus.Enabled)) {
		// MFA required — store partial auth in Redis and return MFA challenge
		mfaSession := GenerateRandomToken(32)
		mfaData := map[string]string{
			"user_id":     user.ID,
			"risk_score":  fmt.Sprintf("%d", riskScore),
			"fingerprint": fingerprint,
			"location":    location,
		}
		for k, v := range oauthParams {
			mfaData[k] = v
		}
		mfaDataJSON, _ := json.Marshal(mfaData)
		s.redis.Client.Set(c.Request.Context(), "mfa_session:"+mfaSession, string(mfaDataJSON), 5*time.Minute)

		// Delete the login session from Redis (password step is done)
		s.redis.Client.Del(c.Request.Context(), "login_session:"+req.LoginSession)

		riskLevel := "medium"
		if riskAssessment != nil {
			riskLevel = riskAssessment.Level
		}

		c.JSON(200, gin.H{
			"mfa_required":      true,
			"mfa_session":       mfaSession,
			"mfa_methods":       availableMFAMethods,
			"risk_score":        riskScore,
			"risk_level":        riskLevel,
			"risk_factors":      riskFactors,
			"device_trusted":    deviceTrusted,
			"can_trust_browser": !browserTrusted,
		})
		return
	}

	// Log if MFA was skipped due to trusted browser
	if skipMFA && mfaEnabled {
		s.logger.Info("MFA skipped due to trusted browser",
			zap.String("user_id", user.ID),
			zap.String("fingerprint", fingerprint),
		)
		// Log audit event in background with timeout
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			s.logAuditEvent(ctx, "authentication", "security", "mfa_skipped", "success",
				user.ID, clientIP, user.ID, "user",
				map[string]interface{}{"reason": "trusted_browser", "fingerprint": fingerprint})
		}()
	}

	// Deny access if risk assessment says so (or legacy: high risk + no MFA)
	if denyAccess {
		s.logger.Warn("Login denied by risk assessment",
			zap.String("user_id", user.ID),
			zap.Int("risk_score", riskScore),
		)
		c.JSON(403, gin.H{
			"error":             "high_risk_login",
			"error_description": "Login from an unrecognized device or location. Please enable MFA to continue.",
			"risk_score":        riskScore,
			"risk_factors":      riskFactors,
		})
		return
	}

	// No MFA required — proceed with authorization code

	// Check concurrent session limits before creating a new session
	action, activeSessions, concErr := s.checkConcurrentSessions(c.Request.Context(), user.ID, oauthParams["client_id"])
	if concErr != nil && action == "denied" {
		c.JSON(403, gin.H{
			"error":             "concurrent_session_limit",
			"error_description": "Maximum number of concurrent sessions reached.",
		})
		return
	}
	if action == "prompt_user" {
		// Store user_id in the login session data so force-login can resume
		oauthParams["user_id"] = user.ID
		pendingData, _ := json.Marshal(oauthParams)
		s.redis.Client.Set(c.Request.Context(), "login_session:"+req.LoginSession, string(pendingData), 5*time.Minute)
		c.JSON(200, gin.H{
			"concurrent_limit_reached": true,
			"active_sessions":          activeSessions,
			"login_session":            req.LoginSession,
		})
		return
	}

	// Create a session linked to this login
	session, sessionErr := s.identityService.CreateSession(c.Request.Context(), user.ID, oauthParams["client_id"], clientIP, userAgent, 24*time.Hour)
	if sessionErr != nil {
		s.logger.Warn("Failed to create session during login", zap.Error(sessionErr))
	}
	if session != nil {
		oauthParams["session_id"] = session.ID
	}

	s.redis.Client.Del(c.Request.Context(), "login_session:"+req.LoginSession)
	s.issueAuthorizationCode(c, oauthParams, user.ID)
}

// issueAuthorizationCode generates an auth code and returns the redirect URL
func (s *Service) issueAuthorizationCode(c *gin.Context, oauthParams map[string]string, userID string) {
	// Enforce per-application consent unless it was just granted in this flow.
	if oauthParams["consent_granted"] != "true" {
		required, cerr := s.consentRequired(c.Request.Context(), oauthParams["client_id"], userID, oauthParams["scope"])
		if cerr != nil {
			s.logger.Error("consent check failed", zap.Error(cerr))
			c.JSON(500, gin.H{"error": "server_error"})
			return
		}
		if required {
			s.beginConsent(c, oauthParams, userID)
			return
		}
	}

	code := GenerateRandomToken(32)
	authCode := &AuthorizationCode{
		Code:                code,
		ClientID:            oauthParams["client_id"],
		UserID:              userID,
		RedirectURI:         oauthParams["redirect_uri"],
		Scope:               oauthParams["scope"],
		State:               oauthParams["state"],
		Nonce:               oauthParams["nonce"],
		CodeChallenge:       oauthParams["code_challenge"],
		CodeChallengeMethod: oauthParams["code_challenge_method"],
	}

	if err := s.CreateAuthorizationCode(c.Request.Context(), authCode); err != nil {
		// DB write failure: a transient outage becomes a retryable 503, a real
		// error stays a 500 (see unavailable.go).
		writeServerOrUnavailable(c, err)
		return
	}

	// Store session_id alongside the auth code in Redis (5-minute TTL)
	if sessionID := oauthParams["session_id"]; sessionID != "" {
		s.redis.Client.Set(c.Request.Context(), "authcode_session:"+code, sessionID, 5*time.Minute)
	}

	redirectURL, _ := url.Parse(oauthParams["redirect_uri"])
	query := redirectURL.Query()
	query.Set("code", code)
	if oauthParams["state"] != "" {
		query.Set("state", oauthParams["state"])
	}
	redirectURL.RawQuery = query.Encode()

	c.JSON(200, gin.H{
		"redirect_url": redirectURL.String(),
	})
}

// handleMFAVerify handles MFA verification after password authentication
// Supports TOTP, backup codes, bypass codes, WebAuthn, push notification, and trusted browser option
func (s *Service) handleMFAVerify(c *gin.Context) {
	var req struct {
		MFASession   string `json:"mfa_session"`
		Code         string `json:"code"`
		Method       string `json:"method"`        // "totp", "backup", "bypass", "webauthn", "push"
		TrustBrowser bool   `json:"trust_browser"` // Request to trust this browser
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "invalid request body"})
		return
	}

	if req.MFASession == "" || req.Code == "" {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "mfa_session and code are required"})
		return
	}

	// Default method is TOTP
	if req.Method == "" {
		req.Method = "totp"
	}

	// Retrieve MFA session from Redis
	mfaDataJSON, err := s.redis.Client.Get(c.Request.Context(), "mfa_session:"+req.MFASession).Result()
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "invalid or expired MFA session"})
		return
	}

	var mfaData map[string]string
	if err := json.Unmarshal([]byte(mfaDataJSON), &mfaData); err != nil {
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}

	userID := mfaData["user_id"]
	clientIP := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	var valid bool
	var verifyErr error

	switch req.Method {
	case "totp":
		// Verify TOTP code
		valid, verifyErr = s.identityService.VerifyTOTP(c.Request.Context(), userID, req.Code)

	case "backup":
		// Verify backup code
		valid, verifyErr = s.identityService.VerifyBackupCode(c.Request.Context(), userID, req.Code)

	case "bypass":
		// Verify admin-generated bypass code
		valid, verifyErr = s.identityService.VerifyBypassCode(c.Request.Context(), userID, req.Code, clientIP, userAgent)

	case "webauthn":
		// Verify WebAuthn assertion — req.Code contains JSON-serialized credential assertion response
		// Look up username from userID (WebAuthn methods require username)
		user, err := s.identityService.GetUser(c.Request.Context(), userID)
		if err != nil {
			c.JSON(400, gin.H{"error": "invalid_request", "error_description": "user not found"})
			return
		}

		// Parse the WebAuthn assertion response from the code field
		parsedResponse, err := protocol.ParseCredentialRequestResponseBody(strings.NewReader(req.Code))
		if err != nil {
			s.logger.Error("Failed to parse WebAuthn assertion response",
				zap.String("user_id", userID),
				zap.Error(err))
			c.JSON(400, gin.H{"error": "invalid_request", "error_description": "invalid WebAuthn response"})
			return
		}

		_, verifyErr = s.identityService.FinishWebAuthnAuthentication(c.Request.Context(), user.UserName, parsedResponse)
		if verifyErr == nil {
			valid = true
		}

	case "push":
		// Verify push notification challenge — req.Code contains the challenge_id
		challenge, err := s.identityService.GetPushMFAChallenge(c.Request.Context(), req.Code)
		if err != nil {
			c.JSON(400, gin.H{"error": "invalid_request", "error_description": "challenge not found"})
			return
		}

		// Verify the challenge belongs to this user, is approved, and not expired
		if challenge.UserID != userID {
			c.JSON(400, gin.H{"error": "invalid_request", "error_description": "challenge does not belong to this user"})
			return
		}
		if challenge.Status != "approved" {
			c.JSON(401, gin.H{"error": "invalid_mfa_code", "error_description": "Push notification not yet approved"})
			return
		}
		if time.Now().After(challenge.ExpiresAt) {
			c.JSON(401, gin.H{"error": "invalid_mfa_code", "error_description": "Push challenge has expired"})
			return
		}
		valid = true

	default:
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "unsupported MFA method"})
		return
	}

	if verifyErr != nil || !valid {
		// Log failed MFA attempt in background with timeout
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			s.logAuditEvent(ctx, "authentication", "security", "mfa_failed", "failure",
				userID, clientIP, userID, "user",
				map[string]interface{}{"method": req.Method, "error": verifyErr})
		}()

		c.JSON(401, gin.H{"error": "invalid_mfa_code", "error_description": "Invalid verification code"})
		return
	}

	// MFA verified — delete session
	s.redis.Client.Del(c.Request.Context(), "mfa_session:"+req.MFASession)

	// Log MFA verification audit event in background with timeout
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.logAuditEvent(ctx, "authentication", "security", "mfa_verified", "success",
			userID, clientIP, userID, "user",
			map[string]interface{}{"method": req.Method, "trust_browser": req.TrustBrowser})
	}()

	// Handle trusted browser request
	var trustedBrowserID string
	if req.TrustBrowser {
		browserHash := ""
		if s.riskService != nil {
			browserHash = s.riskService.ComputeDeviceFingerprint(clientIP, userAgent)
		}
		browserName := parseBrowserNameFromUA(userAgent)

		tb, err := s.identityService.TrustBrowser(c.Request.Context(), userID, browserHash, browserName, clientIP, userAgent)
		if err == nil && tb != nil {
			trustedBrowserID = tb.ID
			s.logger.Info("Browser trusted after MFA",
				zap.String("user_id", userID),
				zap.String("browser_id", tb.ID))
		}
	}

	oauthParams := make(map[string]string)
	for k, v := range mfaData {
		if k != "user_id" && k != "risk_score" && k != "fingerprint" && k != "location" {
			oauthParams[k] = v
		}
	}

	// Create a session linked to this MFA-verified login
	session, sessionErr := s.identityService.CreateSession(c.Request.Context(), userID, oauthParams["client_id"], clientIP, userAgent, 24*time.Hour)
	if sessionErr != nil {
		s.logger.Warn("Failed to create session during MFA verify", zap.Error(sessionErr))
	}
	if session != nil {
		oauthParams["session_id"] = session.ID
	}

	// Issue authorization code with optional trusted browser info
	s.issueAuthorizationCodeWithTrust(c, oauthParams, userID, trustedBrowserID)
}

// handleMFAWebAuthnBegin initiates WebAuthn authentication during MFA flow
func (s *Service) handleMFAWebAuthnBegin(c *gin.Context) {
	var req struct {
		MFASession string `json:"mfa_session"`
	}

	if err := c.ShouldBindJSON(&req); err != nil || req.MFASession == "" {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "mfa_session is required"})
		return
	}

	// Retrieve MFA session from Redis
	mfaDataJSON, err := s.redis.Client.Get(c.Request.Context(), "mfa_session:"+req.MFASession).Result()
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "invalid or expired MFA session"})
		return
	}

	var mfaData map[string]string
	if err := json.Unmarshal([]byte(mfaDataJSON), &mfaData); err != nil {
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}

	userID := mfaData["user_id"]

	// Look up username (WebAuthn methods require username)
	user, err := s.identityService.GetUser(c.Request.Context(), userID)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "user not found"})
		return
	}

	// Begin WebAuthn authentication
	options, err := s.identityService.BeginWebAuthnAuthentication(c.Request.Context(), user.UserName)
	if err != nil {
		s.logger.Error("Failed to begin WebAuthn authentication",
			zap.String("user_id", userID),
			zap.Error(err))
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "Failed to initiate WebAuthn authentication"})
		return
	}

	c.JSON(200, options)
}

// handleMFAPushBegin initiates a push notification MFA challenge
func (s *Service) handleMFAPushBegin(c *gin.Context) {
	var req struct {
		MFASession string `json:"mfa_session"`
	}

	if err := c.ShouldBindJSON(&req); err != nil || req.MFASession == "" {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "mfa_session is required"})
		return
	}

	// Retrieve MFA session from Redis
	mfaDataJSON, err := s.redis.Client.Get(c.Request.Context(), "mfa_session:"+req.MFASession).Result()
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "invalid or expired MFA session"})
		return
	}

	var mfaData map[string]string
	if err := json.Unmarshal([]byte(mfaDataJSON), &mfaData); err != nil {
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}

	userID := mfaData["user_id"]

	// Resolve a friendly application name for the approval screen (rich context).
	appName := ""
	if cid := mfaData["client_id"]; cid != "" {
		if cl, cerr := s.GetClient(c.Request.Context(), cid); cerr == nil && cl != nil && cl.Name != "" {
			appName = cl.Name
		}
	}

	// Create push challenge
	challenge, err := s.identityService.CreatePushMFAChallenge(c.Request.Context(), &identity.PushMFAChallengeRequest{
		UserID:    userID,
		IPAddress: c.ClientIP(),
		UserAgent: c.GetHeader("User-Agent"),
		AppName:   appName,
	})
	if err != nil {
		s.logger.Error("Failed to create push MFA challenge",
			zap.String("user_id", userID),
			zap.Error(err))
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "Failed to create push challenge. Ensure a push device is registered."})
		return
	}

	c.JSON(200, gin.H{
		"challenge_id":   challenge.ID,
		"challenge_code": challenge.ChallengeCode,
		"expires_at":     challenge.ExpiresAt,
	})
}

// handleMFAPushStatus checks the status of a push MFA challenge (polling endpoint)
func (s *Service) handleMFAPushStatus(c *gin.Context) {
	challengeID := c.Param("challenge_id")
	if challengeID == "" {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "challenge_id is required"})
		return
	}

	challenge, err := s.identityService.GetPushMFAChallenge(c.Request.Context(), challengeID)
	if err != nil {
		c.JSON(404, gin.H{"error": "not_found", "error_description": "challenge not found"})
		return
	}

	// Check if expired
	status := challenge.Status
	if status == "pending" && time.Now().After(challenge.ExpiresAt) {
		status = "expired"
	}

	c.JSON(200, gin.H{
		"status":     status,
		"expires_at": challenge.ExpiresAt,
	})
}

// issueAuthorizationCodeWithTrust issues auth code and includes trusted browser info
func (s *Service) issueAuthorizationCodeWithTrust(c *gin.Context, params map[string]string, userID, trustedBrowserID string) {
	// Generate authorization code
	authCode := GenerateRandomToken(32)

	// Store code in Redis with user info
	codeData := map[string]string{
		"user_id":      userID,
		"client_id":    params["client_id"],
		"redirect_uri": params["redirect_uri"],
		"scope":        params["scope"],
		"nonce":        params["nonce"],
	}
	if params["code_challenge"] != "" {
		codeData["code_challenge"] = params["code_challenge"]
		codeData["code_challenge_method"] = params["code_challenge_method"]
	}

	codeDataJSON, _ := json.Marshal(codeData)
	s.redis.Client.Set(c.Request.Context(), "auth_code:"+authCode, string(codeDataJSON), 10*time.Minute)

	// Store session_id alongside the auth code in Redis (5-minute TTL)
	if sessionID := params["session_id"]; sessionID != "" {
		s.redis.Client.Set(c.Request.Context(), "authcode_session:"+authCode, sessionID, 5*time.Minute)
	}

	response := gin.H{
		"code":  authCode,
		"state": params["state"],
	}

	if trustedBrowserID != "" {
		response["trusted_browser_id"] = trustedBrowserID
	}

	c.JSON(200, response)
}

// parseBrowserNameFromUA extracts browser name from user agent
func parseBrowserNameFromUA(userAgent string) string {
	ua := strings.ToLower(userAgent)
	switch {
	case strings.Contains(ua, "edg"):
		return "Microsoft Edge"
	case strings.Contains(ua, "chrome"):
		return "Google Chrome"
	case strings.Contains(ua, "firefox"):
		return "Mozilla Firefox"
	case strings.Contains(ua, "safari"):
		return "Apple Safari"
	default:
		return "Unknown Browser"
	}
}

func (s *Service) handleSSOAuthorize(c *gin.Context, idpID string) {
	// 1. Get IdP from identity service
	idp, err := s.identityService.GetIdentityProvider(c.Request.Context(), idpID)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid_idp"})
		return
	}

	// 2. Store original request parameters in Redis
	state := GenerateRandomToken(32)
	originalParams := map[string]string{
		"client_id":             c.Query("client_id"),
		"redirect_uri":          c.Query("redirect_uri"),
		"response_type":         c.Query("response_type"),
		"scope":                 c.Query("scope"),
		"state":                 c.Query("state"),
		"nonce":                 c.Query("nonce"),
		"code_challenge":        c.Query("code_challenge"),
		"code_challenge_method": c.Query("code_challenge_method"),
	}
	paramsJSON, _ := json.Marshal(originalParams)
	s.redis.Client.Set(c.Request.Context(), "sso_state:"+state, string(paramsJSON), 10*time.Minute)

	// 3. Build external IdP authorization URL
	authURL, _ := url.Parse(idp.IssuerURL + "/protocol/openid-connect/auth")
	query := authURL.Query()
	query.Set("client_id", idp.ClientID)
	query.Set("redirect_uri", s.issuer+"/oauth/callback")
	query.Set("response_type", "code")
	query.Set("scope", strings.Join(idp.Scopes, " "))
	query.Set("state", state)
	authURL.RawQuery = query.Encode()

	// 4. Redirect user to external IdP
	c.Redirect(302, authURL.String())
}

func (s *Service) handleCallback(c *gin.Context) {
	// 1. Get state and code from callback request
	state := c.Query("state")
	code := c.Query("code")

	// 2. Retrieve original request parameters from Redis
	paramsJSON, err := s.redis.Client.Get(c.Request.Context(), "sso_state:"+state).Result()
	if err != nil {
		s.logAuditEvent(c.Request.Context(), "authentication", "sso", "sso_login", "failure",
			"", c.ClientIP(), "", "user", map[string]interface{}{"reason": "invalid_state"})
		c.JSON(400, gin.H{"error": "invalid_state"})
		return
	}
	var originalParams map[string]string
	json.Unmarshal([]byte(paramsJSON), &originalParams)

	// 3. Get IdP from identity service (we need to store idp_id in the state)
	// For now, let's assume we have only one IdP for simplicity
	idps, _, err := s.identityService.ListIdentityProviders(c.Request.Context(), 0, 1)
	if err != nil || len(idps) == 0 {
		c.JSON(500, gin.H{"error": "no identity provider configured"})
		return
	}
	idp := idps[0]

	// 4. Exchange code for tokens
	oauth2Config := &oauth2.Config{
		ClientID:     idp.ClientID,
		ClientSecret: idp.ClientSecret,
		RedirectURL:  s.issuer + "/oauth/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:  idp.IssuerURL + "/protocol/openid-connect/auth",
			TokenURL: idp.IssuerURL + "/protocol/openid-connect/token",
		},
		Scopes: idp.Scopes,
	}
	token, err := oauth2Config.Exchange(c.Request.Context(), code)
	if err != nil {
		s.logAuditEvent(c.Request.Context(), "authentication", "sso", "sso_login", "failure",
			"", c.ClientIP(), "", "user", map[string]interface{}{"reason": "token_exchange_failed", "idp_id": idp.ID.String()})
		c.JSON(500, gin.H{"error": "failed to exchange token"})
		return
	}

	// 5. a new user is created with the information from the ID token.
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		c.JSON(500, gin.H{"error": "id_token not found"})
		return
	}

	// 6. JIT Provisioning & Session Management
	// For simplicity, we'll just create a new user and a new session, and then generate a new authorization code
	var claims struct {
		Email string `json:"email"`
		Sub   string `json:"sub"`
		Name  string `json:"name"`
	}
	// Verify the ID token signature using the IdP's JWKS
	verifiedToken, err := jwt.Parse(rawIDToken, func(t *jwt.Token) (interface{}, error) {
		// Fetch JWKS from the IdP
		jwksURL := idp.IssuerURL + "/protocol/openid-connect/certs"
		return middleware.FetchJWKS(jwksURL, t)
	})
	if err != nil {
		s.logger.Error("Failed to verify ID token", zap.Error(err))
		s.logAuditEvent(c.Request.Context(), "authentication", "sso", "sso_login", "failure",
			"", c.ClientIP(), "", "user", map[string]interface{}{"reason": "id_token_verification_failed", "idp_id": idp.ID.String()})
		c.JSON(401, gin.H{"error": "invalid_id_token", "error_description": "ID token signature verification failed"})
		return
	}
	if mapClaims, ok := verifiedToken.Claims.(jwt.MapClaims); ok {
		if email, ok := mapClaims["email"].(string); ok {
			claims.Email = email
		}
		if sub, ok := mapClaims["sub"].(string); ok {
			claims.Sub = sub
		}
		if name, ok := mapClaims["name"].(string); ok {
			claims.Name = name
		}
	}

	if claims.Email == "" {
		s.logAuditEvent(c.Request.Context(), "authentication", "sso", "sso_login", "failure",
			"", c.ClientIP(), "", "user", map[string]interface{}{"reason": "missing_email_claim", "idp_id": idp.ID.String()})
		c.JSON(400, gin.H{"error": "invalid_claims", "error_description": "email claim is required"})
		return
	}

	// Check if user already exists (JIT provisioning).
	var user *identity.User

	// 1. Prefer the stable federated identity (idp_id + sub): a returning user is
	// matched by the IdP subject even if their email changed at the IdP, which
	// also avoids creating a duplicate that would collide with the unique
	// (idp_id, external_user_id) index. Explicitly org-scoped (belt-and-braces
	// with the RLS the pool acquire hook already applies).
	if org, oerr := orgctx.From(c.Request.Context()); oerr == nil && claims.Sub != "" {
		var uid string
		if err := s.db.Pool.QueryRow(c.Request.Context(),
			`SELECT id FROM users WHERE org_id = $1 AND idp_id = $2 AND external_user_id = $3 LIMIT 1`,
			org.ID, idp.ID, claims.Sub).Scan(&uid); err == nil && uid != "" {
			user = &identity.User{ID: uid}
			s.logAuditEvent(c.Request.Context(), "authentication", "sso", "sso_identity_matched", "success",
				uid, c.ClientIP(), uid, "user", map[string]interface{}{"idp_id": idp.ID.String(), "external_user_id": claims.Sub})
		}
	}

	// 2. Fall back to matching by email.
	if user == nil {
		existingUsers, _, _ := s.identityService.ListUsers(c.Request.Context(), 0, 1, claims.Email)
		if len(existingUsers) > 0 {
			user = &existingUsers[0]
			// Backfill the federated link for a user that predates the (idp_id, sub)
			// binding (created before #364) so subsequent logins match by subject.
			// Only fills when currently unset; best-effort, keyed by the matched PK.
			if claims.Sub != "" {
				if tag, err := s.db.Pool.Exec(c.Request.Context(),
					//orgscope:ignore keyed by globally-unique users.id (UUID PK) from the email match above
					`UPDATE users SET idp_id = $1, external_user_id = $2 WHERE id = $3 AND external_user_id IS NULL`,
					idp.ID, claims.Sub, user.ID); err != nil {
					s.logger.Warn("Failed to backfill federated identity link for existing user",
						zap.String("user_id", user.ID), zap.Error(err))
				} else if tag.RowsAffected() > 0 {
					s.logAuditEvent(c.Request.Context(), "authentication", "sso", "sso_identity_backfilled", "success",
						user.ID, c.ClientIP(), user.ID, "user", map[string]interface{}{"idp_id": idp.ID.String(), "external_user_id": claims.Sub})
				}
			}
		}
	}

	// 3. Otherwise provision a new user.
	if user == nil {
		user = &identity.User{
			UserName:      claims.Email,
			Enabled:       true,
			EmailVerified: true,
		}
		user.SetEmail(claims.Email)
		user.SetFirstName(claims.Name)
		if err := s.identityService.CreateUser(c.Request.Context(), user); err != nil {
			s.logger.Error("Failed to create SSO user", zap.Error(err))
			s.logAuditEvent(c.Request.Context(), "authentication", "sso", "sso_login", "failure",
				"", c.ClientIP(), "", "user", map[string]interface{}{"reason": "provisioning_failed", "idp_id": idp.ID.String(), "email": claims.Email})
			c.JSON(500, gin.H{"error": "failed to provision user"})
			return
		}
		s.logAuditEvent(c.Request.Context(), "authentication", "sso", "sso_user_provisioned", "success",
			user.ID, c.ClientIP(), user.ID, "user", map[string]interface{}{"idp_id": idp.ID.String(), "email": claims.Email})
		// Bind the JIT-provisioned user to the IdP subject so it is a stable
		// federated link (users.idp_id + external_user_id), not just an
		// email-matched account. Best-effort: a unique (idp_id, external_user_id)
		// collision or write error must not fail the login. The UPDATE is
		// RLS-scoped to the caller's org via the pool's acquire hook.
		if claims.Sub != "" {
			if _, err := s.db.Pool.Exec(c.Request.Context(),
				//orgscope:ignore keyed by globally-unique users.id (UUID PK) just returned from CreateUser
				`UPDATE users SET idp_id = $1, external_user_id = $2 WHERE id = $3`,
				idp.ID, claims.Sub, user.ID); err != nil {
				s.logger.Warn("Failed to persist federated identity link for JIT user",
					zap.String("user_id", user.ID), zap.Error(err))
			} else {
				s.logAuditEvent(c.Request.Context(), "authentication", "sso", "sso_identity_linked", "success",
					user.ID, c.ClientIP(), user.ID, "user", map[string]interface{}{"idp_id": idp.ID.String(), "external_user_id": claims.Sub})
			}
		}
	}

	s.logAuditEvent(c.Request.Context(), "authentication", "sso", "sso_login", "success",
		user.ID, c.ClientIP(), user.ID, "user", map[string]interface{}{"idp_id": idp.ID.String()})

	authCode := &AuthorizationCode{
		Code:        GenerateRandomToken(32),
		ClientID:    originalParams["client_id"],
		UserID:      user.ID,
		RedirectURI: originalParams["redirect_uri"],
		Scope:       originalParams["scope"],
		State:       originalParams["state"],
		Nonce:       originalParams["nonce"],
	}
	s.CreateAuthorizationCode(c.Request.Context(), authCode)

	// 7. Redirect back to the original client
	redirectURL, _ := url.Parse(originalParams["redirect_uri"])
	query := redirectURL.Query()
	query.Set("code", authCode.Code)
	if authCode.State != "" {
		query.Set("state", authCode.State)
	}
	redirectURL.RawQuery = query.Encode()

	c.Redirect(302, redirectURL.String())
}

func (s *Service) handleAuthorizeConsent(c *gin.Context) {
	// The subject MUST come from the authenticated session, never the request
	// body. This endpoint previously minted an authorization code for a
	// client-supplied user_id — and because the interactive-flow routes run
	// without auth in development, any caller could obtain a code for any user.
	// The real login flow (POST /oauth/login) derives the user server-side and
	// does not use this endpoint.
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(401, gin.H{
			"error":             "unauthorized",
			"error_description": "authenticated session required",
		})
		return
	}

	var req struct {
		ClientID            string `json:"client_id"`
		RedirectURI         string `json:"redirect_uri"`
		ResponseType        string `json:"response_type"`
		Scope               string `json:"scope"`
		State               string `json:"state"`
		Nonce               string `json:"nonce"`
		CodeChallenge       string `json:"code_challenge"`
		CodeChallengeMethod string `json:"code_challenge_method"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid_request"})
		return
	}

	// Validate redirect_uri against the registered client (previously unchecked
	// here — an open-redirect / code-delivery surface).
	client, err := s.GetClient(c.Request.Context(), req.ClientID)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid_client"})
		return
	}
	validRedirect := false
	for _, uri := range client.RedirectURIs {
		if uri == req.RedirectURI {
			validRedirect = true
			break
		}
	}
	if !validRedirect {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "redirect_uri not registered for client"})
		return
	}

	// Enforce per-application consent before issuing a code. If required and not
	// yet granted, return a consent challenge for the browser to render.
	required, cerr := s.consentRequired(c.Request.Context(), req.ClientID, userID, req.Scope)
	if cerr != nil {
		s.logger.Error("consent check failed", zap.Error(cerr))
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}
	if required {
		s.beginConsent(c, map[string]string{
			"client_id":             req.ClientID,
			"redirect_uri":          req.RedirectURI,
			"response_type":         req.ResponseType,
			"scope":                 req.Scope,
			"state":                 req.State,
			"nonce":                 req.Nonce,
			"code_challenge":        req.CodeChallenge,
			"code_challenge_method": req.CodeChallengeMethod,
		}, userID)
		return
	}

	// Generate authorization code
	code := GenerateRandomToken(32)

	authCode := &AuthorizationCode{
		Code:                code,
		ClientID:            req.ClientID,
		UserID:              userID,
		RedirectURI:         req.RedirectURI,
		Scope:               req.Scope,
		State:               req.State,
		Nonce:               req.Nonce,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
	}

	if err := s.CreateAuthorizationCode(c.Request.Context(), authCode); err != nil {
		// DB write failure: a transient outage becomes a retryable 503, a real
		// error stays a 500 (see unavailable.go).
		writeServerOrUnavailable(c, err)
		return
	}

	// Build redirect URL
	redirectURL, _ := url.Parse(req.RedirectURI)
	query := redirectURL.Query()
	query.Set("code", code)
	if req.State != "" {
		query.Set("state", req.State)
	}
	redirectURL.RawQuery = query.Encode()

	c.JSON(200, gin.H{
		"redirect_url": redirectURL.String(),
	})
}

// handleAuthorizeConsentV2 handles authorization consent using the new AuthorizeHandler
// This is called after user authentication and consent
func (s *Service) handleAuthorizeConsentV2(c *gin.Context) {
	// Subject comes from the authenticated session, never the request body (see
	// handleAuthorizeConsent). Previously user_id was a required body field, so
	// a caller could mint a code for any user against a stored auth session.
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(401, gin.H{
			"error":             "unauthorized",
			"error_description": "authenticated session required",
		})
		return
	}

	var req struct {
		AuthSession string `json:"auth_session" binding:"required"`
		SessionID   string `json:"session_id,omitempty"` // Optional session ID for linkage
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": err.Error()})
		return
	}

	// Issue authorization code using the handler
	code, err := s.authorizeHandler.IssueAuthorizationCode(c.Request.Context(), req.AuthSession, userID, req.SessionID)
	if err != nil {
		s.logger.Error("Failed to issue authorization code", zap.Error(err))
		c.JSON(500, gin.H{"error": "server_error", "error_description": "failed to issue authorization code"})
		return
	}

	// Retrieve the stored request to build redirect
	authReq, err := s.authorizeHandler.GetStoredAuthorizationRequest(c.Request.Context(), req.AuthSession)
	if err != nil {
		s.logger.Error("Failed to retrieve authorization request", zap.Error(err))
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}

	// Build redirect URI with authorization code
	redirectURI, err := BuildRedirectURI(authReq.RedirectURI, code, authReq.State, "", "")
	if err != nil {
		s.logger.Error("Failed to build redirect URI", zap.Error(err))
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}

	c.JSON(200, gin.H{
		"redirect_url": redirectURI,
		"code":         code,
	})
}

func (s *Service) handleToken(c *gin.Context) {
	// CORS is handled by the APISIX gateway for all routes
	if c.Request.Method == "OPTIONS" {
		c.AbortWithStatus(204)
		return
	}

	grantType := c.PostForm("grant_type")

	switch grantType {
	case "authorization_code":
		s.handleAuthorizationCodeGrant(c)
	case "refresh_token":
		s.handleRefreshTokenGrant(c)
	case "client_credentials":
		s.handleClientCredentialsGrant(c)
	case grantTypeTokenExchange:
		s.handleTokenExchangeGrant(c)
	case grantTypeDeviceCode:
		s.handleDeviceCodeGrant(c)
	default:
		c.JSON(400, gin.H{"error": "unsupported_grant_type"})
	}
}

func (s *Service) handleAuthorizationCodeGrant(c *gin.Context) {
	code := c.PostForm("code")
	clientID, clientSecret, credsOK := clientCredentials(c)
	if !credsOK {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "use only one client authentication method"})
		return
	}
	redirectURI := c.PostForm("redirect_uri")
	codeVerifier := c.PostForm("code_verifier")

	s.logger.Debug("Token request received",
		zap.String("client_id", clientID),
		zap.String("redirect_uri", redirectURI),
		zap.Bool("has_code", code != ""),
		zap.Bool("has_verifier", codeVerifier != ""))

	// Atomically retrieve and delete authorization code (single use per RFC 6749 §4.1.2)
	authCode, err := s.ConsumeAuthorizationCode(c.Request.Context(), code)
	if err != nil {
		s.logger.Debug("Failed to consume authorization code", zap.Error(err))
		c.JSON(400, gin.H{"error": "invalid_grant"})
		return
	}

	// Verify the auth code was issued to the requesting client (RFC 6749 §4.1.3)
	if authCode.ClientID != clientID {
		s.logger.Warn("Auth code client_id mismatch",
			zap.String("code_client_id", authCode.ClientID),
			zap.String("request_client_id", clientID))
		c.JSON(400, gin.H{"error": "invalid_grant"})
		return
	}

	// Verify client
	client, err := s.GetClient(c.Request.Context(), clientID)
	if err != nil {
		s.logger.Debug("Failed to get client", zap.String("client_id", clientID), zap.Error(err))
		c.JSON(401, gin.H{"error": "invalid_client"})
		return
	}

	// For confidential clients, verify client_secret
	// For public clients, skip secret verification (use PKCE instead)
	if client.Type == "confidential" && subtle.ConstantTimeCompare([]byte(client.ClientSecret), []byte(clientSecret)) != 1 {
		c.JSON(401, gin.H{"error": "invalid_client"})
		return
	}

	// Verify redirect URI
	if authCode.RedirectURI != redirectURI {
		c.JSON(400, gin.H{"error": "invalid_grant"})
		return
	}

	// Verify PKCE - required for public clients, optional for confidential
	if authCode.CodeChallenge != "" {
		// Reject "plain" PKCE in production: it's a bare string compare with no
		// protection against code interception, and only exists for insecure-
		// context dev clients (crypto.subtle unavailable). A prod console is on
		// HTTPS and always uses S256, so plain here would only help an attacker.
		if authCode.CodeChallengeMethod == "plain" && s.config != nil && s.config.IsProduction() {
			c.JSON(400, gin.H{"error": "invalid_grant", "error_description": "PKCE method 'plain' is not allowed in production; use S256"})
			return
		}
		if !VerifyPKCE(codeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod) {
			c.JSON(400, gin.H{"error": "invalid_grant", "error_description": "PKCE verification failed"})
			return
		}
	} else if client.Type == "public" {
		// Public clients MUST use PKCE
		c.JSON(400, gin.H{"error": "invalid_grant", "error_description": "PKCE required for public clients"})
		return
	}

	// Retrieve session_id associated with this auth code from Redis
	sessionID, _ := s.redis.Client.Get(c.Request.Context(), "authcode_session:"+code).Result()
	// Clean up the Redis key
	if sessionID != "" {
		s.redis.Client.Del(c.Request.Context(), "authcode_session:"+code)
	}

	// Fallback: if the Redis bridge is empty (the login path didn't write
	// one, or the key expired), look up the user's most-recently-started
	// active session. Without this, the access token has no `sid` claim
	// and every downstream handler that requires session_id (stepup,
	// logout, etc.) rejects the token even though a valid session exists.
	// See issue #124.
	if sessionID == "" {
		// Defense in depth: if for any reason the Redis bridge missed,
		// fall back to the user's most-recently-started active session
		// so the access token still carries a usable sid claim.
		if org, oerr := orgctx.From(c.Request.Context()); oerr == nil {
			_ = s.db.Pool.QueryRow(c.Request.Context(), `
				SELECT id FROM sessions
				WHERE user_id = $1
				  AND client_id = $2
				  AND org_id = $3
				  AND (revoked IS NULL OR revoked = false)
				  AND expires_at > NOW()
				ORDER BY started_at DESC
				LIMIT 1
			`, authCode.UserID, clientID, org.ID).Scan(&sessionID)
		}
	}

	// Generate tokens (with session ID linkage)
	accessToken, _ := s.GenerateJWT(c.Request.Context(), authCode.UserID, clientID, authCode.Scope, client.AccessTokenLifetime, sessionID)

	response := TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   client.AccessTokenLifetime,
		Scope:       authCode.Scope,
	}

	// Generate ID token if openid scope is requested
	if strings.Contains(authCode.Scope, "openid") {
		idToken, _ := s.GenerateIDToken(c.Request.Context(), authCode.UserID, clientID, authCode.Nonce, client.AccessTokenLifetime, sessionID)
		response.IDToken = idToken
	}

	// Generate refresh token if allowed
	if client.AllowRefreshToken && strings.Contains(authCode.Scope, "offline_access") {
		refreshToken := GenerateRandomToken(32)
		if err := s.CreateRefreshToken(c.Request.Context(), &RefreshToken{
			Token:     refreshToken,
			ClientID:  clientID,
			UserID:    authCode.UserID,
			Scope:     authCode.Scope,
			SessionID: sessionID,
			ExpiresAt: time.Now().Add(time.Duration(client.RefreshTokenLifetime) * time.Second),
		}); err != nil {
			// Don't hand the client a token we couldn't persist — every
			// subsequent /oauth/token grant_type=refresh_token call would
			// 400 because the row isn't there (exactly how the missing
			// session_id column went undetected until migration v31).
			s.logger.Error("failed to persist refresh token",
				zap.String("client_id", clientID),
				zap.String("user_id", authCode.UserID),
				zap.Error(err))
		} else {
			response.RefreshToken = refreshToken
		}
	}

	c.JSON(200, response)
}

// userIsActive reports whether the user still exists and is enabled. Keyed by
// the globally-unique user id (UUID PK), so no org context is required — the
// refresh-token grant runs without one.
func (s *Service) userIsActive(ctx context.Context, userID string) (bool, error) {
	if userID == "" {
		return false, nil
	}
	var enabled bool
	err := s.db.Pool.QueryRow(ctx,
		//orgscope:ignore keyed by globally-unique users.id (UUID PK); refresh grant has no org context
		"SELECT enabled FROM users WHERE id = $1", userID).Scan(&enabled)
	if err != nil {
		// No row → user deleted; treat as inactive, not an error.
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return enabled, nil
}

func (s *Service) handleRefreshTokenGrant(c *gin.Context) {
	refreshToken := c.PostForm("refresh_token")
	clientID, clientSecret, credsOK := clientCredentials(c)
	if !credsOK {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "use only one client authentication method"})
		return
	}

	// Verify client
	client, err := s.GetClient(c.Request.Context(), clientID)
	if err != nil || subtle.ConstantTimeCompare([]byte(client.ClientSecret), []byte(clientSecret)) != 1 {
		c.JSON(401, gin.H{"error": "invalid_client"})
		return
	}

	// Get refresh token
	token, err := s.GetRefreshToken(c.Request.Context(), refreshToken)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid_grant"})
		return
	}

	// REUSE DETECTION (RFC 6819 §5.2.2.3 / OAuth 2.1 §6.1).
	//
	// A token that is present but already rotated means two parties hold the
	// same secret. The server cannot tell which one is the legitimate client,
	// so it revokes the entire family and forces re-authentication. Revoking
	// just this token would leave the other holder — plausibly the attacker,
	// since the honest client is usually the one that trips the detector —
	// with a working chain.
	if token.UsedAt != nil {
		s.handleRefreshTokenReuse(c.Request.Context(), token, clientID)
		c.JSON(400, gin.H{
			"error":             "invalid_grant",
			"error_description": "refresh token reuse detected; the token family has been revoked",
		})
		return
	}

	// Verify the refresh token was issued to the requesting client (RFC 6749 §10.4)
	if token.ClientID != clientID {
		s.logger.Warn("Refresh token client_id mismatch",
			zap.String("token_client_id", token.ClientID),
			zap.String("request_client_id", clientID))
		c.JSON(400, gin.H{"error": "invalid_grant"})
		return
	}

	// Re-validate the token's subject: a refresh token outlives its access
	// token, so a user disabled or deleted AFTER the grant would keep minting
	// fresh access tokens until the refresh token itself expired. Gate issuance
	// on the user still existing and being enabled — this is the actual
	// kill-switch behind user disable/delete/SCIM-deprovision.
	if active, err := s.userIsActive(c.Request.Context(), token.UserID); err != nil {
		s.logger.Error("refresh grant: failed to check user status",
			zap.String("user_id", token.UserID), zap.Error(err))
		// A DB outage here is a transient brownout, not a client error: tell the
		// client to retry shortly (503 temporarily_unavailable + Retry-After)
		// instead of a hard 500 it would hammer. See unavailable.go.
		writeServerOrUnavailable(c, err)
		return
	} else if !active {
		s.logger.Info("refresh grant denied: user disabled or deleted",
			zap.String("user_id", token.UserID))
		c.JSON(400, gin.H{"error": "invalid_grant", "error_description": "user_inactive"})
		return
	}

	// Check if the linked session has been revoked
	if token.SessionID != "" {
		// Check Redis for revoked session
		revoked, _ := s.redis.Client.Exists(c.Request.Context(), "revoked_session:"+token.SessionID).Result()
		if revoked > 0 {
			c.JSON(400, gin.H{"error": "invalid_grant", "error_description": "session_revoked"})
			return
		}
		// Debounced activity update (only if >30s since last update)
		debounceKey := "session_activity:" + token.SessionID
		if set, _ := s.redis.Client.SetNX(c.Request.Context(), debounceKey, "1", 30*time.Second).Result(); set {
			// Update session activity in background with timeout
			go func(sessionID string) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				s.identityService.UpdateSessionActivity(ctx, sessionID)
			}(token.SessionID)
		}
	}

	// Generate new access token (with session ID linkage)
	accessToken, _ := s.GenerateJWT(c.Request.Context(), token.UserID, clientID, token.Scope, client.AccessTokenLifetime, token.SessionID)

	response := TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   client.AccessTokenLifetime,
		Scope:       token.Scope,
	}

	// Refresh-token rotation (RFC 6749 §6 / RFC 6819 §5.2.2.3): when the
	// scope still carries `offline_access` and the client is allowed
	// refresh tokens, issue a new refresh_token, invalidate the old one,
	// and return both. Without this, clients can't safely store the
	// refresh_token long-term, and refresh-token theft has no detection
	// surface. The integration suite's TestSessionManagement/refresh_access_token
	// expects the rotated token in the response.
	if client.AllowRefreshToken && strings.Contains(token.Scope, "offline_access") {
		// Claim the old token first. The UPDATE is conditional on it being
		// unused, so of two concurrent refreshes with the same token exactly
		// one proceeds; the loser falls through to the reuse path on its next
		// attempt rather than both being handed fresh chains.
		claimed, err := s.markRefreshTokenRotated(c.Request.Context(), refreshToken)
		if err != nil {
			// clientID is attacker-controlled (form field or Basic header), so
			// it is scrubbed of CR/LF before logging — otherwise it can forge
			// or split log lines (CWE-117).
			s.logger.Error("failed to mark refresh token rotated",
				zap.String("client_id", sanitizeForLog(clientID)), zap.Error(err))
			writeServerOrUnavailable(c, err)
			return
		}
		if !claimed {
			// Someone rotated it between our read and this update: same
			// situation the detector above catches, just observed later.
			s.handleRefreshTokenReuse(c.Request.Context(), token, clientID)
			c.JSON(400, gin.H{
				"error":             "invalid_grant",
				"error_description": "refresh token reuse detected; the token family has been revoked",
			})
			return
		}

		newRefresh := GenerateRandomToken(32)
		if err := s.CreateRefreshToken(c.Request.Context(), &RefreshToken{
			Token:     newRefresh,
			ClientID:  clientID,
			UserID:    token.UserID,
			Scope:     token.Scope,
			SessionID: token.SessionID,
			ExpiresAt: time.Now().Add(time.Duration(client.RefreshTokenLifetime) * time.Second),
			// Successors inherit the family so a later replay revokes the
			// whole chain, however many rotations deep it is.
			FamilyID: token.FamilyID,
		}); err != nil {
			s.logger.Error("failed to persist rotated refresh token",
				zap.String("client_id", sanitizeForLog(clientID)),
				zap.String("user_id", sanitizeForLog(token.UserID)),
				zap.Error(err))
		} else {
			response.RefreshToken = newRefresh
		}
	}

	c.JSON(200, response)
}

func (s *Service) handleClientCredentialsGrant(c *gin.Context) {
	clientID, clientSecret, credsOK := clientCredentials(c)
	if !credsOK {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "use only one client authentication method"})
		return
	}
	scope := c.PostForm("scope")

	// Verify client
	client, err := s.GetClient(c.Request.Context(), clientID)
	if err != nil || subtle.ConstantTimeCompare([]byte(client.ClientSecret), []byte(clientSecret)) != 1 {
		c.JSON(401, gin.H{"error": "invalid_client"})
		return
	}

	// SECURITY: the requested scope must be registered for this client
	// (RFC 6749 §3.3). Without this the caller-supplied scope was minted into
	// the access token verbatim, so any confidential client could grant itself
	// any scope it liked regardless of what it was provisioned for.
	if !scopeAllowedForClient(client, scope) {
		c.JSON(400, gin.H{
			"error":             "invalid_scope",
			"error_description": "requested scope exceeds the scopes registered for this client",
		})
		return
	}

	// Generate access token (no user context)
	accessToken, _ := s.GenerateJWT(c.Request.Context(), "", clientID, scope, client.AccessTokenLifetime)

	c.JSON(200, TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   client.AccessTokenLifetime,
		Scope:       scope,
	})
}

// requireTokenEndpointClientAuth authenticates the caller of a token-adjacent
// endpoint. RFC 7662 §2.1 requires the introspection endpoint to be protected,
// and RFC 7009 §2.1 requires client authentication on revocation — both were
// previously wide open, so anyone who obtained (or guessed) a token string
// could read its full metadata or revoke arbitrary tokens.
//
// Confidential clients authenticate with client_id + client_secret; public
// clients (which have no secret to present) authenticate with client_id alone,
// as RFC 7009 §2.1 allows. Credentials are read from the POST body
// (client_secret_post); HTTP Basic support is a separate follow-up.
// It is applied as route middleware (like the /ssf and /clients groups) rather
// than inline, so the endpoint is protected at its only real entry point while
// the handlers stay independently unit-testable.
func (s *Service) requireTokenEndpointClientAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientID, clientSecret, credsOK := clientCredentials(c)
		if !credsOK {
			c.AbortWithStatusJSON(400, gin.H{
				"error":             "invalid_request",
				"error_description": "use only one client authentication method",
			})
			return
		}
		if clientID == "" {
			c.Header("WWW-Authenticate", `Basic realm="oauth"`)
			c.AbortWithStatusJSON(401, gin.H{
				"error":             "invalid_client",
				"error_description": "client authentication required",
			})
			return
		}
		client, err := s.GetClient(c.Request.Context(), clientID)
		if err != nil || client == nil {
			c.AbortWithStatusJSON(401, gin.H{"error": "invalid_client"})
			return
		}
		if client.Type != "public" {
			if subtle.ConstantTimeCompare([]byte(client.ClientSecret), []byte(clientSecret)) != 1 {
				c.AbortWithStatusJSON(401, gin.H{"error": "invalid_client"})
				return
			}
		}
		c.Next()
	}
}

func (s *Service) handleIntrospect(c *gin.Context) {
	token := c.PostForm("token")
	if token == "" {
		c.JSON(200, gin.H{"active": false})
		return
	}

	// Try to parse as JWT
	parsed, err := jwt.Parse(token, s.verificationKeyfunc)
	if err != nil || !parsed.Valid {
		// Check if it's a refresh token (scoped to the caller's org)
		org, oerr := orgctx.From(c.Request.Context())
		if oerr != nil {
			c.JSON(200, gin.H{"active": false})
			return
		}
		var userID, clientID, scope string
		err := s.db.Pool.QueryRow(c.Request.Context(), `
			SELECT user_id, client_id, scope FROM oauth_refresh_tokens
			WHERE token = $1 AND org_id = $2 AND expires_at > NOW()
		`, token, org.ID).Scan(&userID, &clientID, &scope)
		if err != nil {
			c.JSON(200, gin.H{"active": false})
			return
		}
		c.JSON(200, gin.H{
			"active":     true,
			"token_type": "refresh_token",
			"client_id":  clientID,
			"sub":        userID,
			"scope":      scope,
		})
		return
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		c.JSON(200, gin.H{"active": false})
		return
	}

	// Honor revocation: a signature-valid access token may have been revoked via
	// /oauth/revoke or /oauth/logout(-all). RFC 7662 §2.2 — a revoked token (or
	// one whose revocation state can't be verified) introspects as active:false
	// (fail closed; not a 401, since introspection's contract is the boolean).
	userID, _ := claims["sub"].(string)
	var issuedAt int64
	if iatF, ok := claims["iat"].(float64); ok {
		issuedAt = int64(iatF)
	}
	if revoked, err := s.IsAccessTokenRevoked(c.Request.Context(), token, userID, issuedAt); err != nil {
		s.logger.Warn("introspect: revocation check failed", zap.Error(err))
		c.JSON(200, gin.H{"active": false})
		return
	} else if revoked {
		c.JSON(200, gin.H{"active": false})
		return
	}

	response := gin.H{
		"active":     true,
		"token_type": "access_token",
	}
	if sub, ok := claims["sub"].(string); ok {
		response["sub"] = sub
	}
	if clientID, ok := claims["client_id"].(string); ok {
		response["client_id"] = clientID
	}
	if scope, ok := claims["scope"].(string); ok {
		response["scope"] = scope
	}
	if exp, ok := claims["exp"].(float64); ok {
		response["exp"] = int64(exp)
	}
	if iat, ok := claims["iat"].(float64); ok {
		response["iat"] = int64(iat)
	}
	if iss, ok := claims["iss"].(string); ok {
		response["iss"] = iss
	}

	c.JSON(200, response)
}

func (s *Service) handleRevoke(c *gin.Context) {
	token := c.PostForm("token")
	hint := c.PostForm("token_type_hint")
	ctx := c.Request.Context()

	// RFC 7009 says we should accept revocation requests for either token
	// type and figure it out ourselves. Cover both — refresh-token row in
	// Postgres, and access-token blacklist in Redis (so /oauth/userinfo
	// stops accepting the bearer immediately).
	if hint != "refresh_token" {
		// Treat as access token. Verify the signature against our public key
		// before reading exp — only blacklist tokens we actually issued. A
		// garbage / forged token isn't worth a Redis entry, and verifying
		// here lets us read the claim shape with confidence.
		parsed, err := jwt.Parse(token, s.verificationKeyfunc)
		if err == nil && parsed != nil && parsed.Valid {
			if claims, ok := parsed.Claims.(jwt.MapClaims); ok {
				expSec, _ := claims["exp"].(float64)
				if expSec > 0 {
					_ = s.MarkAccessTokenRevoked(ctx, token, time.Unix(int64(expSec), 0))
				}
			}
		}
	}

	// Always best-effort the refresh-token row too; RFC 7009 doesn't
	// require the hint to be honored, and a no-op DELETE is cheap.
	s.RevokeRefreshToken(ctx, token)

	c.JSON(200, gin.H{"status": "revoked"})
}

// parseVerifiedClaims signature-verifies a JWT against the service's RSA signing key (RS256 pinned,
// preventing alg-confusion) and returns its claims. allowExpired skips exp/nbf validation — used only
// for the OIDC id_token_hint, which the spec permits to be expired — while STILL requiring a valid
// signature.
func (s *Service) parseVerifiedClaims(tokenString string, allowExpired bool) (jwt.MapClaims, error) {
	keyfunc := func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return s.verificationKeyfunc(t)
	}
	opts := []jwt.ParserOption{jwt.WithValidMethods([]string{"RS256"})}
	if allowExpired {
		opts = append(opts, jwt.WithoutClaimsValidation())
	}
	token, err := jwt.NewParser(opts...).Parse(tokenString, keyfunc)
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("token signature verification failed: %w", err)
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}
	return claims, nil
}

func (s *Service) handleUserInfo(c *gin.Context) {
	// CORS is handled by the APISIX gateway for all routes
	if c.Request.Method == "OPTIONS" {
		c.AbortWithStatus(204)
		return
	}

	// Extract access token from Authorization header
	authHeader := c.GetHeader("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		c.JSON(401, gin.H{"error": "invalid_token"})
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	// Parse and validate JWT
	token, err := jwt.Parse(tokenString, s.verificationKeyfunc)

	if err != nil || !token.Valid {
		c.JSON(401, gin.H{"error": "invalid_token"})
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.JSON(401, gin.H{"error": "invalid_token"})
		return
	}

	userID, _ := claims["sub"].(string)
	iat, _ := claims["iat"].(float64)

	// Honor revocation: a signature-valid token may still have been revoked
	// via /oauth/revoke or /oauth/logout(-all). Without this, "log out and
	// redirect" UX was security-theater.
	if revoked, err := s.IsAccessTokenRevoked(c.Request.Context(), tokenString, userID, int64(iat)); err != nil {
		s.logger.Warn("userinfo: revocation check failed", zap.Error(err))
		c.JSON(401, gin.H{"error": "invalid_token"})
		return
	} else if revoked {
		c.JSON(401, gin.H{"error": "invalid_token", "error_description": "token has been revoked"})
		return
	}

	// Get user info
	userInfo, err := s.GetUserInfo(c.Request.Context(), userID)
	if err != nil {
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}

	// OIDC Core §5.3.2: the UserInfo `sub` MUST match the one in the ID token.
	// The access token carries the raw user id (that is what the lookup above
	// needs), so the client-facing subject is derived here from the token's
	// audience rather than stored.
	aud, _ := claims["aud"].(string)
	userInfo.Sub = s.subjectFor(userID, aud)

	c.JSON(200, userInfo)
}

// Client management handlers

func (s *Service) handleListClients(c *gin.Context) {
	offset := 0
	if o := c.Query("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil {
			offset = parsed
		}
	}

	limit := 20
	if l := c.Query("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil {
			limit = parsed
		}
	}

	clients, total, err := s.ListClients(c.Request.Context(), offset, limit)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("list clients", err), s.logger)
		return
	}

	c.Header("X-Total-Count", strconv.Itoa(total))
	c.JSON(200, clients)
}

func (s *Service) handleCreateClient(c *gin.Context) {
	var client OAuthClient
	if err := c.ShouldBindJSON(&client); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// Generate the primary key + client ID and secret. The INSERT supplies the
	// id column explicitly, so it must be a valid UUID — leaving it empty makes
	// Postgres reject "" for the uuid type (500), bypassing the column default.
	client.ID = uuid.New().String()
	client.ClientID = "client_" + GenerateRandomToken(16)
	client.ClientSecret = GenerateRandomToken(32)

	if err := s.CreateClient(c.Request.Context(), &client); err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("create client", err), s.logger)
		return
	}

	// Mirror the new client into the applications table so it shows up in the
	// admin console's Applications list (which reads `applications`, not
	// `oauth_clients`) and supports the per-row actions (edit/delete/SSO) that
	// key off an applications row. Best-effort: the OAuth client is already
	// created, so a listing-row failure must not fail the registration.
	if org, oerr := orgctx.From(c.Request.Context()); oerr == nil {
		appType := client.Type
		if appType == "" {
			appType = "web"
		}
		if _, aerr := s.db.Pool.Exec(c.Request.Context(),
			`INSERT INTO applications (client_id, name, description, type, redirect_uris, oauth_client_id, org_id)
			 VALUES ($1, $2, $3, $4, $5, $6, $7)
			 ON CONFLICT (client_id) DO NOTHING`,
			client.ClientID, client.Name, client.Description, appType, client.RedirectURIs, client.ID, org.ID,
		); aerr != nil {
			s.logger.Warn("OAuth client created but applications-list row insert failed",
				zap.String("client_id", client.ClientID), zap.Error(aerr))
		}
	}

	c.JSON(201, client)
}

func (s *Service) handleGetClient(c *gin.Context) {
	client, err := s.GetClient(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(404, gin.H{"error": "client not found"})
		return
	}

	// Don't expose client secret in GET
	client.ClientSecret = ""
	c.JSON(200, client)
}

func (s *Service) handleUpdateClient(c *gin.Context) {
	var client OAuthClient
	if err := c.ShouldBindJSON(&client); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	if err := s.UpdateClient(c.Request.Context(), c.Param("id"), &client); err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("update client", err), s.logger)
		return
	}

	c.JSON(200, client)
}

func (s *Service) handleDeleteClient(c *gin.Context) {
	if err := s.DeleteClient(c.Request.Context(), c.Param("id")); err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("delete client", err), s.logger)
		return
	}

	c.JSON(204, nil)
}

func (s *Service) RegenerateClientSecret(ctx context.Context, clientID string) (string, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return "", err
	}
	newSecret := GenerateRandomToken(32)
	_, err = s.db.Pool.Exec(ctx, "UPDATE oauth_clients SET client_secret = $2, updated_at = NOW() WHERE client_id = $1 AND org_id = $3", clientID, newSecret, org.ID)
	if err != nil {
		return "", err
	}
	return newSecret, nil
}

func (s *Service) handleRegenerateClientSecret(c *gin.Context) {
	secret, err := s.RegenerateClientSecret(c.Request.Context(), c.Param("id"))
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("regenerate client secret", err), s.logger)
		return
	}
	c.JSON(200, gin.H{"client_secret": secret})
}

// handleStepUpChallenge and handleStepUpVerify are in stepup.go

// checkConcurrentSessions checks if the user has reached the concurrent session limit
// and returns the action to take based on the session policy.
func (s *Service) checkConcurrentSessions(ctx context.Context, userID, clientID string) (string, []map[string]interface{}, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return "", nil, err
	}

	policy := s.getEffectiveSessionPolicy(ctx, clientID)
	if policy.MaxConcurrentSessions <= 0 {
		return "", nil, nil // unlimited
	}

	count, err := s.identityService.CountActiveSessions(ctx, userID)
	if err != nil {
		return "", nil, err
	}

	if count < policy.MaxConcurrentSessions {
		return "", nil, nil // under limit
	}

	switch policy.ConcurrentSessionStrategy {
	case "terminate_oldest":
		// Terminate oldest session
		var oldestID string
		err := s.db.Pool.QueryRow(ctx, `
			SELECT id FROM sessions
			WHERE user_id = $1 AND org_id = $2 AND (revoked IS NULL OR revoked = false) AND expires_at > NOW()
			ORDER BY started_at ASC LIMIT 1
		`, userID, org.ID).Scan(&oldestID)
		if err == nil && oldestID != "" {
			s.revokeSessionWithRedis(ctx, oldestID)
		}
		return "", nil, nil
	case "prompt_user":
		// Return active sessions for user to choose
		rows, err := s.db.Pool.Query(ctx, `
			SELECT id, ip_address, user_agent, started_at, last_seen_at
			FROM sessions
			WHERE user_id = $1 AND org_id = $2 AND (revoked IS NULL OR revoked = false) AND expires_at > NOW()
			ORDER BY last_seen_at DESC
		`, userID, org.ID)
		if err != nil {
			return "", nil, err
		}
		defer rows.Close()
		var sessions []map[string]interface{}
		for rows.Next() {
			var id, ip, ua string
			var startedAt, lastSeen time.Time
			if err := rows.Scan(&id, &ip, &ua, &startedAt, &lastSeen); err != nil {
				continue
			}
			sessions = append(sessions, map[string]interface{}{
				"id":           id,
				"ip_address":   ip,
				"user_agent":   ua,
				"started_at":   startedAt,
				"last_seen_at": lastSeen,
			})
		}
		return "prompt_user", sessions, nil
	default: // deny_new
		return "denied", nil, fmt.Errorf("concurrent session limit reached")
	}
}

// handleForceLogin handles POST /oauth/force-login — terminates a chosen session and resumes login
func (s *Service) handleForceLogin(c *gin.Context) {
	var req struct {
		TerminateSessionID string `json:"terminate_session_id"`
		LoginSession       string `json:"login_session"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid_request"})
		return
	}

	// Revoke the specified session
	if req.TerminateSessionID != "" {
		s.revokeSessionWithRedis(c.Request.Context(), req.TerminateSessionID)
	}

	// Retrieve the pending login session from Redis
	sessionKey := "login_session:" + req.LoginSession
	data, err := s.redis.Client.Get(c.Request.Context(), sessionKey).Result()
	if err != nil {
		c.JSON(400, gin.H{"error": "login_session_expired", "error_description": "Login session has expired. Please sign in again."})
		return
	}

	// Parse the stored oauth params
	var oauthParams map[string]string
	if err := json.Unmarshal([]byte(data), &oauthParams); err != nil {
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}

	userID := oauthParams["user_id"]
	clientIP := c.ClientIP()
	userAgent := c.Request.UserAgent()

	// Create session and issue code
	session, sessionErr := s.identityService.CreateSession(c.Request.Context(), userID, oauthParams["client_id"], clientIP, userAgent, 24*time.Hour)
	if sessionErr != nil {
		s.logger.Warn("Failed to create session during force-login", zap.Error(sessionErr))
	}
	if session != nil {
		oauthParams["session_id"] = session.ID
	}

	s.redis.Client.Del(c.Request.Context(), sessionKey)
	s.issueAuthorizationCode(c, oauthParams, userID)
}

// revokeAllUserSessions revokes all active sessions for a user
func (s *Service) revokeAllUserSessions(ctx context.Context, userID string) error {
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
		s.revokeSessionWithRedis(ctx, sessionID)
	}

	// Emit a CAEP session-revoked SET to subscribed SSF receivers so downstream
	// apps drop the user immediately (best-effort; never fails the revocation).
	var email string
	_ = s.db.Pool.QueryRow(ctx, `SELECT COALESCE(email,'') FROM users WHERE id=$1 AND org_id=$2`, userID, org.ID).Scan(&email)
	s.EmitCAEPEvent(ctx, org.ID, EventSessionRevoked, email, userID,
		map[string]interface{}{"reason": "session_revoked"})

	return nil
}

// revokeAllUserRefreshTokens deletes all refresh tokens for a user
func (s *Service) revokeAllUserRefreshTokens(ctx context.Context, userID string) error {
	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}
	_, err = s.db.Pool.Exec(ctx, `DELETE FROM oauth_refresh_tokens WHERE user_id = $1 AND org_id = $2`, userID, org.ID)
	return err
}

// handleLogout handles POST/GET /oauth/logout — OIDC RP-initiated logout
// postLogoutRedirectAllowed reports whether uri is a safe destination to send
// the browser to after an RP-initiated logout.
//
// SECURITY: handleLogout used to redirect to any caller-supplied
// post_logout_redirect_uri with no validation at all — an open redirect from
// the IdP's own origin (OIDC RP-Initiated Logout §2 requires the OP to verify
// it against values registered for the client).
//
// The client model has no dedicated post_logout_redirect_uris list yet, so the
// allowlist is derived from the client's registered redirect_uris by comparing
// ORIGIN (scheme + host + port) rather than the full URI. Matching on origin
// keeps legitimate deployments working — the post-logout landing page is very
// often a different path on the same site than the OAuth callback — while
// still refusing to send the user to an attacker-controlled domain. A
// first-class post_logout_redirect_uris column can tighten this to exact-match
// later.
func (s *Service) postLogoutRedirectAllowed(ctx context.Context, clientID, uri string) bool {
	if clientID == "" || uri == "" {
		return false
	}
	target, err := url.Parse(uri)
	if err != nil || target.Scheme == "" || target.Host == "" {
		return false
	}
	client, err := s.GetClient(ctx, clientID)
	if err != nil || client == nil {
		return false
	}
	for _, registered := range client.RedirectURIs {
		ru, err := url.Parse(registered)
		if err != nil {
			continue
		}
		if strings.EqualFold(ru.Scheme, target.Scheme) && strings.EqualFold(ru.Host, target.Host) {
			return true
		}
	}
	return false
}

// audienceClientID extracts the client_id from an ID token's `aud` claim,
// which may be encoded as a bare string or as an array.
func audienceClientID(claims map[string]interface{}) string {
	switch aud := claims["aud"].(type) {
	case string:
		return aud
	case []interface{}:
		if len(aud) > 0 {
			if first, ok := aud[0].(string); ok {
				return first
			}
		}
	}
	return ""
}

func (s *Service) handleLogout(c *gin.Context) {
	// Try to identify user from id_token_hint or Bearer token
	idTokenHint := c.Query("id_token_hint")
	if idTokenHint == "" {
		idTokenHint = c.PostForm("id_token_hint")
	}
	postLogoutRedirectURI := c.Query("post_logout_redirect_uri")
	if postLogoutRedirectURI == "" {
		postLogoutRedirectURI = c.PostForm("post_logout_redirect_uri")
	}

	var userID string
	var bearerToken string
	// Client identified by the id_token_hint's audience — the only trustworthy
	// way to know which client's registered URIs may be redirected to below.
	var hintClientID string

	if idTokenHint != "" {
		// Parse the ID token (don't validate expiry since it may be expired per OIDC spec,
		// but signature must still be valid to prevent forged id_token_hint attacks).
		if hintClaims, err := s.parseVerifiedClaims(idTokenHint, true); err == nil {
			if sub, ok := hintClaims["sub"].(string); ok {
				userID = sub
			}
			hintClientID = audienceClientID(hintClaims)
		}
	}

	// Also try Bearer token (and remember it so we can blacklist it).
	authHeader := c.GetHeader("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		bearerToken = strings.TrimPrefix(authHeader, "Bearer ")
		if userID == "" {
			if bearerClaims, err := s.parseVerifiedClaims(bearerToken, false); err == nil {
				if sub, ok := bearerClaims["sub"].(string); ok {
					userID = sub
				}
			}
		}
	}

	// Per-token blacklist for the bearer: verify it (RS256-pinned) so we only
	// spend a Redis entry on a token we actually issued. The intent is to make
	// this specific access token stop working at /oauth/userinfo from the next
	// request onward, even if the broader per-user revocation marker isn't set
	// (single-session logout doesn't have to invalidate sibling sessions).
	if bearerToken != "" {
		if claims, err := s.parseVerifiedClaims(bearerToken, false); err == nil {
			if expSec, ok := claims["exp"].(float64); ok && expSec > 0 {
				_ = s.MarkAccessTokenRevoked(c.Request.Context(), bearerToken, time.Unix(int64(expSec), 0))
			}
		}
	}

	if userID != "" {
		s.revokeAllUserSessions(c.Request.Context(), userID)
		s.revokeAllUserRefreshTokens(c.Request.Context(), userID)

		// If the caller authenticated this logout with a Bearer access
		// token, the per-token blacklist above already kills that exact
		// bearer and sibling access tokens are intentionally left alone
		// — single-session logout. But OIDC RP-initiated logout
		// (id_token_hint, no Bearer) has no specific bearer to blacklist;
		// the caller is asserting "end the session associated with this
		// id_token", which in practice means invalidate every access
		// token still tied to that user's now-killed sessions. Fall back
		// to the per-user cutoff in that case so /oauth/userinfo stops
		// accepting any of them — otherwise the redirect to
		// post_logout_redirect_uri is the security-theater PR #82 spent
		// real work eliminating.
		if bearerToken == "" {
			_ = s.MarkUserTokensRevoked(c.Request.Context(), userID)
		}
		s.logger.Info("Single-session logout for user", zap.String("user_id", userID))

		// Log audit event in background with timeout
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			s.logAuditEvent(ctx, "authentication", "security", "logout", "success",
				userID, c.ClientIP(), userID, "user",
				map[string]interface{}{"method": "logout_endpoint"})
		}()
	}

	// Only redirect to a destination registered for the client that issued the
	// id_token_hint. An unverifiable or unregistered target is refused (the
	// logout itself has already happened) rather than followed.
	if postLogoutRedirectURI != "" {
		if s.postLogoutRedirectAllowed(c.Request.Context(), hintClientID, postLogoutRedirectURI) {
			c.Redirect(302, postLogoutRedirectURI)
			return
		}
		s.logger.Warn("refusing unregistered post_logout_redirect_uri",
			zap.String("client_id", sanitizeForLog(hintClientID)))
		c.JSON(400, gin.H{
			"error":             "invalid_request",
			"error_description": "post_logout_redirect_uri is not registered for the client identified by id_token_hint",
		})
		return
	}

	c.JSON(200, gin.H{"status": "logged_out"})
}

// handleLogoutAll handles POST /oauth/logout-all — authenticated self-service sign-out-everywhere
func (s *Service) handleLogoutAll(c *gin.Context) {
	// Get user from Bearer token
	authHeader := c.GetHeader("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		c.JSON(401, gin.H{"error": "unauthorized"})
		return
	}

	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	claims, err := s.parseVerifiedClaims(tokenStr, false)
	if err != nil {
		c.JSON(401, gin.H{"error": "invalid_token"})
		return
	}

	userID, _ := claims["sub"].(string)
	if userID == "" {
		c.JSON(401, gin.H{"error": "invalid_token"})
		return
	}

	s.revokeAllUserSessions(c.Request.Context(), userID)
	s.revokeAllUserRefreshTokens(c.Request.Context(), userID)
	// Bump the per-user revocation cutoff so every outstanding access token
	// (including the one used to call this endpoint) starts being rejected
	// by /oauth/userinfo on the next request.
	_ = s.MarkUserTokensRevoked(c.Request.Context(), userID)

	s.logger.Info("Logout-all for user", zap.String("user_id", userID))

	// Log audit event in background with timeout
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.logAuditEvent(ctx, "authentication", "security", "logout_all", "success",
			userID, c.ClientIP(), userID, "user",
			map[string]interface{}{"method": "logout_all_endpoint"})
	}()

	c.JSON(200, gin.H{"status": "all_sessions_revoked"})
}

// handleSessionInfo handles GET /oauth/session-info — returns session policy info for the current token
func (s *Service) handleSessionInfo(c *gin.Context) {
	// Extract session info from Bearer token
	authHeader := c.GetHeader("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		c.JSON(401, gin.H{"error": "unauthorized"})
		return
	}

	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	claims, err := s.parseVerifiedClaims(tokenStr, false)
	if err != nil {
		c.JSON(401, gin.H{"error": "invalid_token"})
		return
	}

	// Get client_id from aud claim
	clientID, _ := claims["aud"].(string)
	policy := s.getEffectiveSessionPolicy(c.Request.Context(), clientID)

	c.JSON(200, gin.H{
		"idle_timeout":     policy.IdleTimeout,
		"absolute_timeout": policy.AbsoluteTimeout,
		"bind_to_ip":       policy.BindSessionToIP,
	})
}

// generateTokensForUser generates access and ID tokens for a user (used for social login fallback)
func (s *Service) generateTokensForUser(ctx context.Context, user *SAMLUser, clientID string, scopes []string) (*TokenFlowResponse, error) {
	now := time.Now()
	accessLifetime := 1 * time.Hour
	org, _ := orgctx.From(ctx) // best-effort: per-tenant issuer when subdomain tenancy is on

	// Generate access token
	accessToken := generateRandomToken(32)
	accessExpiry := now.Add(accessLifetime)

	// Store access token
	accessTokenData := &AccessTokenData{
		Token:     accessToken,
		ClientID:  clientID,
		UserID:    user.ID,
		Scope:     strings.Join(scopes, " "),
		ExpiresAt: accessExpiry,
		CreatedAt: now,
	}

	// Store in Redis
	key := fmt.Sprintf("access_token:%s", accessToken)
	data, _ := json.Marshal(accessTokenData)
	s.redis.Client.Set(ctx, key, data, accessLifetime)

	// Create JWT for access token
	claims := jwt.MapClaims{
		"sub": user.ID,
		"aud": clientID,
		"iss": s.issuerForOrg(org),
		"exp": accessExpiry.Unix(),
		"iat": now.Unix(),
	}

	if containsScope(scopes, "profile") {
		claims["name"] = user.DisplayName
		claims["given_name"] = user.FirstName
		claims["family_name"] = user.LastName
	}
	if containsScope(scopes, "email") {
		claims["email"] = user.Email
		claims["email_verified"] = true
	}

	signKid, signKey := s.signingKey()
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	jwtToken.Header["kid"] = signKid
	signedToken, err := jwtToken.SignedString(signKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign access token: %w", err)
	}

	response := &TokenFlowResponse{
		AccessToken: signedToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(accessLifetime.Seconds()),
	}

	// Generate ID token for openid scope
	if containsScope(scopes, "openid") {
		idClaims := jwt.MapClaims{
			"iss":            s.issuerForOrg(org),
			"sub":            s.subjectFor(user.ID, clientID),
			"aud":            clientID,
			"exp":            accessExpiry.Unix(),
			"iat":            now.Unix(),
			"auth_time":      now.Unix(),
			"email":          user.Email,
			"email_verified": true,
		}
		if user.DisplayName != "" {
			idClaims["name"] = user.DisplayName
		}
		if user.FirstName != "" {
			idClaims["given_name"] = user.FirstName
		}
		if user.LastName != "" {
			idClaims["family_name"] = user.LastName
		}

		idKid, idSignKey := s.signingKey()
		idToken := jwt.NewWithClaims(jwt.SigningMethodRS256, idClaims)
		idToken.Header["kid"] = idKid
		signedIDToken, err := idToken.SignedString(idSignKey)
		if err == nil {
			response.IDToken = signedIDToken
		}
	}

	return response, nil
}

// containsScope checks if a scope exists in a slice
func containsScope(scopes []string, scope string) bool {
	for _, s := range scopes {
		if s == scope {
			return true
		}
	}
	return false
}
