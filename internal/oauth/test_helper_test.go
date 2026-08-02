// Package oauth provides test helpers for OIDC testing
package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/testutil"
	"github.com/openidx/openidx/internal/identity"
)

// mockIdentityService is a minimal mock for testing
type mockIdentityService struct {
	users map[string]*identity.User
}

func (m *mockIdentityService) GetUser(ctx context.Context, id string) (*identity.User, error) {
	user, ok := m.users[id]
	if !ok {
		return nil, errors.New("user not found")
	}
	return user, nil
}

// TestOIDCContext provides a complete test context for OIDC tests
type TestOIDCContext struct {
	T               *testing.T
	Service         *Service
	OIDCProvider    *OIDCProvider
	Store           *Store
	MiniRedis       *miniredis.Miniredis
	RedisClient     *redis.Client
	RedisWrapper    *database.RedisClient
	IdentityService *mockIdentityService
	Logger          *zap.Logger
	TestKey         *rsa.PrivateKey
	Cleanup         func()
}

// NewTestOIDCContext creates a fully configured test context for OIDC testing
// This helper sets up mock Redis, generates test RSA keys, and creates
// all necessary service instances for comprehensive OIDC testing.
func NewTestOIDCContext(t *testing.T) *TestOIDCContext {
	t.Helper()

	// Create test logger
	logger := zap.NewNop()

	// Setup mock Redis
	mini := miniredis.RunT(t)
	redisClient := redis.NewClient(&redis.Options{
		Addr: mini.Addr(),
	})

	// Create Redis wrapper
	redisWrapper := &database.RedisClient{
		Client: redisClient,
	}

	// Generate test RSA key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create test config
	cfg := &config.Config{
		OAuthIssuer: "https://test.openidx.org",
	}

	// Create identity service mock
	idSvc := &mockIdentityService{
		users: map[string]*identity.User{
			"test-user-123": {
				ID:          "test-user-123",
				UserName:    "testuser",
				DisplayName: strPtr("Test User"),
				Name: &identity.Name{
					GivenName:  strPtr("Test"),
					FamilyName: strPtr("User"),
				},
				Emails: []identity.Email{
					{Value: "test@example.com", Primary: boolPtr(true), Verified: boolPtr(true)},
				},
				Roles:         []string{"user", "admin"},
				Groups:        []string{"developers", "testers"},
				EmailVerified: true,
			},
		},
	}

	// Create a minimal OAuth service without database dependencies
	// We create a service struct directly and set only the fields we need for testing
	svc := &Service{
		privateKey: key,
		publicKey:  &key.PublicKey,
		issuer:     cfg.OAuthIssuer,
		redis:      redisWrapper,
		config:     cfg,
		logger:     logger,
	}

	// Create OIDC provider
	provider := NewOIDCProvider(svc, idSvc, logger, cfg.OAuthIssuer)

	// Create store
	store := NewStore(redisWrapper, logger)

	// Set the store on the provider
	provider.SetStore(store)

	// Create cleanup function
	cleanup := func() {
		mini.Close()
		redisClient.Close()
	}

	return &TestOIDCContext{
		T:               t,
		Service:         svc,
		OIDCProvider:    provider,
		Store:           store,
		MiniRedis:       mini,
		RedisClient:     redisClient,
		RedisWrapper:    redisWrapper,
		IdentityService: idSvc,
		Logger:          logger,
		TestKey:         key,
		Cleanup:         cleanup,
	}
}

// CreateTestUser creates a test user in the mock identity service
func (ctx *TestOIDCContext) CreateTestUser(userID, username, email string) *identity.User {
	user := &identity.User{
		ID:          userID,
		UserName:    username,
		DisplayName: strPtr(username),
		Name: &identity.Name{
			GivenName:  strPtr(username),
			FamilyName: strPtr("Test"),
		},
		Emails: []identity.Email{
			{Value: email, Primary: boolPtr(true), Verified: boolPtr(true)},
		},
		Roles:         []string{"user"},
		EmailVerified: true,
	}
	ctx.IdentityService.users[userID] = user
	return user
}

// CreateTestClient creates test client credentials
func (ctx *TestOIDCContext) CreateTestClient(clientID, clientSecret string, redirectURIs []string) *OAuthClient {
	return &OAuthClient{
		ID:           clientID,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Name:         "Test Client",
		Type:         "confidential",
		RedirectURIs: redirectURIs,
		Scopes:       []string{"openid", "profile", "email"},
	}
}

// SetupTestScopes returns common test scopes
func (ctx *TestOIDCContext) SetupTestScopes() map[string]string {
	return map[string]string{
		"openid":         "OpenID Connect authentication",
		"profile":        "User profile information",
		"email":          "User email address",
		"phone":          "User phone number",
		"address":        "User postal address",
		"offline_access": "Refresh token issuance",
	}
}

// StoreTestAuthCode stores a test authorization code in Redis
func (ctx *TestOIDCContext) StoreTestAuthCode(code, clientID, userID string) error {
	ctx.Store.StoreAuthorizationCode(context.Background(), &StoredAuthorizationCode{
		Code:        code,
		ClientID:    clientID,
		UserID:      userID,
		RedirectURI: "https://example.com/callback",
		Scope:       "openid profile email",
		ExpiresAt:   time.Now().Add(10 * time.Minute),
		CreatedAt:   time.Now(),
	}, 0)
	return nil
}

// StoreTestAccessToken stores a test access token in Redis
func (ctx *TestOIDCContext) StoreTestAccessToken(token, clientID, userID, scope string) error {
	ctx.Store.StoreAccessToken(context.Background(), &AccessTokenData{
		Token:     token,
		ClientID:  clientID,
		UserID:    userID,
		Scope:     scope,
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
	}, 0)
	return nil
}

// FastForward advances time in the mock Redis for TTL testing
func (ctx *TestOIDCContext) FastForward(d time.Duration) {
	ctx.MiniRedis.FastForward(d)
}

// Helper functions

// generateTestRSAKey generates a test RSA key pair
func generateTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key
}

// testLogger creates a test logger
func testLogger() *zap.Logger {
	return zap.NewNop()
}

// strPtr returns a pointer to a string
func strPtr(s string) *string {
	return &s
}

// boolPtr returns a pointer to a bool
func boolPtr(b bool) *bool {
	return &b
}

// NewMockRedisContext creates a mock Redis context using testutil
func NewMockRedisContext(t *testing.T) *testutil.MockRedis {
	t.Helper()
	mock := testutil.NewMockRedis(testLogger())
	err := mock.Setup()
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = mock.Shutdown()
	})
	return mock
}
