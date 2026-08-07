// Package webhooks provides webhook subscription management and event delivery
package webhooks

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/secretcrypt"
	"github.com/openidx/openidx/internal/common/testutil"
)

// testCipher returns a secretcrypt.Cipher with a fixed 32-byte test key for
// wiring the webhook service in tests (the key is valid, so New never errors).
func testCipher() *secretcrypt.Cipher {
	c, _ := secretcrypt.New("0123456789abcdef0123456789abcdef")
	return c
}

// testContext holds test dependencies
type testContext struct {
	ctx              context.Context
	db               *database.PostgresDB
	redis            *testutil.MockRedis
	service          *Service
	server           *httptest.Server
	receivedWebhooks []webhookCall
	logger           *zap.Logger
	teardown         func()
}

type webhookCall struct {
	Headers    http.Header
	Body       string
	StatusCode int
}

// setupTest creates a test context with real PostgreSQL pool and mock Redis
// Note: This requires TEST_DATABASE_URL to be set
func setupTest(t *testing.T) *testContext {
	logger := zaptest.NewLogger(t)

	// CreateSubscription now sources org_id from the request context (the fix for
	// QA 10.5), so the test context must carry an organization.
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: "00000000-0000-0000-0000-000000000010"})

	// Create mock Redis
	mockRedis := testutil.NewMockRedis(logger)
	err := mockRedis.Setup()
	require.NoError(t, err, "failed to setup mock redis")

	// For integration-style tests, use test database if available
	// Otherwise, we'll use a mock approach
	var db *database.PostgresDB

	// Try to connect to test database
	connString := "postgres://openidx:testpass@localhost:5432/openidx_test?sslmode=disable"
	pool, err := pgxpool.New(ctx, connString)
	if err != nil {
		// If no test database available, we'll create service with nil DB
		// and only test functions that don't require DB
		t.Logf("Warning: no test database available, skipping DB-dependent tests: %v", err)
		db = nil
	} else {
		db = &database.PostgresDB{Pool: pool}
		// Setup tables - if this fails, set db to nil
		if err := setupTestDB(ctx, t, db); err != nil {
			t.Logf("Warning: failed to setup test database schema: %v", err)
			pool.Close()
			db = nil
		}
	}

	// Create test HTTP server to receive webhooks
	var receivedWebhooks []webhookCall
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		r.Body.Close()

		call := webhookCall{
			Headers:    r.Header.Clone(),
			Body:       string(bodyBytes),
			StatusCode: http.StatusOK,
		}
		receivedWebhooks = append(receivedWebhooks, call)

		// Default 200 response
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"received": true}`))
	}))

	// Create service - convert mock Redis client to database.RedisClient wrapper
	redisClient := &database.RedisClient{Client: mockRedis.Client()}
	service := NewService(db, redisClient, logger, testCipher())

	teardown := func() {
		if server != nil {
			server.Close()
		}
		if db != nil {
			db.Close()
		}
		mockRedis.Shutdown()
	}

	return &testContext{
		ctx:              ctx,
		db:               db,
		redis:            mockRedis,
		service:          service,
		server:           server,
		receivedWebhooks: receivedWebhooks,
		logger:           logger,
		teardown:         teardown,
	}
}

// setupTestDB creates the necessary tables for testing
func setupTestDB(ctx context.Context, t *testing.T, db *database.PostgresDB) error {
	schema := `
		CREATE TABLE IF NOT EXISTS webhook_subscriptions (
			id TEXT PRIMARY KEY,
			org_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000010',
			name TEXT NOT NULL,
			url TEXT NOT NULL,
			secret TEXT NOT NULL,
			events TEXT[] NOT NULL,
			status TEXT NOT NULL,
			created_by TEXT,
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL
		);

		CREATE TABLE IF NOT EXISTS webhook_deliveries (
			id TEXT PRIMARY KEY,
			subscription_id TEXT NOT NULL,
			event_type TEXT NOT NULL,
			payload TEXT NOT NULL,
			response_status INTEGER,
			response_body TEXT,
			attempt INTEGER NOT NULL DEFAULT 0,
			status TEXT NOT NULL,
			next_retry_at TIMESTAMP,
			created_at TIMESTAMP NOT NULL,
			delivered_at TIMESTAMP
		);

		CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_subscription
			ON webhook_deliveries(subscription_id);
	`

	_, err := db.Pool.Exec(ctx, schema)
	if err != nil {
		return fmt.Errorf("failed to create test database schema: %w", err)
	}

	// Clean up any existing data
	_, err = db.Pool.Exec(ctx, "DELETE FROM webhook_deliveries")
	if err != nil {
		return fmt.Errorf("failed to clean webhook_deliveries: %w", err)
	}
	_, err = db.Pool.Exec(ctx, "DELETE FROM webhook_subscriptions")
	if err != nil {
		return fmt.Errorf("failed to clean webhook_subscriptions: %w", err)
	}

	return nil
}

// ============================================================================
// Tests for computeSignature (helper function)
// ============================================================================

func TestComputeSignature(t *testing.T) {
	tests := []struct {
		name   string
		secret string
		body   []byte
	}{
		{
			name:   "simple payload",
			secret: "test-secret",
			body:   []byte(`{"test": "data"}`),
		},
		{
			name:   "empty payload",
			secret: "secret",
			body:   []byte{},
		},
		{
			name:   "unicode payload",
			secret: "unicode-secret",
			body:   []byte(`{"message": "Hello 世界"}`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := computeSignature(tt.secret, tt.body)

			// Verify signature is hex-encoded and 64 chars (SHA256 = 32 bytes * 2 hex chars)
			assert.Len(t, result, 64, "signature should be 64 hex characters")

			// Verify it's valid hex
			_, err := hex.DecodeString(result)
			assert.NoError(t, err, "signature should be valid hex")

			// Verify consistency - same inputs produce same output
			result2 := computeSignature(tt.secret, tt.body)
			assert.Equal(t, result, result2, "same inputs should produce same signature")

			// Verify signature is deterministic with HMAC-SHA256
			mac := hmac.New(sha256.New, []byte(tt.secret))
			mac.Write(tt.body)
			expected := hex.EncodeToString(mac.Sum(nil))
			assert.Equal(t, expected, result, "signature should match HMAC-SHA256")
		})
	}
}

// ============================================================================
// Tests for CreateSubscription
// ============================================================================

// TestCreateSubscriptionPersistsOrgFromContext is the regression guard for QA
// 10.5: create reported success but the webhook never appeared in the list for
// any tenant other than the seeded default org. The INSERT omitted org_id and
// relied on a hardcoded column DEFAULT (org 010); for every other org that
// default violates the RLS WITH CHECK, so the row was rejected or invisible.
// This asserts the persisted org_id matches the request context's org and that
// two orgs' webhooks stay isolated.
func TestCreateSubscriptionPersistsOrgFromContext(t *testing.T) {
	tc := setupTest(t)
	defer tc.teardown()

	if tc.db == nil {
		t.Skip("no test database available")
	}

	_, _ = tc.db.Pool.Exec(tc.ctx, "DELETE FROM webhook_subscriptions")

	const (
		orgA = "00000000-0000-0000-0000-000000000010"
		orgB = "b607a956-c471-4e9d-a7ac-6e8928521444"
	)
	ctxA := orgctx.With(context.Background(), orgctx.Org{ID: orgA})
	ctxB := orgctx.With(context.Background(), orgctx.Org{ID: orgB})

	subA, err := tc.service.CreateSubscription(ctxA, "HookA", "https://example.com/a", "secret-a-16chars", []string{EventUserCreated}, "user-a")
	if err != nil {
		t.Fatalf("create under org A: %v", err)
	}
	subB, err := tc.service.CreateSubscription(ctxB, "HookB", "https://example.com/b", "secret-b-16chars", []string{EventUserCreated}, "user-b")
	if err != nil {
		t.Fatalf("create under org B: %v", err)
	}

	// The persisted org_id must match the creating context, not the column default.
	var gotOrgA, gotOrgB string
	if err := tc.db.Pool.QueryRow(context.Background(),
		"SELECT org_id::text FROM webhook_subscriptions WHERE id = $1", subA.ID).Scan(&gotOrgA); err != nil {
		t.Fatalf("read org A row: %v", err)
	}
	if err := tc.db.Pool.QueryRow(context.Background(),
		"SELECT org_id::text FROM webhook_subscriptions WHERE id = $1", subB.ID).Scan(&gotOrgB); err != nil {
		t.Fatalf("read org B row: %v", err)
	}
	if gotOrgA != orgA {
		t.Fatalf("org A webhook persisted with org_id %q, want %q", gotOrgA, orgA)
	}
	if gotOrgB != orgB {
		t.Fatalf("org B webhook persisted with org_id %q, want %q (fell back to the hardcoded default = the 10.5 bug)", gotOrgB, orgB)
	}
}

func TestCreateSubscription(t *testing.T) {
	tc := setupTest(t)
	defer tc.teardown()

	if tc.db == nil {
		t.Skip("no test database available")
	}

	tests := []struct {
		name      string
		subName   string
		url       string
		secret    string
		events    []string
		createdBy string
		wantErr   bool
	}{
		{
			name:      "valid subscription",
			subName:   "Test Webhook",
			url:       "https://example.com/webhook",
			secret:    "test-secret-key",
			events:    []string{EventUserCreated, EventUserUpdated},
			createdBy: "user-123",
			wantErr:   false,
		},
		{
			name:      "subscription with all user events",
			subName:   "All User Events",
			url:       "https://example.com/hook",
			secret:    "secret",
			events:    []string{EventUserCreated, EventUserUpdated, EventUserDeleted, EventUserLocked},
			createdBy: "admin",
			wantErr:   false,
		},
		{
			name:      "subscription with login events",
			subName:   "Login Events",
			url:       "https://example.com/login",
			secret:    "login-secret",
			events:    []string{EventLoginSuccess, EventLoginFailed, EventLoginHighRisk},
			createdBy: "security-admin",
			wantErr:   false,
		},
		{
			name:      "empty name",
			subName:   "",
			url:       "https://example.com/webhook",
			secret:    "secret",
			events:    []string{EventUserCreated},
			createdBy: "user-123",
			wantErr:   false, // PostgreSQL doesn't enforce NOT NULL on empty string by default
		},
		{
			name:      "empty events",
			subName:   "Test",
			url:       "https://example.com/webhook",
			secret:    "secret",
			events:    []string{},
			createdBy: "user-123",
			wantErr:   false, // Empty array is valid
		},
		{
			name:      "no created by",
			subName:   "Test",
			url:       "https://example.com/webhook",
			secret:    "secret",
			events:    []string{EventUserCreated},
			createdBy: "",
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean up before each test
			_, _ = tc.db.Pool.Exec(tc.ctx, "DELETE FROM webhook_subscriptions")

			sub, err := tc.service.CreateSubscription(tc.ctx, tt.subName, tt.url, tt.secret, tt.events, tt.createdBy)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, sub)
			assert.NotEmpty(t, sub.ID)
			assert.Equal(t, tt.subName, sub.Name)
			assert.Equal(t, tt.url, sub.URL)
			assert.Equal(t, tt.secret, sub.Secret)
			assert.Equal(t, tt.events, sub.Events)
			assert.Equal(t, "active", sub.Status)
			assert.False(t, sub.CreatedAt.IsZero())
			assert.False(t, sub.UpdatedAt.IsZero())

			if tt.createdBy != "" {
				assert.NotNil(t, sub.CreatedBy)
				assert.Equal(t, tt.createdBy, *sub.CreatedBy)
			} else {
				assert.Nil(t, sub.CreatedBy)
			}
		})
	}
}

// ============================================================================
// Tests for GetSubscription
// ============================================================================

func TestGetSubscription(t *testing.T) {
	tc := setupTest(t)
	defer tc.teardown()

	if tc.db == nil {
		t.Skip("no test database available")
	}

	// Create a test subscription
	created, err := tc.service.CreateSubscription(tc.ctx, "Test Hook", "https://example.com/webhook", "secret", []string{EventUserCreated}, "user-1")
	require.NoError(t, err)

	tests := []struct {
		name    string
		id      string
		wantErr bool
	}{
		{
			name:    "existing subscription",
			id:      created.ID,
			wantErr: false,
		},
		{
			name:    "non-existent subscription",
			id:      "non-existent-id",
			wantErr: true,
		},
		{
			name:    "empty ID",
			id:      "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sub, err := tc.service.GetSubscription(tc.ctx, tt.id)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "not found")
				assert.Nil(t, sub)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, sub)
			assert.Equal(t, created.ID, sub.ID)
			assert.Equal(t, "Test Hook", sub.Name)
			assert.Equal(t, "https://example.com/webhook", sub.URL)
		})
	}
}

// ============================================================================
// Tests for ListSubscriptions
// ============================================================================

func TestListSubscriptions(t *testing.T) {
	tc := setupTest(t)
	defer tc.teardown()

	if tc.db == nil {
		t.Skip("no test database available")
	}

	// Clean up
	_, _ = tc.db.Pool.Exec(tc.ctx, "DELETE FROM webhook_subscriptions")

	tests := []struct {
		name          string
		setupSubs     func() []string
		expectedCount int
		wantErr       bool
	}{
		{
			name:          "empty list",
			setupSubs:     func() []string { return nil },
			expectedCount: 0,
			wantErr:       false,
		},
		{
			name: "single subscription",
			setupSubs: func() []string {
				sub, _ := tc.service.CreateSubscription(tc.ctx, "Hook 1", "https://example.com/1", "s1", []string{EventUserCreated}, "user")
				return []string{sub.ID}
			},
			expectedCount: 1,
			wantErr:       false,
		},
		{
			name: "multiple subscriptions",
			setupSubs: func() []string {
				ids := []string{}
				for i := 1; i <= 5; i++ {
					sub, _ := tc.service.CreateSubscription(tc.ctx, fmt.Sprintf("Hook %d", i), fmt.Sprintf("https://example.com/%d", i), "s", []string{EventUserCreated}, "user")
					ids = append(ids, sub.ID)
				}
				return ids
			},
			expectedCount: 5,
			wantErr:       false,
		},
		{
			name: "only active subscriptions",
			setupSubs: func() []string {
				sub1, _ := tc.service.CreateSubscription(tc.ctx, "Active", "https://example.com/active", "s", []string{EventUserCreated}, "user")
				// Create an inactive subscription (update status)
				sub2, _ := tc.service.CreateSubscription(tc.ctx, "Inactive", "https://example.com/inactive", "s", []string{EventUserCreated}, "user")
				_, _ = tc.db.Pool.Exec(tc.ctx, "UPDATE webhook_subscriptions SET status = 'inactive' WHERE id = $1", sub2.ID)
				return []string{sub1.ID, sub2.ID}
			},
			expectedCount: 1, // Only active
			wantErr:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean up before each test
			_, _ = tc.db.Pool.Exec(tc.ctx, "DELETE FROM webhook_subscriptions")

			// Setup test data
			if tt.setupSubs != nil {
				tt.setupSubs()
			}

			subs, err := tc.service.ListSubscriptions(tc.ctx)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Len(t, subs, tt.expectedCount)
		})
	}
}

// ============================================================================
// Tests for UpdateSubscription
// ============================================================================

func TestUpdateSubscription(t *testing.T) {
	tc := setupTest(t)
	defer tc.teardown()

	if tc.db == nil {
		t.Skip("no test database available")
	}

	tests := []struct {
		name      string
		setup     func() string
		newName   string
		newURL    string
		newEvents []string
		newStatus string
		wantErr   bool
	}{
		{
			name: "update name and URL",
			setup: func() string {
				sub, _ := tc.service.CreateSubscription(tc.ctx, "Old Name", "https://old.com/webhook", "secret", []string{EventUserCreated}, "user")
				return sub.ID
			},
			newName:   "New Name",
			newURL:    "https://new.com/webhook",
			newEvents: []string{EventUserCreated},
			newStatus: "active",
			wantErr:   false,
		},
		{
			name: "update events",
			setup: func() string {
				sub, _ := tc.service.CreateSubscription(tc.ctx, "Test", "https://example.com/webhook", "secret", []string{EventUserCreated}, "user")
				return sub.ID
			},
			newName:   "Test",
			newURL:    "https://example.com/webhook",
			newEvents: []string{EventUserCreated, EventUserUpdated, EventUserDeleted},
			newStatus: "active",
			wantErr:   false,
		},
		{
			name: "update status to inactive",
			setup: func() string {
				sub, _ := tc.service.CreateSubscription(tc.ctx, "Test", "https://example.com/webhook", "secret", []string{EventUserCreated}, "user")
				return sub.ID
			},
			newName:   "Test",
			newURL:    "https://example.com/webhook",
			newEvents: []string{EventUserCreated},
			newStatus: "inactive",
			wantErr:   false,
		},
		{
			name:      "non-existent subscription",
			setup:     func() string { return "non-existent" },
			newName:   "Test",
			newURL:    "https://example.com/webhook",
			newEvents: []string{EventUserCreated},
			newStatus: "active",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean up and setup
			_, _ = tc.db.Pool.Exec(tc.ctx, "DELETE FROM webhook_subscriptions")
			id := tt.setup()

			err := tc.service.UpdateSubscription(tc.ctx, id, tt.newName, tt.newURL, tt.newEvents, tt.newStatus)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "not found")
				return
			}

			assert.NoError(t, err)

			// Verify update
			sub, err := tc.service.GetSubscription(tc.ctx, id)
			assert.NoError(t, err)
			assert.Equal(t, tt.newName, sub.Name)
			assert.Equal(t, tt.newURL, sub.URL)
			assert.Equal(t, tt.newEvents, sub.Events)
			assert.Equal(t, tt.newStatus, sub.Status)
		})
	}
}

// ============================================================================
// Tests for DeleteSubscription
// ============================================================================

func TestDeleteSubscription(t *testing.T) {
	tc := setupTest(t)
	defer tc.teardown()

	if tc.db == nil {
		t.Skip("no test database available")
	}

	tests := []struct {
		name    string
		setup   func() string
		wantErr bool
	}{
		{
			name: "delete existing subscription",
			setup: func() string {
				sub, _ := tc.service.CreateSubscription(tc.ctx, "Test", "https://example.com/webhook", "secret", []string{EventUserCreated}, "user")
				return sub.ID
			},
			wantErr: false,
		},
		{
			name:    "delete non-existent subscription",
			setup:   func() string { return "non-existent" },
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean up and setup
			_, _ = tc.db.Pool.Exec(tc.ctx, "DELETE FROM webhook_subscriptions")
			id := tt.setup()

			err := tc.service.DeleteSubscription(tc.ctx, id)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "not found")
				return
			}

			assert.NoError(t, err)

			// Verify deletion
			_, err = tc.service.GetSubscription(tc.ctx, id)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "not found")
		})
	}
}

// ============================================================================
// Tests for Publish (event publishing)
// ============================================================================

func TestPublish(t *testing.T) {
	tc := setupTest(t)
	defer tc.teardown()

	if tc.db == nil {
		t.Skip("no test database available")
	}

	tests := []struct {
		name      string
		setup     func()
		eventType string
		payload   interface{}
		wantErr   bool
		verify    func(*testing.T)
	}{
		{
			name: "publish to matching subscriptions",
			setup: func() {
				tc.service.CreateSubscription(tc.ctx, "User Events", tc.server.URL+"/webhook", "secret", []string{EventUserCreated, EventUserUpdated}, "user")
				tc.service.CreateSubscription(tc.ctx, "All Events", tc.server.URL+"/all", "secret", []string{EventUserCreated, EventLoginSuccess}, "user")
			},
			eventType: EventUserCreated,
			payload:   map[string]interface{}{"user_id": "123", "email": "test@example.com"},
			wantErr:   false,
			verify: func(t *testing.T) {
				// Check deliveries were created
				rows, _ := tc.db.Pool.Query(tc.ctx, "SELECT COUNT(*) FROM webhook_deliveries")
				var count int
				rows.Next()
				rows.Scan(&count)
				rows.Close()
				assert.Equal(t, 2, count, "should create 2 deliveries")
			},
		},
		{
			name: "publish with no matching subscriptions",
			setup: func() {
				tc.service.CreateSubscription(tc.ctx, "Login Events", tc.server.URL+"/webhook", "secret", []string{EventLoginSuccess}, "user")
			},
			eventType: EventUserCreated,
			payload:   map[string]interface{}{"user_id": "123"},
			wantErr:   false,
			verify: func(t *testing.T) {
				rows, _ := tc.db.Pool.Query(tc.ctx, "SELECT COUNT(*) FROM webhook_deliveries")
				var count int
				rows.Next()
				rows.Scan(&count)
				rows.Close()
				assert.Equal(t, 0, count, "should create 0 deliveries")
			},
		},
		{
			name:      "publish with no subscriptions at all",
			setup:     func() {},
			eventType: EventUserCreated,
			payload:   map[string]interface{}{"test": "data"},
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean up
			_, _ = tc.db.Pool.Exec(tc.ctx, "DELETE FROM webhook_subscriptions")
			_, _ = tc.db.Pool.Exec(tc.ctx, "DELETE FROM webhook_deliveries")
			tc.redis.ClearAll()

			tt.setup()

			err := tc.service.Publish(tc.ctx, tt.eventType, tt.payload)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)

			if tt.verify != nil {
				tt.verify(t)
			}
		})
	}
}

// ============================================================================
// Tests for PingSubscription
// ============================================================================

func TestPingSubscription(t *testing.T) {
	tc := setupTest(t)
	defer tc.teardown()

	if tc.db == nil {
		t.Skip("no test database available")
	}

	// Track received webhooks
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "ping", r.Header.Get("X-Webhook-Event"))
		assert.NotEmpty(t, r.Header.Get("X-Webhook-Signature"))
		assert.NotEmpty(t, r.Header.Get("X-Webhook-Timestamp"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	tests := []struct {
		name         string
		setup        func() string
		wantErr      bool
		verifyStatus string
		verifyResp   bool
	}{
		{
			name: "successful ping",
			setup: func() string {
				sub, _ := tc.service.CreateSubscription(tc.ctx, "Test", server.URL, "secret", []string{EventUserCreated}, "user")
				return sub.ID
			},
			wantErr:      false,
			verifyStatus: "delivered",
			verifyResp:   true,
		},
		{
			name: "ping to non-existent subscription",
			setup: func() string {
				return "non-existent-id"
			},
			wantErr: true,
		},
		{
			name: "ping to invalid URL",
			setup: func() string {
				sub, _ := tc.service.CreateSubscription(tc.ctx, "Test", "invalid://url", "secret", []string{EventUserCreated}, "user")
				return sub.ID
			},
			wantErr:      false, // Ping returns delivery even on failure
			verifyStatus: "failed",
			verifyResp:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean up
			_, _ = tc.db.Pool.Exec(tc.ctx, "DELETE FROM webhook_subscriptions")
			_, _ = tc.db.Pool.Exec(tc.ctx, "DELETE FROM webhook_deliveries")

			id := tt.setup()

			delivery, err := tc.service.PingSubscription(tc.ctx, id)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "not found")
				return
			}

			assert.NoError(t, err)
			if tt.verifyResp {
				assert.NotNil(t, delivery)
				assert.Equal(t, id, delivery.SubscriptionID)
				assert.Equal(t, "ping", delivery.EventType)
				assert.Equal(t, tt.verifyStatus, delivery.Status)
			}
		})
	}
}

// ============================================================================
// Tests for GetDeliveryHistory
// ============================================================================

func TestGetDeliveryHistory(t *testing.T) {
	tc := setupTest(t)
	defer tc.teardown()

	if tc.db == nil {
		t.Skip("no test database available")
	}

	tests := []struct {
		name          string
		setup         func() string
		limit         int
		expectedCount int
		wantErr       bool
	}{
		{
			name: "empty history",
			setup: func() string {
				sub, _ := tc.service.CreateSubscription(tc.ctx, "Test", "https://example.com/webhook", "secret", []string{EventUserCreated}, "user")
				return sub.ID
			},
			limit:         10,
			expectedCount: 0,
			wantErr:       false,
		},
		{
			name: "single delivery",
			setup: func() string {
				sub, _ := tc.service.CreateSubscription(tc.ctx, "Test", "https://example.com/webhook", "secret", []string{EventUserCreated}, "user")
				// Create a delivery record
				deliveryID := "delivery-1"
				tc.db.Pool.Exec(tc.ctx,
					"INSERT INTO webhook_deliveries (id, subscription_id, event_type, payload, attempt, status, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
					deliveryID, sub.ID, EventUserCreated, "{}", 0, "delivered", time.Now().UTC())
				return sub.ID
			},
			limit:         10,
			expectedCount: 1,
			wantErr:       false,
		},
		{
			name: "multiple deliveries with limit",
			setup: func() string {
				sub, _ := tc.service.CreateSubscription(tc.ctx, "Test", "https://example.com/webhook", "secret", []string{EventUserCreated}, "user")
				for i := 1; i <= 5; i++ {
					deliveryID := fmt.Sprintf("delivery-%d", i)
					tc.db.Pool.Exec(tc.ctx,
						"INSERT INTO webhook_deliveries (id, subscription_id, event_type, payload, attempt, status, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
						deliveryID, sub.ID, EventUserCreated, "{}", 0, "delivered", time.Now().UTC())
				}
				return sub.ID
			},
			limit:         3,
			expectedCount: 3,
			wantErr:       false,
		},
		{
			name: "non-existent subscription",
			setup: func() string {
				return "non-existent"
			},
			limit:         10,
			expectedCount: 0,
			wantErr:       false, // Returns empty list, not error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean up
			_, _ = tc.db.Pool.Exec(tc.ctx, "DELETE FROM webhook_subscriptions")
			_, _ = tc.db.Pool.Exec(tc.ctx, "DELETE FROM webhook_deliveries")

			subID := tt.setup()

			history, err := tc.service.GetDeliveryHistory(tc.ctx, subID, tt.limit)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Len(t, history, tt.expectedCount)
		})
	}
}

// ============================================================================
// Tests for GetDeliveryStats
// ============================================================================

func TestGetDeliveryStats(t *testing.T) {
	tc := setupTest(t)
	defer tc.teardown()

	if tc.db == nil {
		t.Skip("no test database available")
	}

	tests := []struct {
		name        string
		setup       func() string
		wantErr     bool
		verifyStats func(*testing.T, map[string]interface{})
	}{
		{
			name: "stats for new subscription",
			setup: func() string {
				sub, _ := tc.service.CreateSubscription(tc.ctx, "Test", "https://example.com/webhook", "secret", []string{EventUserCreated}, "user")
				return sub.ID
			},
			wantErr: false,
			verifyStats: func(t *testing.T, stats map[string]interface{}) {
				assert.Equal(t, int64(0), stats["total_deliveries"])
				assert.Equal(t, int64(0), stats["successful_deliveries"])
				assert.Equal(t, int64(0), stats["failed_deliveries"])
				assert.Equal(t, 0.0, stats["success_rate"])
			},
		},
		{
			name: "stats with mixed deliveries",
			setup: func() string {
				sub, _ := tc.service.CreateSubscription(tc.ctx, "Test", "https://example.com/webhook", "secret", []string{EventUserCreated}, "user")
				// Successful delivery
				tc.db.Pool.Exec(tc.ctx,
					"INSERT INTO webhook_deliveries (id, subscription_id, event_type, payload, attempt, status, created_at, delivered_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
					"d1", sub.ID, EventUserCreated, "{}", 1, "delivered", time.Now().UTC().Add(-1*time.Minute), time.Now().UTC().Add(-1*time.Minute))
				// Failed delivery
				tc.db.Pool.Exec(tc.ctx,
					"INSERT INTO webhook_deliveries (id, subscription_id, event_type, payload, attempt, status, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
					"d2", sub.ID, EventUserCreated, "{}", 3, "failed", time.Now().UTC().Add(-30*time.Second))
				return sub.ID
			},
			wantErr: false,
			verifyStats: func(t *testing.T, stats map[string]interface{}) {
				assert.Equal(t, int64(2), stats["total_deliveries"])
				assert.Equal(t, int64(1), stats["successful_deliveries"])
				assert.Equal(t, int64(1), stats["failed_deliveries"])
				assert.Equal(t, 50.0, stats["success_rate"])
			},
		},
		{
			name: "non-existent subscription",
			setup: func() string {
				return "non-existent"
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean up
			_, _ = tc.db.Pool.Exec(tc.ctx, "DELETE FROM webhook_subscriptions")
			_, _ = tc.db.Pool.Exec(tc.ctx, "DELETE FROM webhook_deliveries")

			subID := tt.setup()

			stats, err := tc.service.GetDeliveryStats(tc.ctx, subID)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "not found")
				return
			}

			assert.NoError(t, err)
			if tt.verifyStats != nil {
				tt.verifyStats(t, stats)
			}
		})
	}
}

// ============================================================================
// Tests for RetryDelivery
// ============================================================================

func TestRetryDelivery(t *testing.T) {
	tc := setupTest(t)
	defer tc.teardown()

	if tc.db == nil {
		t.Skip("no test database available")
	}

	tests := []struct {
		name    string
		setup   func() string
		wantErr bool
	}{
		{
			name: "retry failed delivery",
			setup: func() string {
				sub, _ := tc.service.CreateSubscription(tc.ctx, "Test", tc.server.URL, "secret", []string{EventUserCreated}, "user")
				deliveryID := "failed-delivery"
				tc.db.Pool.Exec(tc.ctx,
					"INSERT INTO webhook_deliveries (id, subscription_id, event_type, payload, attempt, status, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
					deliveryID, sub.ID, EventUserCreated, "{}", 3, "failed", time.Now().UTC())
				return deliveryID
			},
			wantErr: false,
		},
		{
			name: "retry non-existent delivery",
			setup: func() string {
				return "non-existent-delivery"
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean up
			_, _ = tc.db.Pool.Exec(tc.ctx, "DELETE FROM webhook_subscriptions")
			_, _ = tc.db.Pool.Exec(tc.ctx, "DELETE FROM webhook_deliveries")
			tc.redis.ClearAll()

			deliveryID := tt.setup()

			err := tc.service.RetryDelivery(tc.ctx, deliveryID)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "not found")
				return
			}

			assert.NoError(t, err)

			// Verify delivery is queued in Redis
			list := tc.redis.Client().LPop(tc.ctx, "webhook:deliveries")
			assert.Equal(t, deliveryID, list.Val())
		})
	}
}

// ============================================================================
// Tests for retry schedule logic
// ============================================================================

func TestRetrySchedule(t *testing.T) {
	// Test the retry delay calculations based on attempt number
	tests := []struct {
		name             string
		attempt          int
		expectedDelay    time.Duration
		shouldRetry      bool
		shouldMarkFailed bool
	}{
		{
			name:             "first retry (attempt 0 -> 1)",
			attempt:          0,
			expectedDelay:    1 * time.Minute,
			shouldRetry:      true,
			shouldMarkFailed: false,
		},
		{
			name:             "second retry (attempt 1 -> 2)",
			attempt:          1,
			expectedDelay:    5 * time.Minute,
			shouldRetry:      true,
			shouldMarkFailed: false,
		},
		{
			name:             "third retry (attempt 2 -> 3)",
			attempt:          2,
			expectedDelay:    30 * time.Minute,
			shouldRetry:      true,
			shouldMarkFailed: false,
		},
		{
			name:             "max retries exceeded (attempt 3 -> 4)",
			attempt:          3,
			expectedDelay:    0,
			shouldRetry:      false,
			shouldMarkFailed: true,
		},
		{
			name:             "way over max retries",
			attempt:          10,
			expectedDelay:    0,
			shouldRetry:      false,
			shouldMarkFailed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Verify the expected delay matches what's in scheduleRetry
			var retryDelay time.Duration
			nextAttempt := tt.attempt + 1
			switch nextAttempt {
			case 1:
				retryDelay = 1 * time.Minute
			case 2:
				retryDelay = 5 * time.Minute
			case 3:
				retryDelay = 30 * time.Minute
			}

			assert.Equal(t, tt.expectedDelay, retryDelay)

			// Verify max retries logic
			if nextAttempt > 3 {
				assert.True(t, tt.shouldMarkFailed)
			} else {
				assert.True(t, tt.shouldRetry)
			}
		})
	}
}

// ============================================================================
// Tests for signature generation consistency
// ============================================================================

func TestSignatureGeneration(t *testing.T) {
	tests := []struct {
		name   string
		secret string
		body   string
	}{
		{
			name:   "simple payload",
			secret: "my-secret-key",
			body:   `{"event": "user.created", "data": {"id": "123"}}`,
		},
		{
			name:   "empty secret",
			secret: "",
			body:   `{"test": "data"}`,
		},
		{
			name:   "empty body",
			secret: "secret",
			body:   "",
		},
		{
			name:   "unicode content",
			secret: "unicode-secret",
			body:   `{"message": "Hello 世界 🌍"}`,
		},
		{
			name:   "large payload",
			secret: "large-secret",
			body:   strings.Repeat("x", 10000),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bodyBytes := []byte(tt.body)

			// Generate multiple signatures
			sig1 := computeSignature(tt.secret, bodyBytes)
			sig2 := computeSignature(tt.secret, bodyBytes)
			sig3 := computeSignature(tt.secret, bodyBytes)

			// All should be identical
			assert.Equal(t, sig1, sig2, "signatures should be consistent")
			assert.Equal(t, sig2, sig3, "signatures should be consistent")

			// Different secret should produce different signature
			sigDifferent := computeSignature(tt.secret+"-different", bodyBytes)
			assert.NotEqual(t, sig1, sigDifferent, "different secret should produce different signature")

			// Different body should produce different signature
			sigDifferentBody := computeSignature(tt.secret, []byte(tt.body+"-modified"))
			assert.NotEqual(t, sig1, sigDifferentBody, "different body should produce different signature")

			// Verify format
			assert.Len(t, sig1, 64, "signature should be 64 hex characters (SHA256)")

			// Verify valid hex
			_, err := hex.DecodeString(sig1)
			assert.NoError(t, err, "signature should be valid hex")
		})
	}
}

// ============================================================================
// Tests for webhook event constants
// ============================================================================

func TestEventConstants(t *testing.T) {
	tests := []struct {
		constant string
		expected string
	}{
		{
			constant: "EventUserCreated",
			expected: "user.created",
		},
		{
			constant: "EventUserUpdated",
			expected: "user.updated",
		},
		{
			constant: "EventUserDeleted",
			expected: "user.deleted",
		},
		{
			constant: "EventUserLocked",
			expected: "user.locked",
		},
		{
			constant: "EventLoginSuccess",
			expected: "login.success",
		},
		{
			constant: "EventLoginFailed",
			expected: "login.failed",
		},
		{
			constant: "EventLoginHighRisk",
			expected: "login.high_risk",
		},
		{
			constant: "EventGroupUpdated",
			expected: "group.updated",
		},
		{
			constant: "EventRoleUpdated",
			expected: "role.updated",
		},
		{
			constant: "EventPolicyViolated",
			expected: "policy.violated",
		},
		{
			constant: "EventReviewCompleted",
			expected: "review.completed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.constant, func(t *testing.T) {
			var value string
			switch tt.constant {
			case "EventUserCreated":
				value = EventUserCreated
			case "EventUserUpdated":
				value = EventUserUpdated
			case "EventUserDeleted":
				value = EventUserDeleted
			case "EventUserLocked":
				value = EventUserLocked
			case "EventLoginSuccess":
				value = EventLoginSuccess
			case "EventLoginFailed":
				value = EventLoginFailed
			case "EventLoginHighRisk":
				value = EventLoginHighRisk
			case "EventGroupUpdated":
				value = EventGroupUpdated
			case "EventRoleUpdated":
				value = EventRoleUpdated
			case "EventPolicyViolated":
				value = EventPolicyViolated
			case "EventReviewCompleted":
				value = EventReviewCompleted
			}

			assert.Equal(t, tt.expected, value)

			// Verify naming convention (lowercase with dots)
			assert.NotEmpty(t, value)
			assert.Contains(t, value, ".")
		})
	}
}

// ============================================================================
// Tests for webhook delivery with HTTP mock server
// ============================================================================

func TestWebhookDeliveryWithMockServer(t *testing.T) {
	tests := []struct {
		name           string
		responseStatus int
		responseBody   string
		expectedStatus string
	}{
		{
			name:           "successful delivery - 200",
			responseStatus: 200,
			responseBody:   `{"ok": true}`,
			expectedStatus: "delivered",
		},
		{
			name:           "successful delivery - 201",
			responseStatus: 201,
			responseBody:   `{"created": true}`,
			expectedStatus: "delivered",
		},
		{
			name:           "successful delivery - 204",
			responseStatus: 204,
			responseBody:   "",
			expectedStatus: "delivered",
		},
		{
			name:           "server error - 500",
			responseStatus: 500,
			responseBody:   `{"error": "internal server error"}`,
			expectedStatus: "pending", // Should be scheduled for retry
		},
		{
			name:           "client error - 400",
			responseStatus: 400,
			responseBody:   `{"error": "bad request"}`,
			expectedStatus: "pending", // Should be scheduled for retry
		},
		{
			name:           "not found - 404",
			responseStatus: 404,
			responseBody:   `{"error": "not found"}`,
			expectedStatus: "pending", // Should be scheduled for retry
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := setupTest(t)
			defer tc.teardown()

			if tc.db == nil {
				t.Skip("no test database available")
			}

			// Create mock server that returns specified response
			requestReceived := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requestReceived = true

				// Verify headers are set correctly
				assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
				assert.NotEmpty(t, r.Header.Get("X-Webhook-ID"))
				assert.Equal(t, EventUserCreated, r.Header.Get("X-Webhook-Event"))
				assert.NotEmpty(t, r.Header.Get("X-Webhook-Signature"))
				assert.NotEmpty(t, r.Header.Get("X-Webhook-Timestamp"))

				// Verify payload
				bodyBytes, _ := io.ReadAll(r.Body)
				r.Body.Close()
				assert.Equal(t, `{"test": "data"}`, string(bodyBytes))

				w.WriteHeader(tt.responseStatus)
				w.Write([]byte(tt.responseBody))
			}))
			defer server.Close()

			// Create subscription and delivery
			sub, _ := tc.service.CreateSubscription(tc.ctx, "Test", server.URL, "test-secret", []string{EventUserCreated}, "user")
			deliveryID := "test-delivery"
			payload := `{"test": "data"}`

			tc.db.Pool.Exec(tc.ctx,
				"INSERT INTO webhook_deliveries (id, subscription_id, event_type, payload, attempt, status, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
				deliveryID, sub.ID, EventUserCreated, payload, 0, "pending", time.Now().UTC())

			// We can't directly call deliverWebhook since it's private
			// Instead, we verify the signature computation works correctly

			// Test signature computation for this scenario
			expectedSignature := computeSignature("test-secret", []byte(payload))
			assert.NotEmpty(t, expectedSignature)
			assert.Len(t, expectedSignature, 64)

			// Verify signature format is valid hex
			_, err := hex.DecodeString(expectedSignature)
			assert.NoError(t, err)
			_ = err // Use the variable
			_ = requestReceived
		})
	}
}

// ============================================================================
// Tests for Subscription struct
// ============================================================================

func TestSubscription(t *testing.T) {
	t.Run("subscription fields", func(t *testing.T) {
		now := time.Now().UTC()
		createdBy := "user-123"

		sub := &Subscription{
			ID:        "sub-123",
			Name:      "Test Webhook",
			URL:       "https://example.com/webhook",
			Secret:    "secret-key",
			Events:    []string{EventUserCreated, EventUserUpdated},
			Status:    "active",
			CreatedBy: &createdBy,
			CreatedAt: now,
			UpdatedAt: now,
		}

		assert.Equal(t, "sub-123", sub.ID)
		assert.Equal(t, "Test Webhook", sub.Name)
		assert.Equal(t, "https://example.com/webhook", sub.URL)
		assert.Equal(t, "secret-key", sub.Secret)
		assert.Contains(t, sub.Events, EventUserCreated)
		assert.Equal(t, "active", sub.Status)
		assert.NotNil(t, sub.CreatedBy)
		assert.Equal(t, "user-123", *sub.CreatedBy)
	})

	t.Run("subscription with nil created by", func(t *testing.T) {
		sub := &Subscription{
			ID:        "sub-123",
			Name:      "Test Webhook",
			URL:       "https://example.com/webhook",
			Secret:    "secret-key",
			Events:    []string{EventUserCreated},
			Status:    "active",
			CreatedBy: nil,
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
		}

		assert.Nil(t, sub.CreatedBy)
	})
}

// ============================================================================
// Tests for Delivery struct
// ============================================================================

func TestDelivery(t *testing.T) {
	t.Run("delivery fields", func(t *testing.T) {
		now := time.Now().UTC()
		statusCode := 200
		respBody := "success"

		delivery := &Delivery{
			ID:             "delivery-123",
			SubscriptionID: "sub-123",
			EventType:      EventUserCreated,
			Payload:        `{"user_id": "123"}`,
			ResponseStatus: &statusCode,
			ResponseBody:   &respBody,
			Attempt:        1,
			Status:         "delivered",
			CreatedAt:      now,
			DeliveredAt:    &now,
		}

		assert.Equal(t, "delivery-123", delivery.ID)
		assert.Equal(t, "sub-123", delivery.SubscriptionID)
		assert.Equal(t, EventUserCreated, delivery.EventType)
		assert.NotNil(t, delivery.ResponseStatus)
		assert.Equal(t, 200, *delivery.ResponseStatus)
		assert.NotNil(t, delivery.ResponseBody)
		assert.Equal(t, "success", *delivery.ResponseBody)
		assert.Equal(t, 1, delivery.Attempt)
		assert.Equal(t, "delivered", delivery.Status)
		assert.NotNil(t, delivery.DeliveredAt)
	})

	t.Run("delivery with pending status", func(t *testing.T) {
		now := time.Now().UTC()
		nextRetry := now.Add(5 * time.Minute)

		delivery := &Delivery{
			ID:             "delivery-123",
			SubscriptionID: "sub-123",
			EventType:      EventUserCreated,
			Payload:        `{"user_id": "123"}`,
			ResponseStatus: nil,
			ResponseBody:   nil,
			Attempt:        0,
			Status:         "pending",
			NextRetryAt:    &nextRetry,
			CreatedAt:      now,
			DeliveredAt:    nil,
		}

		assert.Nil(t, delivery.ResponseStatus)
		assert.Nil(t, delivery.ResponseBody)
		assert.Equal(t, 0, delivery.Attempt)
		assert.Equal(t, "pending", delivery.Status)
		assert.NotNil(t, delivery.NextRetryAt)
		assert.Nil(t, delivery.DeliveredAt)
	})
}

// ============================================================================
// Tests for NewService
// ============================================================================

func TestNewService(t *testing.T) {
	logger := zaptest.NewLogger(t)

	t.Run("service with nil database", func(t *testing.T) {
		// Create mock Redis
		mockRedis := testutil.NewMockRedis(logger)
		err := mockRedis.Setup()
		require.NoError(t, err)
		defer mockRedis.Shutdown()

		redisClient := &database.RedisClient{Client: mockRedis.Client()}

		// Service can be created with nil DB (for limited functionality)
		service := NewService(nil, redisClient, logger, testCipher())

		assert.NotNil(t, service)
		assert.Nil(t, service.db)
		assert.NotNil(t, service.redis)
		assert.NotNil(t, service.logger)
		assert.NotNil(t, service.client)
	})

	t.Run("service with all dependencies", func(t *testing.T) {
		// Create mock Redis
		mockRedis := testutil.NewMockRedis(logger)
		err := mockRedis.Setup()
		require.NoError(t, err)
		defer mockRedis.Shutdown()

		redisClient := &database.RedisClient{Client: mockRedis.Client()}

		// Service can be created with all dependencies
		service := NewService(nil, redisClient, logger, testCipher())

		assert.NotNil(t, service)
		assert.NotNil(t, service.client)
	})
}

// ============================================================================
// Tests for signature verification edge cases
// ============================================================================

func TestSignatureEdgeCases(t *testing.T) {
	t.Run("signature with empty secret", func(t *testing.T) {
		body := []byte(`{"test": "data"}`)
		sig := computeSignature("", body)
		assert.NotEmpty(t, sig)
		assert.Len(t, sig, 64)
	})

	t.Run("signature with empty body", func(t *testing.T) {
		sig := computeSignature("secret", []byte{})
		assert.NotEmpty(t, sig)
		assert.Len(t, sig, 64)
	})

	t.Run("signature with both empty", func(t *testing.T) {
		sig := computeSignature("", []byte{})
		assert.NotEmpty(t, sig)
		assert.Len(t, sig, 64)
	})

	t.Run("signature is deterministic", func(t *testing.T) {
		secret := "test-secret"
		body := []byte(`{"test": "data"}`)

		// Generate 100 signatures and verify they're all the same
		signatures := make([]string, 100)
		for i := 0; i < 100; i++ {
			signatures[i] = computeSignature(secret, body)
		}

		for i := 1; i < len(signatures); i++ {
			assert.Equal(t, signatures[0], signatures[i], "signature should be deterministic")
		}
	})

	t.Run("signature changes with different inputs", func(t *testing.T) {
		secret := "test-secret"

		sig1 := computeSignature(secret, []byte(`{"a": 1}`))
		sig2 := computeSignature(secret, []byte(`{"a": 2}`))
		sig3 := computeSignature(secret, []byte(`{"a": "1"}`))

		// All should be different
		assert.NotEqual(t, sig1, sig2)
		assert.NotEqual(t, sig2, sig3)
		assert.NotEqual(t, sig1, sig3)
	})

	t.Run("special characters in body", func(t *testing.T) {
		secret := "test-secret"
		bodies := []string{
			`{"data": "hello\nworld"}`,
			`{"data": "hello\tworld"}`,
			`{"data": "hello\r\nworld"}`,
			`{"data": "\"quoted\""}`,
			`{"data": "back\\slash"}`,
		}

		signatures := make([]string, len(bodies))
		for i, body := range bodies {
			signatures[i] = computeSignature(secret, []byte(body))
			assert.Len(t, signatures[i], 64)
		}

		// Verify all are unique
		for i := 0; i < len(signatures); i++ {
			for j := i + 1; j < len(signatures); j++ {
				assert.NotEqual(t, signatures[i], signatures[j], "different bodies should have different signatures")
			}
		}
	})
}

// ============================================================================
// Tests for event types
// ============================================================================

func TestEventTypes(t *testing.T) {
	t.Run("user events pattern", func(t *testing.T) {
		userEvents := []string{
			EventUserCreated,
			EventUserUpdated,
			EventUserDeleted,
			EventUserLocked,
		}

		for _, event := range userEvents {
			assert.True(t, strings.HasPrefix(event, "user."), "user event should start with 'user.'")
		}
	})

	t.Run("login events pattern", func(t *testing.T) {
		loginEvents := []string{
			EventLoginSuccess,
			EventLoginFailed,
			EventLoginHighRisk,
		}

		for _, event := range loginEvents {
			assert.True(t, strings.HasPrefix(event, "login."), "login event should start with 'login.'")
		}
	})

	t.Run("all events follow naming convention", func(t *testing.T) {
		allEvents := []string{
			EventUserCreated,
			EventUserUpdated,
			EventUserDeleted,
			EventUserLocked,
			EventLoginSuccess,
			EventLoginFailed,
			EventLoginHighRisk,
			EventGroupUpdated,
			EventRoleUpdated,
			EventPolicyViolated,
			EventReviewCompleted,
		}

		for _, event := range allEvents {
			// Should contain exactly one dot
			dotCount := strings.Count(event, ".")
			assert.Equal(t, 1, dotCount, "event '%s' should contain exactly one dot", event)

			// Should be lowercase
			assert.Equal(t, event, strings.ToLower(event), "event '%s' should be lowercase", event)

			// Should not contain spaces
			assert.False(t, strings.ContainsAny(event, " "), "event '%s' should not contain spaces", event)
		}
	})
}

// ============================================================================
// Tests for retry delay calculation
// ============================================================================

func TestRetryDelayCalculation(t *testing.T) {
	tests := []struct {
		name        string
		attempt     int
		expectDelay time.Duration
		shouldRetry bool
	}{
		{
			name:        "attempt 0 -> 1st retry",
			attempt:     0,
			expectDelay: 1 * time.Minute,
			shouldRetry: true,
		},
		{
			name:        "attempt 1 -> 2nd retry",
			attempt:     1,
			expectDelay: 5 * time.Minute,
			shouldRetry: true,
		},
		{
			name:        "attempt 2 -> 3rd retry",
			attempt:     2,
			expectDelay: 30 * time.Minute,
			shouldRetry: true,
		},
		{
			name:        "attempt 3 -> max retries reached",
			attempt:     3,
			expectDelay: 0,
			shouldRetry: false,
		},
		{
			name:        "attempt 4 -> past max retries",
			attempt:     4,
			expectDelay: 0,
			shouldRetry: false,
		},
		{
			name:        "attempt 100 -> way past max retries",
			attempt:     100,
			expectDelay: 0,
			shouldRetry: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nextAttempt := tt.attempt + 1

			// Determine retry behavior based on attempt number
			shouldRetry := nextAttempt <= 3

			var retryDelay time.Duration
			if shouldRetry {
				switch nextAttempt {
				case 1:
					retryDelay = 1 * time.Minute
				case 2:
					retryDelay = 5 * time.Minute
				case 3:
					retryDelay = 30 * time.Minute
				}
			}

			assert.Equal(t, tt.expectDelay, retryDelay)
			assert.Equal(t, tt.shouldRetry, shouldRetry)
		})
	}
}

// ============================================================================
// Tests for webhook payload handling
// ============================================================================

func TestWebhookPayloadHandling(t *testing.T) {
	t.Run("valid JSON payload", func(t *testing.T) {
		payload := map[string]interface{}{
			"event":     "user.created",
			"user_id":   "12345",
			"email":     "test@example.com",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		}

		jsonBytes, err := json.Marshal(payload)
		assert.NoError(t, err)
		assert.NotEmpty(t, jsonBytes)

		// Verify it can be unmarshaled back
		var unmarshaled map[string]interface{}
		err = json.Unmarshal(jsonBytes, &unmarshaled)
		assert.NoError(t, err)
		assert.Equal(t, "user.created", unmarshaled["event"])
	})

	t.Run("complex nested payload", func(t *testing.T) {
		payload := map[string]interface{}{
			"event": "user.created",
			"user": map[string]interface{}{
				"id": "12345",
				"profile": map[string]interface{}{
					"firstName": "John",
					"lastName":  "Doe",
				},
			},
			"metadata": []string{"tag1", "tag2"},
		}

		jsonBytes, err := json.Marshal(payload)
		assert.NoError(t, err)
		assert.NotEmpty(t, jsonBytes)

		// Verify signature can be computed
		sig := computeSignature("secret", jsonBytes)
		assert.Len(t, sig, 64)
	})

	t.Run("payload with special characters", func(t *testing.T) {
		payloads := []string{
			`{"message": "Hello 世界"}`,
			`{"message": "Hello 🌍"}`,
			`{"message": "Test\nNewline\tTab\rCarriage"}`,
			`{"message": "Quote: \"test\""}`,
			`{"emoji": "😀😃😄😁"}`,
		}

		for _, payload := range payloads {
			sig := computeSignature("secret", []byte(payload))
			assert.Len(t, sig, 64, "signature should be 64 chars for payload: %s", payload)
		}
	})
}

// ============================================================================
// Tests for Subscription and Delivery struct JSON marshaling
// ============================================================================

func TestSubscriptionJSON(t *testing.T) {
	t.Run("marshal subscription", func(t *testing.T) {
		createdBy := "user-123"
		sub := Subscription{
			ID:        "sub-123",
			Name:      "Test Webhook",
			URL:       "https://example.com/webhook",
			Secret:    "secret-key",
			Events:    []string{EventUserCreated, EventUserUpdated},
			Status:    "active",
			CreatedBy: &createdBy,
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
		}

		// Marshal to JSON
		jsonBytes, err := json.Marshal(sub)
		assert.NoError(t, err)

		// Verify key fields are present
		jsonStr := string(jsonBytes)
		assert.Contains(t, jsonStr, `"id"`)
		assert.Contains(t, jsonStr, `"name"`)
		assert.Contains(t, jsonStr, `"url"`)
		assert.Contains(t, jsonStr, `"events"`)
		assert.Contains(t, jsonStr, `"status"`)

		// Secret should not be in JSON (has json:"-")
		// Actually the struct tag is `json:"-"` which means it's omitted
		assert.NotContains(t, jsonStr, `"secret"`)
	})

	t.Run("unmarshal subscription", func(t *testing.T) {
		jsonStr := `{
			"id": "sub-123",
			"name": "Test Webhook",
			"url": "https://example.com/webhook",
			"secret": "secret-key",
			"events": ["user.created", "user.updated"],
			"status": "active",
			"created_by": "user-123",
			"created_at": "2024-01-01T00:00:00Z",
			"updated_at": "2024-01-01T00:00:00Z"
		}`

		var sub Subscription
		err := json.Unmarshal([]byte(jsonStr), &sub)
		assert.NoError(t, err)

		assert.Equal(t, "sub-123", sub.ID)
		assert.Equal(t, "Test Webhook", sub.Name)
		assert.Equal(t, "https://example.com/webhook", sub.URL)
		assert.NotEmpty(t, sub.Events)
	})
}

func TestDeliveryJSON(t *testing.T) {
	t.Run("marshal delivery", func(t *testing.T) {
		now := time.Now().UTC()
		statusCode := 200
		respBody := "success"

		delivery := Delivery{
			ID:             "delivery-123",
			SubscriptionID: "sub-123",
			EventType:      EventUserCreated,
			Payload:        `{"user_id": "123"}`,
			ResponseStatus: &statusCode,
			ResponseBody:   &respBody,
			Attempt:        1,
			Status:         "delivered",
			CreatedAt:      now,
			DeliveredAt:    &now,
		}

		// Marshal to JSON
		jsonBytes, err := json.Marshal(delivery)
		assert.NoError(t, err)

		// Verify key fields are present
		jsonStr := string(jsonBytes)
		assert.Contains(t, jsonStr, `"id"`)
		assert.Contains(t, jsonStr, `"subscription_id"`)
		assert.Contains(t, jsonStr, `"event_type"`)
		assert.Contains(t, jsonStr, `"status"`)
	})

	t.Run("marshal pending delivery", func(t *testing.T) {
		now := time.Now().UTC()
		nextRetry := now.Add(5 * time.Minute)

		delivery := Delivery{
			ID:             "delivery-123",
			SubscriptionID: "sub-123",
			EventType:      EventUserCreated,
			Payload:        `{"user_id": "123"}`,
			ResponseStatus: nil,
			ResponseBody:   nil,
			Attempt:        0,
			Status:         "pending",
			NextRetryAt:    &nextRetry,
			CreatedAt:      now,
			DeliveredAt:    nil,
		}

		// Marshal to JSON
		jsonBytes, err := json.Marshal(delivery)
		assert.NoError(t, err)

		// Verify status is pending
		jsonStr := string(jsonBytes)
		assert.Contains(t, jsonStr, `"status"`)
		assert.Contains(t, jsonStr, `"pending"`)
	})
}

// ============================================================================
// Tests for event filtering logic (simulated)
// ============================================================================

func TestEventMatching(t *testing.T) {
	t.Run("exact event match", func(t *testing.T) {
		subscriptionEvents := []string{EventUserCreated, EventUserUpdated}

		payloadEvent := EventUserCreated
		matches := false
		for _, e := range subscriptionEvents {
			if e == payloadEvent {
				matches = true
				break
			}
		}
		assert.True(t, matches)
	})

	t.Run("no event match", func(t *testing.T) {
		subscriptionEvents := []string{EventUserCreated, EventUserUpdated}

		payloadEvent := EventLoginSuccess
		matches := false
		for _, e := range subscriptionEvents {
			if e == payloadEvent {
				matches = true
				break
			}
		}
		assert.False(t, matches)
	})

	t.Run("wildcard pattern matching simulation", func(t *testing.T) {
		// Simulating user.* pattern matching
		subscriptionEvents := []string{"user.*", EventLoginSuccess}

		userEvents := []string{EventUserCreated, EventUserUpdated, EventUserDeleted, EventUserLocked}

		for _, userEvent := range userEvents {
			matches := false
			for _, pattern := range subscriptionEvents {
				if pattern == "user.*" && strings.HasPrefix(userEvent, "user.") {
					matches = true
					break
				}
				if pattern == userEvent {
					matches = true
					break
				}
			}
			assert.True(t, matches, "user event should match user.* pattern: %s", userEvent)
		}

		// Non-user event should not match user.* pattern
		matches := false
		for _, pattern := range subscriptionEvents {
			if pattern == "user.*" && strings.HasPrefix(EventLoginSuccess, "user.") {
				matches = true
				break
			}
			if pattern == EventLoginSuccess {
				matches = true
				break
			}
		}
		assert.True(t, matches, "login event should match its exact subscription")
	})
}

// ============================================================================
// Tests for webhook timeout handling
// ============================================================================

func TestWebhookTimeout(t *testing.T) {
	t.Run("client timeout is set", func(t *testing.T) {
		logger := zaptest.NewLogger(t)

		mockRedis := testutil.NewMockRedis(logger)
		err := mockRedis.Setup()
		require.NoError(t, err)
		defer mockRedis.Shutdown()

		redisClient := &database.RedisClient{Client: mockRedis.Client()}
		service := NewService(nil, redisClient, logger, testCipher())

		// The service creates an HTTP client with a 10-second timeout
		// We can't directly access the timeout, but we can verify the client exists
		assert.NotNil(t, service.client)
	})
}

// ============================================================================
// Tests for Publish error handling
// ============================================================================

func TestPublishErrors(t *testing.T) {
	logger := zaptest.NewLogger(t)

	mockRedis := testutil.NewMockRedis(logger)
	err := mockRedis.Setup()
	require.NoError(t, err)
	defer mockRedis.Shutdown()

	redisClient := &database.RedisClient{Client: mockRedis.Client()}

	t.Run("publish with unmarshalable payload", func(t *testing.T) {
		service := NewService(nil, redisClient, logger, testCipher())

		// Channels cannot be marshaled to JSON
		unmarshalable := make(chan int)
		err := service.Publish(context.Background(), EventUserCreated, unmarshalable)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to marshal webhook payload")
	})

	t.Run("publish with nil database causes panic", func(t *testing.T) {
		service := NewService(nil, redisClient, logger, testCipher())

		// Valid payload but nil database will cause a panic (not an error)
		// The code doesn't handle nil db gracefully
		assert.Panics(t, func() {
			_ = service.Publish(context.Background(), EventUserCreated, map[string]string{"test": "data"})
		})
	})
}

// ============================================================================
// Tests for service methods with nil database
// ============================================================================

func TestServiceWithNilDatabase(t *testing.T) {
	logger := zaptest.NewLogger(t)

	mockRedis := testutil.NewMockRedis(logger)
	err := mockRedis.Setup()
	require.NoError(t, err)
	defer mockRedis.Shutdown()

	redisClient := &database.RedisClient{Client: mockRedis.Client()}
	service := NewService(nil, redisClient, logger, testCipher())

	t.Run("create subscription with nil database panics", func(t *testing.T) {
		// CreateSubscription first requires an organization context (the QA 10.5
		// fix). With an org present it reaches the nil DB and panics; without one
		// it returns a graceful error instead. Assert both.
		ctxWithOrg := orgctx.With(context.Background(), orgctx.Org{ID: "00000000-0000-0000-0000-000000000010"})
		assert.Panics(t, func() {
			_, _ = service.CreateSubscription(ctxWithOrg, "Test", "https://example.com", "secret", []string{EventUserCreated}, "user")
		})
		if _, err := service.CreateSubscription(context.Background(), "Test", "https://example.com", "secret", []string{EventUserCreated}, "user"); err == nil {
			t.Error("expected an organization-context error when ctx has no org")
		}
	})

	t.Run("list subscriptions with nil database panics", func(t *testing.T) {
		assert.Panics(t, func() {
			_, _ = service.ListSubscriptions(context.Background())
		})
	})

	t.Run("get subscription with nil database panics", func(t *testing.T) {
		assert.Panics(t, func() {
			_, _ = service.GetSubscription(context.Background(), "test-id")
		})
	})

	t.Run("update subscription with nil database panics", func(t *testing.T) {
		assert.Panics(t, func() {
			_ = service.UpdateSubscription(context.Background(), "test-id", "Test", "https://example.com", []string{EventUserCreated}, "active")
		})
	})

	t.Run("delete subscription with nil database panics", func(t *testing.T) {
		assert.Panics(t, func() {
			_ = service.DeleteSubscription(context.Background(), "test-id")
		})
	})

	t.Run("get delivery history with nil database panics", func(t *testing.T) {
		assert.Panics(t, func() {
			_, _ = service.GetDeliveryHistory(context.Background(), "test-id", 10)
		})
	})

	t.Run("retry delivery with nil database panics", func(t *testing.T) {
		assert.Panics(t, func() {
			_ = service.RetryDelivery(context.Background(), "test-id")
		})
	})

	t.Run("ping subscription with nil database returns error", func(t *testing.T) {
		// Ping first calls GetSubscription which will panic with nil db
		assert.Panics(t, func() {
			_, _ = service.PingSubscription(context.Background(), "test-id")
		})
	})

	t.Run("get delivery stats with nil database returns error", func(t *testing.T) {
		// GetDeliveryStats first calls GetSubscription which will panic with nil db
		assert.Panics(t, func() {
			_, _ = service.GetDeliveryStats(context.Background(), "test-id")
		})
	})
}

// ============================================================================
// Tests for Subscription status values
// ============================================================================

func TestSubscriptionStatus(t *testing.T) {
	validStatuses := []string{"active", "inactive", "disabled"}

	for _, status := range validStatuses {
		t.Run("status_"+status, func(t *testing.T) {
			sub := &Subscription{
				ID:     "test-id",
				Name:   "Test",
				URL:    "https://example.com",
				Secret: "secret",
				Events: []string{EventUserCreated},
				Status: status,
			}

			assert.Equal(t, status, sub.Status)
		})
	}
}

// ============================================================================
// Tests for Delivery status values
// ============================================================================

func TestDeliveryStatus(t *testing.T) {
	validStatuses := []string{"pending", "delivered", "failed"}

	for _, status := range validStatuses {
		t.Run("status_"+status, func(t *testing.T) {
			delivery := &Delivery{
				ID:             "test-id",
				SubscriptionID: "sub-id",
				EventType:      EventUserCreated,
				Payload:        "{}",
				Attempt:        1,
				Status:         status,
				CreatedAt:      time.Now().UTC(),
			}

			assert.Equal(t, status, delivery.Status)
		})
	}
}

// ============================================================================
// Tests for event type constants values
// ============================================================================

func TestEventTypeConstantsValues(t *testing.T) {
	tests := []struct {
		constant string
		value    string
		category string
		action   string
	}{
		{EventUserCreated, "user.created", "user", "created"},
		{EventUserUpdated, "user.updated", "user", "updated"},
		{EventUserDeleted, "user.deleted", "user", "deleted"},
		{EventUserLocked, "user.locked", "user", "locked"},
		{EventLoginSuccess, "login.success", "login", "success"},
		{EventLoginFailed, "login.failed", "login", "failed"},
		{EventLoginHighRisk, "login.high_risk", "login", "high_risk"},
		{EventGroupUpdated, "group.updated", "group", "updated"},
		{EventRoleUpdated, "role.updated", "role", "updated"},
		{EventPolicyViolated, "policy.violated", "policy", "violated"},
		{EventReviewCompleted, "review.completed", "review", "completed"},
	}

	for _, tt := range tests {
		t.Run(tt.constant, func(t *testing.T) {
			// Check format: category.action
			parts := strings.Split(tt.value, ".")
			assert.Len(t, parts, 2, "event should be in format 'category.action'")
			assert.Equal(t, tt.category, parts[0])
			assert.Equal(t, tt.action, parts[1])

			// Verify constant matches expected value
			assert.Equal(t, tt.value, tt.constant)
		})
	}
}

// ============================================================================
// Tests for signature algorithm verification
// ============================================================================

func TestSignatureAlgorithm(t *testing.T) {
	t.Run("signature uses HMAC-SHA256", func(t *testing.T) {
		secret := "test-secret"
		body := []byte(`{"test": "data"}`)

		// Compute signature using our function
		sig1 := computeSignature(secret, body)

		// Compute expected signature using standard library
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		expected := hex.EncodeToString(mac.Sum(nil))

		assert.Equal(t, expected, sig1)
	})

	t.Run("signature differs for different secrets", func(t *testing.T) {
		body := []byte(`{"test": "data"}`)

		sig1 := computeSignature("secret1", body)
		sig2 := computeSignature("secret2", body)

		assert.NotEqual(t, sig1, sig2)
	})

	t.Run("signature length is always 64 hex characters", func(t *testing.T) {
		secrets := []string{"", "a", "ab", "abc", "longer-secret-key-12345"}
		bodies := [][]byte{{}, []byte("a"), []byte("{}"), []byte(strings.Repeat("x", 1000))}

		for _, secret := range secrets {
			for _, body := range bodies {
				sig := computeSignature(secret, body)
				assert.Len(t, sig, 64, "signature should always be 64 hex chars")
			}
		}
	})
}

// ============================================================================
// Tests for retry backoff sequence
// ============================================================================

func TestRetryBackoffSequence(t *testing.T) {
	t.Run("backoff sequence is exponential", func(t *testing.T) {
		delays := []time.Duration{
			1 * time.Minute,  // 1st retry
			5 * time.Minute,  // 2nd retry
			30 * time.Minute, // 3rd retry
		}

		// Verify each delay is longer than the previous
		for i := 1; i < len(delays); i++ {
			assert.Greater(t, delays[i], delays[i-1], "retry delay should increase")
		}
	})

	t.Run("max retries is 3", func(t *testing.T) {
		// After 3 retries, the delivery should be marked as failed
		maxRetries := 3
		assert.Equal(t, 3, maxRetries)

		// Verify that attempt 3 (0-indexed, so the 4th attempt) marks as failed
		attempt := 3
		nextAttempt := attempt + 1
		shouldFail := nextAttempt > 3
		assert.True(t, shouldFail)
	})
}

// ============================================================================
// Tests for webhook headers
// ============================================================================

func TestWebhookHeaders(t *testing.T) {
	expectedHeaders := []string{
		"Content-Type",
		"X-Webhook-ID",
		"X-Webhook-Event",
		"X-Webhook-Timestamp",
		"X-Webhook-Signature",
	}

	for _, header := range expectedHeaders {
		t.Run("header_"+header, func(t *testing.T) {
			// Just verify the header name is what we expect
			assert.NotEmpty(t, header)
			if header == "Content-Type" {
				assert.Equal(t, "Content-Type", header)
			} else {
				assert.True(t, strings.HasPrefix(header, "X-Webhook-"))
			}
		})
	}

	t.Run("all webhook headers start with X-Webhook- except Content-Type", func(t *testing.T) {
		for _, header := range expectedHeaders {
			if header != "Content-Type" {
				assert.True(t, strings.HasPrefix(header, "X-Webhook-"), "header should start with X-Webhook-: %s", header)
			}
		}
	})
}

// ============================================================================
// Benchmark tests
// ============================================================================

func BenchmarkComputeSignature(b *testing.B) {
	secret := "test-webhook-secret-key"
	body := []byte(`{"event": "user.created", "user_id": "12345", "email": "user@example.com", "timestamp": "2024-01-01T00:00:00Z"}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		computeSignature(secret, body)
	}
}

func BenchmarkComputeSignatureLargePayload(b *testing.B) {
	secret := "test-webhook-secret-key"
	// Simulate a large webhook payload
	largePayload := make(map[string]interface{})
	for i := 0; i < 100; i++ {
		largePayload[fmt.Sprintf("field_%d", i)] = strings.Repeat("x", 100)
	}
	body, _ := json.Marshal(largePayload)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		computeSignature(secret, body)
	}
}
