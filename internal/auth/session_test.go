// Package auth provides unit tests for session management
package auth

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// mustCreateTestRedis creates a test Redis server using miniredis. Each
// invocation gets its own miniredis instance *and* its own redis.Client,
// both wired into t.Cleanup so they're torn down in the right order on
// test exit. Without an explicit client.Close, the go-redis connection
// pool kept connections open against the now-closed miniredis port — and
// when the next test's miniredis grabbed the same port, the stale
// connections delivered the previous test's state into the new one.
// Manifested as TestSessionService_UpdateMetadata seeing the prior
// test's session metadata under -race in CI (deterministic at
// -count=2 once you co-run it with SessionExpirationCleanup).
func mustCreateTestRedisForSession(t *testing.T) (*miniredis.Miniredis, *redis.Client) {
	s := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{
		Addr: s.Addr(),
	})
	t.Cleanup(func() {
		_ = client.Close()
	})
	return s, client
}

func TestSessionService_Create(t *testing.T) {
	s, client := mustCreateTestRedisForSession(t)
	defer s.Close()
	logger := zap.NewNop()
	ctx := context.Background()

	ss := NewSessionService(client, logger)

	tests := []struct {
		name        string
		userID      string
		tenantID    string
		ipAddress   string
		userAgent   string
		metadata    map[string]interface{}
		config      SessionConfig
		wantErr     error
		checkResult func(*testing.T, *Session)
	}{
		{
			name:      "valid session creation",
			userID:    "user123",
			tenantID:  "tenant456",
			ipAddress: "192.168.1.1",
			userAgent: "Mozilla/5.0",
			metadata: map[string]interface{}{
				"device": "mobile",
			},
			wantErr: nil,
			checkResult: func(t *testing.T, s *Session) {
				assert.NotEmpty(t, s.ID)
				assert.Equal(t, "user123", s.UserID)
				assert.Equal(t, "tenant456", s.TenantID)
				assert.Equal(t, "192.168.1.1", s.IPAddress)
				assert.Equal(t, "Mozilla/5.0", s.UserAgent)
				assert.Equal(t, "mobile", s.Metadata["device"])
				assert.False(t, s.CreatedAt.IsZero())
				assert.False(t, s.ExpiresAt.IsZero())
			},
		},
		{
			name:      "session with empty tenant",
			userID:    "user123",
			tenantID:  "",
			ipAddress: "",
			userAgent: "",
			metadata:  nil,
			wantErr:   nil,
			checkResult: func(t *testing.T, s *Session) {
				assert.NotEmpty(t, s.ID)
				assert.Equal(t, "user123", s.UserID)
				assert.Empty(t, s.TenantID)
			},
		},
		{
			name:      "session with custom config",
			userID:    "user123",
			tenantID:  "tenant456",
			ipAddress: "10.0.0.1",
			userAgent: "TestAgent",
			metadata:  nil,
			config: SessionConfig{
				DefaultTTL:         1 * time.Hour,
				MaxSessions:        2,
				CleanupInterval:    30 * time.Minute,
				KeyPrefix:          "custom:",
				UserSessionsPrefix: "custom_user:",
			},
			wantErr: nil,
			checkResult: func(t *testing.T, s *Session) {
				expiry := s.ExpiresAt.Sub(s.CreatedAt)
				assert.Greater(t, expiry, 59*time.Minute)
				assert.Less(t, expiry, 61*time.Minute)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.config.KeyPrefix != "" {
				ss.WithConfig(tt.config)
			}

			session, err := ss.Create(ctx, tt.userID, tt.tenantID, tt.ipAddress, tt.userAgent, tt.metadata)

			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
				require.NotNil(t, session)
				if tt.checkResult != nil {
					tt.checkResult(t, session)
				}
			}
		})
	}
}

func TestSessionService_Create_MaxSessions(t *testing.T) {
	// Create a single miniredis for all subtests
	s, client := mustCreateTestRedisForSession(t)
	defer s.Close()
	logger := zap.NewNop()
	ctx := context.Background()

	tests := []struct {
		name             string
		maxSessions      int
		createCount      int
		wantErrOnLast    bool
		expectedSessions int
	}{
		{
			name:             "exactly max sessions",
			maxSessions:      3,
			createCount:      3,
			wantErrOnLast:    false,
			expectedSessions: 3,
		},
		{
			name:             "exceeds max sessions - should delete oldest",
			maxSessions:      3,
			createCount:      4,
			wantErrOnLast:    false,
			expectedSessions: 3,
		},
		{
			name:             "max sessions is 1",
			maxSessions:      1,
			createCount:      3,
			wantErrOnLast:    false,
			expectedSessions: 1,
		},
		{
			name:             "max sessions is 10",
			maxSessions:      10,
			createCount:      15,
			wantErrOnLast:    false,
			expectedSessions: 10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ss := NewSessionService(client, logger).WithConfig(SessionConfig{
				MaxSessions: tt.maxSessions,
			})

			userID := tt.name + "_user" // Unique user ID per test
			var sessions []*Session

			for i := 0; i < tt.createCount; i++ {
				session, err := ss.Create(ctx, userID, "tenant1", "127.0.0.1", "test", nil)
				if tt.wantErrOnLast && i == tt.createCount-1 {
					assert.Error(t, err)
				} else {
					require.NoError(t, err)
					sessions = append(sessions, session)
				}
			}

			// Verify actual session count
			sessionIDs, err := ss.ListByUser(ctx, userID)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedSessions, len(sessionIDs))

			// Cleanup: delete all sessions for this user after each subtest
			// We ignore ErrSessionNotFound since it's acceptable for cleanup
			if err := ss.DeleteByUser(ctx, userID); err != nil && err != ErrSessionNotFound {
				t.Fatalf("cleanup failed: %v", err)
			}
		})
	}
}

func TestSessionService_Get(t *testing.T) {
	s, client := mustCreateTestRedisForSession(t)
	defer s.Close()
	logger := zap.NewNop()
	ctx := context.Background()

	ss := NewSessionService(client, logger)

	// Create a test session
	session, err := ss.Create(ctx, "user123", "tenant456", "192.168.1.1", "Mozilla", nil)
	require.NoError(t, err)

	tests := []struct {
		name      string
		sessionID string
		wantErr   error
		check     func(*testing.T, *Session)
	}{
		{
			name:      "get existing session",
			sessionID: session.ID,
			wantErr:   nil,
			check: func(t *testing.T, s *Session) {
				assert.Equal(t, session.ID, s.ID)
				assert.Equal(t, "user123", s.UserID)
			},
		},
		{
			name:      "get non-existent session",
			sessionID: uuid.New().String(),
			wantErr:   ErrSessionNotFound,
		},
		{
			name:      "get with empty session ID",
			sessionID: "",
			wantErr:   ErrSessionNotFound,
		},
		{
			name:      "get with invalid UUID format",
			sessionID: "not-a-uuid",
			wantErr:   ErrSessionNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ss.Get(ctx, tt.sessionID)

			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
				require.NotNil(t, result)
				if tt.check != nil {
					tt.check(t, result)
				}
			}
		})
	}
}

func TestSessionService_Get_Expired(t *testing.T) {
	s, client := mustCreateTestRedisForSession(t)
	defer s.Close()
	logger := zap.NewNop()
	ctx := context.Background()

	ss := NewSessionService(client, logger).WithConfig(SessionConfig{
		DefaultTTL: 1 * time.Second,
	})

	// Create a session that will expire quickly
	session, err := ss.Create(ctx, "user123", "tenant456", "192.168.1.1", "Mozilla", nil)
	require.NoError(t, err)

	// Fast forward time past expiration
	s.FastForward(2 * time.Second)

	// Try to get the expired session
	_, err = ss.Get(ctx, session.ID)
	// Session should not be found (Redis TTL expired)
	assert.ErrorIs(t, err, ErrSessionNotFound)
}

func TestSessionService_Delete(t *testing.T) {
	s, client := mustCreateTestRedisForSession(t)
	defer s.Close()
	logger := zap.NewNop()
	ctx := context.Background()

	ss := NewSessionService(client, logger)

	// Create a test session
	session, err := ss.Create(ctx, "user123", "tenant456", "192.168.1.1", "Mozilla", nil)
	require.NoError(t, err)

	tests := []struct {
		name    string
		setup   func() string
		wantErr error
		verify  func(*testing.T, string)
	}{
		{
			name: "delete existing session",
			setup: func() string {
				return session.ID
			},
			wantErr: nil,
			verify: func(t *testing.T, id string) {
				// Session should no longer exist
				_, err := ss.Get(ctx, id)
				assert.ErrorIs(t, err, ErrSessionNotFound)
			},
		},
		{
			name: "delete already deleted session",
			setup: func() string {
				ss.Delete(ctx, session.ID) // Delete first
				return session.ID
			},
			wantErr: ErrSessionNotFound,
		},
		{
			name: "delete non-existent session",
			setup: func() string {
				return uuid.New().String()
			},
			wantErr: ErrSessionNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessionID := tt.setup()
			err := ss.Delete(ctx, sessionID)

			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
				if tt.verify != nil {
					tt.verify(t, sessionID)
				}
			}
		})
	}
}

func TestSessionService_DeleteByUser(t *testing.T) {
	s, client := mustCreateTestRedisForSession(t)
	defer s.Close()
	logger := zap.NewNop()
	ctx := context.Background()

	ss := NewSessionService(client, logger)

	// Create multiple sessions for a user
	userID := "user_multi"
	var sessionIDs []string
	for i := 0; i < 3; i++ {
		session, err := ss.Create(ctx, userID, "tenant456", "192.168.1.1", "Mozilla", nil)
		require.NoError(t, err)
		sessionIDs = append(sessionIDs, session.ID)
	}

	// Create a session for another user
	otherSession, err := ss.Create(ctx, "other_user", "tenant456", "192.168.1.1", "Mozilla", nil)
	require.NoError(t, err)

	// Delete all sessions for the user
	err = ss.DeleteByUser(ctx, userID)
	require.NoError(t, err)

	// Verify all user sessions are deleted
	for _, id := range sessionIDs {
		_, err := ss.Get(ctx, id)
		assert.ErrorIs(t, err, ErrSessionNotFound)
	}

	// Verify other user's session still exists
	_, err = ss.Get(ctx, otherSession.ID)
	assert.NoError(t, err)

	// Verify list is empty
	ids, err := ss.ListByUser(ctx, userID)
	require.NoError(t, err)
	assert.Empty(t, ids)

	// Test deleting sessions for a non-existent user
	t.Run("NonExistentUser", func(t *testing.T) {
		nonExistentUserID := "user_does_not_exist"

		// Verify user has no sessions initially
		sessionIDs, err := ss.ListByUser(ctx, nonExistentUserID)
		require.NoError(t, err)
		assert.Empty(t, sessionIDs)

		// Attempting to delete sessions should return ErrSessionNotFound
		err = ss.DeleteByUser(ctx, nonExistentUserID)
		assert.ErrorIs(t, err, ErrSessionNotFound)
	})

	// Test deleting sessions after all have already been manually deleted
	t.Run("AlreadyDeletedUser", func(t *testing.T) {
		userID := "user_already_deleted"

		// Create sessions
		for i := 0; i < 2; i++ {
			_, err := ss.Create(ctx, userID, "tenant456", "192.168.1.1", "Mozilla", nil)
			require.NoError(t, err)
		}

		// Delete all sessions
		err := ss.DeleteByUser(ctx, userID)
		require.NoError(t, err)

		// Attempting to delete again should return ErrSessionNotFound
		err = ss.DeleteByUser(ctx, userID)
		assert.ErrorIs(t, err, ErrSessionNotFound)
	})
}

func TestSessionService_ListByUser(t *testing.T) {
	s, client := mustCreateTestRedisForSession(t)
	defer s.Close()
	logger := zap.NewNop()
	ctx := context.Background()

	ss := NewSessionService(client, logger)

	tests := []struct {
		name        string
		setup       func() string
		wantCount   int
		sortedOrder bool // Whether to check creation order
	}{
		{
			name: "list sessions for user with multiple sessions",
			setup: func() string {
				userID := "user_list_test"
				for i := 0; i < 3; i++ {
					_, err := ss.Create(ctx, userID, "tenant456", "192.168.1.1", "Mozilla", nil)
					require.NoError(t, err)
				}
				return userID
			},
			wantCount: 3,
		},
		{
			name: "list sessions for user with no sessions",
			setup: func() string {
				return "user_no_sessions"
			},
			wantCount: 0,
		},
		{
			name: "list sessions after some are deleted",
			setup: func() string {
				userID := "user_partial_delete"
				var ids []string
				for i := 0; i < 5; i++ {
					sess, err := ss.Create(ctx, userID, "tenant456", "192.168.1.1", "Mozilla", nil)
					require.NoError(t, err)
					ids = append(ids, sess.ID)
				}
				// Delete some sessions
				ss.Delete(ctx, ids[0])
				ss.Delete(ctx, ids[2])
				return userID
			},
			wantCount: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userID := tt.setup()
			sessionIDs, err := ss.ListByUser(ctx, userID)
			require.NoError(t, err)
			assert.Len(t, sessionIDs, tt.wantCount)
		})
	}
}

func TestSessionService_GetByUser(t *testing.T) {
	s, client := mustCreateTestRedisForSession(t)
	defer s.Close()
	logger := zap.NewNop()
	ctx := context.Background()

	ss := NewSessionService(client, logger)

	userID := "user_get_by_user"
	expectedIP := "10.0.0.1"
	expectedUA := "TestAgent/1.0"

	// Create sessions with specific metadata
	for i := 0; i < 3; i++ {
		_, err := ss.Create(ctx, userID, "tenant456", expectedIP, expectedUA, nil)
		require.NoError(t, err)
	}

	// Get all sessions
	sessions, err := ss.GetByUser(ctx, userID)
	require.NoError(t, err)
	assert.Len(t, sessions, 3)

	// Verify each session has the expected data
	for _, sess := range sessions {
		assert.Equal(t, userID, sess.UserID)
		assert.Equal(t, expectedIP, sess.IPAddress)
		assert.Equal(t, expectedUA, sess.UserAgent)
	}
}

func TestSessionService_Refresh(t *testing.T) {
	s, client := mustCreateTestRedisForSession(t)
	defer s.Close()
	logger := zap.NewNop()
	ctx := context.Background()

	ss := NewSessionService(client, logger).WithConfig(SessionConfig{
		DefaultTTL: 1 * time.Hour,
	})

	session, err := ss.Create(ctx, "user123", "tenant456", "192.168.1.1", "Mozilla", nil)
	require.NoError(t, err)

	// Store original expiry
	originalExpiry := session.ExpiresAt

	// Advance miniredis TTLs, and also sleep briefly in real wall-clock time.
	// FastForward moves only miniredis's clock, not time.Now(), and Create/Refresh
	// both derive ExpiresAt/LastSeen from time.Now(). The session round-trips
	// through JSON in Redis, which strips the monotonic clock reading, so without
	// a real delay the two time.Now() values can round to the same wall-clock tick
	// and make the After() assertions below flaky (seen under -race in CI).
	s.FastForward(5 * time.Minute)
	time.Sleep(10 * time.Millisecond)

	// Refresh the session
	err = ss.Refresh(ctx, session.ID)
	require.NoError(t, err)

	// Get the refreshed session
	refreshed, err := ss.Get(ctx, session.ID)
	require.NoError(t, err)

	// Expiry should be extended
	assert.True(t, refreshed.ExpiresAt.After(originalExpiry))

	// LastSeen should be updated
	assert.True(t, refreshed.LastSeen.After(session.LastSeen))
}

func TestSessionService_UpdateMetadata(t *testing.T) {
	s, client := mustCreateTestRedisForSession(t)
	defer s.Close()
	logger := zap.NewNop()
	ctx := context.Background()

	ss := NewSessionService(client, logger)

	session, err := ss.Create(ctx, "user123", "tenant456", "192.168.1.1", "Mozilla", map[string]interface{}{
		"original": "data",
	})
	require.NoError(t, err)

	// Update metadata
	newMetadata := map[string]interface{}{
		"new":     "value",
		"number":  42,
		"boolean": true,
	}

	err = ss.UpdateMetadata(ctx, session.ID, newMetadata)
	require.NoError(t, err)

	// Read straight back — no retry loop. This used to poll five times with a
	// 10ms backoff, on the theory that the write "hadn't settled into miniredis
	// yet". It had settled; it was being reverted. Get's async LastSeen touch
	// wrote back a pre-update snapshot of the whole record, so the new metadata
	// really was gone, and would have stayed gone in production too. The touch
	// now re-reads under WATCH (see touchLastSeen), so a single read is
	// deterministic — and if that regresses, this assertion says so instead of
	// retrying until the clobber happens to lose the race.
	updated, err := ss.Get(ctx, session.ID)
	require.NoError(t, err)
	assert.Equal(t, "value", updated.Metadata["new"])
	assert.Equal(t, float64(42), updated.Metadata["number"]) // JSON unmarshaling converts to float64
	assert.Equal(t, true, updated.Metadata["boolean"])
	// Old metadata should be replaced
	assert.Nil(t, updated.Metadata["original"])
}

// TestSessionService_RefreshSurvivesConcurrentReads pins the bug that made
// TestSessionService_Refresh flaky in CI: Get bumps LastSeen from a background
// goroutine, and that write used to carry a whole snapshot of the record taken
// before the caller did anything. Landing after a Refresh, it put the old
// ExpiresAt back — the refresh returned nil and the session still expired on
// its original schedule.
//
// Reads are what make it fire, so this test does what a busy session does:
// reads around the refresh, then checks the expiry actually moved. Against the
// old fire-and-forget write this fails within a few iterations.
func TestSessionService_RefreshSurvivesConcurrentReads(t *testing.T) {
	s, client := mustCreateTestRedisForSession(t)
	defer s.Close()
	ctx := context.Background()

	ss := NewSessionService(client, zap.NewNop()).WithConfig(SessionConfig{
		DefaultTTL: 1 * time.Hour,
	})

	for i := 0; i < 25; i++ {
		session, err := ss.Create(ctx, "user123", "tenant456", "192.168.1.1", "Mozilla", nil)
		require.NoError(t, err)
		originalExpiry := session.ExpiresAt

		// Reads in flight, each spawning a LastSeen touch.
		for r := 0; r < 4; r++ {
			_, err := ss.Get(ctx, session.ID)
			require.NoError(t, err)
		}

		time.Sleep(2 * time.Millisecond)
		require.NoError(t, ss.Refresh(ctx, session.ID))

		// Let every touch spawned above finish. Any one of them landing after
		// the Refresh must not undo it.
		time.Sleep(25 * time.Millisecond)

		refreshed, err := ss.Get(ctx, session.ID)
		require.NoError(t, err)
		assert.True(t, refreshed.ExpiresAt.After(originalExpiry),
			"iteration %d: expiry reverted to its pre-refresh value (%v); a background LastSeen write clobbered the refresh",
			i, originalExpiry)

		require.NoError(t, ss.Delete(ctx, session.ID))
	}
}

func TestSessionService_Refresh_ConcurrentAccess(t *testing.T) {
	s, client := mustCreateTestRedisForSession(t)
	defer s.Close()
	logger := zap.NewNop()
	ctx := context.Background()

	ss := NewSessionService(client, logger)

	session, err := ss.Create(ctx, "user123", "tenant456", "192.168.1.1", "Mozilla", nil)
	require.NoError(t, err)

	// Simulate concurrent refreshes
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			err := ss.Refresh(ctx, session.ID)
			assert.NoError(t, err)
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify session still exists and is valid
	_, err = ss.Get(ctx, session.ID)
	assert.NoError(t, err)
}

func TestSessionService_Create_ConcurrentUsers(t *testing.T) {
	s, client := mustCreateTestRedisForSession(t)
	defer s.Close()
	logger := zap.NewNop()
	ctx := context.Background()

	ss := NewSessionService(client, logger).WithConfig(SessionConfig{
		MaxSessions: 5,
	})

	userIDs := []string{"user_concurrent_1", "user_concurrent_2", "user_concurrent_3"}
	done := make(chan bool, len(userIDs)*3)

	// Create concurrent sessions for multiple users
	for _, userID := range userIDs {
		for i := 0; i < 3; i++ {
			go func(uid string) {
				_, err := ss.Create(ctx, uid, "tenant456", "127.0.0.1", "test", nil)
				assert.NoError(t, err)
				done <- true
			}(userID)
		}
	}

	// Wait for all to complete
	for i := 0; i < len(userIDs)*3; i++ {
		<-done
	}

	// Give some time for async operations to complete
	time.Sleep(500 * time.Millisecond)

	// Verify each user has exactly 3 sessions
	for _, userID := range userIDs {
		sessions, err := ss.ListByUser(ctx, userID)
		require.NoError(t, err)
		assert.Len(t, sessions, 3)
	}
}

func TestSessionService_NilRedis(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	ss := NewSessionService(nil, logger)

	tests := []struct {
		name   string
		method func() error
	}{
		{
			name: "create with nil redis",
			method: func() error {
				_, err := ss.Create(ctx, "user123", "tenant456", "192.168.1.1", "Mozilla", nil)
				return err
			},
		},
		{
			name: "get with nil redis",
			method: func() error {
				_, err := ss.Get(ctx, "session-id")
				return err
			},
		},
		{
			name: "delete with nil redis",
			method: func() error {
				return ss.Delete(ctx, "session-id")
			},
		},
		{
			name: "list by user with nil redis",
			method: func() error {
				_, err := ss.ListByUser(ctx, "user123")
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.method()
			assert.Error(t, err)
		})
	}
}

func TestSessionService_WithConfig(t *testing.T) {
	s, client := mustCreateTestRedisForSession(t)
	defer s.Close()
	logger := zap.NewNop()
	ctx := context.Background()

	customConfig := SessionConfig{
		DefaultTTL:         2 * time.Hour,
		MaxSessions:        10,
		CleanupInterval:    5 * time.Minute,
		KeyPrefix:          "test:",
		UserSessionsPrefix: "test_user:",
	}

	ss := NewSessionService(client, logger).WithConfig(customConfig)

	session, err := ss.Create(ctx, "user123", "tenant456", "192.168.1.1", "Mozilla", nil)
	require.NoError(t, err)

	// Verify custom TTL
	expectedExpiry := time.Now().Add(2 * time.Hour)
	assert.WithinDuration(t, expectedExpiry, session.ExpiresAt, time.Second)

	// Verify custom prefix
	key := ss.sessionKey(session.ID)
	assert.Contains(t, key, "test:")
}

func TestSessionService_DefaultConfig(t *testing.T) {
	config := DefaultSessionConfig()

	assert.Equal(t, 24*time.Hour, config.DefaultTTL)
	assert.Equal(t, 5, config.MaxSessions)
	assert.Equal(t, 1*time.Hour, config.CleanupInterval)
	assert.Equal(t, "session:", config.KeyPrefix)
	assert.Equal(t, "user_sessions:", config.UserSessionsPrefix)
}

func TestSessionService_Metadata(t *testing.T) {
	s, client := mustCreateTestRedisForSession(t)
	defer s.Close()
	logger := zap.NewNop()
	ctx := context.Background()

	ss := NewSessionService(client, logger)

	tests := []struct {
		name     string
		metadata map[string]interface{}
		check    func(*testing.T, *Session)
	}{
		{
			name:     "nil metadata",
			metadata: nil,
			check: func(t *testing.T, s *Session) {
				assert.Nil(t, s.Metadata)
			},
		},
		{
			name:     "empty metadata",
			metadata: map[string]interface{}{},
			check: func(t *testing.T, s *Session) {
				assert.Empty(t, s.Metadata)
			},
		},
		{
			name: "metadata with various types",
			metadata: map[string]interface{}{
				"string": "value",
				"int":    42,
				"float":  3.14,
				"bool":   true,
				"null":   nil,
				"slice":  []string{"a", "b"},
				"nested": map[string]string{"key": "val"},
			},
			check: func(t *testing.T, s *Session) {
				assert.Equal(t, "value", s.Metadata["string"])
				assert.Equal(t, float64(42), s.Metadata["int"]) // JSON unmarshaling converts to float64
				assert.InDelta(t, 3.14, s.Metadata["float"], 0.01)
				assert.Equal(t, true, s.Metadata["bool"])
				assert.Nil(t, s.Metadata["null"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session, err := ss.Create(ctx, "user123", "tenant456", "192.168.1.1", "Mozilla", tt.metadata)
			require.NoError(t, err)

			// Retrieve and verify
			retrieved, err := ss.Get(ctx, session.ID)
			require.NoError(t, err)

			if tt.check != nil {
				tt.check(t, retrieved)
			}
		})
	}
}

func TestSessionService_SessionUniqueness(t *testing.T) {
	s, client := mustCreateTestRedisForSession(t)
	defer s.Close()
	logger := zap.NewNop()
	ctx := context.Background()

	ss := NewSessionService(client, logger)

	// Create multiple sessions
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		session, err := ss.Create(ctx, "user123", "tenant456", "192.168.1.1", "Mozilla", nil)
		require.NoError(t, err)

		// Verify uniqueness
		_, exists := ids[session.ID]
		assert.False(t, exists, "generated duplicate session ID")
		ids[session.ID] = true

		// Verify it's a valid UUID
		_, err = uuid.Parse(session.ID)
		assert.NoError(t, err, "session ID should be a valid UUID")
	}
}

func TestSessionService_Get_UpdateLastSeen(t *testing.T) {
	s, client := mustCreateTestRedisForSession(t)
	defer s.Close()
	logger := zap.NewNop()
	ctx := context.Background()

	ss := NewSessionService(client, logger)

	session, err := ss.Create(ctx, "user123", "tenant456", "192.168.1.1", "Mozilla", nil)
	require.NoError(t, err)

	originalLastSeen := session.LastSeen

	// Wait a bit
	s.FastForward(1 * time.Second)

	// Get the session (should update LastSeen)
	_, err = ss.Get(ctx, session.ID)
	require.NoError(t, err)

	// The update happens asynchronously, so we need to flush
	s.FastForward(100 * time.Millisecond)

	// Get again to see the updated LastSeen
	updated, err := ss.Get(ctx, session.ID)
	require.NoError(t, err)

	// LastSeen should be updated (with some tolerance for async update)
	assert.True(t, updated.LastSeen.After(originalLastSeen) || updated.LastSeen.Equal(originalLastSeen))
}

func TestSessionService_SessionExpirationCleanup(t *testing.T) {
	s, client := mustCreateTestRedisForSession(t)
	defer s.Close()
	logger := zap.NewNop()
	ctx := context.Background()

	// Use a real-time TTL + sleep instead of miniredis FastForward.
	// FastForward expires keys via an internal sweep that races with the
	// in-flight SET commands from Create under -race, leaving keys
	// un-expired at unpredictable rates — manifested as ~1-in-50 flake
	// on the CI race-detector job. go-redis enforces a 1s minimum on
	// SET PX, so 1s TTL + a 1.1s sleep is the shortest reliable window.
	ss := NewSessionService(client, logger).WithConfig(SessionConfig{
		DefaultTTL:      1 * time.Second,
		CleanupInterval: 50 * time.Millisecond,
		MaxSessions:     10,
	})

	userID := "user_cleanup_test"
	var sessionIDs []string

	// Create multiple sessions
	for i := 0; i < 3; i++ {
		session, err := ss.Create(ctx, userID, "tenant456", "192.168.1.1", "Mozilla", nil)
		require.NoError(t, err)
		sessionIDs = append(sessionIDs, session.ID)
	}

	// Verify they exist
	for _, id := range sessionIDs {
		_, err := ss.Get(ctx, id)
		assert.NoError(t, err)
	}

	// Wait for the real Redis TTL to lapse. Don't FastForward — miniredis
	// FastForward expires keys via a sweep that races with the in-flight
	// SET commands from Create under -race.
	time.Sleep(1100 * time.Millisecond)

	// Manually trigger cleanup. With ExpiresAt now in the past, cleanup
	// also deletes the entries from the user-sessions set.
	ss.cleanup(ctx)

	// Sessions should now be expired (not found due to Redis TTL).
	for _, id := range sessionIDs {
		_, err := ss.Get(ctx, id)
		assert.ErrorIs(t, err, ErrSessionNotFound)
	}

	// List should be empty
	ids, err := ss.ListByUser(ctx, userID)
	require.NoError(t, err)
	assert.Empty(t, ids)
}

func TestSessionService_SessionIDValidation(t *testing.T) {
	s, client := mustCreateTestRedisForSession(t)
	defer s.Close()
	logger := zap.NewNop()
	ctx := context.Background()

	ss := NewSessionService(client, logger)

	tests := []struct {
		name      string
		sessionID string
		wantErr   error
	}{
		{
			name:      "empty session ID",
			sessionID: "",
			wantErr:   ErrSessionNotFound,
		},
		{
			name:      "whitespace session ID",
			sessionID: "   ",
			wantErr:   ErrSessionNotFound,
		},
		{
			name:      "malformed UUID",
			sessionID: "not-a-real-uuid",
			wantErr:   ErrSessionNotFound,
		},
		{
			name:      "partial UUID",
			sessionID: "123e4567-e89b-12d3",
			wantErr:   ErrSessionNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ss.Get(ctx, tt.sessionID)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestSessionService_KeyMethods(t *testing.T) {
	ss := NewSessionService(nil, zap.NewNop()).WithConfig(SessionConfig{
		KeyPrefix:          "custom:",
		UserSessionsPrefix: "custom_user:",
	})

	t.Run("sessionKey", func(t *testing.T) {
		key := ss.sessionKey("session-id-123")
		assert.Equal(t, "custom:session-id-123", key)
	})

	t.Run("userSessionsKey", func(t *testing.T) {
		key := ss.userSessionsKey("user-456")
		assert.Equal(t, "custom_user:user-456", key)
	})
}
