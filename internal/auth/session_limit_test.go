package auth

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// The max-concurrent-session limit used to be enforced by counting first and
// creating afterwards: SCARD, compare, SADD. Two logins arriving together both
// read a count below the limit, both passed, and both created a session — so a
// cap of N admitted more than N, and the window widens with exactly the
// parallelism that credential-stuffing and replayed-credential traffic
// produces.
//
// These tests drive Create concurrently, which is the only way the defect
// shows. A sequential test passes against the broken code.

func TestSessionLimitHoldsUnderConcurrentLogins(t *testing.T) {
	const maxSessions = 3

	for _, racers := range []int{4, 12} {
		t.Run(fmt.Sprintf("%d simultaneous logins", racers), func(t *testing.T) {
			s, client := mustCreateTestRedisForSession(t)
			defer s.Close()

			ss := NewSessionService(client, zap.NewNop()).WithConfig(SessionConfig{
				DefaultTTL:  1 * time.Hour,
				MaxSessions: maxSessions,
			})

			var wg sync.WaitGroup
			wg.Add(racers)
			for i := 0; i < racers; i++ {
				go func() {
					defer wg.Done()
					// Errors are expected once the cap binds; what matters is
					// the state left behind, checked below.
					_, _ = ss.Create(context.Background(), "user123", "tenant", "10.0.0.1", "Mozilla", nil)
				}()
			}
			wg.Wait()

			ids, err := ss.ListByUser(context.Background(), "user123")
			require.NoError(t, err)
			if len(ids) > maxSessions {
				t.Errorf("%d sessions exist with a limit of %d; the cap did not hold under %d concurrent logins",
					len(ids), maxSessions, racers)
			}

			// Every id still in the set must resolve to a real session. A
			// rolled-back creation that left its id behind would inflate the
			// count against future logins without being usable.
			for _, id := range ids {
				if _, err := ss.Get(context.Background(), id); err != nil {
					t.Errorf("session %s is in the user's set but not retrievable: %v", id, err)
				}
			}
		})
	}
}

func TestSessionLimitEvictsOldestSequentially(t *testing.T) {
	// The pre-existing policy: reaching the cap displaces the stalest session
	// rather than refusing the new login. Fixing the race must not quietly
	// change that into a rejection.
	s, client := mustCreateTestRedisForSession(t)
	defer s.Close()

	ss := NewSessionService(client, zap.NewNop()).WithConfig(SessionConfig{
		DefaultTTL:  1 * time.Hour,
		MaxSessions: 2,
	})
	ctx := context.Background()

	first, err := ss.Create(ctx, "user123", "tenant", "10.0.0.1", "Mozilla", nil)
	require.NoError(t, err)
	time.Sleep(5 * time.Millisecond)
	second, err := ss.Create(ctx, "user123", "tenant", "10.0.0.2", "Mozilla", nil)
	require.NoError(t, err)
	time.Sleep(5 * time.Millisecond)

	third, err := ss.Create(ctx, "user123", "tenant", "10.0.0.3", "Mozilla", nil)
	require.NoError(t, err, "reaching the limit should evict, not refuse")

	ids, err := ss.ListByUser(ctx, "user123")
	require.NoError(t, err)
	if len(ids) != 2 {
		t.Fatalf("got %d sessions, want 2", len(ids))
	}

	if _, err := ss.Get(ctx, first.ID); err == nil {
		t.Error("the oldest session survived; a newer one must have been evicted instead")
	}
	for _, keep := range []string{second.ID, third.ID} {
		if _, err := ss.Get(ctx, keep); err != nil {
			t.Errorf("session %s should have been kept: %v", keep, err)
		}
	}
}

func TestSessionLimitOfZeroAdmitsNothing(t *testing.T) {
	// WithConfig ignores non-positive MaxSessions, so this exercises the
	// service default rather than zero — the point is that the guard in
	// enforceSessionLimit cannot be reached with a nonsensical cap and then
	// silently admit a session.
	s, client := mustCreateTestRedisForSession(t)
	defer s.Close()

	ss := NewSessionService(client, zap.NewNop())
	ss.config.MaxSessions = 0

	if _, err := ss.Create(context.Background(), "user123", "tenant", "10.0.0.1", "Mozilla", nil); err == nil {
		t.Error("a session was created with a limit of 0")
	}

	ids, err := ss.ListByUser(context.Background(), "user123")
	require.NoError(t, err)
	if len(ids) != 0 {
		t.Errorf("%d session ids left behind after a rejected create", len(ids))
	}
}
