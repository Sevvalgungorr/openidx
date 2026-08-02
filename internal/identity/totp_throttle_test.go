package identity

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// TOTP verification had no attempt limit at all.
//
// A TOTP code is six digits and validateTOTPWithSkew accepts a ±1 step window,
// so roughly 3 of 10^6 values are valid at any instant. Against an endpoint
// that never says no, an attacker expects a hit within the low hundreds of
// thousands of requests — minutes of traffic. The second factor is only a
// factor if guessing it is expensive.

const totpSchema = `
CREATE TABLE mfa_totp (
    id              UUID PRIMARY KEY,
    user_id         UUID NOT NULL,
    secret          VARCHAR(255) NOT NULL,
    enabled         BOOLEAN DEFAULT false,
    enrolled_at     TIMESTAMPTZ,
    last_used_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    last_failed_at  TIMESTAMPTZ,
    locked_until    TIMESTAMPTZ,
    org_id          UUID NOT NULL
);`

const (
	totpOrg  = "77777777-8888-9999-aaaa-bbbbbbbbbbbb"
	totpUser = "88888888-8888-9999-aaaa-bbbbbbbbbbbb"
)

func newTOTPService(t *testing.T) (*Service, *database.PostgresDB, context.Context, string) {
	t.Helper()

	db, cleanup := setupTestDB(t)
	if db == nil {
		t.SkipNow()
	}
	t.Cleanup(cleanup)

	ctx := orgctx.With(context.Background(), orgctx.Org{ID: totpOrg})
	if _, err := db.Pool.Exec(ctx, totpSchema); err != nil {
		t.Fatalf("schema: %v", err)
	}

	key, err := totp.Generate(totp.GenerateOpts{Issuer: "openidx", AccountName: "alice"})
	if err != nil {
		t.Fatalf("generate totp key: %v", err)
	}
	secret := key.Secret()

	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO mfa_totp (id, user_id, secret, enabled, org_id)
		VALUES ('99999999-8888-9999-aaaa-bbbbbbbbbbbb', $1, $2, true, $3)`,
		totpUser, secret, totpOrg); err != nil {
		t.Fatalf("seed totp: %v", err)
	}

	s := &Service{db: db, cfg: &config.Config{}, logger: zap.NewNop()}
	return s, db, ctx, secret
}

func currentTOTP(t *testing.T, secret string) string {
	t.Helper()
	code, err := totp.GenerateCode(secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	return code
}

func totpState(t *testing.T, db *database.PostgresDB, ctx context.Context) (attempts int, lockedUntil *time.Time) {
	t.Helper()
	if err := db.Pool.QueryRow(ctx,
		`SELECT failed_attempts, locked_until FROM mfa_totp WHERE user_id = $1 AND org_id = $2`,
		totpUser, totpOrg).Scan(&attempts, &lockedUntil); err != nil {
		t.Fatalf("read totp state: %v", err)
	}
	return attempts, lockedUntil
}

func TestVerifyTOTPLocksAfterRepeatedFailures(t *testing.T) {
	s, db, ctx, secret := newTOTPService(t)

	// One short of the threshold: still open for business.
	for i := 0; i < totpMaxAttempts-1; i++ {
		ok, err := s.VerifyTOTP(ctx, totpUser, "000000")
		if err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
		if ok {
			t.Fatalf("attempt %d: a bogus code was accepted", i)
		}
	}
	attempts, locked := totpState(t, db, ctx)
	if attempts != totpMaxAttempts-1 {
		t.Errorf("failed_attempts = %d, want %d", attempts, totpMaxAttempts-1)
	}
	if locked != nil {
		t.Errorf("locked at %d attempts with a threshold of %d", attempts, totpMaxAttempts)
	}

	t.Run("a correct code still works below the threshold", func(t *testing.T) {
		ok, err := s.VerifyTOTP(ctx, totpUser, currentTOTP(t, secret))
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if !ok {
			t.Fatal("a valid code was rejected below the lockout threshold")
		}
		// Success must clear the counter, or a user who mistypes four times
		// over a month eventually locks themselves out on a correct login.
		attempts, locked := totpState(t, db, ctx)
		if attempts != 0 || locked != nil {
			t.Errorf("after success: attempts=%d locked=%v, want 0 and nil", attempts, locked)
		}
	})

	t.Run("the threshold locks the factor", func(t *testing.T) {
		for i := 0; i < totpMaxAttempts; i++ {
			if _, err := s.VerifyTOTP(ctx, totpUser, "000000"); err != nil {
				t.Fatalf("attempt %d: %v", i, err)
			}
		}
		attempts, locked := totpState(t, db, ctx)
		if locked == nil {
			t.Fatalf("not locked after %d failures", attempts)
		}
		if !locked.After(time.Now()) {
			t.Errorf("locked_until %v is not in the future", locked)
		}
	})

	t.Run("a correct code is refused while locked out", func(t *testing.T) {
		// This is the property that makes the lock worth anything. A lockout
		// that still accepts the right code only slows an attacker down until
		// they guess it.
		ok, err := s.VerifyTOTP(ctx, totpUser, currentTOTP(t, secret))
		if ok {
			t.Fatal("a locked-out factor accepted a code")
		}
		if !errors.Is(err, ErrTOTPLockedOut) {
			t.Errorf("err = %v, want ErrTOTPLockedOut so the caller can say 'wait' rather than 'wrong code'", err)
		}
	})

	t.Run("the lock lifts when it expires", func(t *testing.T) {
		if _, err := db.Pool.Exec(ctx,
			`UPDATE mfa_totp SET locked_until = NOW() - INTERVAL '1 minute' WHERE user_id = $1 AND org_id = $2`,
			totpUser, totpOrg); err != nil {
			t.Fatalf("expire lock: %v", err)
		}
		ok, err := s.VerifyTOTP(ctx, totpUser, currentTOTP(t, secret))
		if err != nil {
			t.Fatalf("verify after lock expiry: %v", err)
		}
		if !ok {
			t.Error("a valid code was refused after the lockout expired")
		}
	})
}

func TestVerifyTOTPCounterDoesNotLoseConcurrentFailures(t *testing.T) {
	// The same lost-update shape as the failed-login counter: an attacker's
	// guesses arrive in parallel, so a counter that reads-modifies-writes in Go
	// undercounts exactly when it matters. Counting in SQL is what makes the
	// cap bind.
	//
	// The invariant is "no increment is lost", which is NOT the same as "every
	// call increments". Once the threshold is crossed the factor locks, and
	// later arrivals are refused before the code is examined — by design, they
	// must not count. So the assertion is against the number of calls that
	// actually got past the lockout check, which is whatever the scheduler
	// happened to allow. Asserting a fixed 12 here would be asserting that the
	// lockout does nothing.
	s, db, ctx, _ := newTOTPService(t)

	const attempts = 12
	var (
		mu        sync.Mutex
		notLocked int
	)
	var wg sync.WaitGroup
	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func() {
			defer wg.Done()
			_, err := s.VerifyTOTP(ctx, totpUser, "000000")
			if errors.Is(err, ErrTOTPLockedOut) {
				return // refused before evaluation; must not be counted
			}
			mu.Lock()
			notLocked++
			mu.Unlock()
		}()
	}
	wg.Wait()

	counted, locked := totpState(t, db, ctx)

	// Every guess that was actually evaluated must be recorded. A
	// read-modify-write counter collapses simultaneous ones and lands short.
	if counted != notLocked {
		t.Errorf("failed_attempts = %d but %d guesses were evaluated; %d increments were lost",
			counted, notLocked, notLocked-counted)
	}
	// And the guesses have to have been enough to trip the lock, otherwise this
	// test would pass on an implementation that never locks at all.
	if counted < totpMaxAttempts {
		t.Errorf("only %d of %d guesses were evaluated, too few to exercise the threshold", counted, attempts)
	}
	if locked == nil {
		t.Error("factor not locked after concurrent guesses past the threshold")
	}
}

func TestVerifyTOTPRejectsWhenNotEnabled(t *testing.T) {
	s, db, ctx, secret := newTOTPService(t)

	if _, err := db.Pool.Exec(ctx,
		`UPDATE mfa_totp SET enabled = false WHERE user_id = $1 AND org_id = $2`, totpUser, totpOrg); err != nil {
		t.Fatalf("disable: %v", err)
	}

	ok, err := s.VerifyTOTP(ctx, totpUser, currentTOTP(t, secret))
	if ok {
		t.Error("a disabled factor verified a code")
	}
	if err == nil {
		t.Error("expected an error for a disabled factor")
	}
}
