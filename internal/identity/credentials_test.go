package identity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"testing"

	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// Credential storage and counting.
//
// Three defects, all of the same shape: the code looked correct read top to
// bottom, and was wrong the moment two requests arrived together or a second
// call site existed.
//
//   - Two password policies, so the same password was accepted or rejected
//     depending on which handler received it.
//   - Backup codes hashed with unsalted SHA-256, and consumed with a SELECT
//     followed by a separate UPDATE, so one code could be spent twice.
//   - The failed-login counter read, incremented in Go, and wrote back, so
//     simultaneous attempts collapsed into one and lockout arrived late.

func TestPasswordPolicyIsOneImplementation(t *testing.T) {
	s := &Service{logger: zap.NewNop()}

	// The exact disagreement that existed: no special character. The old
	// ValidatePasswordPolicy accepted this; ValidatePasswordPolicyChecks
	// rejected it. Whichever answer is right, both doors must give it.
	const noSpecial = "Passw0rdd"

	err := s.ValidatePasswordPolicy(noSpecial)
	violations := s.ValidatePasswordPolicyChecks(noSpecial)

	if (err == nil) != (len(violations) == 0) {
		t.Fatalf("the two entry points disagree: ValidatePasswordPolicy=%v, checks=%v", err, violations)
	}
	if err == nil {
		t.Error("expected the special-character requirement to be enforced on both paths")
	}

	t.Run("a compliant password passes both", func(t *testing.T) {
		const good = "Passw0rd!"
		if err := s.ValidatePasswordPolicy(good); err != nil {
			t.Errorf("ValidatePasswordPolicy(%q) = %v", good, err)
		}
		if v := s.ValidatePasswordPolicyChecks(good); len(v) != 0 {
			t.Errorf("checks(%q) = %v", good, v)
		}
	})

	t.Run("the error names every violation", func(t *testing.T) {
		// A caller that only sees "password too short" fixes the length and
		// gets rejected again for a reason it was never told.
		err := s.ValidatePasswordPolicy("abc")
		if err == nil {
			t.Fatal("expected an error")
		}
		for _, want := range []string{"8 characters", "uppercase", "digit", "special"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not mention %q", err, want)
			}
		}
	})
}

func TestBcryptCostIsAboveTheOldDefault(t *testing.T) {
	// bcrypt.DefaultCost is 10; the codebase had one site on 12 and the rest on
	// 10. Unifying downward would have silently weakened that one site.
	if bcryptCost < bcrypt.DefaultCost {
		t.Fatalf("bcryptCost = %d, weaker than bcrypt.DefaultCost = %d", bcryptCost, bcrypt.DefaultCost)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte("correct horse"), bcryptCost)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	got, err := bcrypt.Cost(hash)
	if err != nil {
		t.Fatalf("cost: %v", err)
	}
	if got != bcryptCost {
		t.Errorf("hash carries cost %d, want %d", got, bcryptCost)
	}
}

func TestBackupCodeMatches(t *testing.T) {
	const code = "ABCD2345"

	bcryptHash, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	sum := sha256.Sum256([]byte(code))
	legacyHex := hex.EncodeToString(sum[:])

	t.Run("bcrypt hash", func(t *testing.T) {
		if !backupCodeMatches(string(bcryptHash), code, legacyHex) {
			t.Error("a bcrypt-hashed code did not match")
		}
		if backupCodeMatches(string(bcryptHash), "WRONG123", legacyHex) {
			t.Error("a wrong code matched a bcrypt hash")
		}
	})

	t.Run("legacy SHA-256 rows still verify", func(t *testing.T) {
		// Codes issued before the change must keep working; the alternative is
		// locking users out of their second factor to fix how it is stored.
		if !backupCodeMatches(legacyHex, code, legacyHex) {
			t.Error("a legacy SHA-256 code did not match")
		}
		wrongSum := sha256.Sum256([]byte("WRONG123"))
		if backupCodeMatches(legacyHex, "WRONG123", hex.EncodeToString(wrongSum[:])) {
			t.Error("a wrong code matched a legacy hash")
		}
	})

	t.Run("a legacy hash is not treated as bcrypt", func(t *testing.T) {
		// bcrypt.CompareHashAndPassword on a non-bcrypt string returns an
		// error, which would silently reject every legacy code.
		if strings.HasPrefix(legacyHex, "$2") {
			t.Skip("legacy hex happened to start with $2")
		}
		if !backupCodeMatches(legacyHex, code, legacyHex) {
			t.Error("legacy hash was routed through the bcrypt comparison")
		}
	})
}

// ---- DB-backed ----

const credentialSchema = `
CREATE TABLE users (
    id            UUID PRIMARY KEY,
    username      VARCHAR(255) NOT NULL,
    email         VARCHAR(255) NOT NULL DEFAULT '',
    enabled       BOOLEAN NOT NULL DEFAULT TRUE,
    failed_login_count   INTEGER NOT NULL DEFAULT 0,
    last_failed_login_at TIMESTAMPTZ,
    locked_until         TIMESTAMPTZ,
    org_id        UUID NOT NULL
);
CREATE TABLE mfa_backup_codes (
    id         UUID PRIMARY KEY,
    user_id    UUID NOT NULL,
    code_hash  VARCHAR(255) NOT NULL,
    used       BOOLEAN DEFAULT false,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    org_id     UUID NOT NULL
);
CREATE TABLE system_settings (
    key   VARCHAR(255) PRIMARY KEY,
    value JSONB
);`

const (
	credOrg  = "22222222-3333-4444-5555-666666666666"
	credUser = "33333333-3333-4444-5555-666666666666"
)

func newCredentialService(t *testing.T) (*Service, *database.PostgresDB, context.Context) {
	t.Helper()

	db, cleanup := setupTestDB(t)
	if db == nil {
		t.SkipNow()
	}
	t.Cleanup(cleanup)

	ctx := orgctx.With(context.Background(), orgctx.Org{ID: credOrg})
	if _, err := db.Pool.Exec(ctx, credentialSchema); err != nil {
		t.Fatalf("schema: %v", err)
	}
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO users (id, username, org_id) VALUES ($1, 'alice', $2)`, credUser, credOrg); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	return &Service{db: db, cfg: &config.Config{}, logger: zap.NewNop()}, db, ctx
}

func TestBackupCodesAreStoredHashedAndSpentOnce(t *testing.T) {
	s, db, ctx := newCredentialService(t)

	codes, err := s.GenerateBackupCodes(ctx, credUser, 5)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(codes) != 5 {
		t.Fatalf("got %d codes, want 5", len(codes))
	}

	t.Run("stored as bcrypt, never as the code itself", func(t *testing.T) {
		rows, err := db.Pool.Query(ctx,
			`SELECT code_hash FROM mfa_backup_codes WHERE user_id = $1 AND org_id = $2`, credUser, credOrg)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		defer rows.Close()

		n := 0
		for rows.Next() {
			var h string
			if err := rows.Scan(&h); err != nil {
				t.Fatalf("scan: %v", err)
			}
			n++
			if !strings.HasPrefix(h, "$2") {
				t.Errorf("code_hash %q is not bcrypt", h)
			}
			for _, c := range codes {
				if h == c {
					t.Fatal("a backup code was stored in the clear")
				}
				sum := sha256.Sum256([]byte(c))
				if h == hex.EncodeToString(sum[:]) {
					t.Error("a backup code is still stored as unsalted SHA-256")
				}
			}
		}
		if n != 5 {
			t.Errorf("stored %d rows, want 5", n)
		}
	})

	t.Run("a valid code is accepted", func(t *testing.T) {
		ok, err := s.ValidateBackupCode(ctx, credUser, codes[0])
		if err != nil {
			t.Fatalf("validate: %v", err)
		}
		if !ok {
			t.Fatal("a freshly issued backup code was rejected")
		}
	})

	t.Run("the same code cannot be reused", func(t *testing.T) {
		ok, err := s.ValidateBackupCode(ctx, credUser, codes[0])
		if err != nil {
			t.Fatalf("validate: %v", err)
		}
		if ok {
			t.Error("a spent backup code was accepted a second time")
		}
	})

	t.Run("a wrong code is rejected", func(t *testing.T) {
		ok, err := s.ValidateBackupCode(ctx, credUser, "ZZZZ7777")
		if err != nil {
			t.Fatalf("validate: %v", err)
		}
		if ok {
			t.Error("an unissued code was accepted")
		}
	})

	t.Run("lower-case entry of the same code works", func(t *testing.T) {
		ok, err := s.ValidateBackupCode(ctx, credUser, strings.ToLower(codes[1]))
		if err != nil {
			t.Fatalf("validate: %v", err)
		}
		if !ok {
			t.Error("a lower-case paste of a valid code was rejected")
		}
	})

	t.Run("concurrent presentations of one code spend it once", func(t *testing.T) {
		// The defect: SELECT-then-UPDATE let both requests see the row unused.
		// A backup code is single-use; accepting it twice hands out two MFA
		// passes for one credential.
		const racers = 8
		var wg sync.WaitGroup
		accepted := make([]bool, racers)
		wg.Add(racers)
		for i := 0; i < racers; i++ {
			go func(i int) {
				defer wg.Done()
				ok, err := s.ValidateBackupCode(ctx, credUser, codes[2])
				if err == nil && ok {
					accepted[i] = true
				}
			}(i)
		}
		wg.Wait()

		wins := 0
		for _, a := range accepted {
			if a {
				wins++
			}
		}
		if wins != 1 {
			t.Errorf("%d of %d concurrent uses were accepted, want exactly 1", wins, racers)
		}
	})
}

func TestLegacyBackupCodeStillVerifies(t *testing.T) {
	s, db, ctx := newCredentialService(t)

	// A row exactly as the previous implementation wrote it.
	const legacy = "LEGACY42"
	sum := sha256.Sum256([]byte(legacy))
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO mfa_backup_codes (id, user_id, code_hash, org_id)
		 VALUES ('44444444-3333-4444-5555-666666666666', $1, $2, $3)`,
		credUser, hex.EncodeToString(sum[:]), credOrg); err != nil {
		t.Fatalf("seed legacy code: %v", err)
	}

	ok, err := s.ValidateBackupCode(ctx, credUser, legacy)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if !ok {
		t.Fatal("a code issued before the bcrypt change no longer works — users would be locked out of their second factor")
	}

	// And it is spent, like any other.
	ok, err = s.ValidateBackupCode(ctx, credUser, legacy)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if ok {
		t.Error("a legacy code was accepted twice")
	}
}

func TestFailedLoginCounterDoesNotLoseConcurrentIncrements(t *testing.T) {
	s, db, ctx := newCredentialService(t)

	const attempts = 12
	var wg sync.WaitGroup
	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func() {
			defer wg.Done()
			_ = s.RecordFailedLogin(ctx, "alice")
		}()
	}
	wg.Wait()

	var count int
	var lockedUntil *string
	if err := db.Pool.QueryRow(ctx,
		`SELECT failed_login_count, locked_until::text FROM users WHERE username = 'alice' AND org_id = $1`,
		credOrg).Scan(&count, &lockedUntil); err != nil {
		t.Fatalf("read: %v", err)
	}

	// The read-modify-write version lost increments here: parallel attempts all
	// read the same value and wrote the same value back, so the attacker got
	// more tries than the threshold allows.
	if count != attempts {
		t.Errorf("failed_login_count = %d after %d concurrent attempts, want %d", count, attempts, attempts)
	}
	if lockedUntil == nil {
		t.Error("account not locked after exceeding the failure threshold")
	}
}

func TestFailedLoginLocksAtTheThreshold(t *testing.T) {
	s, db, ctx := newCredentialService(t)

	// Default threshold is 5. Four attempts must not lock.
	for i := 0; i < 4; i++ {
		if err := s.RecordFailedLogin(ctx, "alice"); err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	var lockedUntil *string
	if err := db.Pool.QueryRow(ctx,
		`SELECT locked_until::text FROM users WHERE username = 'alice' AND org_id = $1`, credOrg).Scan(&lockedUntil); err != nil {
		t.Fatalf("read: %v", err)
	}
	if lockedUntil != nil {
		t.Errorf("locked after 4 attempts with a threshold of 5")
	}

	if err := s.RecordFailedLogin(ctx, "alice"); err != nil {
		t.Fatalf("fifth attempt: %v", err)
	}
	if err := db.Pool.QueryRow(ctx,
		`SELECT locked_until::text FROM users WHERE username = 'alice' AND org_id = $1`, credOrg).Scan(&lockedUntil); err != nil {
		t.Fatalf("read: %v", err)
	}
	if lockedUntil == nil {
		t.Error("not locked after reaching the threshold")
	}

	t.Run("clearing resets the counter and the lock", func(t *testing.T) {
		if err := s.ClearFailedLogins(ctx, "alice"); err != nil {
			t.Fatalf("clear: %v", err)
		}
		var count int
		if err := db.Pool.QueryRow(ctx,
			`SELECT failed_login_count, locked_until::text FROM users WHERE username = 'alice' AND org_id = $1`,
			credOrg).Scan(&count, &lockedUntil); err != nil {
			t.Fatalf("read: %v", err)
		}
		if count != 0 || lockedUntil != nil {
			t.Errorf("after clear: count=%d locked_until=%v, want 0 and nil", count, lockedUntil)
		}
	})
}

func TestFailedLoginRespectsConfiguredThreshold(t *testing.T) {
	s, db, ctx := newCredentialService(t)

	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO system_settings (key, value) VALUES ('failed_login_lockout_threshold', '3')`); err != nil {
		t.Fatalf("seed setting: %v", err)
	}

	for i := 0; i < 2; i++ {
		if err := s.RecordFailedLogin(ctx, "alice"); err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	var lockedUntil *string
	if err := db.Pool.QueryRow(ctx,
		`SELECT locked_until::text FROM users WHERE username = 'alice' AND org_id = $1`, credOrg).Scan(&lockedUntil); err != nil {
		t.Fatalf("read: %v", err)
	}
	if lockedUntil != nil {
		t.Error("locked at 2 attempts with a configured threshold of 3")
	}

	if err := s.RecordFailedLogin(ctx, "alice"); err != nil {
		t.Fatalf("third attempt: %v", err)
	}
	if err := db.Pool.QueryRow(ctx,
		`SELECT locked_until::text FROM users WHERE username = 'alice' AND org_id = $1`, credOrg).Scan(&lockedUntil); err != nil {
		t.Fatalf("read: %v", err)
	}
	if lockedUntil == nil {
		t.Error("configured threshold of 3 was not applied")
	}
}
