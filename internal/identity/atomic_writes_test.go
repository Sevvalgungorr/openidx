package identity

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/openidx/openidx/internal/common/pwhash"
)

// Multi-statement writes that were not transactions.
//
// Each of these read fine top to bottom and was wrong the moment a second
// request arrived at the same time, or a statement in the middle failed:
//
//   - Password reset checked used_at in Go, updated the password, then marked
//     the token used in a separate statement whose error was discarded. Two
//     requests with one token both passed the check; a failed mark left a spent
//     token usable.
//   - TOTP enrollment deleted the old factor and inserted the new one as two
//     statements, so a failure between them left the user with no second factor.
//   - Backup-code generation inserted N codes one statement at a time and
//     returned all N plaintexts to be shown once, so a failure partway through
//     handed the user a list where some codes work and some do not.

// failAfterNInserts installs a trigger that raises once a table has more than n
// rows. It is fault injection at the database, which is the only place these
// failures can be provoked without contorting the code under test.
func failAfterNInserts(t *testing.T, s *Service, ctx context.Context, table string, n int) {
	t.Helper()
	_, err := s.db.Pool.Exec(ctx, `
		CREATE OR REPLACE FUNCTION fail_after_n() RETURNS TRIGGER AS $$
		BEGIN
			IF (SELECT COUNT(*) FROM `+table+`) > `+itoa(n)+` THEN
				RAISE EXCEPTION 'injected failure after `+itoa(n)+` rows';
			END IF;
			RETURN NEW;
		END;
		$$ LANGUAGE plpgsql;
		CREATE TRIGGER fail_after_n_trg AFTER INSERT ON `+table+`
		FOR EACH ROW EXECUTE FUNCTION fail_after_n();`)
	if err != nil {
		t.Fatalf("install trigger: %v", err)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestResetTokenIsSpentExactlyOnceUnderConcurrency(t *testing.T) {
	// The race the separate check-then-act allowed: N requests carrying the
	// same token all read used_at as NULL, all pass the Go-side check, and all
	// reset the password. A reset token is single-use precisely so that a
	// leaked link cannot be replayed; a check that N callers can pass at once
	// is not single-use.
	s, db, ctx := newAuthTestService(t)
	userID := seedAuthUser(t, db, ctx, authOrgA, "alice", "alice@example.test", "OldPassw0rd!")

	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO password_reset_tokens (user_id, token, expires_at, org_id)
		VALUES ($1, 'tok-race', NOW() + INTERVAL '1 hour', $2)`, userID, authOrgA); err != nil {
		t.Fatalf("seed token: %v", err)
	}

	const attempts = 8
	var (
		mu       sync.Mutex
		accepted int
	)
	var wg sync.WaitGroup
	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func() {
			defer wg.Done()
			w := resetPassword(t, s, ctx, authOrgA, "tok-race", "BrandNewPass1!")
			if w.Code == 200 {
				mu.Lock()
				accepted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if accepted != 1 {
		t.Errorf("%d of %d concurrent resets were accepted with one token, want exactly 1", accepted, attempts)
	}

	var usedAt *time.Time
	if err := db.Pool.QueryRow(ctx,
		`SELECT used_at FROM password_reset_tokens WHERE token = 'tok-race' AND org_id = $1`,
		authOrgA).Scan(&usedAt); err != nil {
		t.Fatalf("read token: %v", err)
	}
	if usedAt == nil {
		t.Error("token not marked used after a successful reset")
	}

	// And the password really changed — the reset committed rather than just
	// burning the token.
	var hash string
	if err := db.Pool.QueryRow(ctx,
		`SELECT password_hash FROM users WHERE id = $1 AND org_id = $2`, userID, authOrgA).Scan(&hash); err != nil {
		t.Fatalf("read hash: %v", err)
	}
	// Verified through pwhash rather than bcrypt directly: the reset path now
	// writes Argon2id, and asserting one specific algorithm here would make this
	// test a check on the hashing scheme instead of on the reset committing.
	if ok, _, err := pwhash.Verify(hash, "BrandNewPass1!"); err != nil || !ok {
		t.Errorf("password was not updated by the accepted reset (ok=%v err=%v)", ok, err)
	}
}

func TestResetTokenSurvivesAFailedPasswordWrite(t *testing.T) {
	// The other half of the old bug, inverted. Marking the token used and
	// writing the password are now one transaction, so a failure on the write
	// must roll the claim back: a user whose reset failed for a reason they did
	// not cause should still be able to use their link, rather than finding it
	// silently spent.
	s, db, ctx := newAuthTestService(t)
	userID := seedAuthUser(t, db, ctx, authOrgA, "bob", "bob@example.test", "OldPassw0rd!")

	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO password_reset_tokens (user_id, token, expires_at, org_id)
		VALUES ($1, 'tok-rollback', NOW() + INTERVAL '1 hour', $2)`, userID, authOrgA); err != nil {
		t.Fatalf("seed token: %v", err)
	}

	// Make the password write fail.
	if _, err := db.Pool.Exec(ctx, `
		CREATE OR REPLACE FUNCTION fail_pw_update() RETURNS TRIGGER AS $$
		BEGIN
			RAISE EXCEPTION 'injected password write failure';
		END;
		$$ LANGUAGE plpgsql;
		CREATE TRIGGER fail_pw_update_trg BEFORE UPDATE OF password_hash ON users
		FOR EACH ROW EXECUTE FUNCTION fail_pw_update();`); err != nil {
		t.Fatalf("install trigger: %v", err)
	}

	if w := resetPassword(t, s, ctx, authOrgA, "tok-rollback", "BrandNewPass1!"); w.Code == 200 {
		t.Fatal("reset reported success despite the password write failing")
	}

	var usedAt *time.Time
	if err := db.Pool.QueryRow(ctx,
		`SELECT used_at FROM password_reset_tokens WHERE token = 'tok-rollback' AND org_id = $1`,
		authOrgA).Scan(&usedAt); err != nil {
		t.Fatalf("read token: %v", err)
	}
	if usedAt != nil {
		t.Error("the token was burned by a reset that never happened — the claim did not roll back")
	}

	// With the fault removed the same link still works.
	if _, err := db.Pool.Exec(ctx, `DROP TRIGGER fail_pw_update_trg ON users`); err != nil {
		t.Fatalf("drop trigger: %v", err)
	}
	if w := resetPassword(t, s, ctx, authOrgA, "tok-rollback", "BrandNewPass1!"); w.Code != 200 {
		t.Errorf("retry after a transient failure = %d, want 200", w.Code)
	}
}

func TestBackupCodeGenerationIsAllOrNothing(t *testing.T) {
	// GenerateBackupCodes returns the plaintext codes for the caller to show
	// once. If it reports an error, none of them may be live — otherwise the
	// user is holding a list where some codes work, and a retry stacks a second
	// set on top of the partial one.
	s, db, ctx := newAuditService(t)

	failAfterNInserts(t, s, ctx, "mfa_backup_codes", 6)

	codes, err := s.GenerateBackupCodes(ctx, auditUser, 10)
	if err == nil {
		t.Fatalf("expected an error from the injected failure, got %d codes", len(codes))
	}

	var stored int
	if err := db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM mfa_backup_codes WHERE user_id = $1 AND org_id = $2`,
		auditUser, auditOrg).Scan(&stored); err != nil {
		t.Fatalf("count: %v", err)
	}
	if stored != 0 {
		t.Errorf("%d backup codes survived a failed generation, want 0 — the set was written partially", stored)
	}
}

func TestTOTPReEnrollmentNeverLeavesTheUserWithoutAFactor(t *testing.T) {
	// Re-enrolling deletes the existing factor and inserts the replacement. As
	// two statements, a failure on the insert left the user with neither —
	// downgraded to single-factor by a transient error, with nothing to say so.
	s, db, ctx := newAuditService(t)

	firstKey, err := totp.Generate(totp.GenerateOpts{Issuer: "openidx", AccountName: "alice"})
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	firstSecret := firstKey.Secret()
	if err := s.EnrollTOTP(ctx, auditUser, firstSecret, currentTOTP(t, firstSecret)); err != nil {
		t.Fatalf("initial enroll: %v", err)
	}

	// Re-enrollment deletes the existing row inside the transaction before
	// inserting, so the post-insert count is 1, not 2. Fail on any insert.
	failAfterNInserts(t, s, ctx, "mfa_totp", 0)

	secondKey, err := totp.Generate(totp.GenerateOpts{Issuer: "openidx", AccountName: "alice"})
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if err := s.EnrollTOTP(ctx, auditUser, secondKey.Secret(), currentTOTP(t, secondKey.Secret())); err == nil {
		t.Fatal("expected an error from the injected failure")
	}

	var secret string
	var enabled bool
	if err := db.Pool.QueryRow(ctx,
		`SELECT secret, enabled FROM mfa_totp WHERE user_id = $1 AND org_id = $2`,
		auditUser, auditOrg).Scan(&secret, &enabled); err != nil {
		t.Fatalf("the user has no TOTP row at all after a failed re-enrollment: %v", err)
	}
	if secret != firstSecret || !enabled {
		t.Errorf("secret=%q enabled=%v, want the original factor left intact", secret, enabled)
	}
}
