package identity

import (
	"context"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/pwhash"
)

// storedHash reads a user's password_hash straight from the row.
func storedHash(t *testing.T, s *Service, ctx context.Context, userID string) string {
	t.Helper()
	var h string
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT password_hash FROM users WHERE id = $1`, userID).Scan(&h); err != nil {
		t.Fatalf("read password_hash: %v", err)
	}
	return h
}

// TestLoginUpgradesABcryptHashInPlace is the point of the migration path: every
// existing credential is bcrypt, and login is the only moment the plaintext is
// available, so it is the only place an account can move to Argon2id without
// asking the user to change their password.
func TestLoginUpgradesABcryptHashInPlace(t *testing.T) {
	s, db, ctx := newAuthTestService(t)
	orgCtx := orgctx.With(ctx, orgctx.Org{ID: authOrgA})

	id := seedAuthUser(t, db, ctx, authOrgA, "legacy", "legacy@example.com", authGoodPassword)
	before := storedHash(t, s, ctx, id)
	if pwhash.IsArgon2id(before) {
		t.Fatalf("precondition: the seeded user should start on bcrypt, got %q", before)
	}

	if _, err := s.AuthenticateUser(orgCtx, "legacy", authGoodPassword); err != nil {
		t.Fatalf("login with a bcrypt credential failed: %v", err)
	}

	after := storedHash(t, s, ctx, id)
	if !pwhash.IsArgon2id(after) {
		t.Fatalf("hash was not upgraded after login: %q", after)
	}

	// The upgraded hash must actually be a working credential — an upgrade that
	// writes a hash the password no longer opens locks the user out silently.
	if _, err := s.AuthenticateUser(orgCtx, "legacy", authGoodPassword); err != nil {
		t.Fatalf("login failed after the hash was upgraded: %v", err)
	}
	if _, err := s.AuthenticateUser(orgCtx, "legacy", authGoodPassword+"wrong"); err == nil {
		t.Fatalf("the wrong password was accepted after the upgrade")
	}
}

// TestLoginDoesNotRewriteACurrentHash — rewriting on every login would burn a
// write per authentication and churn the row for no gain.
func TestLoginDoesNotRewriteACurrentHash(t *testing.T) {
	s, db, ctx := newAuthTestService(t)
	orgCtx := orgctx.With(ctx, orgctx.Org{ID: authOrgA})

	id := seedAuthUser(t, db, ctx, authOrgA, "modern", "modern@example.com", authGoodPassword)
	current, err := pwhash.Hash(authGoodPassword)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx,
		`UPDATE users SET password_hash = $2 WHERE id = $1`, id, current); err != nil {
		t.Fatal(err)
	}

	if _, err := s.AuthenticateUser(orgCtx, "modern", authGoodPassword); err != nil {
		t.Fatalf("login: %v", err)
	}
	if got := storedHash(t, s, ctx, id); got != current {
		t.Fatalf("an already-current hash was rewritten:\n before %q\n after  %q", current, got)
	}
}

// TestUpgradeDoesNotExtendThePasswordExpiryClock — password_changed_at drives
// password ageing. Touching it during a storage-only upgrade would silently
// grant every user a fresh expiry window they did not earn.
func TestUpgradeDoesNotExtendThePasswordExpiryClock(t *testing.T) {
	s, db, ctx := newAuthTestService(t)
	orgCtx := orgctx.With(ctx, orgctx.Org{ID: authOrgA})

	id := seedAuthUser(t, db, ctx, authOrgA, "ageing", "ageing@example.com", authGoodPassword)
	old := time.Now().Add(-200 * 24 * time.Hour).UTC().Truncate(time.Second)
	if _, err := db.Pool.Exec(ctx,
		`UPDATE users SET password_changed_at = $2 WHERE id = $1`, id, old); err != nil {
		t.Fatal(err)
	}

	if _, err := s.AuthenticateUser(orgCtx, "ageing", authGoodPassword); err != nil {
		t.Fatalf("login: %v", err)
	}
	if got := storedHash(t, s, ctx, id); !pwhash.IsArgon2id(got) {
		t.Fatalf("precondition: expected the upgrade to have run, hash is %q", got)
	}

	var changed time.Time
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT password_changed_at FROM users WHERE id = $1`, id).Scan(&changed); err != nil {
		t.Fatal(err)
	}
	if !changed.UTC().Truncate(time.Second).Equal(old) {
		t.Fatalf("password_changed_at moved from %s to %s — the ageing clock was reset by a storage upgrade",
			old, changed.UTC())
	}
}

// TestUpgradeDoesNotClobberAPasswordChangedMeanwhile pins the compare-and-swap.
// The upgrade writes after the verify, so a password set in between (admin
// reset, or the user on another device) must win — a blind UPDATE here would
// silently restore the credential the user just replaced.
func TestUpgradeDoesNotClobberAPasswordChangedMeanwhile(t *testing.T) {
	s, db, ctx := newAuthTestService(t)

	id := seedAuthUser(t, db, ctx, authOrgA, "raced", "raced@example.com", authGoodPassword)
	staleHash := storedHash(t, s, ctx, id)

	// Someone changes the password after our verify but before our write.
	const newPassword = "Different-Pass!9"
	replacement, err := pwhash.Hash(newPassword)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx,
		`UPDATE users SET password_hash = $2 WHERE id = $1`, id, replacement); err != nil {
		t.Fatal(err)
	}

	// The upgrade still holds the hash it verified. It must not land.
	s.upgradePasswordHash(ctx, id, authOrgA, authGoodPassword, staleHash)

	if got := storedHash(t, s, ctx, id); got != replacement {
		t.Fatalf("the upgrade overwrote a password changed after its verify:\n want %q\n got  %q",
			replacement, got)
	}
	orgCtx := orgctx.With(ctx, orgctx.Org{ID: authOrgA})
	if _, err := s.AuthenticateUser(orgCtx, "raced", newPassword); err != nil {
		t.Fatalf("the newer password stopped working: %v", err)
	}
	if _, err := s.AuthenticateUser(orgCtx, "raced", authGoodPassword); err == nil {
		t.Fatalf("the replaced password still authenticates")
	}
}

// TestPasswordHistoryMatchesBothHashFormats — history rows written before the
// switch are bcrypt and rows written after are Argon2id. If the comparison only
// understood one, reuse prevention would quietly stop working for the other.
func TestPasswordHistoryMatchesBothHashFormats(t *testing.T) {
	s, db, ctx := newAuthTestService(t)

	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE password_history (
		    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		    user_id       UUID        NOT NULL,
		    password_hash TEXT        NOT NULL,
		    org_id        UUID        NOT NULL,
		    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`); err != nil {
		t.Fatalf("history schema: %v", err)
	}

	id := seedAuthUser(t, db, ctx, authOrgA, "hist", "hist@example.com", authGoodPassword)
	orgCtx := orgctx.With(ctx, orgctx.Org{ID: authOrgA})

	const oldBcryptPw = "Ancient-Pass!1"
	const oldArgonPw = "Recent-Pass!2"

	legacy, err := bcrypt.GenerateFromPassword([]byte(oldBcryptPw), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	modern, err := pwhash.Hash(oldArgonPw)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{string(legacy), modern} {
		if _, err := db.Pool.Exec(ctx,
			`INSERT INTO password_history (user_id, password_hash, org_id) VALUES ($1, $2, $3)`,
			id, h, authOrgA); err != nil {
			t.Fatal(err)
		}
	}

	for _, tc := range []struct {
		name     string
		password string
		want     bool
	}{
		{"bcrypt history entry is detected", oldBcryptPw, true},
		{"argon2id history entry is detected", oldArgonPw, true},
		{"an unused password is not flagged", "Brand-New-Pass!3", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reused, err := s.CheckPasswordHistory(orgCtx, id, tc.password, 5)
			if err != nil {
				t.Fatalf("CheckPasswordHistory: %v", err)
			}
			if reused != tc.want {
				t.Fatalf("reuse detected = %v, want %v", reused, tc.want)
			}
		})
	}
}
