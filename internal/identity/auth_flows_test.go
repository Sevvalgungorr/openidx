package identity

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// The password/login flows are the ones an attacker actually reaches without
// credentials, and until now none of them had a test: AuthenticateUser, the
// failed-login lockout, and the reset/verification token lifecycles were all
// covered only by whatever an integration run happened to touch. These are the
// tests that the newly-real unit-test gate is there to run.

const (
	authOrgA = "11111111-0000-0000-0000-00000000000a"
	authOrgB = "22222222-0000-0000-0000-00000000000b"
	// Satisfies every ValidatePasswordPolicyChecks rule (length, upper, lower,
	// digit, special) so a rejection in these tests means a real failure and
	// not a policy violation.
	authGoodPassword = "Str0ng-Pass!x"
)

// authTestSchema is the slice of the users schema these flows touch, matching
// userSelectColumns so the repository's GetByID can scan a row back.
const authTestSchema = `
CREATE TABLE users (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username             VARCHAR(255) NOT NULL,
    email                VARCHAR(255) NOT NULL,
    first_name           VARCHAR(255),
    last_name            VARCHAR(255),
    password_hash        TEXT        NOT NULL DEFAULT '',
    enabled              BOOLEAN     NOT NULL DEFAULT true,
    email_verified       BOOLEAN     NOT NULL DEFAULT false,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at        TIMESTAMPTZ,
    password_changed_at  TIMESTAMPTZ,
    password_must_change BOOLEAN     NOT NULL DEFAULT false,
    failed_login_count   INT         NOT NULL DEFAULT 0,
    last_failed_login_at TIMESTAMPTZ,
    locked_until         TIMESTAMPTZ,
    source               VARCHAR(50),
    directory_id         UUID,
    org_id               UUID        NOT NULL
);
CREATE TABLE system_settings (
    key   VARCHAR(255) PRIMARY KEY,
    value JSONB NOT NULL
);
CREATE TABLE password_reset_tokens (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID        NOT NULL,
    token      TEXT        NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ,
    org_id     UUID        NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE email_verification_tokens (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID        NOT NULL,
    token      TEXT        NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ,
    org_id     UUID        NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);`

// newAuthTestService builds a service over a throwaway Postgres carrying the
// schema above.
func newAuthTestService(t *testing.T) (*Service, *database.PostgresDB, context.Context) {
	t.Helper()

	db, cleanup := setupTestDB(t)
	if db == nil {
		t.SkipNow()
	}
	t.Cleanup(cleanup)

	ctx := context.Background()
	if _, err := db.Pool.Exec(ctx, authTestSchema); err != nil {
		t.Fatalf("schema: %v", err)
	}
	return NewService(db, nil, &config.Config{}, zap.NewNop()), db, ctx
}

// seedAuthUser inserts a local user with the given password and returns its id.
func seedAuthUser(t *testing.T, db *database.PostgresDB, ctx context.Context, org, username, email, password string) string {
	t.Helper()

	hash := ""
	if password != "" {
		h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
		if err != nil {
			t.Fatalf("hash: %v", err)
		}
		hash = string(h)
	}

	var id string
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO users (username, email, password_hash, org_id)
		VALUES ($1, $2, $3, $4) RETURNING id`,
		username, email, hash, org).Scan(&id); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return id
}

func TestAuthenticateUser(t *testing.T) {
	s, db, ctx := newAuthTestService(t)

	aliceID := seedAuthUser(t, db, ctx, authOrgA, "alice", "alice@example.com", authGoodPassword)
	seedAuthUser(t, db, ctx, authOrgA, "disabled", "disabled@example.com", authGoodPassword)
	seedAuthUser(t, db, ctx, authOrgA, "locked", "locked@example.com", authGoodPassword)
	seedAuthUser(t, db, ctx, authOrgA, "nopass", "nopass@example.com", "")
	// Same credentials, different tenant. A login against org A must not be
	// satisfied by org B's row.
	seedAuthUser(t, db, ctx, authOrgB, "bob", "bob@example.com", authGoodPassword)

	if _, err := db.Pool.Exec(ctx,
		`UPDATE users SET enabled = false WHERE username = 'disabled'`); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if _, err := db.Pool.Exec(ctx,
		`UPDATE users SET locked_until = NOW() + INTERVAL '10 minutes' WHERE username = 'locked'`); err != nil {
		t.Fatalf("lock: %v", err)
	}

	orgACtx := orgctx.With(ctx, orgctx.Org{ID: authOrgA})

	t.Run("valid credentials return the user", func(t *testing.T) {
		user, err := s.AuthenticateUser(orgACtx, "alice", authGoodPassword)
		if err != nil {
			t.Fatalf("authenticate: %v", err)
		}
		if user.ID != aliceID {
			t.Errorf("got user %s, want %s", user.ID, aliceID)
		}
	})

	t.Run("email works as the identifier", func(t *testing.T) {
		if _, err := s.AuthenticateUser(orgACtx, "alice@example.com", authGoodPassword); err != nil {
			t.Fatalf("authenticate by email: %v", err)
		}
	})

	t.Run("wrong password is rejected", func(t *testing.T) {
		if _, err := s.AuthenticateUser(orgACtx, "alice", "Wr0ng-Pass!x"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("got %v, want ErrInvalidCredentials", err)
		}
	})

	t.Run("unknown user is rejected without disclosing existence", func(t *testing.T) {
		// Same sentinel as a wrong password: the caller cannot tell the two
		// apart, so login is not a user-enumeration oracle.
		if _, err := s.AuthenticateUser(orgACtx, "ghost", authGoodPassword); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("got %v, want ErrInvalidCredentials", err)
		}
	})

	t.Run("a user with no password set cannot log in with an empty one", func(t *testing.T) {
		if _, err := s.AuthenticateUser(orgACtx, "nopass", ""); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("got %v, want ErrInvalidCredentials", err)
		}
	})

	t.Run("disabled account is rejected", func(t *testing.T) {
		if _, err := s.AuthenticateUser(orgACtx, "disabled", authGoodPassword); !errors.Is(err, ErrAccountDisabled) {
			t.Fatalf("got %v, want ErrAccountDisabled", err)
		}
	})

	t.Run("locked account is rejected even with the right password", func(t *testing.T) {
		if _, err := s.AuthenticateUser(orgACtx, "locked", authGoodPassword); !errors.Is(err, ErrAccountLocked) {
			t.Fatalf("got %v, want ErrAccountLocked", err)
		}
	})

	t.Run("credentials from another tenant do not authenticate", func(t *testing.T) {
		if _, err := s.AuthenticateUser(orgACtx, "bob", authGoodPassword); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("cross-tenant login succeeded or wrong error: %v", err)
		}
	})

	t.Run("no tenant context authenticates nobody", func(t *testing.T) {
		if _, err := s.AuthenticateUser(ctx, "alice", authGoodPassword); err == nil {
			t.Fatal("expected an error without org context")
		}
	})
}

func TestAuthenticateUser_LocksAccountAfterRepeatedFailures(t *testing.T) {
	s, db, ctx := newAuthTestService(t)
	seedAuthUser(t, db, ctx, authOrgA, "target", "target@example.com", authGoodPassword)
	orgACtx := orgctx.With(ctx, orgctx.Org{ID: authOrgA})

	// Default threshold is 5 with no system_settings row present.
	for i := 0; i < 4; i++ {
		if _, err := s.AuthenticateUser(orgACtx, "target", "Wr0ng-Pass!x"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d: got %v, want ErrInvalidCredentials", i+1, err)
		}
	}

	var count int
	var lockedUntil *time.Time
	if err := db.Pool.QueryRow(ctx,
		`SELECT failed_login_count, locked_until FROM users WHERE username = 'target'`).
		Scan(&count, &lockedUntil); err != nil {
		t.Fatalf("read counters: %v", err)
	}
	if count != 4 {
		t.Errorf("failed_login_count = %d, want 4", count)
	}
	if lockedUntil != nil {
		t.Errorf("account locked too early at %d failures", count)
	}

	// The fifth failure crosses the threshold.
	if _, err := s.AuthenticateUser(orgACtx, "target", "Wr0ng-Pass!x"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("attempt 5: got %v, want ErrInvalidCredentials", err)
	}
	if err := db.Pool.QueryRow(ctx,
		`SELECT failed_login_count, locked_until FROM users WHERE username = 'target'`).
		Scan(&count, &lockedUntil); err != nil {
		t.Fatalf("read counters: %v", err)
	}
	if count != 5 || lockedUntil == nil {
		t.Fatalf("after 5 failures: count=%d locked_until=%v, want 5 and a lock", count, lockedUntil)
	}

	// And now the correct password is refused too — that is the whole point of
	// the lockout, and the assertion that would catch a lock applied in name
	// only.
	if _, err := s.AuthenticateUser(orgACtx, "target", authGoodPassword); !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("got %v, want ErrAccountLocked", err)
	}
}

func TestAuthenticateUser_SuccessClearsFailureCounters(t *testing.T) {
	s, db, ctx := newAuthTestService(t)
	seedAuthUser(t, db, ctx, authOrgA, "recover", "recover@example.com", authGoodPassword)
	orgACtx := orgctx.With(ctx, orgctx.Org{ID: authOrgA})

	for i := 0; i < 3; i++ {
		s.AuthenticateUser(orgACtx, "recover", "Wr0ng-Pass!x")
	}
	if _, err := s.AuthenticateUser(orgACtx, "recover", authGoodPassword); err != nil {
		t.Fatalf("authenticate: %v", err)
	}

	var count int
	var lockedUntil, lastLogin *time.Time
	if err := db.Pool.QueryRow(ctx,
		`SELECT failed_login_count, locked_until, last_login_at FROM users WHERE username = 'recover'`).
		Scan(&count, &lockedUntil, &lastLogin); err != nil {
		t.Fatalf("read counters: %v", err)
	}
	if count != 0 || lockedUntil != nil {
		t.Errorf("counters not reset: count=%d locked_until=%v", count, lockedUntil)
	}
	if lastLogin == nil {
		t.Error("last_login_at was not recorded")
	}
}

// resetPassword drives the routed handler with the given token.
func resetPassword(t *testing.T, s *Service, ctx context.Context, org, token, password string) *httptest.ResponseRecorder {
	t.Helper()

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	body := `{"token":"` + token + `","password":"` + password + `"}`
	c.Request = httptest.NewRequest(http.MethodPost, "/reset-password", strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Request = c.Request.WithContext(orgctx.With(ctx, orgctx.Org{ID: org}))
	s.handleResetPassword(c)
	return w
}

func TestHandleResetPassword(t *testing.T) {
	s, db, ctx := newAuthTestService(t)
	userID := seedAuthUser(t, db, ctx, authOrgA, "reset", "reset@example.com", authGoodPassword)
	otherID := seedAuthUser(t, db, ctx, authOrgB, "other", "other@example.com", authGoodPassword)

	mkToken := func(t *testing.T, token, org, user string, expires time.Duration) {
		t.Helper()
		if _, err := db.Pool.Exec(ctx, `
			INSERT INTO password_reset_tokens (user_id, token, expires_at, org_id)
			VALUES ($1, $2, NOW() + $3::interval, $4)`,
			user, token, expires.String(), org); err != nil {
			t.Fatalf("insert token: %v", err)
		}
	}

	t.Run("a valid token changes the password exactly once", func(t *testing.T) {
		mkToken(t, "tok-good", authOrgA, userID, time.Hour)

		const newPassword = "Rot4ted-Pass!x"
		if w := resetPassword(t, s, ctx, authOrgA, "tok-good", newPassword); w.Code != http.StatusOK {
			t.Fatalf("first use: status %d, body %s", w.Code, w.Body.String())
		}

		// The new password works and the old one does not.
		orgACtx := orgctx.With(ctx, orgctx.Org{ID: authOrgA})
		if _, err := s.AuthenticateUser(orgACtx, "reset", newPassword); err != nil {
			t.Fatalf("new password rejected: %v", err)
		}
		if _, err := s.AuthenticateUser(orgACtx, "reset", authGoodPassword); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("old password still accepted: %v", err)
		}

		// Replaying the same token must fail. A reset token is a bearer
		// account-takeover credential, so single-use is the property that
		// bounds the damage of a leaked link.
		w := resetPassword(t, s, ctx, authOrgA, "tok-good", "Replay3d-Pass!x")
		if w.Code != http.StatusBadRequest {
			t.Fatalf("replay: status %d, want 400; body %s", w.Code, w.Body.String())
		}
		if _, err := s.AuthenticateUser(orgACtx, "reset", "Replay3d-Pass!x"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatal("replayed token changed the password")
		}
	})

	t.Run("an expired token is rejected", func(t *testing.T) {
		mkToken(t, "tok-expired", authOrgA, userID, -time.Minute)
		if w := resetPassword(t, s, ctx, authOrgA, "tok-expired", "Exp1red-Pass!x"); w.Code != http.StatusBadRequest {
			t.Fatalf("status %d, want 400; body %s", w.Code, w.Body.String())
		}
	})

	t.Run("an unknown token is rejected", func(t *testing.T) {
		if w := resetPassword(t, s, ctx, authOrgA, "tok-nonexistent", "Unkn0wn-Pass!x"); w.Code != http.StatusBadRequest {
			t.Fatalf("status %d, want 400; body %s", w.Code, w.Body.String())
		}
	})

	t.Run("a token cannot be redeemed from another tenant", func(t *testing.T) {
		mkToken(t, "tok-orgB", authOrgB, otherID, time.Hour)
		if w := resetPassword(t, s, ctx, authOrgA, "tok-orgB", "Cr0ss-Pass!x"); w.Code != http.StatusBadRequest {
			t.Fatalf("cross-tenant redemption: status %d, want 400; body %s", w.Code, w.Body.String())
		}
	})

	t.Run("a weak password is rejected before the token is spent", func(t *testing.T) {
		mkToken(t, "tok-weak", authOrgA, userID, time.Hour)
		if w := resetPassword(t, s, ctx, authOrgA, "tok-weak", "short"); w.Code != http.StatusBadRequest {
			t.Fatalf("status %d, want 400; body %s", w.Code, w.Body.String())
		}
		// The token must survive so the user can retry with a valid password.
		var usedAt *time.Time
		if err := db.Pool.QueryRow(ctx,
			`SELECT used_at FROM password_reset_tokens WHERE token = 'tok-weak'`).Scan(&usedAt); err != nil {
			t.Fatalf("read token: %v", err)
		}
		if usedAt != nil {
			t.Error("a policy rejection consumed the token")
		}
	})
}

func TestHandleForgotPassword_DoesNotEnumerateAccounts(t *testing.T) {
	s, db, ctx := newAuthTestService(t)
	seedAuthUser(t, db, ctx, authOrgA, "known", "known@example.com", authGoodPassword)

	forgot := func(t *testing.T, org, email string) *httptest.ResponseRecorder {
		t.Helper()
		gin.SetMode(gin.TestMode)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPost, "/forgot-password",
			strings.NewReader(`{"email":"`+email+`"}`))
		c.Request.Header.Set("Content-Type", "application/json")
		c.Request = c.Request.WithContext(orgctx.With(ctx, orgctx.Org{ID: org}))
		s.handleForgotPassword(c)
		return w
	}

	known := forgot(t, authOrgA, "known@example.com")
	unknown := forgot(t, authOrgA, "ghost@example.com")

	if known.Code != http.StatusOK || unknown.Code != http.StatusOK {
		t.Fatalf("statuses %d/%d, want 200/200", known.Code, unknown.Code)
	}
	if known.Body.String() != unknown.Body.String() {
		t.Errorf("responses differ, which enumerates accounts:\n known:   %s\n unknown: %s",
			known.Body.String(), unknown.Body.String())
	}

	// A token was minted only for the real account...
	var n int
	if err := db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM password_reset_tokens`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Errorf("token count = %d, want 1", n)
	}

	// ...and the response never carries it. The token is only ever delivered by
	// email; echoing it would make the endpoint itself a takeover primitive.
	if strings.Contains(known.Body.String(), "token") {
		t.Errorf("forgot-password response mentions a token: %s", known.Body.String())
	}

	// The same address in another tenant yields nothing.
	forgot(t, authOrgB, "known@example.com")
	if err := db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM password_reset_tokens`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Errorf("cross-tenant request minted a token: count = %d, want 1", n)
	}
}

func TestHandleVerifyEmail(t *testing.T) {
	s, db, ctx := newAuthTestService(t)
	userID := seedAuthUser(t, db, ctx, authOrgA, "verify", "verify@example.com", authGoodPassword)

	verify := func(t *testing.T, org, token string) *httptest.ResponseRecorder {
		t.Helper()
		gin.SetMode(gin.TestMode)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPost, "/verify-email",
			strings.NewReader(`{"token":"`+token+`"}`))
		c.Request.Header.Set("Content-Type", "application/json")
		c.Request = c.Request.WithContext(orgctx.With(ctx, orgctx.Org{ID: org}))
		s.handleVerifyEmail(c)
		return w
	}

	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO email_verification_tokens (user_id, token, expires_at, org_id)
		VALUES ($1, 'verify-tok', NOW() + INTERVAL '24 hours', $2),
		       ($1, 'verify-expired', NOW() - INTERVAL '1 minute', $2)`,
		userID, authOrgA); err != nil {
		t.Fatalf("insert tokens: %v", err)
	}

	t.Run("a valid token verifies the address once", func(t *testing.T) {
		if w := verify(t, authOrgA, "verify-tok"); w.Code != http.StatusOK {
			t.Fatalf("status %d, body %s", w.Code, w.Body.String())
		}

		var verified bool
		if err := db.Pool.QueryRow(ctx,
			`SELECT email_verified FROM users WHERE id = $1`, userID).Scan(&verified); err != nil {
			t.Fatalf("read user: %v", err)
		}
		if !verified {
			t.Error("email_verified was not set")
		}

		if w := verify(t, authOrgA, "verify-tok"); w.Code != http.StatusBadRequest {
			t.Fatalf("replay: status %d, want 400; body %s", w.Code, w.Body.String())
		}
	})

	t.Run("an expired token is rejected", func(t *testing.T) {
		if w := verify(t, authOrgA, "verify-expired"); w.Code != http.StatusBadRequest {
			t.Fatalf("status %d, want 400; body %s", w.Code, w.Body.String())
		}
	})

	t.Run("a token cannot be redeemed from another tenant", func(t *testing.T) {
		if _, err := db.Pool.Exec(ctx, `
			INSERT INTO email_verification_tokens (user_id, token, expires_at, org_id)
			VALUES ($1, 'verify-crosstenant', NOW() + INTERVAL '24 hours', $2)`,
			userID, authOrgA); err != nil {
			t.Fatalf("insert token: %v", err)
		}
		if w := verify(t, authOrgB, "verify-crosstenant"); w.Code != http.StatusBadRequest {
			t.Fatalf("cross-tenant redemption: status %d, want 400; body %s", w.Code, w.Body.String())
		}
	})
}
