package oauth

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// Refresh-token rotation used to invalidate the old token with a hard DELETE.
// That threw away the only evidence that matters: after the delete, a replayed
// token is simply absent — indistinguishable from a typo or an expired one —
// and whoever holds the newest token keeps working. In the theft case the
// server logged one invalid_grant, revoked nothing, and the attacker carried on.
//
// These tests exercise the stolen-token sequence end to end against a real
// Postgres, because the property under test is a database state machine
// (tombstone + family) rather than a pure function.

const refreshReuseSchema = `
CREATE TABLE oauth_refresh_tokens (
    token       VARCHAR(500) PRIMARY KEY,
    client_id   VARCHAR(255) NOT NULL,
    user_id     UUID NOT NULL,
    scope       TEXT,
    session_id  VARCHAR(255),
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    org_id      UUID NOT NULL,
    family_id   UUID,
    used_at     TIMESTAMPTZ,
    revoked_at  TIMESTAMPTZ
);`

const (
	reuseOrgA = "55555555-0000-0000-0000-00000000000a"
	reuseOrgB = "66666666-0000-0000-0000-00000000000b"
	reuseUser = "77777777-0000-0000-0000-000000000001"
)

func newRefreshReuseService(t *testing.T) (*Service, *database.PostgresDB, context.Context) {
	t.Helper()

	db, cleanup := ssfSetupTestDB(t)
	if db == nil {
		t.SkipNow()
	}
	t.Cleanup(cleanup)

	ctx := orgctx.With(context.Background(), orgctx.Org{ID: reuseOrgA})
	if _, err := db.Pool.Exec(ctx, refreshReuseSchema); err != nil {
		t.Fatalf("schema: %v", err)
	}

	return &Service{db: db, config: &config.Config{}, logger: zap.NewNop()}, db, ctx
}

func mustCreateRefresh(t *testing.T, s *Service, ctx context.Context, tok, family, session string) *RefreshToken {
	t.Helper()
	rt := &RefreshToken{
		Token:     tok,
		ClientID:  "app",
		UserID:    reuseUser,
		Scope:     "openid offline_access",
		SessionID: session,
		FamilyID:  family,
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
	}
	if err := s.CreateRefreshToken(ctx, rt); err != nil {
		t.Fatalf("create refresh token %s: %v", tok, err)
	}
	return rt
}

func TestRefreshTokenRotationAndReuse(t *testing.T) {
	s, db, ctx := newRefreshReuseService(t)

	t.Run("a fresh token has a family and is unused", func(t *testing.T) {
		rt := mustCreateRefresh(t, s, ctx, "tok-1", "", "sess-1")
		if rt.FamilyID == "" {
			t.Fatal("no family assigned; a chain cannot be revoked without one")
		}
		got, err := s.GetRefreshToken(ctx, "tok-1")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.UsedAt != nil {
			t.Error("new token already marked used")
		}
		if got.FamilyID != rt.FamilyID {
			t.Errorf("family not persisted: %q != %q", got.FamilyID, rt.FamilyID)
		}
	})

	t.Run("rotation tombstones rather than deletes", func(t *testing.T) {
		mustCreateRefresh(t, s, ctx, "tok-2", "", "sess-2")

		claimed, err := s.markRefreshTokenRotated(ctx, "tok-2")
		if err != nil || !claimed {
			t.Fatalf("first rotation should win: claimed=%v err=%v", claimed, err)
		}

		// Still retrievable — that is the whole point. A DELETE here is what
		// made replay invisible.
		got, err := s.GetRefreshToken(ctx, "tok-2")
		if err != nil {
			t.Fatalf("rotated token must remain readable for replay detection: %v", err)
		}
		if got.UsedAt == nil {
			t.Error("rotated token not marked used")
		}
	})

	t.Run("a second rotation of the same token loses", func(t *testing.T) {
		// This is the concurrency case: two requests present the same token.
		// Exactly one may win, or both callers would be handed fresh chains.
		claimed, err := s.markRefreshTokenRotated(ctx, "tok-2")
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if claimed {
			t.Error("the same token was rotated twice")
		}
	})

	t.Run("replay revokes the whole family, not just the replayed token", func(t *testing.T) {
		// A chain three rotations deep, as a long-lived client would have.
		first := mustCreateRefresh(t, s, ctx, "chain-1", "", "sess-3")
		family := first.FamilyID
		mustCreateRefresh(t, s, ctx, "chain-2", family, "sess-3")
		mustCreateRefresh(t, s, ctx, "chain-3", family, "sess-3")
		if _, err := s.markRefreshTokenRotated(ctx, "chain-1"); err != nil {
			t.Fatalf("rotate: %v", err)
		}

		replayed, err := s.GetRefreshToken(ctx, "chain-1")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if replayed.UsedAt == nil {
			t.Fatal("expected the replayed token to be marked used")
		}

		s.handleRefreshTokenReuse(ctx, replayed, "app")

		// Every member is now revoked — including chain-3, which the attacker
		// would otherwise still be holding.
		for _, tok := range []string{"chain-1", "chain-2", "chain-3"} {
			if _, err := s.GetRefreshToken(ctx, tok); err == nil {
				t.Errorf("%s still usable after family revocation", tok)
			}
		}
	})

	t.Run("revocation is confined to the family", func(t *testing.T) {
		other := mustCreateRefresh(t, s, ctx, "unrelated-1", "", "sess-4")
		if _, err := s.revokeRefreshTokenFamily(ctx, "00000000-0000-0000-0000-0000000000ff"); err != nil {
			t.Fatalf("revoke: %v", err)
		}
		if _, err := s.GetRefreshToken(ctx, other.Token); err != nil {
			t.Errorf("an unrelated family was revoked: %v", err)
		}
	})

	t.Run("a revoked token is not resurrected by another replay", func(t *testing.T) {
		var revokedAt *time.Time
		if err := db.Pool.QueryRow(ctx,
			`SELECT revoked_at FROM oauth_refresh_tokens WHERE token = 'chain-2'`).Scan(&revokedAt); err != nil {
			t.Fatalf("read: %v", err)
		}
		if revokedAt == nil {
			t.Fatal("chain-2 should be revoked")
		}
	})

	t.Run("a family cannot be revoked across tenants", func(t *testing.T) {
		orgACtx := ctx
		aToken := mustCreateRefresh(t, s, orgACtx, "tenant-a-1", "", "sess-5")

		orgBCtx := orgctx.With(context.Background(), orgctx.Org{ID: reuseOrgB})
		if n, err := s.revokeRefreshTokenFamily(orgBCtx, aToken.FamilyID); err != nil {
			t.Fatalf("revoke: %v", err)
		} else if n != 0 {
			t.Errorf("org B revoked %d of org A's tokens", n)
		}
		if _, err := s.GetRefreshToken(orgACtx, "tenant-a-1"); err != nil {
			t.Errorf("cross-tenant revocation took effect: %v", err)
		}
	})
}

func TestRefreshTokenReuse_LegacyTokenWithoutFamily(t *testing.T) {
	// Tokens issued before migration v122 were backfilled with a family, but a
	// row could still arrive with NULL (e.g. a partially applied migration).
	// Reuse handling must degrade to revoking the single token rather than
	// silently doing nothing.
	s, db, ctx := newRefreshReuseService(t)

	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO oauth_refresh_tokens (token, client_id, user_id, scope, expires_at, created_at, org_id, used_at)
		VALUES ('legacy-1', 'app', $1, 'openid offline_access', NOW() + INTERVAL '1 hour', NOW(), $2, NOW())`,
		reuseUser, reuseOrgA); err != nil {
		t.Fatalf("seed: %v", err)
	}

	replayed, err := s.GetRefreshToken(ctx, "legacy-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if replayed.FamilyID != "" {
		t.Fatalf("expected no family, got %q", replayed.FamilyID)
	}

	s.handleRefreshTokenReuse(ctx, replayed, "app")

	if _, err := s.GetRefreshToken(ctx, "legacy-1"); err == nil {
		t.Error("legacy token still usable after reuse was detected")
	}
}
