package oauth

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/openidx/openidx/internal/common/database"
	"go.uber.org/zap"
)

// TestSocialAccountLinkingOwnership pins the security contract of self-service
// account linking against a real database.
//
// Background: the login path refuses to sign a user in when an unknown social
// account carries the email address of an existing local user
// (ErrSocialAccountConflict), because auto-linking on email is an
// account-takeover vector. Linking is therefore an explicit, authenticated
// action. This test asserts the properties that make that action safe:
//
//  1. a link binds the external account to the local user it was requested for;
//  2. it is mirrored into user_identity_links, which the profile and admin
//     screens read (nothing wrote that table before, so those screens were
//     permanently empty);
//  3. re-linking the same pair is idempotent, not a duplicate;
//  4. a *different* local user cannot take over an already-linked external
//     account, which is what would let an attacker who controls the external
//     account walk it between local identities.
func TestSocialAccountLinkingOwnership(t *testing.T) {
	db, cleanup := ssfSetupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	orgID := uuid.New().String()

	// Minimal schema: the columns and constraints this code actually relies on.
	// Uniqueness on (provider_id, external_id) is what makes takeover detectable.
	mustExec(t, db, ctx, `
		CREATE TABLE users (
			id UUID PRIMARY KEY,
			email TEXT UNIQUE,
			org_id UUID NOT NULL
		)`)
	mustExec(t, db, ctx, `
		CREATE TABLE identity_providers (
			id UUID PRIMARY KEY,
			name TEXT NOT NULL,
			org_id UUID NOT NULL
		)`)
	mustExec(t, db, ctx, `
		CREATE TABLE social_account_links (
			id UUID PRIMARY KEY,
			provider_id UUID NOT NULL REFERENCES identity_providers(id),
			user_id UUID NOT NULL REFERENCES users(id),
			external_id TEXT NOT NULL,
			profile_data JSONB,
			email TEXT,
			linked_at TIMESTAMPTZ,
			last_login_at TIMESTAMPTZ,
			UNIQUE (provider_id, external_id)
		)`)
	mustExec(t, db, ctx, `
		CREATE TABLE user_identity_links (
			id UUID PRIMARY KEY,
			user_id UUID NOT NULL REFERENCES users(id),
			provider_id UUID NOT NULL REFERENCES identity_providers(id),
			external_id TEXT NOT NULL,
			external_email TEXT,
			external_username TEXT,
			display_name TEXT,
			profile_data JSONB,
			is_primary BOOLEAN DEFAULT false,
			linked_at TIMESTAMPTZ,
			last_used_at TIMESTAMPTZ,
			UNIQUE (provider_id, external_id)
		)`)

	providerID := uuid.New().String()
	mustExec(t, db, ctx, `INSERT INTO identity_providers (id, name, org_id) VALUES ($1,'Corp IdP',$2)`,
		providerID, orgID)

	// Two distinct local users that share nothing but the org.
	alice := uuid.New().String()
	bob := uuid.New().String()
	mustExec(t, db, ctx, `INSERT INTO users (id,email,org_id) VALUES ($1,'alice@corp.example',$2)`, alice, orgID)
	mustExec(t, db, ctx, `INSERT INTO users (id,email,org_id) VALUES ($1,'bob@corp.example',$2)`, bob, orgID)

	svc := &Service{db: db, logger: zap.NewNop()}

	external := &SocialUserInfo{
		ID:       "ext-subject-001",
		Email:    "alice@corp.example",
		Name:     "Alice Example",
		Provider: "corp",
	}

	// (1) First link binds to the requesting user.
	created, err := svc.linkSocialAccountToUser(ctx, providerID, alice, external)
	if err != nil {
		t.Fatalf("first link: %v", err)
	}
	if !created {
		t.Fatal("first link should report a newly created link")
	}

	var owner string
	if err := db.Pool.QueryRow(ctx,
		`SELECT user_id FROM social_account_links WHERE provider_id=$1 AND external_id=$2`,
		providerID, external.ID).Scan(&owner); err != nil {
		t.Fatalf("read social link: %v", err)
	}
	if owner != alice {
		t.Fatalf("social link owner = %s, want alice %s", owner, alice)
	}

	// (2) The profile-facing mirror is populated, not left empty.
	var mirrored string
	if err := db.Pool.QueryRow(ctx,
		`SELECT user_id FROM user_identity_links WHERE provider_id=$1 AND external_id=$2`,
		providerID, external.ID).Scan(&mirrored); err != nil {
		t.Fatalf("user_identity_links should be populated so the profile screen has something to show: %v", err)
	}
	if mirrored != alice {
		t.Fatalf("identity link owner = %s, want alice %s", mirrored, alice)
	}

	// (3) Re-linking the same pair is a no-op, not a duplicate row.
	createdAgain, err := svc.linkSocialAccountToUser(ctx, providerID, alice, external)
	if err != nil {
		t.Fatalf("repeat link: %v", err)
	}
	if createdAgain {
		t.Error("re-linking the same account should not report a new link")
	}
	assertCount(t, db, ctx, `SELECT count(*) FROM social_account_links`, 1)
	assertCount(t, db, ctx, `SELECT count(*) FROM user_identity_links`, 1)

	// (4) A different local user must not be able to claim the same external
	// account. Whoever controls the external account could otherwise migrate
	// it onto an identity they are trying to reach.
	if _, err := svc.linkSocialAccountToUser(ctx, providerID, bob, external); err != errLinkOwnedByAnotherUser {
		t.Fatalf("takeover attempt should fail with errLinkOwnedByAnotherUser, got %v", err)
	}

	// The link must be untouched after the rejected attempt.
	if err := db.Pool.QueryRow(ctx,
		`SELECT user_id FROM social_account_links WHERE provider_id=$1 AND external_id=$2`,
		providerID, external.ID).Scan(&owner); err != nil {
		t.Fatalf("read social link after takeover attempt: %v", err)
	}
	if owner != alice {
		t.Fatalf("after rejected takeover, owner = %s, want alice %s", owner, alice)
	}
	assertCount(t, db, ctx, `SELECT count(*) FROM social_account_links`, 1)
}

func mustExec(t *testing.T, db *database.PostgresDB, ctx context.Context, sql string, args ...interface{}) {
	t.Helper()
	if _, err := db.Pool.Exec(ctx, sql, args...); err != nil {
		t.Fatalf("exec %.60s: %v", sql, err)
	}
}

func assertCount(t *testing.T, db *database.PostgresDB, ctx context.Context, sql string, want int) {
	t.Helper()
	var got int
	if err := db.Pool.QueryRow(ctx, sql).Scan(&got); err != nil {
		t.Fatalf("count %.60s: %v", sql, err)
	}
	if got != want {
		t.Fatalf("%.60s = %d, want %d", sql, got, want)
	}
}
