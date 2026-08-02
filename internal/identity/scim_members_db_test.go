package identity

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// The claim this file exists to check is not "the diff is computed correctly" —
// scim_members_test.go covers that with pure functions. It is the claim the
// pure tests cannot make: that a SCIM group patch reaches group_memberships.
//
// That distinction is the whole bug. Every previous group test passed against
// code where the roster was a struct field nobody read and nobody wrote, so a
// test that stops at the struct would have passed then too.

const scimMemberSchema = `
CREATE TABLE users (
    id            UUID PRIMARY KEY,
    username      VARCHAR(255) NOT NULL,
    email         VARCHAR(255) NOT NULL,
    first_name    VARCHAR(255) NOT NULL DEFAULT '',
    last_name     VARCHAR(255) NOT NULL DEFAULT '',
    enabled       BOOLEAN NOT NULL DEFAULT TRUE,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at        TIMESTAMPTZ,
    password_changed_at  TIMESTAMPTZ,
    password_must_change BOOLEAN NOT NULL DEFAULT FALSE,
    failed_login_count   INTEGER NOT NULL DEFAULT 0,
    last_failed_login_at TIMESTAMPTZ,
    locked_until         TIMESTAMPTZ,
    org_id        UUID NOT NULL
);
CREATE TABLE groups (
    id           UUID PRIMARY KEY,
    name         VARCHAR(255) NOT NULL,
    description  TEXT,
    parent_id    UUID,
    allow_self_join  BOOLEAN NOT NULL DEFAULT FALSE,
    require_approval BOOLEAN NOT NULL DEFAULT FALSE,
    max_members  INTEGER,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    org_id       UUID NOT NULL
);
CREATE TABLE group_memberships (
    group_id  UUID NOT NULL,
    user_id   UUID NOT NULL,
    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    org_id    UUID NOT NULL,
    PRIMARY KEY (group_id, user_id)
);`

const (
	memberOrgA = "11111111-2222-3333-4444-555555555555"
	memberOrgB = "99999999-2222-3333-4444-555555555555"
	memberGrp  = "aaaaaaaa-0000-0000-0000-000000000001"
	memberU1   = "bbbbbbbb-0000-0000-0000-000000000001"
	memberU2   = "bbbbbbbb-0000-0000-0000-000000000002"
	memberU3   = "bbbbbbbb-0000-0000-0000-000000000003"
)

func newSCIMMemberService(t *testing.T) (*Service, *database.PostgresDB, context.Context) {
	t.Helper()

	db, cleanup := setupTestDB(t)
	if db == nil {
		t.SkipNow()
	}
	t.Cleanup(cleanup)

	ctx := orgctx.With(context.Background(), orgctx.Org{ID: memberOrgA})
	if _, err := db.Pool.Exec(ctx, scimMemberSchema); err != nil {
		t.Fatalf("schema: %v", err)
	}

	for _, u := range []struct{ id, name string }{
		{memberU1, "alice"},
		{memberU2, "bob"},
		{memberU3, "carol"},
	} {
		if _, err := db.Pool.Exec(ctx,
			`INSERT INTO users (id, username, email, first_name, org_id) VALUES ($1, $2, $3, $4, $5)`,
			u.id, u.name, u.name+"@example.com", u.name, memberOrgA); err != nil {
			t.Fatalf("seed user: %v", err)
		}
	}
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO groups (id, name, org_id) VALUES ($1, 'Engineering', $2)`,
		memberGrp, memberOrgA); err != nil {
		t.Fatalf("seed group: %v", err)
	}

	s := &Service{
		db:     db,
		cfg:    &config.Config{},
		logger: zap.NewNop(),
		users:  NewPostgresUserRepository(db),
		groups: NewPostgresGroupRepository(db),
	}
	return s, db, ctx
}

func storedMembers(t *testing.T, db *database.PostgresDB, ctx context.Context) []string {
	t.Helper()
	rows, err := db.Pool.Query(ctx,
		`SELECT user_id::text FROM group_memberships WHERE group_id = $1 AND org_id = $2 ORDER BY user_id`,
		memberGrp, memberOrgA)
	if err != nil {
		t.Fatalf("read memberships: %v", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, id)
	}
	return out
}

func TestSyncGroupMembersWritesToTheDatabase(t *testing.T) {
	s, db, ctx := newSCIMMemberService(t)
	group := &Group{ID: memberGrp, DisplayName: "Engineering"}

	t.Run("an add reaches group_memberships", func(t *testing.T) {
		if err := s.syncGroupMembers(ctx, memberGrp, nil, members(memberU1, memberU2)); err != nil {
			t.Fatalf("sync: %v", err)
		}
		got := storedMembers(t, db, ctx)
		if len(got) != 2 {
			t.Fatalf("stored members = %v, want 2 rows", got)
		}
	})

	t.Run("the roster reads back", func(t *testing.T) {
		if err := s.loadGroupMembers(ctx, group); err != nil {
			t.Fatalf("load: %v", err)
		}
		if len(group.Members) != 2 {
			t.Fatalf("loaded %d members, want 2 — an empty roster is what made clients re-push every sync", len(group.Members))
		}
		if group.Members[0].Display == nil || *group.Members[0].Display == "" {
			t.Error("member display is empty")
		}
		if group.Members[0].Type != "User" {
			t.Errorf("member type = %q, want User", group.Members[0].Type)
		}
	})

	t.Run("a filtered patch detaches exactly one member", func(t *testing.T) {
		before := append([]Member(nil), group.Members...)
		if err := ApplySCIMPatchToGroup(group, patchOp("remove", `members[value eq "`+memberU1+`"]`, nil)); err != nil {
			t.Fatalf("patch: %v", err)
		}
		if err := s.syncGroupMembers(ctx, memberGrp, before, group.Members); err != nil {
			t.Fatalf("sync: %v", err)
		}

		got := storedMembers(t, db, ctx)
		if len(got) != 1 || got[0] != memberU2 {
			t.Fatalf("stored members = %v, want only %s", got, memberU2)
		}
	})

	t.Run("re-running the same sync is a no-op, not an error", func(t *testing.T) {
		// Okta and Entra retry; a retry that 500s makes a connector look broken.
		if err := s.syncGroupMembers(ctx, memberGrp, members(memberU1, memberU2), members(memberU2)); err != nil {
			t.Fatalf("idempotent re-sync failed: %v", err)
		}
		if got := storedMembers(t, db, ctx); len(got) != 1 {
			t.Errorf("stored members = %v, want 1", got)
		}
	})

	t.Run("a swap in one call keeps the roster consistent", func(t *testing.T) {
		if err := s.syncGroupMembers(ctx, memberGrp, members(memberU2), members(memberU3)); err != nil {
			t.Fatalf("sync: %v", err)
		}
		got := storedMembers(t, db, ctx)
		if len(got) != 1 || got[0] != memberU3 {
			t.Errorf("stored members = %v, want only %s", got, memberU3)
		}
	})

	t.Run("an unknown member is refused as the client's error", func(t *testing.T) {
		unknown := "cccccccc-0000-0000-0000-0000000000ff"
		err := s.syncGroupMembers(ctx, memberGrp, nil, members(unknown))
		if err == nil {
			t.Fatal("adding a non-existent user reported success")
		}
		if status, scimType := scimMemberErrorStatus(err); status != 400 || scimType != "invalidValue" {
			t.Errorf("got %d/%q, want 400/invalidValue (err: %v)", status, scimType, err)
		}
	})
}

func TestGroupMembersAreTenantScoped(t *testing.T) {
	s, db, ctx := newSCIMMemberService(t)

	if err := s.syncGroupMembers(ctx, memberGrp, nil, members(memberU1)); err != nil {
		t.Fatalf("sync: %v", err)
	}

	// The same group id, read as another tenant. The membership row belongs to
	// org A; org B must not see it, and must not be able to detach it.
	orgB := orgctx.With(context.Background(), orgctx.Org{ID: memberOrgB})
	group := &Group{ID: memberGrp, DisplayName: "Engineering"}
	if err := s.loadGroupMembers(orgB, group); err != nil {
		t.Fatalf("load as org B: %v", err)
	}
	if len(group.Members) != 0 {
		t.Errorf("org B read %d of org A's members", len(group.Members))
	}

	// The batched list path has to hold the same line — it is a different query
	// from the single-group read, so it needs its own tenant check.
	batch := []Group{{ID: memberGrp, DisplayName: "Engineering"}}
	if err := s.loadMembersForGroups(orgB, batch); err != nil {
		t.Fatalf("batch load as org B: %v", err)
	}
	if len(batch[0].Members) != 0 {
		t.Errorf("org B read %d of org A's members through the list endpoint", len(batch[0].Members))
	}

	if err := s.syncGroupMembers(orgB, memberGrp, members(memberU1), nil); err != nil {
		t.Fatalf("sync as org B: %v", err)
	}
	if got := storedMembers(t, db, ctx); len(got) != 1 {
		t.Errorf("org A's membership was removed by org B: %v", got)
	}
}

func TestLoadMembersForGroupsBatchesTheWholePage(t *testing.T) {
	s, db, ctx := newSCIMMemberService(t)

	second := "aaaaaaaa-0000-0000-0000-000000000002"
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO groups (id, name, org_id) VALUES ($1, 'Support', $2)`, second, memberOrgA); err != nil {
		t.Fatalf("seed group: %v", err)
	}
	if err := s.syncGroupMembers(ctx, memberGrp, nil, members(memberU1, memberU2)); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if err := s.syncGroupMembers(ctx, second, nil, members(memberU3)); err != nil {
		t.Fatalf("sync: %v", err)
	}

	groups := []Group{
		{ID: memberGrp, DisplayName: "Engineering"},
		{ID: second, DisplayName: "Support"},
		{ID: "aaaaaaaa-0000-0000-0000-0000000000ff", DisplayName: "Empty"},
	}
	if err := s.loadMembersForGroups(ctx, groups); err != nil {
		t.Fatalf("batch load: %v", err)
	}

	if len(groups[0].Members) != 2 {
		t.Errorf("Engineering has %d members, want 2", len(groups[0].Members))
	}
	if len(groups[1].Members) != 1 || groups[1].Members[0].Value != memberU3 {
		t.Errorf("Support members = %+v, want only %s", groups[1].Members, memberU3)
	}
	// A group with no members must come back empty rather than inheriting
	// another group's roster — the failure mode of a mis-keyed batch join.
	if len(groups[2].Members) != 0 {
		t.Errorf("empty group got %d members", len(groups[2].Members))
	}
}
