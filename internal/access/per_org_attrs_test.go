package access

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
)

// TestSanitizeAttr verifies that arbitrary strings are coerced into the
// Ziti-legal role-attribute charset ([A-Za-z0-9._-]).
func TestSanitizeAttr(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"engineers", "engineers"},
		{"Sales-Team_1", "Sales-Team_1"},
		{"platform.eng", "platform.eng"},
		{"finance & ops", "finance---ops"},
		{"a/b\\c", "a-b-c"},
		{"", ""},
	}
	for _, c := range cases {
		if got := sanitizeAttr(c.in); got != c.want {
			t.Errorf("sanitizeAttr(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestOrgScopedAttr verifies per-org namespacing: a non-empty org yields an
// org-prefixed attribute; a nil/empty org falls back to the bare (sanitized)
// name so global groups keep their existing service policies.
func TestOrgScopedAttr(t *testing.T) {
	org := "11111111-2222-3333-4444-555555555555"
	empty := ""

	if got := orgScopedAttr(&org, "engineers"); got != "org-"+org+"-engineers" {
		t.Errorf("org-scoped: got %q", got)
	}
	if got := orgScopedAttr(nil, "engineers"); got != "engineers" {
		t.Errorf("nil org should fall back to bare name, got %q", got)
	}
	if got := orgScopedAttr(&empty, "engineers"); got != "engineers" {
		t.Errorf("empty org should fall back to bare name, got %q", got)
	}

	// Two tenants with an identically named group must NOT collide.
	orgA := "aaaaaaaa-0000-0000-0000-000000000000"
	orgB := "bbbbbbbb-0000-0000-0000-000000000000"
	if orgScopedAttr(&orgA, "admins") == orgScopedAttr(&orgB, "admins") {
		t.Error("identical group names in different orgs must map to distinct attributes")
	}
}

// TestGetUserGroupNamesPerOrg proves the flag actually changes what the
// user-sync engine emits: OFF -> bare group names (back-compat), ON ->
// org-namespaced attributes that isolate identically named cross-tenant groups.
func TestGetUserGroupNamesPerOrg(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	schema := `
	CREATE TABLE groups (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		name TEXT NOT NULL,
		org_id UUID
	);
	CREATE TABLE group_memberships (
		group_id UUID NOT NULL,
		user_id UUID NOT NULL
	);`
	if _, err := db.Pool.Exec(ctx, schema); err != nil {
		t.Fatalf("schema: %v", err)
	}

	orgA := "aaaaaaaa-0000-0000-0000-000000000000"
	orgB := "bbbbbbbb-0000-0000-0000-000000000000"
	userA := "11111111-0000-0000-0000-000000000000"
	userB := "22222222-0000-0000-0000-000000000000"

	// Both orgs have an "engineers" group; each user belongs to their own.
	var gA, gB string
	if err := db.Pool.QueryRow(ctx,
		`INSERT INTO groups (name, org_id) VALUES ('engineers', $1) RETURNING id`, orgA).Scan(&gA); err != nil {
		t.Fatalf("insert group A: %v", err)
	}
	if err := db.Pool.QueryRow(ctx,
		`INSERT INTO groups (name, org_id) VALUES ('engineers', $1) RETURNING id`, orgB).Scan(&gB); err != nil {
		t.Fatalf("insert group B: %v", err)
	}
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO group_memberships (group_id, user_id) VALUES ($1,$2),($3,$4)`,
		gA, userA, gB, userB); err != nil {
		t.Fatalf("insert memberships: %v", err)
	}

	// Flag OFF: bare names, so both users get "engineers" (the collision A2 fixes).
	zmOff := &ZitiManager{db: db, logger: zap.NewNop(), cfg: &config.Config{ZitiPerOrgAttributes: false}}
	offA, err := zmOff.getUserGroupNames(ctx, userA)
	if err != nil {
		t.Fatalf("off userA: %v", err)
	}
	if len(offA) != 1 || offA[0] != "engineers" {
		t.Fatalf("flag off should yield bare name, got %v", offA)
	}

	// Flag ON: org-namespaced, so the two tenants no longer collide.
	zmOn := &ZitiManager{db: db, logger: zap.NewNop(), cfg: &config.Config{ZitiPerOrgAttributes: true}}
	onA, err := zmOn.getUserGroupNames(ctx, userA)
	if err != nil {
		t.Fatalf("on userA: %v", err)
	}
	onB, err := zmOn.getUserGroupNames(ctx, userB)
	if err != nil {
		t.Fatalf("on userB: %v", err)
	}
	if len(onA) != 1 || onA[0] != "org-"+orgA+"-engineers" {
		t.Fatalf("flag on userA got %v", onA)
	}
	if len(onB) != 1 || onB[0] != "org-"+orgB+"-engineers" {
		t.Fatalf("flag on userB got %v", onB)
	}
	if onA[0] == onB[0] {
		t.Fatal("per-org attributes must isolate identically named cross-tenant groups")
	}
}

// TestOrgMarkerAttr proves the bare org marker used by per-org Dial policies is
// stable, sanitized, and distinct per org — so a tenant's identities match only
// their own org's openidx-orgdial-* policy.
func TestOrgMarkerAttr(t *testing.T) {
	orgA := "aaaaaaaa-0000-0000-0000-000000000000"
	orgB := "bbbbbbbb-0000-0000-0000-000000000000"

	if got := orgMarkerAttr(orgA); got != "org-"+orgA {
		t.Errorf("orgMarkerAttr(%q) = %q", orgA, got)
	}
	if orgMarkerAttr(orgA) == orgMarkerAttr(orgB) {
		t.Error("distinct orgs must yield distinct markers")
	}
	// Charset coercion (Ziti-legal attribute).
	if got := orgMarkerAttr("weird/org id"); got != "org-weird-org-id" {
		t.Errorf("marker not sanitized: %q", got)
	}
	// The marker prefix matches the group-attribute prefix, so a per-org Dial
	// policy on #org-<id> and a group attr org-<id>-<group> share the tenant scope.
	group := orgScopedAttr(&orgA, "engineers")
	marker := orgMarkerAttr(orgA)
	if len(group) < len(marker) || group[:len(marker)] != marker {
		t.Errorf("group attr %q should start with marker %q", group, marker)
	}
}

// TestUserOrgID proves the per-org marker source: buildUserAttributes stamps the
// identity with the user's own org (org-<id>) when the flag is on, so the
// reconciler's per-org Dial policy grants only that tenant's services.
func TestUserOrgID(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE users (
			id UUID PRIMARY KEY,
			org_id UUID,
			username TEXT,
			enabled BOOLEAN DEFAULT true
		);`); err != nil {
		t.Fatalf("schema: %v", err)
	}
	orgA := "aaaaaaaa-0000-0000-0000-000000000000"
	userA := "11111111-0000-0000-0000-000000000000"
	userNoOrg := "22222222-0000-0000-0000-000000000000"
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO users (id, org_id, username) VALUES ($1,$2,'a'),($3,NULL,'b')`,
		userA, orgA, userNoOrg); err != nil {
		t.Fatalf("insert: %v", err)
	}

	zm := &ZitiManager{db: db, logger: zap.NewNop(), cfg: &config.Config{ZitiPerOrgAttributes: true}}
	if got := zm.userOrgID(ctx, userA); got != orgA {
		t.Errorf("userOrgID(userA) = %q, want %q", got, orgA)
	}
	if got := zm.userOrgID(ctx, userNoOrg); got != "" {
		t.Errorf("userOrgID(null-org) = %q, want empty", got)
	}
	if got := zm.userOrgID(ctx, "99999999-0000-0000-0000-000000000000"); got != "" {
		t.Errorf("userOrgID(missing) = %q, want empty", got)
	}
	// The marker built from that org matches what a per-org Dial policy grants.
	if orgMarkerAttr(zm.userOrgID(ctx, userA)) != "org-"+orgA {
		t.Error("marker from userOrgID must equal org-<id>")
	}
}
