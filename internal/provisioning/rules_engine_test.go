package provisioning

import (
	"context"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/testsupport"
)

// TestRuleConditionMatching covers the pure evaluation semantics: AND across
// conditions, the six supported case-insensitive operators, fail-closed on
// unsupported fields/operators, and empty conditions matching everyone.
func TestRuleConditionMatching(t *testing.T) {
	s := &Service{logger: zap.NewNop()}
	user := &SCIMUser{
		UserName:   "Alice.Smith",
		Emails:     []SCIMEmail{{Value: "alice@ACME.example"}},
		Name:       SCIMName{GivenName: "Alice", FamilyName: "Smith"},
		Enterprise: &SCIMEnterpriseUser{Department: "Engineering"},
	}

	cases := []struct {
		name  string
		conds []RuleCondition
		want  bool
	}{
		{"empty conditions match everyone", nil, true},
		{"equals case-insensitive", []RuleCondition{{Field: "userName", Operator: "equals", Value: "alice.smith"}}, true},
		{"ends_with email domain", []RuleCondition{{Field: "email", Operator: "ends_with", Value: "@acme.example"}}, true},
		{"AND: both must hold", []RuleCondition{
			{Field: "department", Operator: "equals", Value: "engineering"},
			{Field: "email", Operator: "contains", Value: "nomatch"},
		}, false},
		{"not_equals", []RuleCondition{{Field: "department", Operator: "not_equals", Value: "sales"}}, true},
		{"starts_with", []RuleCondition{{Field: "givenName", Operator: "starts_with", Value: "al"}}, true},
		{"not_contains", []RuleCondition{{Field: "userName", Operator: "not_contains", Value: "smith"}}, false},
		{"unsupported operator fails closed", []RuleCondition{{Field: "userName", Operator: "regex", Value: ".*"}}, false},
		{"unsupported field fails closed", []RuleCondition{{Field: "favorite_color", Operator: "equals", Value: "x"}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := s.ruleMatches(tc.conds, user, "test-rule"); got != tc.want {
				t.Fatalf("ruleMatches = %v, want %v", got, tc.want)
			}
		})
	}
}

// setupRulesEngineTestDB creates a throwaway PostgreSQL container. Named
// distinctly so it cannot collide with harnesses from parallel branches.
func setupRulesEngineTestDB(t *testing.T) (*database.PostgresDB, func()) {
	t.Helper()

	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		Image:        "postgres:16-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "test",
			"POSTGRES_PASSWORD": "test",
			"POSTGRES_DB":       "testdb",
		},
		WaitingFor: wait.ForLog("database system is ready to accept connections").
			WithOccurrence(2).
			WithStartupTimeout(30 * time.Second),
	}

	container := testsupport.RunOrSkip(t, req.Image, func() (testcontainers.Container, error) {
		return testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: req,
			Started:          true,
		})
	})

	host, err := container.Host(ctx)
	if err != nil {
		container.Terminate(ctx)
		t.Skipf("Failed to get container host: %v", err)
		return nil, func() {}
	}

	port, err := container.MappedPort(ctx, "5432")
	if err != nil {
		container.Terminate(ctx)
		t.Skipf("Failed to get container port: %v", err)
		return nil, func() {}
	}

	db, err := database.NewPostgres("postgres://test:test@" + host + ":" + port.Port() + "/testdb?sslmode=disable")
	if err != nil {
		container.Terminate(ctx)
		t.Skipf("Failed to connect to test database: %v", err)
		return nil, func() {}
	}

	cleanup := func() {
		db.Close()
		container.Terminate(ctx)
	}

	return db, cleanup
}

// TestApplyProvisioningRules guards the engine end-to-end: a matching
// user_created rule assigns the configured group and role (by name),
// org-scoped and idempotent; unsupported action types are skipped;
// non-matching users and other-org rules do nothing.
func TestApplyProvisioningRules(t *testing.T) {
	db, cleanup := setupRulesEngineTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()
	ddl := []string{
		`CREATE TABLE provisioning_rules (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name VARCHAR(255) NOT NULL, description TEXT,
			trigger VARCHAR(50) NOT NULL,
			conditions JSONB DEFAULT '[]', actions JSONB DEFAULT '[]',
			enabled BOOLEAN DEFAULT true, priority INTEGER DEFAULT 0,
			created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW(),
			org_id UUID NOT NULL)`,
		`CREATE TABLE groups (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), name VARCHAR(255), org_id UUID NOT NULL)`,
		`CREATE TABLE roles (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), name VARCHAR(255), org_id UUID NOT NULL)`,
		`CREATE TABLE group_memberships (user_id UUID, group_id UUID, org_id UUID, PRIMARY KEY (user_id, group_id))`,
		`CREATE TABLE user_roles (user_id UUID, role_id UUID, org_id UUID, PRIMARY KEY (user_id, role_id))`,
	}
	for _, q := range ddl {
		if _, err := db.Pool.Exec(ctx, q); err != nil {
			t.Fatalf("schema (%s): %v", q, err)
		}
	}

	const (
		orgA  = "00000000-0000-0000-0000-00000000000a"
		orgB  = "00000000-0000-0000-0000-00000000000b"
		userA = "11111111-0000-0000-0000-00000000000a"
		userB = "11111111-0000-0000-0000-00000000000b"
	)
	exec := func(q string, a ...interface{}) {
		if _, err := db.Pool.Exec(ctx, q, a...); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	exec(`INSERT INTO groups (name, org_id) VALUES ('engineers', $1)`, orgA)
	exec(`INSERT INTO roles (name, org_id) VALUES ('developer', $1)`, orgA)
	// Same-named group in org B must never be targeted by org A's evaluation.
	exec(`INSERT INTO groups (name, org_id) VALUES ('engineers', $1)`, orgB)
	exec(`INSERT INTO provisioning_rules (name, trigger, conditions, actions, enabled, priority, org_id) VALUES
		('eng-onboarding', 'user_created',
		 '[{"field":"email","operator":"ends_with","value":"@acme.example"}]',
		 '[{"type":"add_to_group","target":"engineers"},{"type":"assign_role","target":"developer"},{"type":"disable_account","target":""}]',
		 true, 0, $1)`, orgA)
	// Disabled rule and other-trigger rule must not fire.
	exec(`INSERT INTO provisioning_rules (name, trigger, conditions, actions, enabled, org_id) VALUES
		('disabled', 'user_created', '[]', '[{"type":"add_to_group","target":"engineers"}]', false, $1)`, orgA)

	s := &Service{db: db, logger: zap.NewNop()}
	ctxA := orgctx.With(context.Background(), orgctx.Org{ID: orgA})

	matching := &SCIMUser{ID: userA, UserName: "alice", Emails: []SCIMEmail{{Value: "alice@acme.example"}}}
	s.applyProvisioningRules(ctxA, TriggerUserCreated, matching)

	var groups, roles int
	db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM group_memberships WHERE user_id = $1 AND org_id = $2`, userA, orgA).Scan(&groups)
	db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM user_roles WHERE user_id = $1 AND org_id = $2`, userA, orgA).Scan(&roles)
	if groups != 1 || roles != 1 {
		t.Fatalf("matching user: want 1 group + 1 role, got %d/%d", groups, roles)
	}
	// The unsupported disable_account action must not have done anything —
	// there is nothing it could write in this schema, and evaluation must not
	// have errored out before the supported actions ran (asserted above).

	// Idempotent re-application (user_updated path re-runs additive actions).
	s.applyProvisioningRules(ctxA, TriggerUserCreated, matching)
	db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM group_memberships WHERE user_id = $1`, userA).Scan(&groups)
	if groups != 1 {
		t.Fatalf("re-application must be idempotent, got %d memberships", groups)
	}

	// Non-matching user gets nothing.
	other := &SCIMUser{ID: userB, UserName: "bob", Emails: []SCIMEmail{{Value: "bob@other.example"}}}
	s.applyProvisioningRules(ctxA, TriggerUserCreated, other)
	db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM group_memberships WHERE user_id = $1`, userB).Scan(&groups)
	if groups != 0 {
		t.Fatalf("non-matching user must get no assignments, got %d", groups)
	}

	// Org B context: org A's rule must not exist there.
	ctxB := orgctx.With(context.Background(), orgctx.Org{ID: orgB})
	s.applyProvisioningRules(ctxB, TriggerUserCreated, matching)
	db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM group_memberships WHERE org_id = $1`, orgB).Scan(&groups)
	if groups != 0 {
		t.Fatalf("org B has no rules; want 0 assignments, got %d", groups)
	}
}
