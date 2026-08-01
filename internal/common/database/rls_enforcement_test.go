package database

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/testsupport"
)

// startPostgresOrSkip boots a throwaway Postgres for this test, skipping when
// no container runtime is available (see testsupport.StartContainerOrSkip for
// why that path needs a recover rather than an error check).
func startPostgresOrSkip(t *testing.T, ctx context.Context) testcontainers.Container {
	t.Helper()

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
			WithStartupTimeout(60 * time.Second),
	}
	return testsupport.RunOrSkip(t, req.Image, func() (testcontainers.Container, error) {
		return testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: req,
			Started:          true,
		})
	})
}

// TestRLSEnforcedEndToEnd is the backstop the tenant-isolation design was
// missing: it proves that the FORCE-RLS belt actually filters rows in Postgres,
// not just that rlsValuesFromContext computes the right GUC values.
//
// Everything else in the isolation story is verified somewhere — the GUC
// mapping by TestRLSValuesFromContext, the org predicates by tools/orgscope —
// but nothing exercised the database end of it. That gap is exactly how the
// SSF tables shipped with no policy at all (fixed in migration v121): the app
// layer looked scoped, the lint had nothing to say, and no test would have
// noticed the missing belt.
//
// Two details make this test meaningful rather than decorative:
//
//   - It connects as a NON-SUPERUSER role. Superusers bypass RLS entirely, so
//     running this as the container's default user would pass no matter what.
//   - It uses the real configureRLS checkout hook against a real pool, so a
//     regression in the hook (not just in the policy) fails the test.
func TestRLSEnforcedEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed RLS test in -short mode")
	}

	ctx := context.Background()

	container := startPostgresOrSkip(t, ctx)
	defer func() { _ = container.Terminate(ctx) }()

	host, err := container.Host(ctx)
	if err != nil {
		t.Skipf("could not resolve container host: %v", err)
	}
	port, err := container.MappedPort(ctx, "5432")
	if err != nil {
		t.Skipf("could not resolve container port: %v", err)
	}

	const (
		orgA = "aaaaaaaa-0000-0000-0000-000000000001"
		orgB = "bbbbbbbb-0000-0000-0000-000000000002"
	)

	// Admin connection: build the tenant-scoped table exactly the way the v37
	// belt does, plus a non-superuser role for the pool under test.
	adminDSN := fmt.Sprintf("postgres://test:test@%s:%s/testdb?sslmode=disable", host, port.Port())
	admin, err := pgxpool.New(ctx, adminDSN)
	if err != nil {
		t.Fatalf("admin pool: %v", err)
	}
	defer admin.Close()

	setup := []string{
		`CREATE TABLE tenant_rows (
		     id     BIGSERIAL PRIMARY KEY,
		     org_id UUID NOT NULL,
		     note   TEXT NOT NULL)`,
		// The standard belt policy: bypass marker OR matching org. An empty
		// app.org_id yields NULL, so the predicate matches nothing.
		`CREATE POLICY pol_tenant_rows_org_scope ON tenant_rows
		     USING (current_setting('app.bypass_rls', true) = 'on'
		            OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)`,
		`ALTER TABLE tenant_rows ENABLE ROW LEVEL SECURITY`,
		`ALTER TABLE tenant_rows FORCE  ROW LEVEL SECURITY`,
		fmt.Sprintf(`INSERT INTO tenant_rows (org_id, note) VALUES ('%s','a-secret'), ('%s','b-secret')`, orgA, orgB),
		// RLS does not apply to superusers, so the pool under test must log in
		// as an ordinary role for this test to prove anything.
		`CREATE ROLE openidx_app LOGIN PASSWORD 'app_secret'`,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_rows TO openidx_app`,
		`GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO openidx_app`,
	}
	for _, stmt := range setup {
		if _, err := admin.Exec(ctx, stmt); err != nil {
			t.Fatalf("setup failed (%s): %v", stmt, err)
		}
	}

	// The pool under test: ordinary role + the production RLS checkout hook.
	appDSN := fmt.Sprintf("postgres://openidx_app:app_secret@%s:%s/testdb?sslmode=disable", host, port.Port())
	cfg, err := pgxpool.ParseConfig(appDSN)
	if err != nil {
		t.Fatalf("parse app dsn: %v", err)
	}
	configureRLS(cfg)
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("app pool: %v", err)
	}
	defer pool.Close()

	// notesFor runs an intentionally UNSCOPED query — no org_id predicate at
	// all. Whatever comes back is what row-level security alone permits, which
	// is the whole point: this is what protects a query that forgot its filter.
	notesFor := func(t *testing.T, reqCtx context.Context) []string {
		t.Helper()
		rows, err := pool.Query(reqCtx, `SELECT note FROM tenant_rows ORDER BY note`)
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var note string
			if err := rows.Scan(&note); err != nil {
				t.Fatalf("scan: %v", err)
			}
			out = append(out, note)
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("rows: %v", err)
		}
		return out
	}

	t.Run("org A sees only its own row", func(t *testing.T) {
		got := notesFor(t, orgctx.With(ctx, orgctx.Org{ID: orgA, Slug: "a"}))
		if len(got) != 1 || got[0] != "a-secret" {
			t.Fatalf("cross-tenant leak: got %v, want [a-secret]", got)
		}
	})

	t.Run("org B sees only its own row", func(t *testing.T) {
		got := notesFor(t, orgctx.With(ctx, orgctx.Org{ID: orgB, Slug: "b"}))
		if len(got) != 1 || got[0] != "b-secret" {
			t.Fatalf("cross-tenant leak: got %v, want [b-secret]", got)
		}
	})

	t.Run("unresolved tenant sees nothing (fail-closed)", func(t *testing.T) {
		got := notesFor(t, ctx) // no orgctx at all
		if len(got) != 0 {
			t.Fatalf("unscoped request must see no rows, got %v", got)
		}
	})

	t.Run("explicit bypass sees every tenant", func(t *testing.T) {
		got := notesFor(t, orgctx.WithBypassRLS(ctx))
		if len(got) != 2 {
			t.Fatalf("background bypass should see both rows, got %v", got)
		}
	})

	t.Run("a write cannot be attributed to another tenant", func(t *testing.T) {
		// The policy doubles as the INSERT check (no separate WITH CHECK), so
		// org A cannot plant a row belonging to org B.
		aCtx := orgctx.With(ctx, orgctx.Org{ID: orgA, Slug: "a"})
		if _, err := pool.Exec(aCtx,
			`INSERT INTO tenant_rows (org_id, note) VALUES ($1,'planted')`, orgB); err == nil {
			t.Fatal("expected RLS to reject an insert attributed to another tenant")
		}
	})
}
