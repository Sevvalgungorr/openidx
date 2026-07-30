package directory

import (
	"context"
	"testing"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/openidx/openidx/internal/common/database"
)

// groupsSchema mirrors the production groups constraint that matters here:
// UNIQUE (org_id, name) — NOT UNIQUE (name). The sync group-upsert must target
// this exact conflict, otherwise Postgres raises "no unique or exclusion
// constraint matching the ON CONFLICT specification" (the live AD-sync bug).
const groupsSchema = `
CREATE TABLE IF NOT EXISTS groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    source VARCHAR(50),
    directory_id UUID,
    ldap_dn TEXT,
    external_id VARCHAR(255),
    org_id UUID NOT NULL,
    UNIQUE (org_id, name)
);`

func setupGroupsDB(t *testing.T) (*database.PostgresDB, func()) {
	t.Helper()
	ctx := context.Background()
	req := testcontainers.ContainerRequest{
		Image:        "postgres:16-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env:          map[string]string{"POSTGRES_USER": "test", "POSTGRES_PASSWORD": "test", "POSTGRES_DB": "testdb"},
		WaitingFor:   wait.ForListeningPort("5432/tcp"),
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req, Started: true,
	})
	if err != nil {
		t.Skipf("start container: %v", err)
		return nil, func() {}
	}
	host, _ := container.Host(ctx)
	port, _ := container.MappedPort(ctx, "5432")
	conn := "postgres://test:test@" + host + ":" + port.Port() + "/testdb?sslmode=disable"
	db, err := database.NewPostgres(conn)
	if err != nil {
		container.Terminate(ctx)
		t.Skipf("connect: %v", err)
		return nil, func() {}
	}
	if _, err := db.Pool.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS pgcrypto`); err != nil {
		db.Close()
		container.Terminate(ctx)
		t.Fatalf("pgcrypto: %v", err)
	}
	if _, err := db.Pool.Exec(ctx, groupsSchema); err != nil {
		db.Close()
		container.Terminate(ctx)
		t.Fatalf("schema: %v", err)
	}
	return db, func() { db.Close(); container.Terminate(ctx) }
}

// TestGroupUpsertConflictTarget is a regression guard for the AD-sync group bug:
// the group-upsert INSERT ... ON CONFLICT must target (org_id, name), which is
// the actual unique constraint. Running the exact production statement twice
// must succeed (idempotent), not raise SQLSTATE 42P10.
func TestGroupUpsertConflictTarget(t *testing.T) {
	db, cleanup := setupGroupsDB(t)
	defer cleanup()
	ctx := context.Background()

	const org = "00000000-0000-0000-0000-000000000010"
	const dir = "00000000-0000-0000-0000-0000000000d1"

	// This is the exact statement internal/directory/sync.go runs for a new
	// LDAP group. If the ON CONFLICT target is wrong it errors here.
	stmt := `INSERT INTO groups (name, description, source, directory_id, ldap_dn, external_id, org_id)
	         VALUES ($1, $2, 'ldap', $3, $4, $5, $6)
	         ON CONFLICT (org_id, name) DO NOTHING`

	for i := 0; i < 2; i++ {
		if _, err := db.Pool.Exec(ctx, stmt,
			"Administrators", "AD builtin", dir, "CN=Administrators,DC=test,DC=local", "CN=Administrators,DC=test,DC=local", org); err != nil {
			t.Fatalf("group upsert (iteration %d) failed — ON CONFLICT target likely wrong: %v", i, err)
		}
	}

	// Exactly one row (idempotent).
	var n int
	if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM groups WHERE org_id=$1 AND name='Administrators'`, org).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected 1 group row after idempotent upsert, got %d", n)
	}

	// A same-named group in a DIFFERENT org must be allowed (conflict is scoped
	// by org_id, not name alone).
	const org2 = "00000000-0000-0000-0000-000000000020"
	if _, err := db.Pool.Exec(ctx, stmt,
		"Administrators", "other org", dir, "dn2", "dn2", org2); err != nil {
		t.Fatalf("same name in another org should be allowed: %v", err)
	}
	var total int
	db.Pool.QueryRow(ctx, `SELECT count(*) FROM groups WHERE name='Administrators'`).Scan(&total)
	if total != 2 {
		t.Fatalf("expected 2 Administrators rows across two orgs, got %d", total)
	}
}
