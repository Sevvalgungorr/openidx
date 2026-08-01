package portal

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

// setupPortalTestDB creates a throwaway PostgreSQL container for DB-backed
// portal tests. Named distinctly so it cannot collide with harnesses landing
// in this package from parallel branches.
func setupPortalTestDB(t *testing.T) (*database.PostgresDB, func()) {
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

	connString := "postgres://test:test@" + host + ":" + port.Port() + "/testdb?sslmode=disable"

	db, err := database.NewPostgres(connString)
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

// TestRegisterDevice_OrgScoped guards the mis-tenanting fix: RegisterDevice
// must stamp the caller's org onto the row instead of relying on the
// known_devices.org_id column DEFAULT (the primary org), and re-registration
// must heal a previously mis-tenanted row.
func TestRegisterDevice_OrgScoped(t *testing.T) {
	db, cleanup := setupPortalTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()
	const (
		defaultOrg = "00000000-0000-0000-0000-000000000010"
		orgA       = "00000000-0000-0000-0000-00000000000a"
		userA      = "11111111-0000-0000-0000-00000000000a"
	)
	// Mirrors production known_devices: org_id carries the primary-org DEFAULT
	// that was silently applied before this fix.
	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE known_devices (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			user_id UUID NOT NULL,
			fingerprint VARCHAR(128) NOT NULL,
			name VARCHAR(255),
			ip_address VARCHAR(45),
			user_agent TEXT,
			location VARCHAR(255),
			trusted BOOLEAN DEFAULT false,
			last_seen_at TIMESTAMPTZ DEFAULT NOW(),
			created_at TIMESTAMPTZ DEFAULT NOW(),
			org_id UUID NOT NULL DEFAULT '`+defaultOrg+`',
			UNIQUE(user_id, fingerprint)
		);
	`); err != nil {
		t.Fatalf("schema: %v", err)
	}

	s := &Service{db: db, logger: zap.NewNop()}

	// Without an org in context registration must fail closed, not fall back
	// to the column default.
	if _, err := s.RegisterDevice(ctx, userA, "Laptop", "fp-1", "10.0.0.1", "UA", "loc"); err == nil {
		t.Fatal("RegisterDevice without org context: want error, got nil")
	}

	ctxA := orgctx.With(context.Background(), orgctx.Org{ID: orgA})
	dev, err := s.RegisterDevice(ctxA, userA, "Laptop", "fp-1", "10.0.0.1", "UA", "loc")
	if err != nil {
		t.Fatalf("RegisterDevice(org A): %v", err)
	}

	var gotOrg string
	if err := db.Pool.QueryRow(ctx,
		`SELECT org_id::text FROM known_devices WHERE id = $1`, dev.ID,
	).Scan(&gotOrg); err != nil {
		t.Fatalf("read row: %v", err)
	}
	if gotOrg != orgA {
		t.Fatalf("registered device org: want %s (caller's org), got %s", orgA, gotOrg)
	}

	// A pre-fix row mis-tenanted to the default org is healed on
	// re-registration of the same (user, fingerprint).
	if _, err := db.Pool.Exec(ctx,
		`UPDATE known_devices SET org_id = $1 WHERE id = $2`, defaultOrg, dev.ID); err != nil {
		t.Fatalf("simulate mis-tenanted row: %v", err)
	}
	if _, err := s.RegisterDevice(ctxA, userA, "Laptop-renamed", "fp-1", "10.0.0.2", "UA2", "loc2"); err != nil {
		t.Fatalf("re-register: %v", err)
	}
	if err := db.Pool.QueryRow(ctx,
		`SELECT org_id::text FROM known_devices WHERE user_id = $1 AND fingerprint = 'fp-1'`, userA,
	).Scan(&gotOrg); err != nil {
		t.Fatalf("read healed row: %v", err)
	}
	if gotOrg != orgA {
		t.Fatalf("healed device org: want %s, got %s", orgA, gotOrg)
	}
}
