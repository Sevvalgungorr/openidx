package audit

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

// setupConsentMetricsTestDB creates a throwaway PostgreSQL container for the
// consent-metrics tests. Named distinctly so it cannot collide with other DB
// harnesses landing in this package from parallel branches.
func setupConsentMetricsTestDB(t *testing.T) (*database.PostgresDB, func()) {
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

// TestGetConsentMetrics_RealTable guards the GDPR gap fix: consent metrics
// read the real user_consents table (org-scoped) instead of the phantom
// `consent_records` table whose guaranteed error was silently swallowed and
// forced ComplianceStatus to non_compliant on every install.
func TestGetConsentMetrics_RealTable(t *testing.T) {
	db, cleanup := setupConsentMetricsTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()
	// Mirrors user_consents (v32 base + org_id from v34).
	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE user_consents (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			user_id UUID NOT NULL,
			consent_type VARCHAR(100) NOT NULL,
			version VARCHAR(50) NOT NULL DEFAULT '1.0',
			granted BOOLEAN NOT NULL,
			granted_at TIMESTAMPTZ,
			revoked_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ DEFAULT NOW(),
			org_id UUID NOT NULL
		);
	`); err != nil {
		t.Fatalf("schema: %v", err)
	}

	const (
		orgA  = "00000000-0000-0000-0000-00000000000a"
		orgB  = "00000000-0000-0000-0000-00000000000b"
		orgC  = "00000000-0000-0000-0000-00000000000c" // no rows
		userA = "11111111-0000-0000-0000-00000000000a"
		userB = "11111111-0000-0000-0000-00000000000b"
	)
	seed := func(user, ctype string, granted bool, revoked bool, org string) {
		var revokedAt interface{}
		if revoked {
			revokedAt = time.Now()
		}
		if _, err := db.Pool.Exec(ctx, `
			INSERT INTO user_consents (user_id, consent_type, granted, granted_at, revoked_at, org_id)
			VALUES ($1, $2, $3, NOW(), $4, $5)
		`, user, ctype, granted, revokedAt, org); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	seed(userA, "marketing", true, false, orgA) // active
	seed(userA, "analytics", true, true, orgA)  // withdrawn
	seed(userB, "marketing", true, false, orgB) // other org

	s := &Service{db: db, logger: zap.NewNop()}

	// Org A: 2 records, 1 active, 1 withdrawn, compliant, real timestamp.
	mA := s.getConsentMetrics(orgctx.With(context.Background(), orgctx.Org{ID: orgA}))
	if mA.TotalConsentRecords != 2 || mA.ActiveConsents != 1 || mA.WithdrawnConsents != 1 {
		t.Fatalf("org A metrics: got total=%d active=%d withdrawn=%d", mA.TotalConsentRecords, mA.ActiveConsents, mA.WithdrawnConsents)
	}
	if mA.ComplianceStatus != "compliant" {
		t.Fatalf("org A status: want compliant, got %s", mA.ComplianceStatus)
	}
	if mA.LastConsentUpdate.Before(time.Now().Add(-time.Hour)) {
		t.Fatalf("org A LastConsentUpdate should be recent, got %v", mA.LastConsentUpdate)
	}

	// Org B sees only its own record — no cross-tenant bleed.
	mB := s.getConsentMetrics(orgctx.With(context.Background(), orgctx.Org{ID: orgB}))
	if mB.TotalConsentRecords != 1 || mB.ActiveConsents != 1 || mB.WithdrawnConsents != 0 {
		t.Fatalf("org B metrics: got total=%d active=%d withdrawn=%d", mB.TotalConsentRecords, mB.ActiveConsents, mB.WithdrawnConsents)
	}

	// An org with genuinely zero consents is non_compliant — but that verdict
	// now comes from real data, not from a swallowed query error.
	mC := s.getConsentMetrics(orgctx.With(context.Background(), orgctx.Org{ID: orgC}))
	if mC.TotalConsentRecords != 0 || mC.ComplianceStatus != "non_compliant" {
		t.Fatalf("org C: want 0/non_compliant, got %d/%s", mC.TotalConsentRecords, mC.ComplianceStatus)
	}

	// The key-rotation metric's new source query executes against the real
	// audit_events table (was: phantom key_rotation_events).
	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE audit_events (id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			event_type VARCHAR(100), timestamp TIMESTAMPTZ DEFAULT NOW(), org_id UUID);
	`); err != nil {
		t.Fatalf("audit_events schema: %v", err)
	}
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO audit_events (event_type, org_id) VALUES ('key_rotation', $1)`, orgA); err != nil {
		t.Fatalf("seed audit_events: %v", err)
	}
	var lastRotation time.Time
	if err := db.Pool.QueryRow(ctx, `
		SELECT COALESCE(MAX(timestamp), '1970-01-01'::timestamptz)
		FROM audit_events
		WHERE event_type = 'key_rotation' AND org_id = $1
	`, orgA).Scan(&lastRotation); err != nil {
		t.Fatalf("key-rotation query: %v", err)
	}
	if lastRotation.Before(time.Now().Add(-time.Hour)) {
		t.Fatalf("key rotation timestamp should be recent, got %v", lastRotation)
	}
}
