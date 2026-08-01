package risk

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

// setupRiskDeviceTestDB creates a throwaway PostgreSQL container for the risk
// device-tracking tests. Named distinctly so it cannot collide with harnesses
// landing in this package from parallel branches.
func setupRiskDeviceTestDB(t *testing.T) (*database.PostgresDB, func()) {
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

// TestRiskDeviceTracking_RealColumns guards the v76 fix: risk device tracking
// reads/writes the columns known_devices actually has (seen_count added by
// v76; created_at/last_seen_at instead of the never-created
// first_seen/last_seen). Pre-fix, the new-device INSERT failed on every call
// and the whole device-trust progression was dead.
func TestRiskDeviceTracking_RealColumns(t *testing.T) {
	db, cleanup := setupRiskDeviceTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()
	// Mirrors known_devices post-v76 (v19 base + org_id + device_type + seen_count).
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
			org_id UUID NOT NULL,
			device_type VARCHAR(50),
			seen_count INTEGER NOT NULL DEFAULT 1,
			UNIQUE(user_id, fingerprint)
		);
	`); err != nil {
		t.Fatalf("schema: %v", err)
	}

	const (
		orgA  = "00000000-0000-0000-0000-00000000000a"
		orgB  = "00000000-0000-0000-0000-00000000000b"
		userA = "11111111-0000-0000-0000-00000000000a"
	)
	now := time.Now()

	// The exact new-device INSERT from GetOrRegisterDevice (keep in sync with
	// internal/risk/device.go) must succeed against the real schema.
	var newID string
	if err := db.Pool.QueryRow(ctx,
		`INSERT INTO known_devices (user_id, fingerprint, name, ip_address, user_agent, seen_count, created_at, last_seen_at, trusted, org_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		 RETURNING id`,
		userA, "fp-new", "Chrome on Mac", "10.0.0.1", "UA", 1, now, now, false, orgA).Scan(&newID); err != nil {
		t.Fatalf("new-device INSERT (the pre-fix guaranteed failure): %v", err)
	}

	// The exact seen-again UPDATE must succeed too.
	if _, err := db.Pool.Exec(ctx,
		`UPDATE known_devices
		 SET seen_count = $2, last_seen_at = $3, ip_address = $4, user_agent = $5
		 WHERE id = $1 AND org_id = $6`,
		newID, 2, now, "10.0.0.2", "UA2", orgA); err != nil {
		t.Fatalf("seen-again UPDATE: %v", err)
	}

	// Seed a trusted, frequently-seen device for the trust-level read.
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO known_devices (user_id, fingerprint, name, seen_count, trusted, org_id)
		 VALUES ($1, 'fp-old', 'Laptop', 50, true, $2)`, userA, orgA); err != nil {
		t.Fatalf("seed: %v", err)
	}

	f := NewDeviceFingerprinter(db, nil, DefaultFingerprintingConfig(), zap.NewNop())
	ctxA := orgctx.With(context.Background(), orgctx.Org{ID: orgA})
	ctxB := orgctx.With(context.Background(), orgctx.Org{ID: orgB})

	// GetUserDevices reads seen_count and maps created_at/last_seen_at onto
	// FirstSeen/LastSeen.
	devices, err := f.GetUserDevices(ctxA, userA)
	if err != nil {
		t.Fatalf("GetUserDevices: %v", err)
	}
	if len(devices) != 2 {
		t.Fatalf("want 2 devices, got %d", len(devices))
	}
	for _, d := range devices {
		if d.SeenCount < 1 || d.FirstSeen.IsZero() || d.LastSeen.IsZero() {
			t.Fatalf("device %s: seen_count/first/last not populated: %+v", d.Fingerprint, d)
		}
	}

	// Trust level derives from the (now real) seen_count column.
	if lvl := f.GetDeviceTrustLevel(ctxA, userA, "fp-old"); lvl != TrustLevelTrusted {
		t.Fatalf("fp-old: want trusted, got %v", lvl)
	}
	if lvl := f.GetDeviceTrustLevel(ctxA, userA, "fp-unknown"); lvl != TrustLevelUnknown {
		t.Fatalf("fp-unknown: want unknown, got %v", lvl)
	}

	// Cross-org: org B sees none of org A's devices.
	if got, err := f.GetUserDevices(ctxB, userA); err != nil || len(got) != 0 {
		t.Fatalf("cross-org: want 0 devices, got %d (err %v)", len(got), err)
	}
}
