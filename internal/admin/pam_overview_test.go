package admin

import (
	"context"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/testsupport"
	"github.com/openidx/openidx/internal/migrations"
)

// setupPAMTestDB creates a throwaway PostgreSQL container (same pattern as the
// internal/access test harness) and migrates it to latest.
func setupPAMTestDB(t *testing.T) (*database.PostgresDB, func()) {
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

	if err := migrations.NewMigrator(db.Pool, zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		db.Close()
		container.Terminate(ctx)
		t.Fatalf("migrate to latest: %v", err)
	}

	return db, func() {
		db.Close()
		container.Terminate(context.Background())
	}
}

// TestAggregatePAMOverview proves the PAM overview aggregation counts vault
// inventory, rotation health, checkout activity, and privileged-session state
// for the given org only (an org-B secret must not leak into org-A totals; the
// container superuser bypasses RLS so the explicit org_id predicates carry
// the scoping here).
func TestAggregatePAMOverview(t *testing.T) {
	db, cleanup := setupPAMTestDB(t) // skips if testcontainers unavailable
	defer cleanup()

	ctx := context.Background()
	const orgA = "00000000-0000-0000-0000-000000000010" // seeded by migrations
	const orgB = "00000000-0000-0000-0000-0000000000aa"

	// Second org for the isolation check.
	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO organizations (id, name, slug)
		VALUES ($1::uuid, 'Org B', 'org-b') ON CONFLICT DO NOTHING`, orgB); err != nil {
		t.Fatalf("seed org B: %v", err)
	}

	// Vault inventory: two passwords + one ssh_key in org A, one in org B.
	var secretID string
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO vault_secrets (org_id, name, type) VALUES
			($1::uuid, 'db-admin',   'password'),
			($1::uuid, 'app-svc',    'password'),
			($1::uuid, 'bastion-key','ssh_key')
		RETURNING id::text`, orgA).Scan(&secretID); err != nil {
		t.Fatalf("seed vault secrets: %v", err)
	}
	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO vault_secrets (org_id, name, type) VALUES ($1::uuid, 'other-org', 'password')`,
		orgB); err != nil {
		t.Fatalf("seed org B secret: %v", err)
	}

	// Rotation: one enabled+overdue+failing policy; one succeeded and one failed run in the window.
	var policyID string
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO credential_rotation_policies
			(org_id, secret_id, connector_type, enabled, next_run_at, last_status)
		VALUES ($1::uuid, $2::uuid, 'generate_only', true, NOW() - INTERVAL '1 hour', 'failed')
		RETURNING id::text`, orgA, secretID).Scan(&policyID); err != nil {
		t.Fatalf("seed rotation policy: %v", err)
	}
	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO credential_rotations (org_id, policy_id, secret_id, connector_type, status, started_at)
		VALUES ($1::uuid, $2::uuid, $3::uuid, 'generate_only', 'succeeded', NOW() - INTERVAL '2 days'),
		       ($1::uuid, $2::uuid, $3::uuid, 'generate_only', 'failed',    NOW() - INTERVAL '1 day'),
		       ($1::uuid, $2::uuid, $3::uuid, 'generate_only', 'succeeded', NOW() - INTERVAL '60 days')`,
		orgA, policyID, secretID); err != nil {
		t.Fatalf("seed rotation runs: %v", err)
	}

	// Checkouts: one live lease, one expired, one returned long ago (outside 30d).
	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO vault_checkouts (org_id, secret_id, secret_version, mode, status, leased_at, expires_at)
		VALUES ($1::uuid, $2::uuid, 1, 'reveal', 'active',   NOW(),                     NOW() + INTERVAL '15 minutes'),
		       ($1::uuid, $2::uuid, 1, 'reveal', 'expired',  NOW() - INTERVAL '1 day',  NOW() - INTERVAL '23 hours'),
		       ($1::uuid, $2::uuid, 1, 'reveal', 'returned', NOW() - INTERVAL '45 days', NOW() - INTERVAL '44 days')`,
		orgA, secretID); err != nil {
		t.Fatalf("seed checkouts: %v", err)
	}

	// One pending JIT credential request (+ one pending role request that must not count).
	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO access_requests (org_id, requester_id, resource_type, resource_id, status)
		VALUES ($1::uuid, gen_random_uuid(), 'vault_credential', $2::uuid, 'pending'),
		       ($1::uuid, gen_random_uuid(), 'role',             gen_random_uuid(), 'pending')`,
		orgA, secretID); err != nil {
		t.Fatalf("seed access requests: %v", err)
	}

	// Sessions: one active, one ended with an unreleased legal hold; one pending request.
	var heldSessionID string
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO guacamole_sessions (org_id, connection_id, status, started_at, ended_at, recording_path)
		VALUES ($1::uuid, gen_random_uuid(), 'ended', NOW() - INTERVAL '2 hours', NOW() - INTERVAL '1 hour', '/rec/x')
		RETURNING id::text`, orgA).Scan(&heldSessionID); err != nil {
		t.Fatalf("seed ended session: %v", err)
	}
	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO guacamole_sessions (org_id, connection_id, status) VALUES ($1::uuid, gen_random_uuid(), 'active')`,
		orgA); err != nil {
		t.Fatalf("seed active session: %v", err)
	}
	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO guacamole_recording_legal_holds (session_id, reason) VALUES ($1::uuid, 'litigation')`,
		heldSessionID); err != nil {
		t.Fatalf("seed legal hold: %v", err)
	}
	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO guacamole_session_requests (org_id, connection_id, requester_id, status, expires_at)
		VALUES ($1::uuid, gen_random_uuid(), gen_random_uuid(), 'pending', NOW() + INTERVAL '1 hour')`,
		orgA); err != nil {
		t.Fatalf("seed session request: %v", err)
	}

	s := &Service{db: db, logger: zap.NewNop()}
	o, err := s.aggregatePAMOverview(ctx, orgA)
	if err != nil {
		t.Fatalf("aggregatePAMOverview: %v", err)
	}

	if o.Secrets.Total != 3 {
		t.Errorf("secrets.total = %d, want 3 (org B secret must not count)", o.Secrets.Total)
	}
	if o.Secrets.ByType["password"] != 2 || o.Secrets.ByType["ssh_key"] != 1 {
		t.Errorf("secrets.by_type = %v, want password:2 ssh_key:1", o.Secrets.ByType)
	}
	if o.Rotation.Policies != 1 || o.Rotation.PoliciesEnabled != 1 ||
		o.Rotation.PoliciesFailing != 1 || o.Rotation.PoliciesOverdue != 1 {
		t.Errorf("rotation = %+v, want policies/enabled/failing/overdue all 1", o.Rotation)
	}
	if o.Rotation.Runs30d != 2 || o.Rotation.Failures30d != 1 {
		t.Errorf("rotation runs = %d/%d failures, want 2/1 (60-day-old run outside window)",
			o.Rotation.Runs30d, o.Rotation.Failures30d)
	}
	if o.Checkouts.ActiveLeases != 1 {
		t.Errorf("checkouts.active_leases = %d, want 1", o.Checkouts.ActiveLeases)
	}
	if o.Checkouts.Checkouts30d != 2 {
		t.Errorf("checkouts.checkouts_30d = %d, want 2 (45-day-old lease outside window)", o.Checkouts.Checkouts30d)
	}
	if o.Checkouts.PendingCredentialRequests != 1 {
		t.Errorf("checkouts.pending_credential_requests = %d, want 1 (role request must not count)",
			o.Checkouts.PendingCredentialRequests)
	}
	if o.Sessions.ActiveSessions != 1 || o.Sessions.Sessions30d != 2 ||
		o.Sessions.PendingRequests != 1 || o.Sessions.RecordingsOnHold != 1 {
		t.Errorf("sessions = %+v, want active:1 30d:2 pending:1 on_hold:1", o.Sessions)
	}
}
