package audit

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/testsupport"
)

// setupDetailedReportsTestDB creates a throwaway PostgreSQL container for the
// detailed-compliance-reports tests. Named distinctly so it cannot collide
// with other DB harnesses landing in this package from parallel branches.
func setupDetailedReportsTestDB(t *testing.T) (*database.PostgresDB, func()) {
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

// TestDetailedComplianceReports_StoreAndOrgScope guards the v74 fix: detailed
// compliance reports persist into the (previously phantom)
// detailed_compliance_reports table, storeDetailedReport surfaces errors and
// is org-scoped, and the evidence read never crosses tenants.
func TestDetailedComplianceReports_StoreAndOrgScope(t *testing.T) {
	db, cleanup := setupDetailedReportsTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()
	// Schema mirrors migration v74 (+ a minimal organizations parent for the FK).
	ddl := []string{
		`CREATE TABLE organizations (id UUID PRIMARY KEY, name VARCHAR(255))`,
		`CREATE TABLE detailed_compliance_reports (
			id UUID PRIMARY KEY,
			org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
			framework VARCHAR(50) NOT NULL,
			period VARCHAR(255),
			generated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			overall_score DOUBLE PRECISION NOT NULL DEFAULT 0,
			summary TEXT,
			report_data JSONB NOT NULL
		)`,
	}
	for _, q := range ddl {
		if _, err := db.Pool.Exec(ctx, q); err != nil {
			t.Fatalf("schema (%s): %v", q, err)
		}
	}

	const (
		orgA     = "00000000-0000-0000-0000-00000000000a"
		orgB     = "00000000-0000-0000-0000-00000000000b"
		reportID = "dddddddd-0000-0000-0000-000000000001"
	)
	for _, org := range []string{orgA, orgB} {
		if _, err := db.Pool.Exec(ctx, `INSERT INTO organizations (id, name) VALUES ($1, $2)`, org, "org-"+org); err != nil {
			t.Fatalf("seed org: %v", err)
		}
	}

	s := &Service{db: db, logger: zap.NewNop()}
	report := &DetailedComplianceReport{
		ID:           reportID,
		Framework:    "SOC 2 Type II",
		Period:       "2026-01-01 to 2026-06-30",
		GeneratedAt:  time.Now(),
		OverallScore: 87.5,
		Summary:      "test summary",
		Controls: []ControlAssessment{
			{ControlID: "CC1", Name: "Control Environment", Status: "compliant", Score: 87.5},
		},
	}

	// Without an org in context the store must fail closed, not write an
	// unscoped row.
	if err := s.storeDetailedReport(ctx, report); err == nil {
		t.Fatal("storeDetailedReport without org context: want error, got nil")
	}

	ctxA := orgctx.With(context.Background(), orgctx.Org{ID: orgA})
	if err := s.storeDetailedReport(ctxA, report); err != nil {
		t.Fatalf("storeDetailedReport(org A): %v", err)
	}
	// Idempotent re-store of the same report id (ON CONFLICT DO NOTHING).
	if err := s.storeDetailedReport(ctxA, report); err != nil {
		t.Fatalf("storeDetailedReport(org A, repeat): %v", err)
	}

	var gotOrg, gotFramework string
	if err := db.Pool.QueryRow(ctx,
		`SELECT org_id::text, framework FROM detailed_compliance_reports WHERE id = $1`,
		reportID,
	).Scan(&gotOrg, &gotFramework); err != nil {
		t.Fatalf("stored row: %v", err)
	}
	if gotOrg != orgA || gotFramework != "SOC 2 Type II" {
		t.Fatalf("stored row: got org=%s framework=%s", gotOrg, gotFramework)
	}

	// The evidence read (handleDownloadEvidence's primary query) is scoped by
	// id AND org_id: org B must not fetch org A's evidence package.
	var reportJSON []byte
	err := db.Pool.QueryRow(ctx, `
		SELECT report_data
		FROM detailed_compliance_reports
		WHERE id = $1 AND org_id = $2
	`, reportID, orgB).Scan(&reportJSON)
	if err != pgx.ErrNoRows {
		t.Fatalf("cross-org evidence read: want ErrNoRows, got err=%v data=%s", err, reportJSON)
	}
	if err := db.Pool.QueryRow(ctx, `
		SELECT report_data
		FROM detailed_compliance_reports
		WHERE id = $1 AND org_id = $2
	`, reportID, orgA).Scan(&reportJSON); err != nil {
		t.Fatalf("same-org evidence read: %v", err)
	}
	if len(reportJSON) == 0 {
		t.Fatal("same-org evidence read returned empty report_data")
	}
}
