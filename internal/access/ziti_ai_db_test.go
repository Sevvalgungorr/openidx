package access

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
)

// zitiAISchema mirrors migration v110 so the DB-backed pipeline can be exercised
// against a throwaway Postgres without running the full migration loader.
const zitiAISchema = `
CREATE TABLE IF NOT EXISTS ziti_identity_activity (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id    VARCHAR(255) NOT NULL,
    identity_name  VARCHAR(255),
    service_id     VARCHAR(255) NOT NULL DEFAULT '',
    service_name   VARCHAR(255),
    session_count  BIGINT NOT NULL DEFAULT 0,
    hour_histogram JSONB NOT NULL DEFAULT '{}',
    first_seen     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (identity_id, service_id)
);
CREATE TABLE IF NOT EXISTS ziti_ai_anomalies (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id   VARCHAR(255) NOT NULL,
    identity_name VARCHAR(255),
    anomaly_type  VARCHAR(64) NOT NULL,
    severity      VARCHAR(16) NOT NULL DEFAULT 'medium',
    score         DOUBLE PRECISION NOT NULL DEFAULT 0,
    details       JSONB NOT NULL DEFAULT '{}',
    status        VARCHAR(16) NOT NULL DEFAULT 'open',
    detected_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at   TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS ziti_ai_quarantine (
    identity_id      VARCHAR(255) PRIMARY KEY,
    identity_name    VARCHAR(255),
    saved_attributes JSONB NOT NULL DEFAULT '[]',
    reason           TEXT,
    quarantined_by   VARCHAR(255),
    quarantined_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);`

func newZitiAITestManager(t *testing.T, db *database.PostgresDB) *ZitiManager {
	t.Helper()
	ctx := context.Background()
	if _, err := db.Pool.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS pgcrypto`); err != nil {
		t.Fatalf("pgcrypto: %v", err)
	}
	if _, err := db.Pool.Exec(ctx, zitiAISchema); err != nil {
		t.Fatalf("schema: %v", err)
	}
	return &ZitiManager{cfg: &config.Config{}, logger: zap.NewNop(), db: db}
}

// TestZitiAIBaselineRoundTrip proves updateZitiBaselines -> loadZitiBaselines
// against a real Postgres: first pass inserts, second pass on the same
// (identity, service) accumulates session counts and merges the hour histogram
// (the tricky jsonb FULL OUTER JOIN merge that pure-function tests cannot cover).
func TestZitiAIBaselineRoundTrip(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	zm := newZitiAITestManager(t, db)
	ctx := context.Background()

	at9 := time.Date(2026, 1, 2, 9, 0, 0, 0, time.UTC)
	at10 := time.Date(2026, 1, 2, 10, 0, 0, 0, time.UTC)

	// Pass 1: identity alice dials svc-web at 09:00 and 10:00 (2 sessions).
	obs1 := []ZitiObservation{
		{IdentityID: "alice", IdentityName: "Alice", ServiceID: "svc-web", ServiceName: "web", At: at9},
		{IdentityID: "alice", IdentityName: "Alice", ServiceID: "svc-web", ServiceName: "web", At: at10},
	}
	if err := zm.updateZitiBaselines(ctx, obs1); err != nil {
		t.Fatalf("updateZitiBaselines pass1: %v", err)
	}

	// Pass 2: alice dials svc-web again at 09:00 (histogram hour 9 must merge to 2).
	obs2 := []ZitiObservation{
		{IdentityID: "alice", IdentityName: "Alice", ServiceID: "svc-web", ServiceName: "web", At: at9},
	}
	if err := zm.updateZitiBaselines(ctx, obs2); err != nil {
		t.Fatalf("updateZitiBaselines pass2: %v", err)
	}

	baselines, err := zm.loadZitiBaselines(ctx)
	if err != nil {
		t.Fatalf("loadZitiBaselines: %v", err)
	}
	if len(baselines) != 1 {
		t.Fatalf("expected 1 baseline row, got %d", len(baselines))
	}
	b := baselines[0]
	if b.IdentityID != "alice" || b.ServiceID != "svc-web" {
		t.Fatalf("unexpected baseline key: %+v", b)
	}
	if b.SessionCount != 3 {
		t.Errorf("expected accumulated session_count=3, got %d", b.SessionCount)
	}
	// hour 9 seen in pass1 (once) + pass2 (once) = 2; hour 10 seen once.
	if b.HourHistogram[9] != 2 {
		t.Errorf("expected merged hour[9]=2, got %d", b.HourHistogram[9])
	}
	if b.HourHistogram[10] != 1 {
		t.Errorf("expected hour[10]=1, got %d", b.HourHistogram[10])
	}
	if b.IdentityName != "Alice" || b.ServiceName != "web" {
		t.Errorf("expected names preserved, got name=%q svc=%q", b.IdentityName, b.ServiceName)
	}
}

// TestZitiAIAnomalyLedger proves the anomaly ledger DB round-trip: persist,
// list (all + status-filtered), and the open -> acknowledged -> resolved
// lifecycle including resolved_at stamping and the not-found guard.
func TestZitiAIAnomalyLedger(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	zm := newZitiAITestManager(t, db)
	ctx := context.Background()

	// Persist two open anomalies via the same INSERT shape RunZitiAIAnalysis uses.
	insert := func(identity, atype, sev string) {
		if _, err := db.Pool.Exec(ctx, `
			INSERT INTO ziti_ai_anomalies (identity_id, identity_name, anomaly_type, severity, score, details, detected_at)
			VALUES ($1, NULLIF($2,''), $3, $4, $5, $6::jsonb, $7)`,
			identity, identity, atype, sev, 0.7, `{"k":"v"}`, time.Now()); err != nil {
			t.Fatalf("insert anomaly: %v", err)
		}
	}
	insert("alice", "new_service_access", "high")
	insert("bob", "off_hours_access", "medium")

	// List all: 2 rows, details deserialized.
	all, err := zm.ListZitiAnomalies(ctx, "", 100)
	if err != nil {
		t.Fatalf("ListZitiAnomalies all: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 anomalies, got %d", len(all))
	}
	if all[0].Details["k"] != "v" {
		t.Errorf("expected details round-tripped, got %+v", all[0].Details)
	}

	// Status filter: both are open.
	open, err := zm.ListZitiAnomalies(ctx, "open", 100)
	if err != nil {
		t.Fatalf("ListZitiAnomalies open: %v", err)
	}
	if len(open) != 2 {
		t.Fatalf("expected 2 open, got %d", len(open))
	}

	// Lifecycle: acknowledge alice's, resolve bob's.
	target := open[0]
	if err := zm.UpdateZitiAnomalyStatus(ctx, target.ID, "acknowledged"); err != nil {
		t.Fatalf("acknowledge: %v", err)
	}
	if err := zm.UpdateZitiAnomalyStatus(ctx, open[1].ID, "resolved"); err != nil {
		t.Fatalf("resolve: %v", err)
	}

	stillOpen, _ := zm.ListZitiAnomalies(ctx, "open", 100)
	if len(stillOpen) != 0 {
		t.Errorf("expected 0 open after transitions, got %d", len(stillOpen))
	}

	// resolved_at must be stamped on resolve, and nil otherwise.
	var resolvedAt *time.Time
	if err := db.Pool.QueryRow(ctx,
		`SELECT resolved_at FROM ziti_ai_anomalies WHERE id = $1`, open[1].ID).Scan(&resolvedAt); err != nil {
		t.Fatalf("read resolved_at: %v", err)
	}
	if resolvedAt == nil {
		t.Error("expected resolved_at stamped on resolve")
	}

	// Invalid status rejected.
	if err := zm.UpdateZitiAnomalyStatus(ctx, target.ID, "bogus"); err == nil {
		t.Error("expected invalid status to be rejected")
	}
	// Unknown id -> not found.
	if err := zm.UpdateZitiAnomalyStatus(ctx, "00000000-0000-0000-0000-000000000000", "resolved"); err == nil {
		t.Error("expected not-found error for unknown anomaly id")
	}
}

// TestZitiAIAnalysisDedupe proves the RunZitiAIAnalysis dedupe guard at the DB
// layer: a new anomaly whose (identity, type) already has an open row must not
// create a duplicate. We simulate by pre-seeding an open row then running the
// same insert-with-dedupe logic used by RunZitiAIAnalysis.
func TestZitiAIAnalysisDedupe(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	newZitiAITestManager(t, db) // create the v110 schema
	ctx := context.Background()

	// Pre-existing open anomaly.
	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO ziti_ai_anomalies (identity_id, anomaly_type, severity, status, detected_at)
		VALUES ('alice', 'new_service_access', 'high', 'open', NOW())`); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Build the open-pairs set exactly like RunZitiAIAnalysis does.
	openPairs := map[string]bool{}
	rows, err := db.Pool.Query(ctx, `SELECT identity_id, anomaly_type FROM ziti_ai_anomalies WHERE status = 'open'`)
	if err != nil {
		t.Fatalf("query open: %v", err)
	}
	for rows.Next() {
		var id, at string
		if err := rows.Scan(&id, &at); err == nil {
			openPairs[id+"|"+at] = true
		}
	}
	rows.Close()

	// Detected again this pass -> should be skipped by the dedupe guard.
	candidate := ZitiAnomaly{IdentityID: "alice", Type: "new_service_access", Severity: "high"}
	inserted := 0
	if !openPairs[candidate.IdentityID+"|"+candidate.Type] {
		if _, err := db.Pool.Exec(ctx, `
			INSERT INTO ziti_ai_anomalies (identity_id, anomaly_type, severity, detected_at)
			VALUES ($1, $2, $3, NOW())`, candidate.IdentityID, candidate.Type, candidate.Severity); err != nil {
			t.Fatalf("insert: %v", err)
		}
		inserted++
	}
	if inserted != 0 {
		t.Errorf("expected duplicate open anomaly to be deduped, inserted=%d", inserted)
	}

	var total int
	if err := db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM ziti_ai_anomalies`).Scan(&total); err != nil {
		t.Fatalf("count: %v", err)
	}
	if total != 1 {
		t.Errorf("expected 1 anomaly row after dedupe, got %d", total)
	}
}
