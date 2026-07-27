package audit

import (
	"context"
	"testing"

	"github.com/openidx/openidx/internal/common/config"
	"go.uber.org/zap"
)

const meteringSchema = `
CREATE TABLE IF NOT EXISTS users (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), org_id UUID);
CREATE TABLE IF NOT EXISTS unified_audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), source VARCHAR(50) NOT NULL,
    event_type VARCHAR(100) NOT NULL, route_id UUID, user_id UUID, actor_ip VARCHAR(45),
    details JSONB DEFAULT '{}', created_at TIMESTAMPTZ DEFAULT NOW());
CREATE TABLE IF NOT EXISTS usage_metering_daily (
    id BIGSERIAL PRIMARY KEY, org_id UUID, user_id UUID, service VARCHAR(255) NOT NULL DEFAULT '',
    metric VARCHAR(64) NOT NULL, day DATE NOT NULL, count BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE (org_id, user_id, service, metric, day));
CREATE TABLE IF NOT EXISTS usage_metering_cursor (
    id INT PRIMARY KEY DEFAULT 1, last_ts TIMESTAMPTZ NOT NULL DEFAULT 'epoch', last_id UUID,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), CONSTRAINT usage_metering_cursor_singleton CHECK (id = 1));
INSERT INTO usage_metering_cursor (id) VALUES (1) ON CONFLICT (id) DO NOTHING;`

func TestUsageMeteringAggregation(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	db.Pool.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS pgcrypto`)
	if _, err := db.Pool.Exec(ctx, meteringSchema); err != nil {
		t.Fatalf("schema: %v", err)
	}

	orgA := "00000000-0000-0000-0000-0000000000aa"
	var uA string
	db.Pool.QueryRow(ctx, `INSERT INTO users (org_id) VALUES ($1) RETURNING id`, orgA).Scan(&uA)

	// Seed fabric events: 2 overlay logins + 3 service dials (2 to svc-x, 1 svc-y).
	// Anchor every event to a fixed midday-UTC instant on the current day so the
	// daily rollup buckets deterministically. Using NOW()-based offsets is flaky
	// near a UTC midnight boundary (events straddle two days -> split counters).
	base := "(date_trunc('day', now() at time zone 'utc') at time zone 'utc' + interval '12 hours')"
	db.Pool.Exec(ctx, `INSERT INTO unified_audit_events (source, event_type, user_id, details, created_at) VALUES
        ('ziti','ziti.api_session.created',$1,'{}'::jsonb, `+base+` - interval '2 hours'),
        ('ziti','ziti.api_session.created',$1,'{}'::jsonb, `+base+` - interval '1 hour'),
        ('ziti','ziti.service.dialed',$1,'{"service":"svc-x"}'::jsonb, `+base+` - interval '90 minutes'),
        ('ziti','ziti.service.dialed',$1,'{"service":"svc-x"}'::jsonb, `+base+` - interval '30 minutes'),
        ('ziti','ziti.service.dialed',$1,'{"service":"svc-y"}'::jsonb, `+base+` - interval '10 minutes'),
        ('agent','agent.report',$1,'{}'::jsonb, `+base+`)`, uA)

	svc := &Service{db: db, logger: zap.NewNop(), config: &config.Config{}}
	w := &meteringWorker{svc: svc, logger: zap.NewNop()}

	n, err := w.aggregateBatch(ctx)
	if err != nil {
		t.Fatalf("aggregateBatch: %v", err)
	}
	// 5 ziti events processed (the agent event is filtered out).
	if n != 5 {
		t.Fatalf("expected 5 ziti events rolled up, got %d", n)
	}

	// Overlay logins: 2 for the day.
	var logins int64
	db.Pool.QueryRow(ctx,
		`SELECT count FROM usage_metering_daily WHERE metric='overlay_login' AND org_id=$1`, orgA).Scan(&logins)
	if logins != 2 {
		t.Errorf("expected 2 overlay logins, got %d", logins)
	}
	// Service dials: svc-x=2, svc-y=1.
	var svcx, svcy int64
	db.Pool.QueryRow(ctx,
		`SELECT count FROM usage_metering_daily WHERE metric='service_dial' AND service='svc-x' AND org_id=$1`, orgA).Scan(&svcx)
	db.Pool.QueryRow(ctx,
		`SELECT count FROM usage_metering_daily WHERE metric='service_dial' AND service='svc-y' AND org_id=$1`, orgA).Scan(&svcy)
	if svcx != 2 {
		t.Errorf("expected svc-x dials=2, got %d", svcx)
	}
	if svcy != 1 {
		t.Errorf("expected svc-y dials=1, got %d", svcy)
	}

	// A second pass processes nothing (cursor advanced).
	n2, _ := w.aggregateBatch(ctx)
	if n2 != 0 {
		t.Errorf("expected 0 on second pass (cursor advanced), got %d", n2)
	}

	// A new event after the cursor rolls up incrementally (idempotent counter).
	// Place it 1 minute past the base anchor so it is strictly after the cursor
	// and still lands in the same UTC day as the rest of the batch.
	db.Pool.Exec(ctx, `INSERT INTO unified_audit_events (source, event_type, user_id, details, created_at) VALUES
        ('ziti','ziti.service.dialed',$1,'{"service":"svc-x"}'::jsonb, `+base+` + interval '1 minute')`, uA)
	w.aggregateBatch(ctx)
	db.Pool.QueryRow(ctx,
		`SELECT count FROM usage_metering_daily WHERE metric='service_dial' AND service='svc-x' AND org_id=$1`, orgA).Scan(&svcx)
	if svcx != 3 {
		t.Errorf("expected svc-x dials=3 after incremental event, got %d", svcx)
	}
}
