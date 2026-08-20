package access

import (
	"context"
	"testing"

	"go.uber.org/zap"
)

// enrolledAgentsSchema is the minimal enrolled_agents table (with the v92
// device_fingerprint column + partial unique index) needed to exercise
// issueAgentCredentials idempotency.
var enrolledAgentsSchema = []string{
	`CREATE TABLE IF NOT EXISTS enrolled_agents (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		agent_id TEXT UNIQUE NOT NULL,
		device_id TEXT NOT NULL,
		ziti_identity_id TEXT,
		status TEXT NOT NULL DEFAULT 'active',
		auth_token_hash TEXT,
		enrolled_at TIMESTAMPTZ DEFAULT NOW(),
		last_seen_at TIMESTAMPTZ,
		last_report_at TIMESTAMPTZ,
		compliance_status TEXT NOT NULL DEFAULT 'unknown',
		compliance_score DOUBLE PRECISION,
		metadata JSONB,
		created_by TEXT,
		platform TEXT,
		form_factor TEXT,
		is_device_owner BOOLEAN NOT NULL DEFAULT false,
		enrollment_method TEXT,
		enrolled_by_user_id UUID,
		management_mode TEXT,
		known_device_id UUID,
		device_fingerprint TEXT
	)`,
	`CREATE UNIQUE INDEX IF NOT EXISTS enrolled_agents_device_fingerprint_key
		ON enrolled_agents (device_fingerprint) WHERE device_fingerprint IS NOT NULL`,
}

// TestEnrollIdempotentByFingerprint is the regression test for the "one agent
// per physical device" fix: two enrollments carrying the same
// device_fingerprint must reuse a single agent_id / row (rotating only the auth
// token), instead of piling up a new enrolled_agents row per install.
func TestEnrollIdempotentByFingerprint(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	for _, stmt := range enrolledAgentsSchema {
		if _, err := db.Pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("schema: %v", err)
		}
	}

	h := NewAgentAPIHandler(zap.NewNop(), db, nil, nil)
	req := enrollRequest{
		Hostname:          "DANA-PC",
		OS:                "windows",
		Platform:          "windows",
		DeviceFingerprint: "win:abc123",
	}

	first := h.issueAgentCredentials(ctx, req, "token", "")
	if first.AgentID == "" {
		t.Fatal("first enroll returned empty agent_id")
	}
	second := h.issueAgentCredentials(ctx, req, "token", "")

	if second.AgentID != first.AgentID {
		t.Errorf("re-enroll minted a new agent_id: %q then %q", first.AgentID, second.AgentID)
	}
	if second.DeviceID != first.DeviceID {
		t.Errorf("re-enroll changed device_id: %q then %q", first.DeviceID, second.DeviceID)
	}
	if second.AuthToken == "" || second.AuthToken == first.AuthToken {
		t.Errorf("re-enroll should rotate the auth token (got %q, prev %q)", second.AuthToken, first.AuthToken)
	}

	var rows int
	if err := db.Pool.QueryRow(ctx,
		`SELECT count(*) FROM enrolled_agents WHERE device_fingerprint = $1`, req.DeviceFingerprint).
		Scan(&rows); err != nil {
		t.Fatalf("count: %v", err)
	}
	if rows != 1 {
		t.Errorf("expected exactly 1 row for the fingerprint, got %d", rows)
	}
}

// TestEnrollDistinctFingerprintsDistinctAgents confirms different devices still
// get different agent_ids (the idempotency is scoped to the fingerprint).
func TestEnrollDistinctFingerprintsDistinctAgents(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	for _, stmt := range enrolledAgentsSchema {
		if _, err := db.Pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("schema: %v", err)
		}
	}
	h := NewAgentAPIHandler(zap.NewNop(), db, nil, nil)

	a := h.issueAgentCredentials(ctx, enrollRequest{Hostname: "A", DeviceFingerprint: "win:aaa"}, "token", "")
	b := h.issueAgentCredentials(ctx, enrollRequest{Hostname: "B", DeviceFingerprint: "win:bbb"}, "token", "")
	if a.AgentID == b.AgentID {
		t.Errorf("distinct fingerprints shared an agent_id: %q", a.AgentID)
	}

	// And a legacy enroll (no fingerprint) always gets a fresh row.
	c1 := h.issueAgentCredentials(ctx, enrollRequest{Hostname: "C"}, "token", "")
	c2 := h.issueAgentCredentials(ctx, enrollRequest{Hostname: "C"}, "token", "")
	if c1.AgentID == c2.AgentID {
		t.Errorf("legacy fingerprint-less enroll should NOT dedupe: %q", c1.AgentID)
	}
}
