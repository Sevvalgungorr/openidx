package access

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/migrations"
)

// TestMCPToolApprovalFlow exercises the PAM C5 HITL gate helpers against a
// migrated DB: a require_approval tool call opens a pending approval bound to
// the request body; the wrong body cannot consume it; approving lets the exact
// call proceed exactly once (single-use); a different body needs its own
// approval.
func TestMCPToolApprovalFlow(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool, zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	const org = "00000000-0000-0000-0000-000000000010"

	// Seed an MCP server + a require_approval policy for the agent client.
	var serverID string
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO mcp_servers (org_id, name, upstream_url)
		VALUES ($1::uuid, 'deploy-mcp', 'http://localhost:1')
		RETURNING id::text`, org).Scan(&serverID); err != nil {
		t.Fatalf("seed server: %v", err)
	}
	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO mcp_tool_policies (org_id, server_id, principal, tool, require_approval)
		VALUES ($1::uuid, $2::uuid, 'client:agent1', 'deploy', true)`, org, serverID); err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	s := &Service{db: db, logger: zap.NewNop()}
	roles := []string{}
	body := []byte(`{"env":"prod","service":"api"}`)

	// require_approval is detected.
	if !s.toolRequiresApproval(ctx, serverID, "agent1", roles, "deploy") {
		t.Fatal("expected deploy to require approval")
	}
	// A non-sensitive tool does not.
	if s.toolRequiresApproval(ctx, serverID, "agent1", roles, "list") {
		t.Fatal("list should not require approval")
	}

	// No approval yet → cannot consume.
	if ok, err := s.consumeApprovedToolCall(ctx, serverID, "deploy", "agent1", body); err != nil || ok {
		t.Fatalf("consume before approval: ok=%v err=%v", ok, err)
	}

	// Open a pending approval; idempotent for the same body.
	id, status, err := s.createOrGetPendingToolApproval(ctx, org, serverID, "deploy", "agent1", "sub1", body)
	if err != nil || status != "pending" {
		t.Fatalf("create approval: id=%s status=%s err=%v", id, status, err)
	}
	id2, _, _ := s.createOrGetPendingToolApproval(ctx, org, serverID, "deploy", "agent1", "sub1", body)
	if id2 != id {
		t.Fatalf("expected idempotent pending approval, got %s vs %s", id2, id)
	}

	// Approve it.
	if _, err := db.Pool.Exec(ctx,
		`UPDATE mcp_tool_approvals SET status='approved', decided_at=NOW() WHERE id=$1`, id); err != nil {
		t.Fatalf("approve: %v", err)
	}

	// The wrong body must NOT consume the approval.
	if ok, _ := s.consumeApprovedToolCall(ctx, serverID, "deploy", "agent1", []byte(`{"env":"staging"}`)); ok {
		t.Fatal("a different body should not consume the approval")
	}

	// The exact body consumes it once.
	if ok, err := s.consumeApprovedToolCall(ctx, serverID, "deploy", "agent1", body); err != nil || !ok {
		t.Fatalf("consume approved: ok=%v err=%v", ok, err)
	}
	// Single-use: a second consume fails.
	if ok, _ := s.consumeApprovedToolCall(ctx, serverID, "deploy", "agent1", body); ok {
		t.Fatal("approval should be single-use")
	}
}
