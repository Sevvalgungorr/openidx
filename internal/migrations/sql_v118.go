package migrations

// Migration v118 — AI-agent tool-call approval (PAM C5).
//
// The MCP gateway (internal/access/mcp_gateway.go) lets AI agents invoke tools
// on brokered MCP servers, gated by a per-(principal, tool) allowlist. C5 adds
// human-in-the-loop (HITL) approval for SENSITIVE tools: a policy can mark a
// tool require_approval, and the gateway then pauses the invocation until a
// human approves it — the AI-agent equivalent of privileged-access approval,
// with every decision on the audit trail.
//
// Two additive changes:
//
//  1. mcp_tool_policies.require_approval — per-policy flag (default false, so
//     existing allowlist entries invoke immediately as before).
//
//  2. mcp_tool_approvals — the pending-approval ledger: pending → approved /
//     denied / expired. A single-use approval token lets the agent retry the
//     exact call once a human approves.
var mcpToolApprovalUp = `-- Migration 118: AI-agent tool-call approval (HITL).

ALTER TABLE mcp_tool_policies
    ADD COLUMN IF NOT EXISTS require_approval BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS mcp_tool_approvals (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        UUID,
    server_id     UUID NOT NULL,
    tool          VARCHAR(255) NOT NULL,
    client_id     VARCHAR(255) NOT NULL,
    subject       VARCHAR(255),
    request_hash  VARCHAR(64) NOT NULL,   -- sha256 of the invocation body, binds the approval to one call
    status        VARCHAR(16) NOT NULL DEFAULT 'pending', -- pending|approved|denied|expired|consumed
    approver_id   VARCHAR(255),
    reason        TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    decided_at    TIMESTAMPTZ,
    expires_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_mcp_tool_approvals_pending
    ON mcp_tool_approvals (server_id, status)
    WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS idx_mcp_tool_approvals_org_status
    ON mcp_tool_approvals (org_id, status);

ALTER TABLE mcp_tool_approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE mcp_tool_approvals FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS mcp_tool_approvals_isolation ON mcp_tool_approvals;
CREATE POLICY mcp_tool_approvals_isolation ON mcp_tool_approvals
    USING (
        current_setting('app.bypass_rls', true) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', true) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid
    );
`

var mcpToolApprovalDown = `-- Rollback 118: drop AI-agent tool-call approval.
DROP TABLE IF EXISTS mcp_tool_approvals;
ALTER TABLE mcp_tool_policies DROP COLUMN IF EXISTS require_approval;
`
