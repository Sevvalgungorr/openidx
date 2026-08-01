package migrations

// Migration v120 — link an enrolled agent to a Windows app host.
//
// P3 of Windows Application Delivery is agent-based discovery: the OpenIDX
// agent installed on an RDS host runs Prepare-OpenIDXAppHost.ps1 -Report and
// posts the resulting discoveryReport JSON back, so the app catalog stays in
// sync without an admin pasting it by hand. For that report to route to the
// right host (and the right tenant), the agent must be bound to the
// windows_app_host pam_entries row it prepares.
//
// This adds a nullable windows_app_host_entry_id FK on enrolled_agents. An
// admin sets it (an org-scoped action that verifies the entry is a
// windows_app_host in their tenant); the public agent-report endpoint then
// resolves the host + its org_id from this column and writes discovered apps +
// host posture exactly as the paste-import path does. enrolled_agents is a
// global fleet table (no org_id), so the tenant is derived from the linked
// entry, not stored here. ON DELETE SET NULL so deleting the host entry simply
// unlinks the agent rather than orphaning it. Additive + idempotent; agents
// stay unlinked (NULL) until an admin binds them, so nothing changes for
// existing fleets.
var agentWindowsAppHostUp = `-- Migration 120: bind an enrolled agent to a Windows app host for discovery.
ALTER TABLE enrolled_agents
    ADD COLUMN IF NOT EXISTS windows_app_host_entry_id UUID
    REFERENCES pam_entries(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_enrolled_agents_windows_app_host
    ON enrolled_agents (windows_app_host_entry_id)
    WHERE windows_app_host_entry_id IS NOT NULL;
`

var agentWindowsAppHostDown = `-- Rollback 120.
DROP INDEX IF EXISTS idx_enrolled_agents_windows_app_host;
ALTER TABLE enrolled_agents DROP COLUMN IF EXISTS windows_app_host_entry_id;
`
