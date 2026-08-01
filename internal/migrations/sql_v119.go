package migrations

// Migration v119 — Windows application delivery (app catalog + pools).
//
// Turns "an RDP entry with a magic remote-app settings key" into a real app
// catalog. An app *host* stays a normal pam_entries row (new entry_type
// windows_app_host, kind session, protocol rdp) so it inherits vault
// injection, linked credentials, Ziti reach, recording, approval, grants and
// checkout controls unchanged. This migration adds only the app/pool layer on
// top:
//
//   - windows_app_pools         a named set of interchangeable hosts
//   - windows_app_pool_members  host membership + per-host session capacity
//   - windows_apps              a published app, bound to one host OR one pool
//   - windows_app_host_state    posture snapshot from the prep/discovery script
//
// Placement (choosing which host in a pool serves a launch) is done in Go
// against pam_entry_sessions liveness; the schema only records capacity and
// membership. Every table is org-scoped under the v37 FORCE-RLS belt. Plain
// statements only — the runner's splitSQL cannot handle DO $$ blocks.
var windowsAppsUp = `-- Migration 119: Windows application delivery — pools, members, apps, host posture state.

CREATE TABLE IF NOT EXISTS windows_app_pools (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID NOT NULL,
    name        VARCHAR(255) NOT NULL,
    description TEXT,
    -- how a launch picks a host among the members with free capacity
    placement   VARCHAR(16) NOT NULL DEFAULT 'least_loaded'
                CHECK (placement IN ('least_loaded','round_robin')),
    created_by  UUID,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_windows_app_pools_org ON windows_app_pools(org_id);

CREATE TABLE IF NOT EXISTS windows_app_pool_members (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        UUID NOT NULL,
    pool_id       UUID NOT NULL REFERENCES windows_app_pools(id) ON DELETE CASCADE,
    host_entry_id UUID NOT NULL REFERENCES pam_entries(id) ON DELETE CASCADE,
    -- max concurrent RemoteApp sessions this host serves. 1 for a Windows
    -- 10/11 desktop edition (single session); higher for Windows Server + RDS.
    max_sessions  INTEGER NOT NULL DEFAULT 1 CHECK (max_sessions >= 1),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, pool_id, host_entry_id)
);
CREATE INDEX IF NOT EXISTS idx_windows_app_pool_members_pool ON windows_app_pool_members(pool_id);
CREATE INDEX IF NOT EXISTS idx_windows_app_pool_members_host ON windows_app_pool_members(host_entry_id);

CREATE TABLE IF NOT EXISTS windows_apps (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        UUID NOT NULL,
    -- an app targets exactly one host OR one pool (enforced by the CHECK below)
    host_entry_id UUID REFERENCES pam_entries(id) ON DELETE CASCADE,
    pool_id       UUID REFERENCES windows_app_pools(id) ON DELETE CASCADE,
    alias         VARCHAR(255) NOT NULL,   -- the TSAppAllowList alias (no "||" prefix)
    display_name  VARCHAR(255) NOT NULL,
    exec_path     TEXT,                    -- Path/ShortPath as published (may be an App-V launcher path)
    args          TEXT,
    working_dir   TEXT,
    icon_png      BYTEA,                   -- small (<= few KB); validated app-side
    -- deterministic per-app Guacamole connection id (pam-<host>-app-<id>)
    guac_connection_id VARCHAR(255),
    source        VARCHAR(16) NOT NULL DEFAULT 'manual'
                  CHECK (source IN ('manual','discovered')),
    -- set only when the alias was seen in the host's TSAppAllowList (published & launchable)
    verified_at   TIMESTAMPTZ,
    -- active | inconsistent (pool members disagree on what this alias resolves to)
    status        VARCHAR(16) NOT NULL DEFAULT 'active'
                  CHECK (status IN ('active','inconsistent','disabled')),
    -- per-app policy overrides. NULL = inherit the host entry. Enforced in Go
    -- to only TIGHTEN (a host requiring approval cannot be loosened per-app).
    require_approval BOOLEAN,
    record_session   BOOLEAN,
    created_by    UUID,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT windows_apps_one_target CHECK ((host_entry_id IS NULL) <> (pool_id IS NULL))
);
CREATE INDEX IF NOT EXISTS idx_windows_apps_org  ON windows_apps(org_id);
CREATE INDEX IF NOT EXISTS idx_windows_apps_host ON windows_apps(host_entry_id);
CREATE INDEX IF NOT EXISTS idx_windows_apps_pool ON windows_apps(pool_id);
-- one alias per host (per-host apps). Pool apps are unique per pool via the app row.
CREATE UNIQUE INDEX IF NOT EXISTS uq_windows_apps_host_alias
    ON windows_apps(org_id, host_entry_id, alias) WHERE host_entry_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_windows_apps_pool_alias
    ON windows_apps(org_id, pool_id, alias) WHERE pool_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS windows_app_host_state (
    org_id                          UUID NOT NULL,
    host_entry_id                   UUID NOT NULL REFERENCES pam_entries(id) ON DELETE CASCADE,
    os_edition                      VARCHAR(128),
    nla_enabled                     BOOLEAN,
    -- the dangerous shortcut: 1 lets ANY program run as a RemoteApp (incl.
    -- cmd.exe). Surfaced as a prominent console warning; OpenIDX never sets it.
    allow_unlisted_remote_programs  BOOLEAN,
    allowlist_enforced              BOOLEAN,
    published_app_count             INTEGER,
    checked_at                      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (org_id, host_entry_id)
);

-- v37-style RLS belts.
DROP POLICY IF EXISTS pol_windows_app_pools_org_scope ON windows_app_pools;
CREATE POLICY pol_windows_app_pools_org_scope ON windows_app_pools
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE windows_app_pools ENABLE ROW LEVEL SECURITY;
ALTER TABLE windows_app_pools FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_windows_app_pool_members_org_scope ON windows_app_pool_members;
CREATE POLICY pol_windows_app_pool_members_org_scope ON windows_app_pool_members
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE windows_app_pool_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE windows_app_pool_members FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_windows_apps_org_scope ON windows_apps;
CREATE POLICY pol_windows_apps_org_scope ON windows_apps
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE windows_apps ENABLE ROW LEVEL SECURITY;
ALTER TABLE windows_apps FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_windows_app_host_state_org_scope ON windows_app_host_state;
CREATE POLICY pol_windows_app_host_state_org_scope ON windows_app_host_state
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE windows_app_host_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE windows_app_host_state FORCE  ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE, DELETE ON windows_app_pools, windows_app_pool_members, windows_apps, windows_app_host_state TO openidx_app;
`

var windowsAppsDown = `-- Rollback 119.
DROP TABLE IF EXISTS windows_app_host_state CASCADE;
DROP TABLE IF EXISTS windows_apps CASCADE;
DROP TABLE IF EXISTS windows_app_pool_members CASCADE;
DROP TABLE IF EXISTS windows_app_pools CASCADE;
`
