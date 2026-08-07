package migrations

// Migration v130 — upstream pools: turn a route's single address into a
// load-balanced set of backends with active health checking.
//
// Today proxy_routes.to_url holds exactly one upstream address, so a route can
// only ever point at one backend. If that backend dies the route dies with it,
// and there is no way to spread load across several instances. Measured on this
// deployment: 0 of 19 edge routes had more than one node, and 0 had an active
// health check.
//
// The data plane (APISIX) already supports weighted multi-node upstreams and
// active checks; what was missing was a place to *express* that intent. These
// tables are that place, and the reconciler renders them into the upstream
// object it already builds.
//
// Backward compatibility is the main constraint. proxy_routes.upstream_pool_id
// is NULLABLE and defaults to NULL, which means "keep using to_url exactly as
// before". Existing routes are untouched and behave identically; a pool is
// opt-in, per route. That property is what makes this migration safe to apply
// to a live edge.
var upstreamPoolsUp = `-- Migration 130: upstream pools + members.

CREATE TABLE IF NOT EXISTS upstream_pools (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id              UUID NOT NULL,
    name                TEXT NOT NULL,
    description         TEXT,

    -- How traffic is spread. 'roundrobin' spreads by weight; 'chash' pins a
    -- caller to one backend (session stickiness) using hash_on/hash_key.
    algorithm           TEXT NOT NULL DEFAULT 'roundrobin'
                        CHECK (algorithm IN ('roundrobin', 'chash')),
    -- Only meaningful for chash. Defaults describe "stick by client IP".
    hash_on             TEXT NOT NULL DEFAULT 'vars'
                        CHECK (hash_on IN ('vars', 'header', 'cookie')),
    hash_key            TEXT NOT NULL DEFAULT 'remote_addr',

    -- Active health checking. When enabled the data plane probes each member
    -- and stops sending traffic to failing ones without operator action.
    health_check_enabled  BOOLEAN NOT NULL DEFAULT true,
    health_check_path     TEXT    NOT NULL DEFAULT '/',
    -- Consecutive probe results required to flip a member's state. Two
    -- thresholds (not one) avoid flapping on a single blip.
    healthy_threshold     INT     NOT NULL DEFAULT 2  CHECK (healthy_threshold   BETWEEN 1 AND 10),
    unhealthy_threshold   INT     NOT NULL DEFAULT 3  CHECK (unhealthy_threshold BETWEEN 1 AND 10),
    health_check_interval INT     NOT NULL DEFAULT 5  CHECK (health_check_interval BETWEEN 1 AND 300),
    health_check_timeout  INT     NOT NULL DEFAULT 3  CHECK (health_check_timeout  BETWEEN 1 AND 60),

    -- Retry the next member when one fails mid-request. NULL lets the data
    -- plane pick its own default (member count - 1).
    retries             INT CHECK (retries IS NULL OR retries BETWEEN 0 AND 10),

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- A pool name is how an operator refers to it, so it must be unambiguous
    -- inside one tenant.
    CONSTRAINT upstream_pools_org_name_key UNIQUE (org_id, name)
);

CREATE TABLE IF NOT EXISTS upstream_pool_members (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    pool_id     UUID NOT NULL REFERENCES upstream_pools(id) ON DELETE CASCADE,
    org_id      UUID NOT NULL,

    host        TEXT NOT NULL,
    port        INT  NOT NULL CHECK (port BETWEEN 1 AND 65535),
    -- Relative share of traffic. 0 drains a member without deleting it, which
    -- is how you take a backend out for maintenance and put it back.
    weight      INT  NOT NULL DEFAULT 1 CHECK (weight BETWEEN 0 AND 1000),
    -- Distinct from weight=0: disabled removes the member from the rendered
    -- upstream entirely, so it is not even health-checked.
    enabled     BOOLEAN NOT NULL DEFAULT true,

    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- The same backend listed twice would silently double its share.
    CONSTRAINT upstream_pool_members_unique UNIQUE (pool_id, host, port)
);

CREATE INDEX IF NOT EXISTS idx_upstream_pool_members_pool ON upstream_pool_members(pool_id);
CREATE INDEX IF NOT EXISTS idx_upstream_pools_org         ON upstream_pools(org_id);

-- Opt-in link from a route to a pool. NULL (the default, and the state of every
-- existing row) means "use to_url", so this migration cannot change the
-- behaviour of any route that is running today.
ALTER TABLE proxy_routes ADD COLUMN IF NOT EXISTS upstream_pool_id UUID
    REFERENCES upstream_pools(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_proxy_routes_upstream_pool ON proxy_routes(upstream_pool_id);

-- Tenant isolation, matching the policy already on proxy_routes: rows are
-- visible only within their org unless a trusted caller sets app.bypass_rls
-- (used by the reconciler, which must see every org's desired state).
ALTER TABLE upstream_pools        ENABLE ROW LEVEL SECURITY;
ALTER TABLE upstream_pool_members ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pol_upstream_pools_org_scope ON upstream_pools;
CREATE POLICY pol_upstream_pools_org_scope ON upstream_pools
    USING (current_setting('app.bypass_rls', true) = 'on'
           OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
    WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
           OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);

DROP POLICY IF EXISTS pol_upstream_pool_members_org_scope ON upstream_pool_members;
CREATE POLICY pol_upstream_pool_members_org_scope ON upstream_pool_members
    USING (current_setting('app.bypass_rls', true) = 'on'
           OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
    WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
           OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON upstream_pools        TO openidx_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON upstream_pool_members TO openidx_app;
`

// Rollback drops the link column first so no route can reference a pool that is
// about to disappear. Routes fall back to to_url, which was never removed.
var upstreamPoolsDown = `-- Rollback 130.
DROP INDEX IF EXISTS idx_proxy_routes_upstream_pool;
ALTER TABLE proxy_routes DROP COLUMN IF EXISTS upstream_pool_id;
DROP TABLE IF EXISTS upstream_pool_members;
DROP TABLE IF EXISTS upstream_pools;
`
