# Sub-project C — Security & Network Operations Cockpit + Topology (Design Spec)

**Date:** 2026-08-22
**Part of:** roadmap Wave 3. Builds on A (#795) + B (#796).
**Solves:** #6 (no network topology visualization — the network-architect gap) + situational-awareness consolidation. Deep insight-actionability (#9) stays with D.

**Goal:** give a network/security architect (1) an interactive map of the ZTNA overlay — who reaches what over which router — and (2) one situational-awareness screen. Both read EXISTING endpoints; no backend changes.

## Data (all existing on this branch)
- `/api/v1/access/ziti/identities` — identities (agents/users on the overlay)
- `/api/v1/access/ziti/services` — services (`{services: ZitiService[]}`)
- `/api/v1/access/ziti/fabric/routers` — edge routers (`FabricRouter[]`)
- `/api/v1/access/ziti/service-policies` — Dial/Bind policies linking identity-roles ↔ service-roles (**the edges**)
- `/api/v1/access/ziti/edge-router-policies` — which routers serve which identities
- `/api/v1/access/ziti/sessions` — live sessions (client↔service, for a "live" overlay)
- `/api/v1/access/ziti/posture/summary`, `/ziti/status`, `/ziti/fabric/overview` — health/posture
- risk/threat: `/api/v1/audit|risk` dashboards' existing endpoints (reused read-only for cockpit tiles)

## Architecture
Two new surfaces + one graph component + a small graph-model helper. Uses `@xyflow/react` (react-flow) for the interactive canvas (added as a dependency). All read-only v1 (click → detail panel; no mutations from the graph). Behavior is additive — no existing page changes except nav/routes.

## Units

### 1. Graph model (`src/lib/topology-model.ts`, pure + unit-tested)
`buildTopology(identities, services, routers, servicePolicies, sessions?) → { nodes: TopoNode[], edges: TopoEdge[] }`.
- Node kinds: `identity`, `router`, `service`. Each carries `id, label, status` (up/down/degraded/unknown from the source data).
- Edges: identity→service from service-policies (resolve `@role`/`#attribute` refs to concrete ids where possible; fall back to role-group nodes when a policy targets a role, not a single id). identity/service→router from edge-router-policies (or, if that mapping is coarse, connect everything to the routers as the fabric layer). Optional live-session edges highlighted when `sessions` passed.
- Pure functions so the (fiddly) edge-resolution logic is unit-tested without a canvas.

### 2. Topology graph component (`src/components/topology-graph.tsx`)
Wraps `@xyflow/react`: takes `{nodes, edges}` from the model, applies a simple layered layout (identities left, routers middle, services right — a deterministic dagre-free column layout computed in the model or a light helper), token-styled nodes (dark-mode correct), status coloring, node click → `onSelect(node)`. Read-only (no drag-to-edit persistence). Renders a legend + a "N identities · M routers · K services" summary.

### 3. Topology page (`src/pages/network-topology.tsx`)
Route `/network-topology` (nav: ZTNA domain, minRole operator). Fetches the five ziti endpoints (via `QueryGate` — A's primitive — so a 401/403 shows QueryError), builds the model, renders `TopologyGraph` + a right-hand detail panel for the selected node (its policies, status, links to the existing ziti-network/identity pages). A "show live sessions" toggle overlays session edges. Filter by node kind / search.

### 4. Ops Cockpit page (`src/pages/ops-cockpit.tsx`)
Route `/ops-cockpit` (nav: Home or ZTNA, minRole operator). One situational-awareness screen aggregating existing reads:
- **Health row:** services up/total, routers up/total, active sessions, overlay status (from ziti/status + fabric/overview).
- **Posture:** compliant/at-risk identities (posture/summary).
- **Security:** open threats/alerts count + top items (reuse risk-dashboard/security-alerts read endpoints), each linking to its page.
- **Topology preview:** a compact `TopologyGraph` (fit-view, non-interactive) with a "Open full map" link to `/network-topology`.
- Each tile is a drill-down link (not a dead number). Uses QueryGate + Skeleton (B) for loading.

## Nav / routes
Add `/network-topology` and `/ops-cockpit` to `src/config/navigation.ts` (+ `App.tsx` routes wrapped appropriately, `pages` lazy exports). Update `navigation.test.ts` expectations (route-integrity test).

## Dependency
Add `@xyflow/react` to `web/admin-console/package.json`. (Installed into the shared node_modules; isolated to this branch's package.json/lock.)

## Testing
- `topology-model.test.ts`: builds nodes/edges from sample identities/services/routers/policies; role-ref resolution; empty inputs → empty graph; a session overlay adds highlighted edges.
- Component/page tests: `TopologyGraph` renders nodes without crashing (react-flow needs ResizeObserver — the test setup polyfills it; assert node labels render, or shallow-assert the model→node mapping); `network-topology`/`ops-cockpit` render with mocked queries (loading→Skeleton, error→QueryError, data→tiles/graph). react-flow's canvas measurement is jsdom-limited, so component tests assert data/labels, not pixel layout.
- `tsc`, `npm run build`, full vitest green.

## Success criteria (measurable)
1. `/network-topology` renders an interactive graph of identities↔routers↔services from live data; clicking a node shows its detail; a live-sessions toggle works.
2. `/ops-cockpit` shows health + posture + security + a topology preview, every tile drilling down.
3. Both use QueryGate (no masked 401/403) and are dark-mode correct (tokens).
4. Nav entries + routes added; route-integrity test green.
5. `topology-model` unit-tested; full suite + build green.

## Out of scope
Editing the overlay from the graph (drag-to-connect persistence); self-heal cockpit integration (that API is on the unmerged selfheal branch — add once merged); deep insight-actionability across analytics pages (Sub-project D); a bespoke force-directed physics layout (use the deterministic layered layout).
