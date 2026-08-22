# Sub-project C — Ops Cockpit + Topology Implementation Plan

> subagent-driven. Builds on A (#795) + B (#796). Read-only visualizations from existing endpoints; no backend changes.

**Goal:** an interactive ZTNA topology map (`/network-topology`) + a situational-awareness cockpit (`/ops-cockpit`), from existing ziti/risk endpoints, using `@xyflow/react`.

**Tech:** React+TS, react-query, `@xyflow/react` (new dep), tailwind tokens (B), QueryGate/Skeleton (A/B). Commands from `web/admin-console`. Commit trailer `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.

**Spec:** `docs/ux-audit/specs/2026-08-22-subproject-c-ops-cockpit-topology-design.md`

---

### Task 1: Add `@xyflow/react`
- `cd web/admin-console && npm install @xyflow/react` (updates package.json + package-lock.json; node_modules is a shared symlink — additive). Verify `npx tsc --noEmit` still clean and `npm run build` works with a trivial import.
- Commit `build(ui): add @xyflow/react for topology graph`.

### Task 2: Topology model (`src/lib/topology-model.ts`) — pure, TDD
- Types `TopoNode {id,kind:'identity'|'router'|'service',label,status}`, `TopoEdge {id,source,target,kind:'policy'|'router'|'session'}`, `Topology {nodes,edges}`.
- `buildTopology({identities, services, routers, servicePolicies, sessions?})`: create a node per identity/router/service; for each service-policy, add identity→service edges (resolve `@id`/`#attr`/`role` refs to node ids; when a ref is a role/attribute group with >1 member, connect each matching node, else keep the policy's raw ref as a synthetic role node labelled by the ref); connect services/identities to routers as the fabric layer (from edge-router-policies if provided, else attach all to routers); when `sessions` given, add `kind:'session'` edges (highlighted). Assign a layered `column` (identity=0, router=1, service=2) + a `row` index for deterministic layout.
- Test `src/lib/topology-model.test.ts`: sample inputs → expected node counts + an identity→service edge from a policy; empty inputs → `{nodes:[],edges:[]}`; a session adds a session edge; a role-ref policy resolves to member edges. (Read the real response shapes in `src/pages/ziti-network.tsx` types first — reuse `ZitiService`/`FabricRouter` if exported, else define minimal input types.)
- Commit `feat(ui): topology-model — build identity/router/service graph from ziti data`.

### Task 3: TopologyGraph component (`src/components/topology-graph.tsx`)
- Props `{ topology: Topology, onSelect?(node), interactive?=true, showSessions?=false }`. Map `TopoNode`→react-flow node (position from column/row, token-styled per kind + status color, kind icon), `TopoEdge`→edge (session edges animated/highlighted). Include `<Background/> <Controls/>` when interactive, a legend, and a summary line. `onNodeClick`→`onSelect`. Token-based styling (dark-correct).
- Test `topology-graph.test.tsx`: renders given a small topology; asserts node labels appear (react-flow renders node DOM; `src/test/setup.ts` polyfills ResizeObserver — if a node's label isn't queryable due to virtualization, assert the component mounts without throwing + a legend/summary renders). Keep it resilient.
- Commit `feat(ui): TopologyGraph (react-flow, layered, status-colored)`.

### Task 4: Topology page (`src/pages/network-topology.tsx`)
- Fetch identities/services/routers/service-policies (and sessions for the toggle) via `useQuery`; wrap the primary render in `QueryGate` (resource "network topology"); build the model; render `TopologyGraph` + a right detail panel for the selected node (status, its policies, links to `/ziti-network` + `/devices`); a "Show live sessions" toggle; a kind filter + search. Skeleton loading (B). Dark-correct tokens.
- Route `/network-topology` in `App.tsx` (+ lazy export in `src/pages/pages/index.ts` if that's the pattern, else `App.tsx` import); nav entry in `src/config/navigation.ts` (ziti domain, `minRole:'operator'`, icon e.g. `Network`/`Share2`).
- Test: renders with mocked queries (loading→skeleton, error→QueryError, data→graph summary + a node). Commit `feat(ui): /network-topology page (interactive overlay map)`.

### Task 5: Ops Cockpit page (`src/pages/ops-cockpit.tsx`)
- Aggregate reads: ziti/status + fabric/overview (services/routers/sessions counts), posture/summary, security-alerts/risk (open threats + top items), and a compact non-interactive `TopologyGraph` preview. Each tile is a drill-down `Link` (to /network-topology, /zero-trust, /risk-dashboard, /security-alerts, /devices). QueryGate + Skeleton; dark tokens. Header "Operations Cockpit".
- Route `/ops-cockpit` + nav entry (home or ziti domain, `minRole:'operator'`, icon `Gauge`/`LayoutDashboard`).
- Test: renders tiles with mocked queries; a failed primary query → QueryError. Commit `feat(ui): /ops-cockpit situational-awareness page`.

### Task 6: Route-integrity + guards
- Update `src/config/navigation.test.ts` (or the route-integrity test) so the two new hrefs map to routes. Run it.
- Run all UI guards (A+B) `--enforce` — the two new pages must use QueryGate (guard 1), no hand-rolled tables (guard 2), no raw literals (guard 3): fix any offense. Commit `test(ui): route integrity for topology + cockpit`.

### Task 7: Verify + PR
- `npx tsc --noEmit && npm run build && npx vitest run` all green; all 4 guards `--enforce` green. Push; open PR (base `feat/ui-design-system-shell`).

## Success criteria
Both pages render from live data; topology is interactive with node detail + session toggle; cockpit tiles drill down; QueryGate + tokens throughout; nav+routes+route-test green; model unit-tested; full suite + build green; guards enforce-green.
