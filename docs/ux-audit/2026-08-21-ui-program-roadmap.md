# OpenIDX Admin Console — UI Program Roadmap

**Date:** 2026-08-21
**Basis:** `docs/ux-audit/2026-08-21-admin-console-ux-audit.md` (9 systemic problems)
**Goal:** make the console fully functional, safe, consistent, and situationally-aware — from a systems/network/security UI architect lens — as **four independently-shippable sub-projects**, each with its own spec → plan → build.

## Principles
- **Fix patterns, not pages.** The audit found ~8 repeating patterns across 110 pages; shared primitives + a systematic sweep beat per-page rework.
- **Safety before polish.** P0 security (secret exposure, unconfirmed destructive actions) leads.
- **Enforce, don't just fix.** Each foundation ships with a lint/CI guard or codemod so the fix cannot rot back.
- **Every wave ships.** No wave depends on a later one to be usable.
- **Preserve strengths:** real API wiring, ~97% test coverage, ⌘K palette, role-based nav + route-integrity test.

---

## Shared foundations (built in Sub-project A, reused by B/C/D)
These four primitives are the reusable spine everything else consumes:
1. **`useApiQuery` wrapper + `QueryError` adoption** — a thin standard query hook that renders `QueryError` on error, so 401/403 can never mask as empty.
2. **Global session-expiry UX** — axios 401 interceptor → force re-login; wire the existing (dead) `idle-timeout-dialog.tsx`.
3. **`<ConfirmAction>` danger-dialog primitive** — one component all destructive/privileged mutations route through (impact summary + optional required reason); a lint rule flags direct `.mutate()` on delete/revoke/rotate/terminate handlers.
4. **Secret-handling helpers** — `<SecretField>` (never echoes stored secrets; "leave blank to keep"), `revealSecret()` (auto-clear on timeout/unmount + clipboard warning).

---

## Sub-project A — Reliability & Security-UX Foundation
**Solves:** #1 (error masking), #2 (session expiry), #3 (unconfirmed destructive actions), #4 (secret exposure).
**Dependencies:** none (this is the foundation).
**Scope (in):** the four shared primitives above; then a systematic sweep applying them — `QueryError` on every list/detail query; `ConfirmAction` on every destructive/privileged mutation (audit lists dozens: deprovision, quarantine, revert-cert, broadcast-all, legal-hold, revoke, bulk-approve, delete-*); `SecretField`/reveal-autoclear on `identity-providers`, `directories`, `vault-secrets`, `pam-connections`; fix `passwordless-settings` fake-posture fallback.
**Scope (out):** visual redesign, new pages, topology.
**Deliverables:** 4 primitives + tests; sweep across ~96 pages; CI guards (error-branch + destructive-mutation lint); regression tests.
**Success criteria (measurable):** 100% of query pages render `QueryError` on error; a global 401 always yields a re-login dialog (no scattered empties); every destructive mutation goes through `ConfirmAction` (lint-enforced); no stored secret is echoed into a form; revealed secrets auto-clear; CI blocks regressions.
**Size:** L (few primitives, wide sweep — parallelizable by domain).

## Sub-project B — Design System & Shell Completion
**Solves:** #5 (half-adopted design system, dead dark mode), #7 (no responsive shell, no breadcrumbs, spinners-over-skeletons).
**Dependencies:** A's `ConfirmAction`/`QueryError` (so migrated pages keep the safety behavior). Otherwise independent.
**Scope (in):** migrate 27 hand-rolled tables + raw inputs/selects/buttons to `components/ui/*`; replace hardcoded gray/blue literals with the existing HSL tokens; deliver dark mode + a theme toggle; responsive shell (mobile drawer, breakpoints); breadcrumbs across deep routes; skeleton loaders for primary lists.
**Scope (out):** new feature surfaces; IA consolidation.
**Deliverables:** primitive migration codemod + manual passes; token lint (no raw color literals in pages); theme toggle; responsive `layout.tsx`; `<Breadcrumbs>`; skeleton components.
**Success criteria:** 0 hand-rolled `<table>` in pages; dark mode togglable and correct on every page; usable at 375px (mobile drawer); breadcrumbs on all ≥2-level routes; skeletons on primary lists; token lint green.
**Size:** L (mechanical breadth + shell rework).

## Sub-project C — Security & Network Operations Cockpit + Topology
**Solves:** #6 (no topology visualization), part of #9 (insight actionability), unifies situational awareness.
**Dependencies:** A (safe actions + error handling) and B (responsive shell, tokens, canvas primitives).
**Scope (in):** an interactive **overlay/topology map** (identities ↔ edge-routers ↔ services ↔ clients, live status, client→gateway→resource path) — the network-architect's missing mental model; a **unified ops cockpit** aggregating health + self-heal + posture + threats + topology into one role-based situational-awareness surface; make its insights actionable (drill-down, act-on-finding).
**Scope (out):** re-plumbing backends beyond what already exposes the data.
**Deliverables:** topology graph component (react-flow/d3) reading existing Ziti/reconciler data; cockpit page; actionable insight wiring.
**Success criteria:** a network architect can see and trace reachability without reading tables; one screen answers "is the estate healthy / under attack / self-healing"; insights link to actions.
**Size:** L–XL (the flagship new build).

## Sub-project D — IA Consolidation & Insight Actionability
**Solves:** #8 (duplicate surfaces), remainder of #9 (dead-end insights).
**Dependencies:** A (consolidated pages keep error handling); independent of C.
**Scope (in):** collapse 3 branding editors → 1; 3 certification surfaces → 1 (tabs); 3 audit tables → 1 canonical + cross-links; dedupe `auth`/`login` analytics and `ai-identity-intelligence`/`ziti-ai-insights`; add drill-down/actions to `predictive-analytics`, `risk-dashboard` alerts, `unified-audit`; fix export-only-current-page.
**Scope (out):** net-new analytics.
**Deliverables:** merged pages with redirects from retired routes (nav + route-integrity test updated); drill-down/action wiring.
**Success criteria:** exactly 1 branding / 1 certification / 1 audit surface; no duplicate analytics; every insight is actionable or drills down; retired routes redirect, nav test green.
**Size:** M–L.

---

## Sequencing (waves)
1. **Wave 1 — A** (foundation + security sweep). Nothing else should build on masked errors or unconfirmed actions.
2. **Wave 2 — B** (design system + shell). Migrated pages inherit A's safety.
3. **Wave 3 — C** (cockpit + topology). Needs A's safe data + B's shell/canvas.
4. **Wave 4 — D** (IA consolidation + insights). Can partly overlap Wave 3 (independent of C).

**Parallelization:** within A and B, work splits cleanly by domain (6 domains → parallel sweeps). D is independent of C and could start alongside it if capacity allows.

## Problem → sub-project traceability
| Systemic problem | Sub-project |
|---|---|
| #1 error masking · #2 session expiry · #3 unconfirmed destructive · #4 secret exposure | **A** |
| #5 design system / dark mode · #7 responsive / breadcrumbs / skeletons | **B** |
| #6 topology · #9 insight actionability (part) | **C** |
| #8 IA overlaps · #9 insight actionability (rest) | **D** |

## Next step
Brainstorm **Sub-project A** into a full design spec (the four primitives + the sweep + the CI guards), then writing-plans → build. B/C/D each get their own spec→plan when their wave begins.
