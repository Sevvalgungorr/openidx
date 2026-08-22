# OpenIDX Admin Console — UX / Architecture Audit

**Date:** 2026-08-21
**Lens:** systems / network / security UI architect
**Scope:** all 7 nav domains, 110 pages, 99 nav items, shell + cross-cutting concerns
**Method:** 6 parallel domain auditors scoring each page against a shared rubric (FUNC / STATE / IA / SEC-UX / CONSISTENCY / A11Y / RESPONSIVE + domain-specific lenses).

---

## Verdict

OpenIDX is **more built than it looks** and functionally healthy: every page is wired to a real API (no mock/demo data anywhere), ~97% of pages have `.test.tsx`, nav is role-filtered with a route-integrity test, there's a ⌘K command palette, and `QueryError` is a well-designed component. The problems are **not "missing features" — they are systemic consistency, safety, and situational-awareness gaps** that repeat across every domain. Fixing ~8 patterns fixes most of the console.

## Strengths (must not regress)
- Real API wiring on all 110 pages; **zero** mock/placeholder data.
- ~107 `.test.tsx` for 110 pages (~97%); `navigation.test.ts` guards route integrity (0 orphan nav items).
- ⌘K command palette, role-based nav (`minRole` hierarchy + view-mode lens), route-keyed ErrorBoundary + Suspense.
- Mature pages (ziti-network, devices, organizations, webhooks, pam-connections) already confirm destructive actions and use primitives — the good pattern exists, it's just not universal.

---

## The 9 systemic problems (ranked by leverage)

### 1. 401/403 masked as empty state — app-wide (P0/P1, highest frequency)
Only **13 of 110 pages use `QueryError`; ~96 have no read-error branch.** The axios client rejects on 401/403 but never redirects, so a permission denial or dead session renders as "No X found" — indistinguishable from genuinely empty. Worst: `passwordless-settings.tsx` falls back to hardcoded `enabled:true`, painting a **fake security posture**. Present in every domain.

### 2. No reactive global 401 / session-expiry UX (P1)
`api.ts` explicitly does not redirect on 401 (only `console.warn`). `idle-timeout-dialog.tsx` **exists but is wired into nothing**. A mid-session token death degrades into scattered masked-empty-states instead of a clean re-login. Compounds #1.

### 3. Destructive / privileged actions fire on one click, no confirm (P0/P1, security)
Dozens across domains: live deprovision (`lifecycle-policies`, `dry_run:false`), delete campaign/policy/workflow/report/schedule/retention-policy, **quarantine identity** (`ziti-ai-insights`, severs sessions), **revert platform TLS cert to self-signed** (`certificates`), **send broadcast to all users** (`notification-admin`), revoke access/tokens, bulk device-trust approval, legal-hold via `window.prompt()`, ISPM/AI auto-remediate. One misclick is irreversible.

### 4. Secrets exposed / retained client-side (P0/P1, security)
`identity-providers` echoes `client_secret` into the edit form; `directories` hydrates `bind_password`/`client_secret`; `vault-secrets` & `pam-connections` hold revealed plaintext in React state + copy to OS clipboard with **no auto-clear** (despite a banner claiming otherwise). Stored federation secrets are recoverable via devtools.

### 5. Design system half-adopted; dark mode undeliverable (P2, consistency)
**27 pages hand-roll `<table>`** (the `ui/table` primitive is unused by pages), +17 raw `<select>`, +19 raw `<button>`, +12 raw `<input>`. A full HSL token system + `.dark` palette exists in `index.css` but **only 9/110 pages use `dark:`** and most hardcode gray/blue literals — dark mode can't ship, there's no theme toggle, and spacing/density drift.

### 6. No network topology / overlay visualization (P1, network-architect core gap)
The entire ZTNA domain is **tables-only** except one static 4-column status strip on `ziti-setup`. There is no graph of identities ↔ edge-routers ↔ services, no client→gateway→resource path map. The network architect's core mental model is absent.

### 7. No responsive shell, no breadcrumbs (P1/P2, usability)
The sidebar has **no mobile/tablet breakpoints or drawer** — desktop-only. **Zero breadcrumbs across 99 pages.** Spinners over skeletons (90 vs 4) worsen perceived performance.

### 8. IA overlaps & duplicates (P1, information architecture)
Three branding editors (`branding` + `tenant-management` tab + `settings` tab, divergent endpoints/defaults); three overlapping certification surfaces (`access-reviews` / `certification-campaigns` / `attestation-campaigns`); three audit-table pages (`audit-logs` / `unified-audit` / `admin-audit-log`); `auth-analytics` ≈ `login-analytics`; `ai-identity-intelligence` ≈ `ziti-ai-insights`; `ispm-dashboard` ≈ `ziti-network` posture. 41 items in IAM alone.

### 9. Insight dead-ends (P1/P2, actionability)
`predictive-analytics` fully read-only; `risk-dashboard` alerts not actionable (no ack/investigate/resolve); `unified-audit` flat dump, no drill-down (`details` fetched but never rendered); `admin-audit-log` "Export CSV" exports only the current 20-row page.

---

## Proposed roadmap (4 sub-projects, each its own spec → plan → build)

**A. Reliability & Security-UX Foundation** *(fixes #1–#4; recommended first)*
The correctness + safety spine. Shared primitives + a systematic sweep: adopt `QueryError` on every query; add a reactive global-401 handler + wire session-expiry; a reusable `<ConfirmAction>`/danger-dialog applied to all destructive/privileged actions; a secret-handling policy (never echo secrets, auto-clear reveals, clipboard warnings). Highest leverage, directly serves "fully functional + safe," touches the most pages.

**B. Design System & Shell Completion** *(fixes #5, #7)*
Migrate hand-rolled tables/inputs/selects to primitives; replace hardcoded color literals with tokens; deliver dark mode + a theme toggle; add a responsive shell (mobile drawer), breadcrumbs, and skeleton loaders.

**C. Security & Network Operations Cockpit + Topology** *(fixes #6, part of #9)*
The flagship network/security-architect surface: an interactive overlay/topology map (identities ↔ routers ↔ services ↔ clients) + a unified situational-awareness command center (health + self-heal + posture + threats + topology) with actionable insights.

**D. IA Consolidation & Insight Actionability** *(fixes #8, rest of #9)*
Merge duplicate branding/certification/audit/analytics surfaces; make insights drill-down/actionable.

**Recommended order:** A → B → C → D (A is P0 security + highest leverage; each is independently shippable). The full per-page finding list (P0/P1/P2 with file:line) is retained from the domain audits and feeds each sub-project's plan.
