# Sub-project D — IA Consolidation Implementation Plan

> subagent-driven. Builds on A/B/C. Conservative: one true redirect-merge + cross-links + additive actionability. NO different-backend merges.

**Spec:** `docs/ux-audit/specs/2026-08-22-subproject-d-ia-consolidation-design.md`
**Tech:** React+TS, react-router, react-query, tokens (B), QueryGate/ui-Table (A/B). Commands from `web/admin-console`. Trailer `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.

### Task 1: `RelatedLinks` component
- Create `src/components/related-links.tsx` (+ test): props `{ links: {to:string,label:string}[] }`; renders a token-styled "Related:" row of react-router `<Link>`s (dark-correct, no raw literals). Test: renders each label as a link with the right href.
- Commit `feat(ui): RelatedLinks strip`.

### Task 2: Branding consolidation
- `src/App.tsx`: change the `/branding` route element to `<Navigate to="/tenant-management" replace />` (import Navigate from react-router-dom; keep the route so old links resolve). Remove the now-unused Branding lazy import if it becomes unused.
- `src/config/navigation.ts`: remove the `Branding` nav item (`/branding`).
- `src/config/navigation.test.ts`: update the assertions referencing `/branding` (it should NO LONGER be in nav; the route still exists as a redirect). Run the test.
- `src/pages/settings.tsx`: at the top of the Branding tab content, add a token-styled banner: "Full per-tenant branding (logo, colors, login preview) is managed in Tenant Management → Branding." with a `<Link to="/tenant-management">`. Do NOT remove the tab or change its /settings save.
- Verify `tsc` + `navigation.test.ts` + `settings.test.tsx`. Commit `refactor(ui): consolidate branding — redirect /branding to Tenant Management + settings cross-link`.

### Task 3: Cross-links on the clusters
Add `<RelatedLinks links={...}/>` near the top (under the header) of each page:
- `access-reviews.tsx`, `certification-campaigns.tsx`, `attestation-campaigns.tsx` → the other two.
- `audit-logs.tsx`, `unified-audit.tsx`, `admin-audit-log.tsx` → the other two.
- `auth-analytics.tsx` ↔ `login-analytics.tsx`.
- `ispm-dashboard.tsx` → `/zero-trust` (Ziti posture); `ai-identity-intelligence.tsx` ↔ `/ziti-ai-insights`.
Use the correct hrefs (verify each page's route in navigation.ts). One commit (or a few). Verify `tsc` + affected tests. Commit `feat(ui): cross-link related surfaces (certification / audit / analytics)`.

### Task 4: Actionability
- `unified-audit.tsx`: it fetches `details` but never renders it → add a row click (or an expand button) that opens a Dialog showing the event's `details` (JSON-ish, formatted) + the row's key fields. Preserve QueryGate/table. Test: clicking a row opens the modal showing a details value.
- `risk-dashboard.tsx`: wrap each "Active Security Alerts" item in a `<Link to="/security-alerts">` (drill-down to where ack/resolve exist). Do NOT duplicate the mutation UI. Test: an alert links to /security-alerts.
- `predictive-analytics.tsx`: make each churn-risk username a `<Link>` to the user drill-down route (verify: likely `/user-access-360` — check navigation.ts / how other pages link to a user; if none, link to `/users`). Test: a user renders as a link.
- `admin-audit-log.tsx`: change "Export CSV" to fetch ALL pages (loop the existing paginated GET until exhausted, cap at e.g. 50 pages) then build the CSV from the full set. Test: mock 2 pages, assert the CSV includes rows from both.
- One commit per page: `feat(ui): <page> — <actionable drill-down / full export>`. Verify `tsc` + each page test.

### Task 5: Verify + PR
- All 4 guards `--enforce` green (new code must use tokens, QueryGate where it fetches, ui/Table not raw). `npx tsc --noEmit`, `npm run build`, `npx vitest run` all green. Push; PR base `feat/ui-ops-cockpit-topology`.

## Success criteria
`/branding`→redirect + nav dedup; settings banner; related-links on 3 clusters; unified-audit detail modal; risk-dashboard alerts link out; predictive-analytics users drill down; admin-audit-log exports all pages; no different-backend merges; full suite + build + 4 guards green.
