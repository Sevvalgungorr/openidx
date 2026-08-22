# Sub-project D — IA Consolidation & Insight Actionability (Design Spec)

**Date:** 2026-08-22
**Part of:** roadmap Wave 4 (final). Builds on A/B/C (#795/#796/#797).
**Solves:** #8 (duplicate/overlapping surfaces) + rest of #9 (dead-end insights).

## Key finding (reshapes the scope)
An endpoint investigation of every "duplicate" the audit flagged found that **almost all of them hit DIFFERENT backends** and are therefore distinct data, not duplicates — hard-merging would lose features:
- Certification trio: `/governance/reviews` vs `/governance/campaigns` vs `/attestation-campaigns` — three different resources.
- Audit trio: `/audit/events` (general, fullest) vs `/access/audit/unified` (cross-service merge) vs `/audit-log` (admin actions + before/after diffs) — three datasets.
- Analytics pairs: auth vs login analytics, ISPM vs Ziti posture, AI-intelligence vs Ziti-AI — all different services/metrics.
- **Only true duplicate:** `branding.tsx` and the Tenant-Management Branding tab hit the IDENTICAL `/api/v1/tenants/{org}/branding` with the same 12-field payload.

**Therefore D = one safe redirect-merge + cross-linking + additive actionability. It explicitly does NOT hard-merge different-backend pages.**

## Scope

### 1. Branding consolidation (the one true merge)
- **Canonical:** the Tenant-Management Branding tab (superset — same endpoint + live login preview + org picker + adjacent Settings/Domains tabs).
- **Retire `branding.tsx`:** replace the route element with `<Navigate to="/tenant-management" replace />` (keep the `/branding` route so old links still resolve). Remove the `Branding` nav item (`navigation.ts`). Update `navigation.test.ts` (the `/branding` assertions) — the route stays as a redirect, the nav entry goes.
- **`settings.tsx` Branding tab** writes a DIFFERENT record (`/api/v1/settings`, 7 fields, no org scope) — a data-split footgun. SAFE action: add a cross-link banner at the top of that tab ("Full per-tenant branding lives in Tenant Management →"). Do NOT remove the tab or merge the endpoints (would risk the /settings branding path).

### 2. Cross-links (additive, no merges) — a reusable `RelatedLinks` strip
New `src/components/related-links.tsx`: a small "Related:" row of `<Link>`s. Place it on each near-duplicate cluster so users discover siblings:
- Certification: Access Reviews ↔ Cert Campaigns ↔ Attestation.
- Audit: Audit Logs ↔ Unified Audit ↔ Admin Audit Log.
- Analytics: Auth Analytics ↔ Login Analytics; ISPM ↔ Ziti posture (zero-trust/ziti-network); AI Intelligence ↔ Ziti AI Insights.
Token-styled, dark-correct.

### 3. Insight actionability (additive, low-risk)
- **`unified-audit.tsx`:** it already fetches a `details` object it never renders → add a row click → detail modal (or expandable row) showing the event `details`. No new endpoint.
- **`risk-dashboard.tsx`:** its "Active Security Alerts" are a read-only dead end → make each alert card link to `/security-alerts` (where acknowledge/resolve already exist via `PUT /security-alerts/:id/status`). (Drill-down-to-act, not a duplicated mutation UI.)
- **`predictive-analytics.tsx`:** churn-risk usernames are plain text → link each to the user's detail (`/user-access-360` or `/users` — whichever the app uses for a user drill-down; verify the route).
- **`admin-audit-log.tsx`:** "Export CSV" only exports the current page → change it to fetch all pages (loop the existing paginated GET) before building the CSV, so the export is complete. (No server endpoint exists; client-side full export is the safe win. If page count is huge, cap + note.)

## Explicitly OUT (would lose features / needs backend)
Hard-merging the certification trio, the audit trio, or any analytics pair; removing the settings branding tab; a server-side admin-audit export endpoint; backend analytics consolidation. These are noted as future work, not done here.

## Testing
- `related-links.test.tsx`: renders the given links.
- branding redirect: `navigation.test.ts` passes with `/branding` as a redirect + nav item removed; a test that `/branding` renders a Navigate (or that the nav no longer lists it).
- `unified-audit` detail modal test (opens on row click, shows a details field); `risk-dashboard` alert links present; `predictive-analytics` user links present; `admin-audit-log` export-all fetches all pages (mock paginated responses, assert the CSV covers >1 page).
- All 4 A/B guards stay enforce-green; `tsc`, `build`, full vitest green.

## Success criteria
1. `/branding` redirects to Tenant Management; nav no longer duplicates branding; route-integrity green.
2. Settings branding tab shows the cross-link banner.
3. Related-links strips on the certification, audit, and analytics clusters.
4. unified-audit has a details drill-down; risk-dashboard alerts link to where you can act; predictive-analytics users drill down; admin-audit-log exports all pages.
5. No different-backend pages were merged (no feature loss); full suite + build + 4 guards green.
