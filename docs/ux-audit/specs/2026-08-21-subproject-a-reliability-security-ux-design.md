# Sub-project A — Reliability & Security-UX Foundation (Design Spec)

**Date:** 2026-08-21
**Part of:** `docs/ux-audit/2026-08-21-ui-program-roadmap.md` (Wave 1)
**Solves:** systemic problems #1 (401/403 masked as empty), #2 (no session-expiry UX), #3 (unconfirmed destructive/privileged actions), #4 (secrets exposed/retained client-side).

**Goal:** four reusable safety primitives + a safety-first sweep that applies them across the console, all locked in by CI guards so the fixes cannot rot back.

## Architecture
Four small, independently-testable units in `web/admin-console/src/`, then a domain-by-domain sweep that adopts them, then two `check-*.sh` CI guards (repo convention) that keep adoption at 100%. No backend changes. No visual redesign (that's Sub-project B).

---

## Unit 1 — Query error handling (`QueryGate` + convention)
**What:** structurally prevent a failed read from rendering as an empty state.
**Files:** `src/components/query-gate.tsx` (+ test).
**Interface:**
```tsx
<QueryGate query={usersQuery} resource="users" empty={<EmptyUsers/>}>
  {(data) => <UsersTable rows={data} />}
</QueryGate>
```
Renders `LoadingSpinner` while `isLoading`, `<QueryError error resource/>` on `isError`, `empty` when data is empty (optional), else `children(data)`. `QueryError` already exists and distinguishes 401/403/generic.
**Sweep rule:** every page's *primary* list/detail query renders through `QueryGate` (or an explicit `if (isError) return <QueryError/>`). Secondary/background queries either use `QueryGate` or degrade gracefully with a visible inline error — never a silent `|| []`.
**Depends on:** existing `QueryError`, `LoadingSpinner`.

## Unit 2 — Global session-expiry UX
**What:** a dead session yields one clean re-login prompt, not scattered empty states.
**Files:** `src/lib/api.ts` (interceptor), `src/lib/auth.tsx` (handler + state), wire the existing dead `src/components/idle-timeout-dialog.tsx` (or a new `session-expired-dialog.tsx`) into `App.tsx`.
**Behavior:** axios response interceptor catches a 401 that is **not** the token-refresh or OAuth callback call; after a refresh attempt fails, it invokes an `onAuthExpired` callback registered by the auth context, which sets `sessionExpired=true` and renders a modal ("Your session ended — sign in again") that routes to the OAuth login. Guard against redirect loops (exempt `/oauth/*`, refresh, and the login route). The existing 30s proactive refresh timer stays.
**Depends on:** Unit 1 (so pre-dialog renders don't mask the 401), auth context.

## Unit 3 — `<ConfirmAction>` danger-dialog primitive
**What:** one component every destructive/privileged mutation routes through.
**Files:** `src/components/confirm-action.tsx` (+ test).
**Interface:**
```tsx
<ConfirmAction
  title="Revert platform certificate?"
  description="Replaces the active TLS cert with a self-signed one; services restart."
  impact={<ImpactList .../>}          // optional blast-radius summary
  destructive                          // red styling
  requireReason                        // renders a Textarea; confirm disabled until non-empty
  confirmLabel="Revert"
  onConfirm={(reason) => revertMutation.mutateAsync({ reason })}
>
  {(open) => <Button variant="destructive" onClick={open}>Revert</Button>}
</ConfirmAction>
```
Built on the existing `AlertDialog`. `onConfirm` receives the typed reason when `requireReason`. Also export a `useConfirm()` hook for imperative call-sites.
**Policy:** `requireReason` is **mandatory** for security-critical actions (revoke access/token, terminate session, legal-hold place/release, revert-cert, live deprovision, quarantine identity, broadcast-to-all, bulk device-trust). Ordinary deletes need confirmation but not a reason.
**Depends on:** `AlertDialog`, `Textarea`, `Button`.

## Unit 4 — Secret handling
**What:** stored secrets never reach the browser; revealed secrets don't linger.
**Files:** `src/components/secret-field.tsx` (+ test), `src/lib/secret-reveal.ts` (+ test).
- **`<SecretField>`** — for edit forms: renders empty with placeholder "leave blank to keep current"; never prefilled from the API; exposes `changed`; parent sends the value only if changed. On create, behaves as a normal required field.
- **`useRevealedSecret()` / `revealSecret`** — holds a revealed plaintext, **auto-clears** after a timeout and on unmount; `copyWithWarning()` copies to clipboard with a `.catch` (toast on failure), a persistence warning, and an optional scheduled clipboard clear.
**Sweep targets:** `identity-providers` (stop echoing `client_secret`), `directories` (`bind_password`/`client_secret`), `vault-secrets` + `pam-connections` (reveal auto-clear + clipboard), and fix `passwordless-settings` (remove the hardcoded `enabled:true` fallback; gate toggles behind `isError`).
**Depends on:** `Input`, toast.

## Unit 5 — CI guards (repo-idiomatic `check-*.sh` + `*.test.sh`)
**What:** keep adoption at 100% so the sweep can't regress.
**Files:** `scripts/check-query-error-coverage.sh` + `.test.sh`; `scripts/check-destructive-confirm.sh` + `.test.sh`; a CI job (like the self-heal job) running both.
- **Guard 1 (query-error):** flags a page that calls `useQuery`/a list fetch but never references `QueryError`/`QueryGate`. Small allowlist for legitimate exceptions (e.g. pure-form pages).
- **Guard 2 (destructive-confirm):** flags a destructive handler (name matches `delete|revoke|rotate|terminate|deprovision|quarantine|legalHold|broadcast`) that calls `.mutate(`/`api.delete(` without a `ConfirmAction`/`AlertDialog` in the same component. Heuristic + allowlist; each guard has a mutation-tested `.test.sh` (must-catch a bad sample, must-ignore a good one), matching the repo's existing checker convention.
Guards ship in **warn mode**, flip to **enforce** after the sweep completes (A4).

---

## Sweep sequencing (feeds the implementation plan)
- **A0 — primitives + guards.** Build Units 1–5; guards in warn mode.
- **A1 — P0 security.** Unit 4 targets (secrets) + Unit 3 on the highest-blast-radius actions (revert-cert, quarantine, live deprovision, broadcast-all, legal-hold, bulk device-trust, delete campaign/policy/workflow, revoke access/token).
- **A2 — broad error sweep.** Unit 1 across all domains (parallelizable by domain: home/iam/ziti/pam/audit/platform).
- **A3 — session-expiry.** Wire Unit 2.
- **A4 — enforce.** Flip guards to enforce; final regression pass.

## Error handling
The whole sub-project *is* error handling. Meta-rule: a primitive that fails must fail loudly (visible error), never silently. The 401 interceptor must not loop. Guards must go red on a real regression and green on correct code (mutation-tested).

## Testing
- Unit tests per primitive: `QueryGate` (loading/error/empty/data branches); `ConfirmAction` (confirm fires onConfirm; `requireReason` blocks until filled; destructive styling); `SecretField` (empty on edit, `changed` flag, send-only-if-changed); `useRevealedSecret` (auto-clear on timeout + unmount; clipboard `.catch`).
- Integration: a 401 mid-session renders the re-login dialog once (not scattered empties); a secret is not prefilled on edit.
- The existing ~97% page tests + the two CI guards cover the sweep; add targeted tests where a page's behavior changes materially (e.g. `passwordless-settings` no longer shows enabled on error).

## Success criteria (measurable)
1. 100% of pages with a list/detail query render `QueryError`/`QueryGate` on error (Guard 1 green in enforce mode).
2. A global 401 always yields the re-login dialog; no page masks a dead session as empty.
3. Every destructive/privileged mutation routes through `ConfirmAction` (Guard 2 green); security-critical ones require a reason.
4. No stored secret is echoed into a form; revealed secrets auto-clear; `passwordless-settings` never shows a fake "enabled" posture.
5. Both CI guards run in the pipeline and block regressions.

## Out of scope (later waves)
Visual redesign, tokens, dark mode, responsive shell, breadcrumbs (**B**); topology/cockpit (**C**); merging duplicate pages / insight drill-down (**D**). This sub-project changes behavior and safety, not layout or IA.
