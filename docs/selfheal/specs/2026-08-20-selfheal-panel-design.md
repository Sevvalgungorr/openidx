# Self-Heal Control Panel — Design Spec

**Goal:** Surface the self-heal loop (PR #793) in the admin console as an admin-only "System Health" page — view health/findings/remediation history, and control mode + kill-switch — so operators and UI testers can see and drive it from the interface.

**Depends on:** the self-heal loop scripts + state dir (`feat/selfheal-loop-mvp`, PR #793). This branch stacks on it.

## Locked decisions
- **Scope:** full control panel (view + control), not read-only.
- **Security model:** *full* — `tier1` IS settable from the UI, behind an extra typed confirmation and a dedicated `selfheal:manage` permission. All mutations are `RequireAdmin` + `selfheal:manage`, **always-on auth (no dev-mode bypass)**, and every mutation writes an admin audit event (actor, action, old→new). Kill-switch and any mode change require an explicit confirm dialog.

## Architecture
The scripts already own the state on disk. The panel is a thin read/write veneer:
- **admin-api service (:8005)** gains a `selfheal` handler group under `/api/v1/selfheal/*` (flat under v1, matching `dashboard`/`settings`).
- Reads `latest.json` + `ledger.jsonl` + `actions.jsonl` from `SELFHEAL_STATE_DIR`; reads/writes `MODE` and `DISABLE` files (the scripts already honor them).
- **No synchronous sweeps in the request path.** A scheduled watch (cron, deploy step) keeps `ledger.jsonl`/`latest.json` fresh; the API only reads them. One optional `POST /selfheal/sweep` shells out to `selfheal-watch.sh` with a hard timeout for an on-demand "refresh now".
- **Frontend:** new page `system-health.tsx`, admin-gated route + nav entry.

## Data units
- `internal/selfheal/store.go` (new, pure, temp-dir testable): `Store{Dir}` with
  `Status()` (parse latest.json → snapshot + health tiles), `Findings()` (parse ledger.jsonl),
  `History(limit)` (parse actions.jsonl), `Mode()`/`SetMode(m)` (read/write MODE, validate enum),
  `KillSwitch()`/`SetKillSwitch(bool)` (stat/create/remove DISABLE). No gin, no DB — unit-testable.
- `internal/admin/handlers/selfheal.go` (new): HTTP handler wrapping the Store + audit + authz.
- `remediate.sh` change: append one line per action to `actions.jsonl`
  (`{ts,fingerprint,action,result}` where result ∈ recovered|still-bad|halted|escalated|dry-run) so the
  panel has a remediation history. Existing stdout lines are unchanged.

## Endpoints (all under `/api/v1/selfheal`)
| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/status` | RequireAdmin | latest.json summary + health tiles + current mode + kill-switch state |
| GET | `/findings` | RequireAdmin | ledger.jsonl (optional `?class=&severity=&status=`) |
| GET | `/history` | RequireAdmin | last N actions from actions.jsonl |
| PUT | `/mode` | RequireAdmin + `selfheal:manage` | set off/observe/tier0/tier1 (audit) |
| POST | `/kill-switch` | RequireAdmin + `selfheal:manage` | `{enabled:bool}` toggle DISABLE (audit) |
| POST | `/sweep` | RequireAdmin + `selfheal:manage` | shell out to selfheal-watch.sh, 20s timeout (audit) |

**Validation:** `SetMode` rejects anything not in {off,observe,tier0,tier1} → 400. `PUT /mode` to `tier1`
requires body `{"mode":"tier1","confirm":"tier1"}` (server checks the confirm token) — the extra guard the
UI enforces with a typed dialog and the API double-checks.

## RBAC
Add `PermSelfHealManage = "selfheal:manage"` to `internal/auth/roles.go`, in `AllPermissions`, granted to
`super_admin` and `admin` (direct), NOT operator/auditor/user. Reads (`/status`,`/findings`,`/history`)
gate on `RequireAdmin` only (admin sees state); mutations additionally require the permission (so a future
narrower role can be denied control while still viewing).

## Config
Add to `internal/common/config/config.go` (mirroring `AgentDownloadsDir`):
- `SelfHealStateDir` (`SELFHEAL_STATE_DIR`, default `/home/cmit/oidx-runtime/selfheal`)
- `SelfHealScriptsDir` (`SELFHEAL_SCRIPTS_DIR`, default `scripts/selfheal`) — for the sweep shell-out.

## Frontend
`web/admin-console/src/pages/system-health.tsx`:
- Health tiles: 7 services + edge (from `/status`), green/red.
- Findings table: class, severity, service, message, count, first/last seen, status — filter chips by class/severity. Security findings shown with a "no auto-action" badge.
- Remediation history: recent actions with result.
- **Mode control:** segmented selector off/observe/tier0/tier1. Selecting `tier1` opens a dialog requiring the user to type `tier1`. Confirm → `PUT /mode`.
- **Kill-switch:** prominent toggle with a confirm dialog ("halts ALL autonomy").
- "Refresh now" button → `POST /sweep` then refetch.
- Uses `useQuery`/`useMutation`, `QueryError`, toast; route wrapped in `<AdminRoute>`; nav entry under an "Operations" domain, `minRole: 'admin'`.

## Error handling
File-missing (state dir not yet populated) → empty snapshot / empty findings, `200` with `{stale:true}`,
not a 500. Invalid mode → 400. Sweep timeout → 504 with a clear message. Non-admin → 403 (`QueryError`
renders the permission message, never a silent empty state).

## Testing
- `store_test.go`: round-trip Mode set/get (enum validation), kill-switch create/remove, findings/history parse from a temp dir, missing-file → empty not error.
- `selfheal_test.go` (handler): route registration; non-admin → 403; invalid mode → 400; `tier1` without confirm → 400, with confirm → 200; kill-switch toggle writes DISABLE; audit called on each mutation.
- `roles` test: `super_admin`/`admin` have `selfheal:manage`; `operator` does not.
- `remediate.test.sh`: assert an `actions.jsonl` line is appended with the right `result`.
- Frontend: build + lint clean; the page renders tiles/table; tier1 dialog requires the typed token before the mutation fires.

## Rollout / deploy
Backend + frontend deploy via the standard box recipe (8-binary rebuild is unnecessary — only admin-api
changes + frontend dist). Add a cron/systemd-timer running `selfheal-watch.sh` every ~15 min in observe so
the panel shows live data (documented in the runbook; not created by this PR unless asked). Panel ships with
box mode still `observe`.

## Out of scope
Per-finding "fix now" buttons, Tier-1 code-fix harness, notifications/paging, historical charts. Phase 2.
