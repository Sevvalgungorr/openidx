# Self-Heal Control Panel — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:executing-plans. Steps use checkbox tracking.

**Goal:** Admin-only "System Health" page + `/api/v1/selfheal/*` endpoints to view findings/history and control mode + kill-switch (full model: tier1 from UI behind typed confirm + `selfheal:manage`, always-on auth, audited).

**Architecture:** Thin veneer over the on-disk self-heal state. `internal/selfheal.Store` (pure, temp-dir testable) reads latest.json/ledger.jsonl/actions.jsonl and reads/writes MODE/DISABLE. `internal/admin/handlers/selfheal.go` wraps it with authz + audit. React page in admin-console.

**Tech:** Go (gin, pgx, zap, viper), React (react-query, axios).

---

### Task 1: RBAC — `selfheal:manage` permission
**Files:** Modify `internal/auth/roles.go`; Test `internal/auth/roles_selfheal_test.go`
- [ ] Add `PermSelfHealManage = "selfheal:manage"` const; append to `AllPermissions`; add `{"selfheal","manage"}` to `RolePermissions[RoleSuperAdmin]` and `[RoleAdmin]`.
- [ ] Test: `HasPermission(RoleAdmin,"selfheal","manage")==true`, `RoleSuperAdmin` true, `RoleOperator`/`RoleAuditor`/`RoleUser` false.
- [ ] Commit.

### Task 2: Config — state + scripts dirs
**Files:** Modify `internal/common/config/config.go`; Test `internal/common/config/config_selfheal_test.go`
- [ ] Add `SelfHealStateDir` (`mapstructure:"selfheal_state_dir"`, default `/home/cmit/oidx-runtime/selfheal`, BindEnv `SELFHEAL_STATE_DIR`) and `SelfHealScriptsDir` (default `scripts/selfheal`, `SELFHEAL_SCRIPTS_DIR`).
- [ ] Test: defaults load; env override wins.
- [ ] Commit.

### Task 3: `internal/selfheal.Store` — state read/write
**Files:** Create `internal/selfheal/store.go`; Test `internal/selfheal/store_test.go`
- [ ] `type Store struct{ Dir string }`; `type Finding`, `type Snapshot`, `type Action`, `type State`.
- [ ] Methods: `Status()(Snapshot,bool,error)` (bool=stale/missing), `Findings(filter)([]Finding,error)`, `History(limit)([]Action,error)`, `Mode()(string,error)` default observe, `SetMode(string)error` (reject non-enum), `KillSwitch()(bool,error)`, `SetKillSwitch(bool)error`.
- [ ] Tests (temp dir): SetMode round-trips + rejects "bogus"; kill-switch create then remove; Findings parses 2 lines + skips bad JSON; missing files → empty + no error.
- [ ] Commit.

### Task 4: `remediate.sh` — append `actions.jsonl`
**Files:** Modify `scripts/selfheal/remediate.sh`; Modify `scripts/selfheal/remediate.test.sh`
- [ ] After each terminal branch (recovered/still-bad/halted/escalate/dry-run/observe) append `{ts,fingerprint,action,result}` to `$SELFHEAL_STATE_DIR/actions.jsonl` via a `_record <result>` helper.
- [ ] Test: after a tier0 restart, `actions.jsonl` has a line with `"result":"recovered"`; after kill-switch, `"result":"halted"`.
- [ ] Commit.

### Task 5: Handler — `internal/admin/handlers/selfheal.go`
**Files:** Create `internal/admin/handlers/selfheal.go`; Test `internal/admin/handlers/selfheal_test.go`
- [ ] `SelfHealHandler{logger, store, scriptsDir, audit func(...)}`; `NewSelfHealHandler(logger, stateDir, scriptsDir, auditFn)`.
- [ ] Handlers: `GetStatus`, `GetFindings`, `GetHistory`, `PutMode` (400 on bad enum; `tier1` needs `confirm=="tier1"`), `PostKillSwitch`, `PostSweep` (exec `selfheal-watch.sh` via `context.WithTimeout` 20s).
- [ ] `SelfHealRoutes(group, handler, adminMW, manageMW)`: reads under adminMW; PutMode/PostKillSwitch/PostSweep under adminMW+manageMW.
- [ ] Tests (gin TestMode, role injection): routes registered; non-admin→403; PutMode "bogus"→400; PutMode tier1 no-confirm→400, with confirm→200 (audit called); PostKillSwitch writes DISABLE; each mutation invokes the audit fn.
- [ ] Commit.

### Task 6: Permission middleware for `selfheal:manage`
**Files:** Modify `internal/admin/handler.go` (or reuse); Test in Task 5 file
- [ ] Add `RequirePermission(resource, action string) gin.HandlerFunc` if none exists (checks `permissions` claim in context, else 403). If one exists, reuse it.
- [ ] Wire `manageMW` from it in main.go.
- [ ] Commit (folded into Task 5 if trivial).

### Task 7: Wire into `cmd/admin-api/main.go`
**Files:** Modify `cmd/admin-api/main.go`, `internal/admin/handlers/routes.go`
- [ ] Construct `NewSelfHealHandler(log, cfg.SelfHealStateDir, cfg.SelfHealScriptsDir, adminService.RecordAdminAction-adapter)`; register via `SelfHealRoutes(v1, handler, admin.RequireAdmin(), admin.RequirePermission("selfheal","manage"))`.
- [ ] Test: `TestRegisterAllRoutes`-style assert the 6 selfheal paths exist.
- [ ] Build `go build ./cmd/admin-api`. Commit.

### Task 8: Frontend API client + types
**Files:** Modify `web/admin-console/src/lib/api.ts`
- [ ] Add `SelfHealFinding`, `SelfHealStatus`, `SelfHealAction` types + `api.selfheal.{status,findings,history,setMode,killSwitch,sweep}`.
- [ ] Commit.

### Task 9: Frontend page `system-health.tsx`
**Files:** Create `web/admin-console/src/pages/system-health.tsx`; Modify `pages/pages/index.ts`, `App.tsx`, `config/navigation.ts`
- [ ] Page: health tiles, findings table (filter chips, security "no auto-action" badge), history list, mode segmented control (tier1 → typed-confirm dialog), kill-switch toggle (confirm dialog), refresh-now. `useQuery`/`useMutation`/`QueryError`/toast.
- [ ] Export lazy `SystemHealth`; add `<Route path="system-health" element={<AdminRoute><SystemHealth/></AdminRoute>}/>`; nav entry (Operations domain, `minRole:'admin'`).
- [ ] `npm run build` + `npm run lint` clean. Commit.

### Task 10: Verify + deploy
- [ ] `go build ./... && go vet ./internal/selfheal/... ./internal/admin/... ./internal/auth/...`; run new Go tests; run `scripts/selfheal/*.test.sh`; frontend build/lint.
- [ ] Deploy to box (admin-api rebuild + frontend dist rebuild-in-place per the nginx-mount lesson); smoke: GET /status as admin, PUT /mode observe→tier0→observe (audit rows), kill-switch on/off; confirm no dev-bypass (unauth → 401/403).
- [ ] Add a `selfheal-watch` cron/timer note to the runbook.

## Self-Review
- Spec coverage: endpoints (T5/7), Store (T3), RBAC (T1), config (T2), history source (T4), page+control+tier1-confirm (T9), tests each task, deploy (T10). ✓
- No placeholders: each task names files, funcs, and assertions.
- Name consistency: `SelfHealStateDir`/`SelfHealScriptsDir`, `PermSelfHealManage="selfheal:manage"`, `/api/v1/selfheal/*`, `actions.jsonl` result enum {recovered,still-bad,halted,escalated,dry-run,observe} used identically in T4 emitter and T3/T5 readers.
