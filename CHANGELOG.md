# Changelog

All notable changes to OpenIDX are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Clientless remote access + Quick Links launcher + attended-support consent.**
  A user can now reach support/collaboration systems and remote connections with
  no installed client, and admins manage it centrally. (1) **In-browser SSH**
  ("wasm-ssh" renderer): a PAM SSH entry opens an xterm.js terminal in the
  browser over a WebSocket->TCP relay (`GET /api/v1/access/pam/entries/:id/ws`)
  that dials the target over the Ziti overlay — no PuTTY/guacd, the browser tab
  is the SSH client. Reuses the existing PAM permission/approval gate (enforced
  before the socket upgrade) and credential vault; the token rides as a
  `bearer.<jwt>` WS subprotocol. `pam_entries.renderer` (migration v89) selects
  guacamole (default, unchanged) vs wasm-ssh. (2) **Quick Links** (migration
  v90): an admin-curated, user-searchable launcher. `type=external` opens a safe
  URL (Teams/Zoom/status/ticketing); `type=pam` references a connection and
  launches it clientlessly via its renderer. Org-scoped + forced RLS, role-gated
  by `min_role`, unsafe URLs rejected. New user page (`/quick-links`) + admin
  CRUD (`/quick-links-admin`). (3) **Attended-support consent** (migration v91):
  a remote-support session can require the person at the device to Allow it
  before the admin can view/control — the admin WebSocket is refused (403
  "awaiting device consent") until the device grants via
  `POST /agent/remote-support/sessions/:id/consent`; a denial ends the session.
  Plus a **live view<->control toggle** in the support viewer (hand control back
  and forth without restarting). Verified live end-to-end (real SSH handshake;
  quick-links create/list/reject; consent 403->101). Also fixed a pre-existing
  bug where `remote_support_sessions` lacked `org_id`/`recording_retention_days`
  (referenced by session-start but never migrated), and a migration-runner
  dollar-quote splitter bug that broke fresh `migrate` on v89.

- **Dark platform (Ziti-first / overlay-only posture) — Phases 1-6, fully opt-in.**
  A staged path to make OpenIDX's own surfaces reachable only over the OpenZiti
  overlay, defaults preserving today's public behavior at every step. (1)
  `SERVICE_BIND_ADDR` + `DARK_MODE_TIER1/2` config and `cfg.ListenAddr()` so every
  service can bind loopback-only (verified live). (2) `#enrolled-users` on every
  identity + gated `#device-trusted`, and a reconciler `ensureTierDialPolicy`.
  (3) A single hardened public enroll door `POST /api/v1/access/enroll`
  (session/token → Ziti enrollment JWT, rate-limited + audited; verified live,
  fail-closed on every bad path). (4) `DARK_MODE={off|tier2|tier1}` edge route
  set + `scripts/dark-mode.sh` (`--verify`/`--undark`/`--self-test`) + `make
  dark-drill`. (5) The reconciler now models OpenIDX's own surfaces as tier'd
  dark Ziti services via `defaultDarkServices()` (admin-api/governance/audit/
  provisioning/scim/access → Tier 2 `#device-trusted`; identity self-service +
  console → Tier 1 `#enrolled-users`; enroll/oauth/jwks never darked), plus
  `scripts/register-console-dark-app.sh` registering the admin console as a
  BrowZer dark app (Tier-1 shell, same-origin `/api/*` tunnels to the Tier-2
  backends). (6) Staged **cutover runbook + break-glass** in
  `OPENIDX_ZITI_ARCHITECTURE.md` (enroll fleet → drill → cut Tier 2 then Tier 1
  → `--undark`), linked from `DEPLOYMENT.md`, and **mutation-tested tier
  invariants** wired into `make dark-drill` (Tier-2 surfaces must be
  `#device-trusted`; no Tier-0 surface is ever darked; dark upstreams are
  loopback). Spec/plan under `docs/superpowers/`.

- **Scoped the Tier 3b cutover: `docs/tier3b-cutover-runbook.md`.** The
  availability plan recommended moving prod off the single VM onto the
  already-written EKS/managed path but left the *cutover* itself unsequenced. New
  runbook lays out the end-to-end move: preconditions (a passing `make ha-drill`
  and a live DR game-day PASS), closing the two open infra gaps (add an OpenSearch
  Terraform module; activate the RDS read replica via `externalSecrets.readReplica`
  — everything else is wired), standing up the EKS stack in parallel on a shadow
  DNS name, the data cutover (logical replication preferred, dump/restore
  fallback), a DNS traffic cutover that deliberately flips the **DB-independent
  verify surfaces first** so token validation never stops, post-cutover
  activation/verification, and rollback at each stage. It leans on the
  always-available invariant (verification does not depend on which stack/DB is
  live) that `make dr-game-day` checks at every gate. Also surfaced and wired the
  concrete config gap it identified: `values-prod.yaml` now carries a documented
  `externalSecrets.readReplica` flag (left `false` so a fresh cutover's
  ExternalSecret doesn't reference a missing key; flip on as a follow-on step).
  Verified `helm template` renders clean with the flag both off (no
  `DATABASE_READ_URL`) and on (rendered). Linked from the availability plan and
  `DEPLOYMENT.md`.

- **Repository pattern reaches the admin god-object (`SettingsRepository`).**
  Began strangling `internal/admin/service.go` (3,439 lines — the largest
  god-object in the design-patterns review) by extracting all `system_settings`
  access into `internal/admin/settings_repository.go`. That table is a key/value
  JSON store (`system`, `sms_config`, `mfa_methods`, ...) whose identical
  `SELECT value FROM system_settings WHERE key = $1` + `INSERT ... ON CONFLICT
  (key) DO UPDATE` UPSERT was copy-pasted inline across ~6 handlers, each free to
  pick its own pool. It's now one `GetRaw`/`PutRaw` port with a typed
  `ErrSettingNotFound` and nil-db guards; `admin.Service`'s `GetSettings`/
  `UpdateSettings` + the SMS/MFA-methods handlers delegate to it. **Pool
  judgment:** reads use the **primary**, not the replica — `system_settings`
  carries password policy, `RequireMFA`, lockout, and session limits, so a
  just-tightened policy must take effect immediately (read-after-write); a lagging
  replica could briefly enforce a weaker policy. Locked by a mutation-tested
  invariant guard (`TestSettingsRepositoryGetUsesPrimary`/`WritesUsePrimary`,
  wired into `make ha-drill`; verified it fails when a write is moved to
  `.Reader()`) and unit-tested with a fake repo and no database (defaulting,
  corrupt-row fallback, write-error propagation, nil-db guards).

- **`make dr-game-day` — the data-tier failover game-day is now runnable, not a
  copy-paste runbook.** `docs/disaster-recovery.md` §1D previously described the
  RDS Multi-AZ / Patroni failover drill as manual shell steps in a comment block.
  New `scripts/dr-game-day.sh` executes it end-to-end: a synthetic auth canary
  probes `/health/live` (verify path — must stay 200 the entire window, since
  verify is DB-free/serve-stale) and `/health/ready` (issue path — may 503 while
  the LB drains new logins, then must self-recover as pgxpool re-dials the
  promoted primary), then prints a pass/fail verdict and exits non-zero on any
  contract violation. It can trigger failover itself (`--trigger --provider
  rds|patroni`) or just observe. Crucially it ships a **`--self-test` mode** that
  stands up a local stdlib mock simulating a failover window and runs the whole
  canary/verdict logic against it — so the drill is verified with no
  infrastructure and can't silently rot into a false-green (a false-green DR
  drill is worse than none). `make dr-game-day` runs that self-test; verified it
  passes on a clean window and fails correctly on both a verify-path drop and a
  non-recovering issue path.

- **`make ha-drill` — one command to verify the always-available-auth
  guarantees.** Runs the focused Go tests that encode each availability tier
  (serve-stale JWKS + Auth-survives-issuer-outage; bounded DB timeouts +
  read-replica seam; dependency-outage classification + 503 brownout + Redis
  revocation breaker) plus the mutation-tested read/write pool-safety guards. The
  wrapper (`scripts/ha-drill.sh`) fails loudly if a guarantee test is renamed or
  removed (no silent "[no tests to run]" false-green), so the drill stays
  trustworthy. Runs in ~15s with no infrastructure; complements the DR failover
  game-day. See `docs/architecture/always-available-auth-plan.md` §5.

- **Repository pattern reference implementation (identity/User).** Introduced
  `internal/identity/user_repository.go`: a `UserRepository` interface +
  `PostgresUserRepository` pgx implementation
  (`GetByID`/`GetByUsername`/`GetByEmail`/`Exists` reads via `db.Reader()`, plus
  `Create`/`Update`/`Delete` writes on the primary pool) that isolates user SQL
  into one type, scopes every query to the caller's tenant, and makes the
  primary-vs-replica choice explicit (reads offload to the Tier 1.6 replica;
  writes never do). `identity.Service.GetUser`/`GetUserByUsername`/
  `GetUserByEmail`/`CreateUser`/`UpdateUser`/`DeleteUser` now delegate to it
  (behavior-preserving; domain side effects like audit logging, deprovisioning,
  and delete ordering stay in the service). Along the way this fixed a latent
  NULL-name scan error in the username/email lookups, guarded two nil-DB
  panics (`logAuditEvent`, `deprovisionUser`), and surfaces duplicate
  username/email as a typed `ErrUserAlreadyExists` (409). This is the template
  for splitting the god-object services (see
  `docs/architecture/design-patterns-review.md`). Business logic (full CRUD) is
  now unit-testable with a fake repo and no database (`user_repository_test.go`).

- **Repository pattern — second aggregate (identity/Group).** `Group` is now
  behind `GroupRepository` (`internal/identity/group_repository.go`) following the
  same template: `GetByID`/`GetByName` reads on the replica, `Create`/`Update`/
  `Delete` writes on the primary (Delete removes memberships then the group row),
  typed `ErrGroupNotFound`/`ErrGroupAlreadyExists`. `identity.Service`'s
  `GetGroup`/`GetGroupByDisplayName`/`CreateGroup`/`UpdateGroup`/`DeleteGroup`
  delegate to it. Unit-tested with a fake repo and no database
  (`group_repository_test.go`).

- **Repository pattern — third aggregate (identity/Session).**
  `SessionRepository` (`internal/identity/session_repository.go`) demonstrates
  per-query pool judgment: lag-tolerant reads (`ListByUser`/`CountActive`) use the
  replica, while `IsValid` deliberately reads the **primary** because session
  validity is a read-after-write security check (a just-revoked session must not
  read as valid off a lagging replica). Writes (`Create`/`UpdateActivity`/
  `Terminate`) use the primary. `identity.Service`'s `GetUserSessions`/
  `CreateSession`/`UpdateSessionActivity`/`IsSessionValid`/`CountActiveSessions`/
  `TerminateSession` delegate to it. The security-critical primary read is locked
  by a mutation-tested guard (`TestSecurityCriticalReadUsesPrimary`), and the
  writes-never-replica guard now covers all three repositories. Unit-tested with a
  fake repo and no database (`session_repository_test.go`).

- **Repository pattern generalizes to the oauth service (OAuth clients).** OAuth
  client CRUD is now behind `OAuthClientStore`
  (`internal/oauth/oauth_client_store.go`): `GetByClientID` reads the primary
  (client validation gates every token grant and checks the secret), `List` reads
  the replica, and `Create`/`Update`/`Delete` write the primary.
  `oauth.Service`'s `GetClient`/`ListClients`/`CreateClient`/`UpdateClient`/
  `DeleteClient` delegate to it; guarded by a mutation-tested invariant test and
  unit-tested with a fake store and no database. Also documented a pre-existing
  smell surfaced by this work: the oauth package has a *separate* `ClientRepository`
  (`client.go`, used by `token_flow.go`) that models the same `oauth_clients` table
  differently — a worthwhile unification follow-up (see
  `docs/architecture/design-patterns-review.md`). **(Resolved below in
  Removed — that duplicate turned out to be unwired, security-divergent dead code
  and was deleted.)**

### Fixed

- **Android/iOS client no longer boots to a blank white screen.** `main()` ran
  the desktop boot path on every platform: it awaited
  `windowManager.ensureInitialized()` (and later `TrayController.init()`), but
  `window_manager` / `tray_manager` are desktop-only plugins with no method-channel
  implementation on mobile. The call threw
  `MissingPluginException(No implementation found for method ensureInitialized on
  channel window_manager)` **before `runApp()`**, so the app started, painted
  nothing, and showed no crash dialog — it just sat on white. `main()` now
  branches on `EngineClientFactory.isMobile`: mobile calls `runApp()` directly
  (leaving `engineSupervisorProvider` un-overridden so `engineClientProvider`
  builds the in-process `MobileEngineClient`), while desktop keeps the unchanged
  window-chrome + tray + sidecar-supervisor path. The rest of the mobile
  code (`MobileShell`, `SettingsScreen`) was already platform-guarded; `main.dart`
  was the only unguarded entry point. The Flutter client version also now tracks
  the release tag (`1.33.2+13302`, was `0.1.0+1`) so the installed build is
  identifiable on-device.

- **Admin-console unit tests can run again (frontend test env repaired).**
  `vitest.config.ts` requested `environment: 'happy-dom'`, but `happy-dom` was
  never in `package.json` (only `jsdom` is a pinned devDependency), so `npm test`
  / CI's `npm test -- --run` died immediately with `ERR_MODULE_NOT_FOUND` and
  ran **zero** tests. Switched the config to the installed `jsdom` environment
  and added the one jsdom shim happy-dom provided that Radix UI needs:
  `Element.prototype.scrollIntoView` (a no-op mock in `src/test/setup.ts`),
  which `@radix-ui/react-select` calls on mount and which otherwise threw
  `candidate?.scrollIntoView is not a function` and failed every Select-based
  test. Result: the full suite now runs green — **761 tests across 122 files
  pass** (previously: could not start). This also unblocks the `ci-web`
  pipeline. No new dependency added.

### Security

- **Closed ~170 server-error information-disclosure sites: 5xx responses no
  longer leak `err.Error()` to clients.** Handlers across 30+ files (access/Ziti,
  identity MFA/risk, vault, credentials, audit, organization, portal, oauth
  client-management) were returning the raw wrapped error
  (`c.JSON(500, gin.H{"error": err.Error()})`) — which can expose SQL fragments,
  hostnames, driver text, and internal paths. Every 5xx `err.Error()` leak was
  migrated to the typed renderer `apperrors.HandleErrorWithLogger(c,
  apperrors.Internal("<action>", err), logger)`, which returns a safe, typed body
  (`{"error":"INTERNAL_ERROR","message":"<action>"}`) to the client while logging
  the real cause server-side with request-id/path context. Where a handler
  already logged the error immediately before leaking it, that now-redundant log
  line was removed to avoid double-logging (the renderer logs). Protocol
  endpoints kept their RFC 6749 shape (e.g. the OAuth authorize/consent path
  still returns `{"error":"server_error"}`, now with a static
  `error_description` instead of the raw error). A count check enforces zero
  remaining 5xx `err.Error()` leaks. **Surfaced and fixed a latent bug in the
  process:** `portal.ReviewGroupRequest` returned its "invalid decision"
  *validation* error as a 500 leak; it now returns a typed `ErrInvalidDecision`
  sentinel that the handler maps to a proper 400. `go build ./...`,
  `go vet ./...`, and the touched-package tests all pass.

### Removed

- **Collapsed the admin-console's two parallel API clients — deleted the entire
  dead `src/lib/api/` directory (client + domain wrappers + barrel; ~800 lines).**
  The console had two API layers: the live `src/lib/api.ts` (the `api` object,
  imported by ~199 modules) and a second, separate `src/lib/api/` package
  (`client.ts` axios instance + `admin`/`audit`/`governance`/`identity` wrappers +
  `types.ts` + an `index.ts` barrel re-exporting `apiClient as api`). Because a
  file (`api.ts`) wins module resolution over a same-named directory
  (`api/index.ts`), **every `@/lib/api` import hit `api.ts` and the whole
  directory had zero live importers** — a classic duplicate-that-can-drift trap
  (the two clients had already diverged on token-storage keys and the
  refresh-token endpoint, both fixed earlier). Verified exhaustively that nothing
  outside the directory imported any of its modules, then removed it. The one
  place that referenced it — `dashboard.test.tsx` — was `vi.mock()`-ing the dead
  `./lib/api/client` while the component under test actually imports `{ api }`
  from `../lib/api`, so the mock was inert; retargeted it to mock the real
  `../lib/api`, which also makes the test's stubbing actually take effect.
  `tsc --noEmit`, the full vitest suite (746 tests / 121 files pass; the −15 vs
  before are exactly the deleted `audit.test.ts` that only tested the dead
  `auditApi`), and `vite build` all pass.

- **Deleted a dead, security-divergent duplicate OAuth/OIDC pipeline
  (`client.go`, `authorize_flow.go`, `token_flow.go`; ~3,100 lines incl. tests).**
  The oauth package carried a second, fully parallel implementation
  (`Client` / `ClientRepository` / `AuthorizeFlow` / `TokenFlow`) operating on the
  same `oauth_clients` table as the live `OAuthClient` / `OAuthClientStore`, but it
  was **never wired to a live route** — only reachable from tests. It had also
  already diverged from the live path on a security check: the dead
  `ClientRepository.ValidateRedirectURI` permitted wildcard-subdomain redirect
  URIs (`https://*.example.com`, an open-redirect risk), while the live authorize
  handler requires exact byte-equality. Two representations of one table that can
  disagree — and insecure dead code invites someone to wire it — so the cluster
  was removed. The authoritative representation is `OAuthClient` (+
  `OAuthClientStore`); live token/authorize/userinfo flows remain in
  `service.go` / `authorize.go`. The three genuinely-live symbols the cluster
  exported (`TokenFlowResponse`, `generateUUID`, and the RFC 6749 error-code
  constants used by the 503 brownout path) were preserved in a small new
  `internal/oauth/oauth_types.go`. Redundant validation tests were dropped only
  after confirming equivalent live coverage
  (`TestAuthorizeHandler_ValidateRedirectURI`, `TestValidatePKCE`,
  `TestSecurityFeatures`); `TestOAuthConstants` was retargeted onto the preserved
  constants. `go build ./...`, `go vet ./...`, and `go test ./internal/oauth/`
  all pass. See `docs/architecture/design-patterns-review.md` §1.

### Changed

- **Hardened the shared error renderer (`internal/common/errors`).** `HandleError`
  now guarantees the client only sees safe, typed fields (never the wrapped
  internal error), and a new `HandleErrorWithLogger(c, err, logger)` logs the real
  cause server-side for 5xx (with request id + path) instead of silently dropping
  it. Closes an information-disclosure vector and an observability gap. Tests in
  `render_test.go` verify a DB error containing a password/hostname is logged but
  not leaked to the response body. First adopters migrated in
  `internal/identity/handlers_otp.go` (internal-error sites that previously
  discarded the underlying error now log it via `HandleErrorWithLogger`).

- **Always-available authentication — Tier 0 (verify-path survives a DB outage).**
  Token *verification* (validating an already-issued JWT) is now hardened to keep
  working through an outage of the OAuth/JWKS endpoint and the shared database:
  - **Serve-stale JWKS.** The shared verify path
    (`internal/common/middleware`, used by all services) and the gateway JWT
    middleware now keep serving the last successfully fetched signing keys when a
    JWKS refresh fails, bounded by `JWKS_MAX_STALE` (default 12h) past the
    `JWKS_TTL` freshness window (default 1h). Previously a failed refresh after
    cache expiry rejected otherwise-valid tokens, turning a database blip into an
    auth outage.
  - **Metrics + alerts.** New `openidx_jwks_refresh_failures_total`,
    `openidx_jwks_serve_stale_total`, and `openidx_jwks_stale_seconds`, with a
    `openidx.jwks_availability` PrometheusRule group (issuer-down, serving-stale,
    and near-max-stale alerts).
  - **Liveness/readiness probe split.** Every Helm service pointed both probes at
    `/health` (which 503s when the shared DB is down), so a DB blip would restart
    every pod at once and wipe warm JWKS caches. Liveness now uses `/health/live`
    (process-only), readiness uses `/health/ready` (drains from the LB on a
    critical dependency outage), for graceful degradation instead of a crash-loop.
  - Docs: `docs/architecture/always-available-auth-plan.md`.

- **Always-available authentication — Tier 1 (issue path survives DB failover).**
  - **Bounded DB connect timeout.** pgxpool's default `ConnectTimeout` was 0
    (unbounded), so a runtime reconnect to a dead primary during an RDS/Patroni
    failover could hang for minutes, pin the request, and exhaust the pool — a DB
    failover cascading into a service-wide outage. `internal/common/database` now
    sets a 5s connect timeout (`DB_CONNECT_TIMEOUT`) so failover fails fast and the
    pool re-dials the promoted primary.
  - **Optional per-statement timeout** (`DB_STATEMENT_TIMEOUT`, 30s in prod
    values) so a query on a degraded primary can't hold a connection open forever.
    Off by default; migrations run out-of-band and are unaffected.
  - Wired through the Helm configmap (`database.connectTimeout` /
    `database.statementTimeout`), set in `values-prod.yaml`. Tests:
    `internal/common/database/pool_config_test.go`. Added a Postgres failover
    game-day to the DR runbook.
  - **Optional read-replica pool.** `DATABASE_READ_URL` opens a second read-only
    pool exposed via `(*PostgresDB).Reader()`, which falls back to the primary
    when no replica is configured (correct-by-construction call sites). A replica
    outage never fails startup (degrades to primary-only) and is surfaced by a
    new non-critical `database_replica` health check. Delivered via the external
    secret store (`externalSecrets.readReplica`). Query call sites are not
    auto-routed — adoption is per-query where read-after-write is not required.
    Tests: `read_replica_test.go`, `read_replica_checker_test.go`.

- **Always-available authentication — Tier 2 (graceful brownout on the issue path).**
  Added `internal/oauth/unavailable.go`: a classifier that distinguishes a
  transient dependency outage (Postgres/Redis unreachable, pool exhausted, dial
  timeout, `57P0x`/`08xxx`/`53300`/`25006` SQLSTATEs, network errors) from a
  genuine application error, and returns RFC 6749 `503 temporarily_unavailable`
  with a `Retry-After` header for the former (clients back off and retry) while
  keeping `500 server_error` for the latter. Applied to the DB-backed OAuth
  issue-path sites (authorization-code creation, refresh-grant user-status
  check), so a database failover degrades login to a brief, retryable brownout
  instead of a hammered 500. Tests: `internal/oauth/unavailable_test.go`.
  - **Redis revocation-check circuit breaker.** `IsAccessTokenRevoked` (the
    hot-path revocation read used by token introspection/verification) now runs
    its Redis reads through a circuit breaker (`oauth-redis-revocation`,
    threshold 5, 5s reset). During a Redis brownout the breaker opens and the
    check fails fast instead of every request paying the 3s Redis read timeout.
    Callers already fail closed on error, so opening the breaker changes cost, not
    security. Observable via `openidx_circuit_breaker_state{name=
    "oauth-redis-revocation"}` (existing `CircuitBreakerOpen` alert). Test:
    `internal/oauth/revocation_breaker_test.go`.

- **Always-available authentication — Tier 3 (infra for HA prod).** The Terraform
  RDS module now provisions optional read replica(s) (`read_replica_count`,
  defaulted to 1 in prod / 0 in dev) and exposes `rds_reader_endpoints` /
  `rds_reader_addresses`. This is the managed reader endpoint the Tier 1.6
  `DATABASE_READ_URL` app seam points at — previously the app supported a read
  pool that prod had no way to create. Wire the output into the external secret
  `.../database-read-url` and set `externalSecrets.readReplica=true` to activate
  it. (`deployments/terraform/modules/rds`, `deployments/terraform/main.tf`.)

## [1.27.0] - 2026-07-13

### Added

- **PAM per-connection broker routing — direct vs OpenZiti (#439)** — each connection
  entry selects a `reach_mode`: `direct` (guacd dials the target) or `ziti` (guacd →
  loopback → ziti-tunnel → OpenZiti overlay → target, no inbound target exposure).
  Migration **v82** adds `reach_mode`/`ziti_service_name`/`ziti_intercept_port` to
  `pam_entries`.
- **PAM dedicated session brokers — deploy artifacts (#440)** — opt-in docker-compose
  overlay and Helm templates for two isolated Guacamole brokers (direct + ziti) with
  their own DB and admin credentials, kept separate from any shared Guacamole. Gated by
  `pamBroker.enabled` (default off → zero manifests).
- **Split internal vs browser-facing Guacamole URL (#441)** — `GUACAMOLE_PUBLIC_URL` /
  `GUACAMOLE_ZITI_PUBLIC_URL`: the access service dials the internal broker for the REST
  API but hands the browser a reverse-proxy-reachable connect URL. Falls back to the
  internal URL when unset.

### Fixed

- **Brokered PAM launch was not idempotent (#441)** — the Guacamole connection name is
  deterministic (`pam-<entryID>`); once created, a relaunch without a persisted connection
  id hit Guacamole's `409/400 "already exists"` → 500. Now the launcher looks the
  connection up by name, updates it in place, and reuses it.
- **SAML service-provider schema drift** — `internal/oauth/saml_sp.go` read/wrote columns
  (`description`, `metadata_url`, `want_assertions_signed`, `encryption_enabled`,
  `last_used_at`) that no migration had created, so the SP admin list/create/update paths
  errored with `42703`. Migration **v83** reconciles the table (additive; TEXT columns
  `NOT NULL DEFAULT ''`, booleans default false, `last_used_at` nullable).

### Migrations

- **v82** — `pam_entries` reach mode (direct|ziti) columns + partial unique index on the
  ziti intercept port.
- **v83** — `saml_service_providers` column reconcile.

## [1.26.0] - 2026-07-12

### Added

- **PAM connection manager — RDM parity (#437)** — a Remote Desktop Manager-style privileged
  connection tree for brokered, passwordless sessions:
  - Folders/entries model (`pam_folders`, `pam_entries`) with tags, per-entry policy flags
    (`allow_reveal`, `require_approval`, `record_session`), grants (`pam_entry_grants`),
    favorites, access requests, and a session ledger (`pam_entry_sessions`) — all org-scoped
    under FORCE RLS.
  - Import path for existing connection inventories and a launch path that opens brokered
    sessions without exposing the underlying vault credential.
  - New **PAM Connections** console page (`/pam-connections`) and API client wiring; nav entry
    under the Privileged Access section.
  - CR/LF scrubbing on user-derived values in the import/launch log lines.

### Migrations

- **v81** (additive) — `pam_folders`, `pam_entries`, `pam_entry_grants`, `pam_entry_favorites`,
  `pam_entry_access_requests`, `pam_entry_sessions` with per-table org-scope RLS policies and
  `openidx_app` grants.

## [1.25.0] - 2026-07-12

Large security-and-correctness release (workstreams WS-01…WS-05) plus cross-pillar
correlation, OAuth signing-key rotation, PAM self-service, and a substantial dead-code
purge. Schema advances **v68 → v80** (migrations v69–v80, all additive). Deployed to the
reference box via a full catch-up (schema v68→v80, 8-binary swap); functional sweep of all
services clean.

### Security

- **OAuth step-up MFA bypass closed (WS-01)** — the step-up flow no longer rubber-stamps MFA,
  and MFA-gating can't be bypassed; the authorize-consent subject is derived from the session,
  not the request body.
- **Cross-tenant IDOR fixes (WS-03)** — tenant-scoped `published_apps`/`discovered_paths`,
  `temp_access_links`, and `device_trust_requests`; `GET /organizations` no longer enumerates
  other tenants and org write paths are authorized; Elasticsearch audit search is tenant-scoped;
  portal device registration now stamps the caller's `org_id` (was mis-tenanted to the default org).
- **Minted API keys now actually authenticate requests (WS-03)** — previously issued keys were inert.
- **Separation-of-duty enforced and fail-closed (WS-05)** — SoD policies are evaluated at
  access-request fulfillment and in identity; evaluation failures fail closed.
- **Fail-open hardening** — `CheckPolicies` fails closed when org context is absent; three
  fail-open error paths in the live security checks are closed. Approval policies'
  `auto_approve_conditions` evaluate fail-closed.
- **Log-injection sanitization** — CR/LF and user-derived values scrubbed from cross-pillar,
  step-up MFA, and IBDR/continuous-auth log lines (CodeQL).

### Added

- **Cross-pillar correlation** — correlate IAM, PAM, and Ziti per user: unified access map,
  kill switch, and lifecycle propagation; a user's devices are correlated across IAM trust and
  Ziti compliance.
- **OAuth DB-backed signing-key rotation** — `oauth_signing_keys` (migration v79) backs rotatable
  RS256 signing keys.
- **Governance (WS-05)** — audit + session-kill on access-review revocation; manager-based
  reviewer resolution; `org_id` + FORCE RLS on certification/ABAC tables; JIT expiry now revokes
  application access.
- **Provisioning** — provisioning rules are evaluated on SCIM user create/update (safe additive
  subset); SCIM `filter` applied in `ListSCIMUsers`/`ListSCIMGroups`.
- **Audit** — `detailed_compliance_reports` table (migration v74) with org-scoped evidence access;
  GDPR report routed; WebAuthn MFA counted from `mfa_webauthn` in SOC2/ISO metrics.
- **Identity** — `known_devices.device_type` (migrations v75/v76) so corporate-device
  auto-approval works.
- **PAM finalization — end-user self-service** — non-admin users get a first-class PAM surface:
  - `GET /api/v1/access/guacamole/my-connections` — org-scoped catalog of brokered Guacamole
    connections with the PAM flags the launcher needs (approval required / recorded /
    credential injected); never exposes the vault secret id or Guacamole-internal identifiers.
  - `GET /api/v1/access/guacamole/my-session-requests` — the caller's own session requests
    (previously only admins could list requests), joined with route info so an approved
    request can be launched.
  - New **My Privileged Access** console page (`/my-privileged-access`, in the user nav):
    launch/request brokered remote sessions, track request status, and manage JIT credential
    checkouts (one-shot retrieve + early return) in one place.
- **PAM finalization — management dashboard** — new aggregated stats endpoint
  `GET /api/v1/pam/overview` (admin-api, admin-guarded; explicit org predicates on top of
  FORCE-RLS) covering vault inventory by type, rotation health (enabled/failing/overdue
  policies, 30-day runs/failures), checkout activity (active leases, 30-day checkouts,
  pending JIT credential requests), and privileged sessions (active, 30-day, pending
  approvals, recordings on legal hold). New **PAM Dashboard** console page
  (`/pam-dashboard`) renders it with health labels and manage links; linked from the
  dashboard's Privileged Access card and the Privileged Access nav section.

### Changed

- **Admin PAM routes are now role-gated client-side** — `/pam-dashboard`, `/vault-secrets`,
  `/rotation-policies`, and `/guacamole-sessions` no longer mount for non-admins (redirect
  to the dashboard); the backend 403 remains the enforcement layer. Vault Secrets and
  Privileged Sessions now render a friendly "admin access required" state on 403 (matching
  Rotation Policies) instead of a generic failure.
- **Legal-hold reasons via a proper dialog** — the Session History place/release legal-hold
  flow uses an accessible reason dialog (reason required to place a hold) instead of
  `window.prompt`.

### Fixed

- **Governance revocation actually revokes** — access-review revoke decisions now revoke access;
  role-based approval steps get real approvers; stopped silent audit loss on JIT grant/expiry.
- **"Phantom table" correctness sweep** — features now read the real schema instead of
  never-created tables: MFA/WebAuthn metrics from `mfa_webauthn` (not `webauthn_credentials`),
  GDPR consent from `user_consents` (not `consent_records`), user groups from `group_memberships`
  (not `user_groups`), breach detection and continuous auth on real tables, MFA method status and
  biometric/passwordless from real enrollment tables.
- **Risk** — admin-configured risk policies are applied (was a `parseJSON` no-op); device tracking
  uses real `known_devices` columns; `GetUserDevices` no longer silently drops rows with NULL text
  columns.
- **Dashboard** — dropped a non-existent `users.deleted_at` predicate that errored and made the
  admin dashboard silently report zero users (#435).
- **Admin console** — reads the bare-array `/organizations` response so the tenant UI renders (WS-03).

### Removed

- **Dead-code purge (~8.8k+ lines)** — deleted five never-wired subsystems and additional dead
  paths: the OAuth `KeyManager` and its phantom `oauth_signing_keys` layer, the unrouted
  `CertificationService` and WebAuthn subsystem, the never-functional admin passwordless subsystem,
  the dead AI policy-recommendations route, and orphaned CSV-import handlers.

### Migrations

- **v69–v80** (all additive): governance org-isolation (v69), `users.manager_id` (v70),
  `temp_access_links`/`device_trust_requests`/`published_apps` tenant isolation (v71–v73),
  `detailed_compliance_reports` (v74), `known_devices.device_type`/`seen_count` (v75/v76),
  session-risk history (v77), recording retention policies (v78), `oauth_signing_keys` (v79),
  enrolled-agent ↔ known-device link (v80).

## [1.24.11] - 2026-07-09

### Changed

- **tailwind-merge 2→3** (#54, flagged dependabot runtime major) — used only via the default
  `twMerge(clsx(...))` `cn()` helper, so v3's custom-config breaking changes don't apply. Validated by
  `vite build`, eslint, and 730 vitest tests; admin-console dist rebuilt + deployed.

## [1.24.10] - 2026-07-09

### Changed

- **Frontend build/type tooling majors** — `@types/node` 22→25, `globals` 15→17, `@vitejs/plugin-react`
  4→5 (from the flagged dependabot backlog). `tsc`+`vite build` clean, `eslint` 0 errors; admin-console
  dist rebuilt + deployed. `eslint` 9→10 is **deferred** — the eslint-10 ecosystem isn't ready
  (`eslint-plugin-react-hooks` peer-requires eslint≤9; eslint 10 drops bundled `@eslint/js`).

## [1.24.9] - 2026-07-09

### Fixed

- **SSO audit events now counted in compliance reports & statistics** (#392) — the OIDC SSO audit
  events added in v1.24.7/v1.24.8 used `event_type=sso.login` (with `category=authentication`),
  backwards from the platform convention where authentication events use `event_type=authentication`
  and the compliance/statistics queries filter on it. As a result SSO activity was excluded from
  compliance reports and failed-auth stats. Normalized all OIDC SSO events to
  `event_type=authentication`, `category=sso` (the `sso.*` descriptor is retained as the `action`,
  e.g. `sso_login`, `sso_user_provisioned`), so SSO logins/failures are counted like every other
  authentication event.

## [1.24.8] - 2026-07-09

### Added

- **Failed-login audit for SSO/SAML** (#388, #389) — the OIDC callback and SAML IdP SSO handler
  now emit `outcome=failure` audit events at every failure exit (OIDC: invalid_state,
  token_exchange_failed, id_token_verification_failed, missing_email_claim, provisioning_failed;
  SAML: invalid_authn_request, unknown_service_provider, acs_url_mismatch, sp_disabled,
  response_build_failed). This surfaces attacks/misconfiguration (forged tokens, unregistered-SP
  probing, ACS-URL tampering) in the audit trail, complementing the success events from v1.24.7.
- **Audit events queryable by target** (#390) — `GET /api/v1/audit/events` now honours a
  `target_id` filter (the `AuditQuery.TargetID` field was previously unused), so auditors can scope
  the trail to everything affecting a specific user or resource.

### Changed

- **Dependency bumps** (#386, #387) — `go.uber.org/zap` 1.27→1.28, `pquerna/otp` 1.4→1.5,
  `spf13/viper` 1.18→1.21; frontend `autoprefixer`, `lucide-react`, `eslint-plugin-react-refresh`.
  Part of clearing the dependabot backlog (superseded/stale PRs closed; major bumps flagged for review).

## [1.24.7] - 2026-07-09

### Added

- **SSO/OAuth audit events are now persisted** (#384) — the oauth service's `logAuditEvent`
  previously logged only to the application log, so SSO/OAuth/SAML activity (logins, logouts,
  single-logout, JIT provisioning) never reached the `audit_events` table and was absent from the
  audit query API (`GET /api/v1/audit/events`) and compliance reports. It now persists to
  `audit_events` (async, org-scoped, best-effort — never blocks or fails the request), matching the
  identity service's pattern; the application log is retained.
- **SSO JIT lifecycle audit trail** (#384) — the OIDC callback now emits `sso.user.provisioned`,
  `sso.identity.linked`, `sso.identity.matched`, `sso.identity.backfilled`, and `sso.login`,
  giving a queryable record of how SSO accounts are provisioned, federated-linked, and
  authenticated (builds on the federated-identity work in v1.24.4–v1.24.6).

## [1.24.6] - 2026-07-08

### Changed

- **Backfill the federated identity link for email-matched JIT users** (#369) — completes the
  #364/#367 migration: when a returning OIDC user is matched by email (created before the
  `idp_id`/`external_user_id` binding existed), the login handler now best-effort backfills those
  columns (only when currently unset), so subsequent logins match by `(idp_id, sub)`. Keyed by the
  matched `users.id`; nil-guarded and error-logged, never affects login.

## [1.24.5] - 2026-07-08

### Changed

- **OIDC JIT provisioning matches returning users by IdP subject before email** (#367) — the login
  handler now looks an existing user up by `(idp_id, sub)` first (explicitly org-scoped), falling
  back to email, then creating. A federated user whose email changed at the IdP is no longer treated
  as new (which would have created a duplicate colliding with the unique `(idp_id, external_user_id)`
  index #364 populates). Additive: any lookup miss/error falls through to the prior email path, so
  existing behavior is preserved.

## [1.24.4] - 2026-07-08

### Security

- **Go toolchain → go1.25.12** (#363) — the pinned `toolchain go1.25.11` forced builds onto a
  `crypto/tls` affected by **GO-2026-5856**, failing the govulncheck gate and shipping the vulnerable
  TLS stack in binaries. Bumped to go1.25.12 (govulncheck clean).
- **SAML SLO session-cookie cleared with `Secure` in production** (#362) — `clearIdPSession` cleared
  `openidx_session` with `Secure=false` unconditionally; now tied to `IsProduction()` (matching the
  proxy session-cookie convention), so the deletion still clears over plain HTTP in dev while carrying
  `Secure` in production. Clears `go/cookie-secure-not-set`.

### Fixed

- **Capture `Close` errors on writable files** (#361) — three writable-file writers
  (session-recording append, append-only store, shell-completion install) deferred a bare `Close()`,
  discarding the error; for a writable handle the final flush can surface only at `Close`, so this
  silently dropped data. Each now propagates the `Close` error. Clears `go/unhandled-writable-file-close`.
- **Bind JIT-provisioned users to the IdP subject** (#364) — the OIDC login handler captured the ID
  token `sub` but discarded it, leaving `users.idp_id`/`external_user_id` unpopulated. It now persists
  the federated link on JIT create (best-effort, RLS-scoped). Resolves the dropped-value
  `go/useless-assignment-to-field` on `claims.Sub`.
- **Drop dead `entry.Error` assignment in the request logger** (#365) — the access logger emits via
  `logFields`, not by marshalling the entry, so the assignment was never read; the error is still
  logged. Clears `go/useless-assignment-to-field`.

## [1.24.3] - 2026-07-08

### Fixed

- **Out-of-bounds read in `User.GetFormattedName`** (#359) — the method returned
  `parts[0] + " " + parts[1]` whenever any name component was present, but `parts` holds only one
  element when a user has only a given name or only a family name, so `parts[1]` panicked with an
  index-out-of-range. Now joins the collected parts, which is correct for one or two components.
  Clears the repo's only `error`-severity CodeQL alert (`go/index-out-of-bounds`).

## [1.24.2] - 2026-07-08

### Security

- **Audit report export filename built from allowlisted constants** (#357) — the export file name
  was assembled from the raw request `report_type`/`format` strings, so CodeQL traced
  caller-controlled data to `os.Stat`/`os.Create` even behind the `filepath.Base` + `reportDir`-prefix
  guards it doesn't model. Both fields are already validated against fixed enums; the name is now
  built from a compile-time-constant `typeSlug`/`ext` chosen inside those switches (plus the
  server-generated ID and timestamp), so no request string reaches `filepath.*`. Closes the last
  three `go/path-injection` alerts as fixed — the repo is now at **0 open critical and 0 open high**
  CodeQL alerts. The `reportFilePath` clean+prefix guard remains as defense-in-depth.

## [1.24.1] - 2026-07-08

### Security

- **Audit report export path containment proven to static analysis** (#355) — `reportFilePath`
  already constrained the export file to a single element under `reportDir` via `filepath.Base`
  (#349), but CodeQL does not model `Base`-through-`Join` as a path-injection barrier, so the
  `os.Stat`/`os.Create` sinks stayed flagged. Added an explicit `filepath.Clean` + `reportDir`-prefix
  check (returning an error the caller handles) so containment is provable to static analysis,
  closing the three `go/path-injection` alerts as fixed. With this and the ziti request-forgery
  findings confirmed as trusted-config false positives, the repo is at **0 open critical and
  0 open high** CodeQL alerts.

## [1.24.0] - 2026-07-08

### Security

- **CodeQL critical + high remediation complete.** This release closes the backup-encryption weak-KDF
  (#353) and caps a sweep that brought the repo to **0 open critical and 0 open high** CodeQL alerts —
  via real fixes across v1.23.1–v1.23.5 (integer-overflow env parsing, Ziti management-API SSRF hardening,
  OAuth logout/session JWT signature verification, audit report path-injection, hardware-token secret
  encryption at rest) plus documented false-positive dismissals (HIBP SHA-1 k-anonymity, MySQL DDL,
  trusted-config Ziti base URL, e2e-test regex/randomness, helm empty-password placeholders, dev-profiler
  cert-check) and the structured-`zap`-field log-injection class.
- **Backup encryption KDF → scrypt** (#353) — `internal/backup` derived its AES-256 key from a raw
  `sha256(passphrase)`; it now uses `scrypt` (N=1<<15, r=8, p=1) over a random salt in a versioned,
  magic-prefixed format, with a legacy `sha256` fallback so existing encrypted backups still decrypt.
  Removed the dead `EncryptPassword` helper.

## [1.23.5] - 2026-07-08

### Fixed

- **Hardware-token secrets encrypted at rest** (#351, security) — the hardware-token (YubiKey OATH-HOTP)
  handler stored the TOTP/HOTP seed as `hex(sha256(secret)) + ":" + secret`, i.e. the seed was
  recoverable in plaintext (the hash prefix was security-theater). It's now encrypted with the identity
  service's AES-256-GCM `secretcrypt` cipher (the KEK-backed cipher already used for IdP client secrets);
  decrypt reads both the new `encv1:` format and the legacy format, so existing rows keep working and
  upgrade on the next write. Clears `go/weak-sensitive-data-hashing` (high).

## [1.23.4] - 2026-07-08

### Fixed

- **Audit report export path-injection** (#349, security) — the compliance report exporter built its
  output file path from the request-controlled `report_type`/`format` (`filepath.Join(reportDir, fileName)`)
  with no sanitization, so a `report_type`/`format` containing `../` could write/stat a file outside the
  report directory. Now routed through `reportFilePath()`, which applies `filepath.Base` to constrain the
  name to a single element under `reportDir`. Clears `go/path-injection` (high ×3).

## [1.23.3] - 2026-07-08

### Fixed

- **Ziti management-API request hardening + dependency security bump** (#347) — the generic Ziti
  `mgmtRequest` helper now builds requests through the validated `mgmtURL()` (parses `ZitiCtrlURL`,
  pins scheme+host) instead of raw string concatenation, so a malformed/hostile controller URL cannot
  redirect management calls. Also bumps the indirect `quic-go` dependency v0.59.0→v0.59.1 to resolve
  `GO-2026-5676` (govulncheck). The residual `go/request-forgery` findings on this helper are documented
  false positives (the host is pinned; the appended path holds only internal Ziti resource IDs).

## [1.23.2] - 2026-07-07

### Fixed

- **JWT signature verification on OAuth logout/session endpoints** (#345, security) — `handleLogoutAll`,
  `handleSessionInfo`, and `handleLogout` (end-session) parsed the caller's JWT with `ParseUnverified`
  and acted on the unverified `sub`, so a forged/unsigned token could revoke another user's sessions or
  read their session info. Added `parseVerifiedClaims` (RS256-pinned signature check against the service
  key, alg-confusion-proof, with an expiry-tolerant mode for the OIDC `id_token_hint`) and routed all
  parse sites through it; logout-all/session-info now return 401 on an unverified token, and end-session
  no longer acts on an unverified subject. Clears `go/missing-jwt-signature-check` (high ×3).

## [1.23.1] - 2026-07-07

### Fixed

- **CodeQL critical/high remediation** (#343) — (a) `database.go envInt32` now uses
  `strconv.ParseInt(s, 10, 32)` instead of `int32(strconv.Atoi(...))`, fixing a silent integer-overflow
  truncation of pool-sizing env vars (go/incorrect-integer-conversion ×2); (b) the Ziti management-API
  calls route through a new `mgmtURL()` helper that parses + validates `ZitiCtrlURL` (scheme/host) and
  the response-derived identity ID is `url.PathEscape`'d, clearing the server-side request-forgery
  vectors (go/request-forgery). The MySQL `ALTER USER` DDL (which cannot bind identifiers/passwords and
  is charset-validated + escaped) and the Ziti call against the trusted operator-configured controller
  base URL are documented false positives. No runtime behavior change.

## [1.23.0] - 2026-07-07

### Changed

- **Admin console code-splitting follow-ups** (#341) — `lucide-react` and `@tanstack` now build into
  their own cacheable chunks (`icons`, `query`; the `vendor` chunk drops ~1,176→1,071 kB), and the
  `Layout` outlet is wrapped in its own `<Suspense>` so navigating to an unvisited page spins only the
  content area (the sidebar/header stay rendered) instead of a full-screen fallback. Frontend-only.

## [1.22.0] - 2026-07-07

### Added

- **GCP service-account key rotation connector** (#339) — a new `gcp_sa` PAM rotation connector that
  rotates a Google Cloud service-account key, completing the cloud-IAM rotation pair (AWS shipped in
  v1.21.0). It reuses the engine `Minter`/`PostRotateCleaner` seam: `Mint` creates a new key via the IAM
  API (deleting the oldest USER_MANAGED key first if at GCP's 10-key limit) and stores the decoded
  key-file JSON; `Verify` obtains an OAuth token from the new key (retrying for propagation); cleanup
  deletes all USER_MANAGED keys except the newest after promotion. Selectable from the Rotation Policies
  admin page. Config: `service_account_email`, `admin_secret_id` (a vault secret holding an admin SA
  key-file JSON). The target service account must be dedicated to rotation. Google IAM calls sit behind
  a small interface so the connector is covered by mocked-SDK unit tests. Adds `google.golang.org/api`.

## [1.21.1] - 2026-07-07

### Fixed

- **CodeQL `go/unsafe-quoting` (critical) in AD `unicodePwd` encoding** (#337) — `encodePasswordAD`
  built the Active Directory password value by concatenating double quotes around the password
  (`"\"" + password + "\""`) before UTF-16LE encoding. The encoded bytes are sent as a binary LDAP
  attribute in a `ModifyRequest` (never interpolated into a filter/DN/parsed context), so this was not
  exploitable, but the pattern is now rewritten to a single bounded allocation that writes the quote
  code units directly — clearing the alert (and an allocation-size-overflow on the same function) with
  byte-identical output. Added byte-exact and embedded-quote regression tests.

## [1.21.0] - 2026-07-07

### Added

- **AWS IAM access-key rotation connector** (#335) — a new `aws_iam` PAM rotation connector that rotates
  an IAM user's access keys, selectable from the Rotation Policies admin page. Introduces an engine
  "minter" seam (`Minter` + `PostRotateCleaner`) for providers that mint the secret themselves: the
  connector calls `CreateAccessKey`, verifies the new key via STS `GetCallerIdentity` (retrying for IAM
  eventual consistency), and retires the superseded key only after the new one is promoted. AWS calls
  sit behind small interfaces so the connector is covered by mocked-SDK unit tests. Config:
  `target_user`, `admin_secret_id` (a vault secret holding admin AWS creds as
  `{access_key_id, secret_access_key}` JSON), `region`. The target IAM user must be dedicated to
  rotation (cleanup deletes all its access keys except the newest). GCP service-account keys are a
  planned follow-up on the same seam.

## [1.20.0] - 2026-07-07

### Changed

- **Admin console bundle code-splitting** (#333) — the console shipped as a single ~3.4 MB (875 KB
  gzip) JS chunk. Route pages are now lazy-loaded (`React.lazy` + `<Suspense>`) and `node_modules`
  vendors are split into cacheable chunks via vite `manualChunks`. The initial entry chunk drops from
  ~3,394 KB to ~62 KB (17 KB gzip); heavy libs now load only with the page that needs them
  (`swagger-ui-react` → API-docs page, `recharts` → dashboard). Frontend-only, no behavior change
  beyond a brief loading spinner on first visit to a route.

## [1.19.0] - 2026-07-07

### Added

- **Rotation-policies admin UI — SSH / SSH-key / PostgreSQL / MySQL connectors** (#331) — the Rotation
  Policies page can now create policies for all six registered rotators, not just `directory` and
  `generate_only`. The Connector Type dropdown gains **SSH (password)**, **SSH key-pair**,
  **PostgreSQL**, and **MySQL**, each rendering its required config fields (host, port, admin
  credential secret-picker, target user/role, DB name, SSL/TLS, pinned host key, …) driven by a
  declarative field schema that mirrors the backend validators. The SSH/DB rotation connectors shipped
  in v1.14.0 were previously creatable only via `curl`. Frontend-only — no backend or schema change
  (`connector_config` is a free-form map validated server-side by each connector's `ValidateConfig`).

## [1.18.0] - 2026-07-06

### Added

- **Guacamole recording legal-hold — admin console UI** (#329) — the Session History table on the
  Guacamole Sessions page now has per-recording **Place hold** / **Release hold** controls (with a
  reason prompt) and an **On hold** badge, wired to the existing legal-hold endpoints
  (`POST/DELETE /api/v1/access/guacamole/sessions/:id/legal-hold`). Previously those endpoints — which
  exempt a held recording from the retention sweeper — could only be driven by `curl`. The
  `session-history` list endpoint now returns two read-only, org-scoped flags (`recording_available`,
  `on_legal_hold`) so the UI can render the correct state. No schema change (uses the v68
  `guacamole_recording_legal_holds` table shipped in v1.15.0).

## [1.17.0] - 2026-07-06

### Added

- **OpenZiti made easy** (#326) — the Ziti reconciler is now on by default (`ziti_reconciler=true`), the
  dev compose bundles the ZAC console (`ziti_console_url`), the router runs from a version-controlled
  declarative config (`deployments/docker/ziti-router/`) instead of sed/awk-patching at startup, agents
  auto-enroll, and a one-command Ziti quickstart (`scripts/ziti-quickstart.sh` + guided setup page).
- **One-command box deploy script** (#323) — `scripts/deploy-box.sh` automates the release recipe
  (backup → migrate → roll binaries → verify).

### Changed

- **Security hardening** (#324) — access-revocation and privilege checks tightened; OAuth signing keys
  are now **encrypted at rest** (via the prefix-aware `secretcrypt` helper — legacy plaintext keys are
  read transparently and re-encrypted on rotation); SCIM PATCH support extended in provisioning; the
  published default `ziti_admin_password`/`guacamole_admin_password` must be overridden in production
  (new `ValidateProduction` check).
- Dependency bumps: `go-ldap/ldap/v3` 3.4.8→3.4.12 (#325); Docker base images alpine 3.20→3.24 (#262),
  nginx (#93), node (#94). CI now compiles the integration test suite on every build (#73).

## [1.16.1] - 2026-07-06

### Fixed

- **IAM→Ziti revocation sweep failed on a uuid `user_id`** — the deprovision sweep added in v1.16.0
  queried `WHERE zi.user_id != ''` against the uuid column `ziti_identities.user_id`, which forced an
  empty-string→uuid cast and failed the whole query (`22P02`) every poll, so a disabled user's Ziti
  identity was never deleted. Dropped the redundant `!= ''` (`IS NOT NULL` suffices for a uuid column)
  and added a regression test. Released as a hotfix on top of v1.16.0.

## [1.16.0] - 2026-07-05

### Added

- **Guided Ziti Network Setup** — new admin-console page **Network Setup** (`/ziti-setup`) that makes
  the OpenZiti onboarding understandable, visual, and self-explanatory:
  - **Topology strip**: Clients → Edge Routers → Control Plane → Applications with live status dots.
  - **Setup checklist**: ordered steps (controller connection, CA trust, access-proxy identity,
    edge routers, app exposure, user-identity sync, client access) — each with live status, plain
    remediation text, and a deep-link action button.
  - **Install advisor**: which pieces must be installed *for this deployment* — controller, edge
    router (with `--tunneler-enabled` enrollment commands), BrowZer bootstrapper, client tunneler /
    OpenIDX Agent, hop nginx — labeled Required / Needed-for-your-setup / Optional.
  - **Per-route advice**: stored vs *effective* hosting mode (with auto-correct warnings), the full
    next-hop data path (`edge router → hop nginx :port → upstream`), what the client side needs,
    per-mode requirements, and the reconciler's live converge state per route.
  Backend: `GET /api/v1/access/ziti/setup/status` (aggregated checklist/advisor/route payload,
  reusing the reconciler's `effectiveHostingMode` + install-wide hop-port map so the UI explains
  exactly what will happen) and `GET /api/v1/access/ziti/reconciler/status` (per-service converge
  state, previously log-only). `/ziti-network` tabs are now deep-linkable via `?tab=`.

### Fixed

- **Ziti reconciler survives admin-panel reconnects** — the reconciler ran on the provider slot's
  context, so `POST /ziti/connect` (which Swaps the slot and cancels that context) silently killed
  the reconcile loop for good; subsequent route changes were never converged. It now runs on a
  process-lifetime context (no-ops while disconnected), and the connect handler wakes it via
  `Enqueue()` instead of imperatively hosting services alongside it — the reconciler stays the
  sole mutator, eliminating the double-hosting 502 path.
- **`PUT /ziti/settings` validates before persisting** — a malformed/empty controller URL or empty
  admin user is now rejected with 400 instead of being saved silently and only failing at the next
  connect. CI: the Benchmarks job could never post its PR comment (workflow token is read-only) and
  failed after the benchmarks had passed; it now has job-level write permission and degrades to a
  warning when the token can't comment.

### Security

- **Disabled/deleted IAM users are deprovisioned from Ziti** — the user-sync poller now sweeps
  Ziti identities whose user is disabled or gone (controller delete + mirror-row delete, batched,
  retried). Previously a revoked user's enrolled tunneler kept a valid Ziti identity — and network
  access — indefinitely. Infrastructure identities (access-proxy, admin, routers) are untouched.

## [1.15.0] - 2026-07-05

### Added

- **Guacamole recording legal-hold** (#318) — place a legal-hold on a Guacamole session's recording
  so it is never deleted by the retention purger. New `guacamole_recording_legal_holds` table
  (migration **v68**, FK → `guacamole_sessions` with a UNIQUE active-hold index), the recording
  retention sweeper (`sweepExpiredGuacRecordings`) now excludes sessions under an active hold, and
  admin-gated, audited endpoints:
  - `POST   /api/v1/access/guacamole/sessions/:id/legal-hold` (409 if one is already active)
  - `DELETE /api/v1/access/guacamole/sessions/:id/legal-hold`
  - `GET    /api/v1/access/guacamole/sessions/:id/legal-holds`
  Each endpoint verifies the session is visible under the caller's org before acting. Mirrors the
  existing remote-support legal-hold; a testcontainer test proves a held recording survives the
  sweep and is purged once released.

### Upgrade

- Migration **v68** adds a table (additive). Run `cmd/migrate up` (or the compose `migrate` service)
  before/at deploy.

## [1.14.1] - 2026-07-04

### Changed

- **All registered rotation connectors are now creatable via the CreatePolicy API** (#316) —
  `validatePolicyInput` previously accepted only `directory`/`generate_only`, so `ssh`, `postgres`,
  `ssh_key`, and `mysql` rotation policies required a direct DB insert. A new optional
  `ConfigValidator` interface lets each connector validate its own `connector_config` (delegating to
  its existing config parser), and the engine now accepts any **registered** connector type.
  **Note:** the accepted connector-type set is now registration-dependent rather than a hardcoded
  pair; unregistered types are rejected with a clear error.

## [1.14.0] - 2026-07-04

Two new PAM credential-rotation connectors, extending the M5 rotation engine.

### Added

- **SSH key-pair rotation connector** (`ssh_key`) (#313) — rotates a POSIX account's SSH key: the
  stored secret value is a freshly generated ed25519 OpenSSH private key; the derived public key is
  installed into the target's `authorized_keys` (a single tagged line, replaced each rotation) over
  an admin SSH session, and rotation is verified by logging in as the target with the new key. Reuses
  the existing `FixedHostKey` verification. No new dependencies.
- **`ValueGenerator` engine seam** (#313) — an optional interface letting a connector produce the
  secret value itself (e.g. a private key) instead of the engine's default random password. Existing
  connectors are unaffected.
- **MySQL rotation connector** (`mysql`) (#314) — rotates a MySQL user's password via `ALTER USER`,
  authenticating with a bootstrap admin credential from the vault, verified by connecting as the
  target with the new password. New dependency: `github.com/go-sql-driver/mysql`. Because MySQL DDL
  cannot bind the password, the connector strictly validates identifiers, escapes the password as a
  single-quoted literal, and strips `NO_BACKSLASH_ESCAPES` on a pinned connection — verified against
  injection-shaped inputs.

### Notes

- Cloud-IAM (AWS/GCP) rotation is deferred (heavy SDKs, not locally verifiable).
- Follow-up: `validatePolicyInput` accepts only `directory`/`generate_only`, so `ssh`/`postgres`/
  `ssh_key`/`mysql` rotation policies must currently be created out-of-band (pre-existing gap).

## [1.13.1] - 2026-07-04

### Fixed

- **Elasticsearch client validates auth at construction** (#311) — `NewElasticsearchFromConfig`'s
  connectivity ping only inspected the transport error, so a wrong/absent password against a
  security-enabled cluster (a 401/403 with `err == nil`) silently "connected" and then failed every
  operation. It now checks `res.IsError()` and returns a clear error, so bad ES credentials surface at
  startup. Audit-service still treats Elasticsearch as best-effort (warn + continue), so this turns a
  silent operation-time failure into a clear startup warning. Surfaced by the v1.13.0 ES-auth smoke test.

## [1.13.0] - 2026-07-04

Elasticsearch authentication for the docker-compose deploy path — the last deferred item from
the prod-compose hardening bundle. Compose-only; the app-side ES auth was already built.

### Changed

- **Elasticsearch security enabled in prod compose** (#309) — `docker-compose.prod.yml` sets
  `xpack.security.enabled=true` + `xpack.security.http.ssl.enabled=false` + `ELASTIC_PASSWORD` on
  the `elasticsearch` service (HTTP basic auth over the private network), and wires
  `ELASTICSEARCH_USERNAME`/`ELASTICSEARCH_PASSWORD` into `audit-service` (the only ES consumer,
  which already passes them to the auth-aware client). Dev/infra compose keep security disabled.
- **`ValidateProduction` requires ES credentials** (#309) — when `APP_ENV=production` and
  `elasticsearch_url` is set, `elasticsearch_username`/`elasticsearch_password` must be provided
  (conditional, so ES-unused deployments are unaffected).

### Notes

- Baseline is HTTP basic auth; self-signed ES HTTP TLS (parity with the v1.12.0 Postgres TLS) is a
  documented follow-up. Dedicated least-privilege ES roles are also a follow-up (uses the built-in
  `elastic` user for now).
- Upgrade: set `ELASTIC_PASSWORD` and a matching `ELASTICSEARCH_PASSWORD` in `.env` before a prod
  `docker compose up`.

## [1.12.0] - 2026-07-04

Production-readiness hardening for the docker-compose deploy path. Compose-only —
systemd/managed deployments are unaffected.

### Added

- **Startup readiness probes** (#307) — `internal/common/health.WaitForDependency` (bounded
  retry) plus `ProbeHTTP`/`ProbeOPA`. Services now verify hard dependencies at boot instead of
  returning 500s later: the OPA-using services (admin-api, provisioning, governance) probe
  `OPA/health` and the access service probes its Ziti controller — **fail-fast in production,
  warn and continue in development**. The OPA probe is gated on `EnableOPAAuthz` so a deploy
  that doesn't use OPA never blocks on it; APISIX is intentionally not probed (its reconciler
  already self-heals).
- **Self-signed Postgres TLS in prod compose** (#306) — a `pg-certgen` one-shot service
  generates a server cert (owned uid 70, key mode 0600) into a `pg_certs` volume; the prod
  Postgres runs with `ssl=on`, and the app/migrate/seed DSNs default to
  `sslmode=${DATABASE_SSL_MODE:-require}` so DB traffic is encrypted out of the box. Point at an
  external managed Postgres by setting `DATABASE_SSL_MODE` and supplying your own certs.

### Changed

- **DB pool sizing is configurable** (#306) — `DB_MAX_CONNS`/`DB_MIN_CONNS` (defaults 25/5)
  replace the hardcoded pool limits in `internal/common/database`.
- **APISIX admin key sourced from `APISIX_ADMIN_KEY`** (#306) via native APISIX `${{...}}` env
  substitution (no more `CHANGE_ME_ADMIN_KEY` in the config), wired into all three compose files;
  `admin_allow_ip` tightened to loopback + the container bridge ranges (`10.0.0.0/8`,
  `172.16.0.0/12`).
- **Graceful-shutdown timeout is configurable** (#306) — `SHUTDOWN_TIMEOUT_SECONDS` (default 30)
  replaces the hardcoded 30s across all services.

### Notes

- Elasticsearch `xpack.security` remains deferred (needs ES-client auth wiring).
- Upgrade: the `openidx_app` password hook and now Postgres TLS certs are generated on **first
  init of a fresh `postgres_data` volume**; existing volumes need the operator to provision them
  once (see the v1.11.0 note for the role password).

## [1.11.0] - 2026-07-04

Docker-compose deployments are now tenant-isolated. Previously a fresh
`docker compose up` was pre-multi-tenancy at the schema level (`init-db.sql` had no
RLS belt and app services connected as the `openidx` superuser, which bypasses RLS
entirely). This release makes migrations the sole schema source in compose and cuts
the app services over to the non-owner `openidx_app` role so the FORCE'd RLS
policies enforce — matching the box and managed/RDS deployments.

### Added

- **`migrate` + `seed` one-shot compose services** (#303) — a `migrate` service builds
  the full v1–v67 schema (as the superuser) after Postgres is healthy, then a `seed`
  service applies the functional-delta bootstrap. App services gate on the seed
  completing (`depends_on: service_completed_successfully`). Wired into
  `docker-compose.yml`, `docker-compose.prod.yml`, and `docker-compose.infra.yml`.
- **`deployments/docker/bootstrap.sql`** (#303) — minimal first-init (the passwordless
  `openidx_app` role + `GRANT CONNECT`); migrations own everything else.
- **`deployments/docker/seed.sql`** (#303) — idempotent functional-delta bootstrap
  (`role_permissions` + default risk/posture/privacy/notification/lifecycle/ispm
  policies + tenant branding), org-scoped, applied under `app.bypass_rls`.
- **`deployments/docker/set-app-role-password.sh`** (#304) — first-init hook that sets
  the `openidx_app` password from `OPENIDX_APP_PASSWORD` (sorts after `bootstrap.sql`).
- **`test/integration/compose_seed_test.go`** (#303) — e2e guard: migrate-from-empty →
  `seed.sql` → asserts the login bootstrap and that RLS fails closed for a NOSUPERUSER
  role without an org GUC and returns default-org rows with one set.

### Changed

- **Compose app services connect as `openidx_app`** (NOSUPERUSER, NOBYPASSRLS) (#304),
  so the v37 FORCE-RLS policies enforce. `migrate`/`seed` stay on the `openidx`
  superuser (they own DDL + seed). Add `OPENIDX_APP_PASSWORD` to the postgres env and
  `.env` / `.env.production`.
- **`scripts/seed.sh`** now re-applies `seed.sql` (migrations own the schema + login
  bootstrap) instead of the removed `init-db.sql`.

### Removed

- **`deployments/docker/init-db.sql`** — retired as the schema source. Layering
  migrations on top of it was permanently blocked (v29 `ziti_certificates(identity_id)`
  ordering), and the file was itself broken on current Postgres (`NOW()` in a
  partial-index predicate). Migrate-from-empty is clean to v67 and already seeds a
  working admin install (default org, admin user, `admin-console` client, roles).
- **`TestInitDBParity` / `TestInitDBColumnParity`** (`internal/migrations/initdb_parity_test.go`)
  — no subject once `init-db.sql` is gone; migrations are the sole schema source.

### Upgrade note

The `openidx_app` password hook runs only on **first init of a fresh `postgres_data`
volume**. On an **existing** volume, set the password once:
`ALTER ROLE openidx_app WITH LOGIN PASSWORD '<OPENIDX_APP_PASSWORD>';` (or
`docker compose down -v` / `make dev-clean` to recreate the volume). This is a
compose-only change — systemd/managed deployments are unaffected.

## [1.10.1] - 2026-07-04

Encrypt-secrets-at-rest hardening pass. Secret columns that were previously stored as plaintext
are now AES-256-GCM encrypted at rest, keyed by `ENCRYPTION_KEY`. Rollout is lazy and
flag-day-free: reads are prefix-aware (tagged ciphertext is decrypted; legacy plaintext passes
through untouched), and environments without a usable key fall back to a warned passthrough rather
than crashing.

### Added

- **`internal/common/secretcrypt`** — shared AES-256-GCM helper (#298). `Encrypt` emits
  `encv1:<base64(nonce‖ciphertext)>`; `Decrypt` is prefix-aware (tagged → decrypt, untagged legacy
  plaintext → passthrough); `NewNoop()` provides a best-effort passthrough cipher for environments
  without a 32-byte key (services warn and continue rather than fail closed).

### Changed

- **Webhook signing secrets encrypted at rest** (#299) — `webhook_subscriptions.secret` is now
  encrypted on create and decrypted on read and before HMAC signature computation. Column widened to
  `TEXT` (migration **v65**; file-based `202607030001`).
- **Identity-provider client secrets encrypted at rest** (#300) — `identity_providers.client_secret`
  is encrypted on create/update and decrypted on every read path: identity get/list, the access
  service's multi-IdP route resolution, and the OAuth social-login token exchange. Column widened to
  `TEXT` (migration **v66**; file-based `202607030002`).
- **Guacamole pool tokens encrypted at rest** (#301) — `guacamole_connection_pool.token` is encrypted
  on write. The column is write-only (the in-memory pool serves reads), so there is no decrypt path — a
  database dump cannot yield usable session tokens. Column widened to `TEXT` (migration **v67**).

### Notes

- `oauth_clients.client_secret` was already SHA-256 hashed (constant-time compare, never re-returned)
  and is intentionally out of scope for this pass; the stale `-- TODO: Encrypt` marker was removed.
- Highest migration is now **v67**. `init-db.sql` defines all three columns as `TEXT` directly, so
  fresh installs need no backfill.

## [1.10.0] - 2026-07-03

Readiness-finalization pass across three workstreams: make the shipped PAM usable from the
admin console (W1), close correctness/tenant-isolation gaps (W2), and light production
hardening (W3).

### Added
- **PAM admin console** — the previously backend-only PAM surface is now driveable from the
  console: **Vault Secrets** page (list/create/versions/grants + reason-gated one-shot reveal +
  checkout ledger; #284), **Rotation Policies** page + per-secret rotate-now/history (#285),
  **Privileged Sessions** page (Guacamole pending-request approve/deny, active-session
  monitor/share/force-terminate, transcript download; #286), and a **`vault_credential`** option
  in Access Requests with one-shot retrieve + return-early (#287). A "Privileged Access" nav
  group + dashboard entry point (#289).
- **`GET /api/v1/access/guacamole/session-history`** — admin-guarded, org-scoped listing of
  Guacamole session rows with a `transcript_available` flag (no file paths), so transcripts are
  reachable from the console. (#286)
- **`GET /api/v1/vault/secrets/:id/grants`** — list a secret's access grants (metadata only). (#284)
- **OpenAPI specs** for all shipped PAM endpoints (vault, rotation, Guacamole sessions,
  `vault_credential` retrieve/return) across the admin-api/access/governance specs. (#288)
- **Column-level init-db↔migrations parity guard** (`TestInitDBColumnParity`) — fails CI when an
  `init-db.sql` column is created by no migration (the drift class that breaks migrate-only
  RDS/Helm installs). (#292)

### Changed / Security
- **Attestation tenant isolation** — `attestation_campaigns`/`attestation_items` (created by v54
  without `org_id`) gained `org_id` + the v37 FORCE-RLS belt (USING + WITH CHECK); handlers tag
  `org_id` on write and rely on RLS for reads. Closes a cross-org read/write exposure. Migration
  v61. (#290)
- **`org_id` + FORCE-RLS belt** added to `jit_grants` and `request_approval_chains` (previously
  org-scoped only in-handler). Migration v64. (#293)
- **Access-proxy idle timeout enforced** — routes' `idle_timeout` was dead config on the data
  plane (only absolute expiry was checked). The proxy + forward-auth paths now revoke and re-auth
  a cookie session idle beyond `idle_timeout` (sliding window; bearer tokens unaffected). (#294)
- **Production requires an explicit vault KEK** — `ValidateProduction` now fails unless `VAULT_KEK`
  or `VAULT_KEKS` is set, instead of silently falling back to `ENCRYPTION_KEY` for the vault
  key-encryption key. (#295)

### Fixed
- **Referenced-but-uncreated tables reconciled** — `admin_console_settings`, `auth_contexts`,
  `breach_incidents`, `breach_alerts` were referenced by code but created by neither a migration
  nor `init-db.sql` (latent 500s, the `jit_grants`-class drift). Migration v62 creates them.
  (`access_stats`, also flagged, was a false positive — a CTE, not a table.) (#291)
- **`ziti_certificates` column drift** — the migration schema had diverged wholesale from the
  code/init-db schema (`cert_data NOT NULL`, … vs `cert_type`/`not_after`/`status`/…), breaking
  cert-hardening on migrate-only installs. Reconciled to the code schema; also reconciled 8 other
  tables whose init-db `ALTER … ADD COLUMN` patches were never mirrored into a migration.
  Migration v63. (#292)

### Notes
- **OPA fail-open** was verified to be unreachable in production (the middleware's `devMode` is
  `cfg.IsDevelopment()`, false in prod → fails closed with 403); a regression test now pins the
  invariant. No code change to `opa.go`. (#295)
- **Deferred follow-ups** (tracked; not implemented):
  - **MySQL and cloud-IAM (AWS/GCP/Azure) rotation connectors** behind the M5 `Rotator`
    interface (v1.9.1 shipped SSH + PostgreSQL); **SSH *key* rotation** (v1.9.1 shipped SSH
    *password* rotation).
  - **Guacamole recording legal-hold** — retention works, but `recording_legal_holds` is FK'd to
    `remote_support_sessions` only; covering `guacamole_sessions` recordings needs a shared-hold refactor.
  - **Multi-tenant / production-GA hardening**: docker-compose `openidx_app` (non-owner) cutover +
    FORCE-RLS for compose; prod-compose TLS/Elasticsearch-security/APISIX-admin-key hardening;
    encrypt-at-rest for the legacy plaintext secret columns (`oauth_clients.client_secret`,
    `identity_providers.client_secret`, webhook secrets, guac pool token) via the vault; rotate the
    git-history-compromised APISIX admin key.

## [1.9.1] - 2026-07-02

PAM session assurance (M4) + rotation connectors (M5), plus a recording
data-loss fix.

### Added
- **Session transcripts** — a `guaclog`-based sweep generates a keystroke/command
  transcript for ended/terminated recorded Guacamole sessions and serves it via an
  admin-guarded `GET /api/v1/access/guacamole/sessions/:id/transcript`. Generation is
  `exec.LookPath`-gated (inert if `guaclog` is absent); `guaclog` is included in the
  access-service image. (#279)
- **Live session monitor** — `POST /api/v1/access/guacamole/sessions/:id/share` mints a
  read-only Guacamole connection-sharing link (falls back to the active-session list when
  the server lacks the sharing API). (#279)
- **Session-end detection** — a background sweep reconciles tracked sessions against
  Guacamole's active connections and marks naturally-ended sessions (2-minute grace;
  fail-safe when Guacamole is unreachable). (#279)
- **Attestation of privileged entitlements** — new `vault_access` and `rotation_policy`
  access-certification campaign types; a revoke decision deletes the vault grant / disables
  the rotation policy. (#279)
- **SSH + PostgreSQL rotation connectors** — the rotation engine can now rotate credentials
  on Linux/SSH hosts (`chpasswd` over SSH, host-key-pinned, password via stdin) and
  PostgreSQL (`ALTER ROLE` with server-side identifier/literal quoting). Each resolves its
  bootstrap/admin credential from the vault and verifies by authenticating with the new
  credential; both fail closed. No new dependencies. (#280)

### Fixed
- **Guacamole recording data loss** — `guacamole_sessions.recording_path` stored the shared
  recordings *directory*, so the retention sweep's `RemoveAll` could delete every recording.
  The full recording *file* path is now persisted and purge is guarded so it can never
  remove the recordings root. (#279)

## [1.9.0] - 2026-07-02

Privileged Access Management (PAM) — an integrated credential vault, automated
rotation, just-in-time credential checkout, and privileged-session brokering with
server-side credential injection. Built on the existing vault crypto, approval
workflows, Guacamole brokering, and recording/retention pipeline.

### Added
- **Credential vault** — tenant-isolated, envelope-encrypted secret store
  (per-version HKDF + AES-256-GCM under a rotatable key-encryption keyring that
  defaults to `ENCRYPTION_KEY`; fail-closed). Versioned secrets, per-secret access
  grants, internal server-side `use` vs. reason-gated + audited `reveal`;
  admin-guarded `/api/v1/vault/*` API. Migration v56. (#273)
- **Automated credential rotation** — leader-gated rotation engine with pluggable
  connectors (Active Directory / LDAP / Azure AD via directory write-back;
  generate-only). Candidate-version → apply-to-target → verify → promote, so a
  failed rotation never locks the account out. Scheduled, on-demand (admin), and
  rotate-on-checkout triggers. Migration v57. (#274)
- **Just-in-time credential checkout** — request a vault credential through the
  existing multi-step approval workflow (`resource_type=vault_credential`); on
  approval the requester retrieves the secret once for a bounded window, after
  which access auto-revokes and the credential rotates. (#276)
- **Privileged session brokering with credential injection** — Guacamole
  RDP/SSH/VNC sessions inject the target credential from the vault **server-side**
  (the browser never receives it), with an optional pre-session approval gate,
  admin force-terminate (with reason), and native session recording retained via
  the existing recording-retention policy. Migration v59. (#277)

### Fixed
- Created `jit_grants` and `request_approval_chains` — referenced by governance
  code but never created by any migration, so JIT elevation, the escalation
  worker, and `POST /api/v1/governance/requests` were returning 500s. Migration
  v58. (#275)

### Notes
- Each service that uses the vault (admin-api, governance, access) reads the shared
  `ENCRYPTION_KEY` / `VAULT_KEK` and instantiates an in-process vault; the access
  service additionally needs a shared recording volume for Guacamole recordings.

## [1.8.2] - 2026-07-01

### Added
- **Optional device-trust enforcement for clientless (BrowZer) access.** With
  `OPENIDX_REQUIRE_DEVICE_TRUST_FOR_CLIENTLESS=true` (off by default), an OIDC
  login for the clientless (BrowZer) client from an untrusted device is refused —
  the login page shows "This device must be approved before clientless access" and
  a device-trust request is filed for admin approval (admin console → **Device
  Trust Approval**); after approval, the retry succeeds. Closes the gap where a
  BrowZer route's `require_device_trust` was silently unenforced (BrowZer traffic
  bypasses the proxy's HTTP forward-auth). Enforced at the OIDC login
  (`handleAuthorizeCallback` — BrowZer's server-rendered login — and
  `handleLogin`); per-device, not per-route. (#268, #269, #270)

## [1.8.1] - 2026-07-01

Security & production-readiness hardening — remediation of the v2.0 GA
production-readiness audit (all P0s + four P1s + a P2 cluster).

### Security
- Access proxy now verifies a bearer JWT's signature + expiry (RS256 via the
  OAuth JWKS) before building a session; forged/unsigned tokens are rejected
  (P0-1, #255).
- Pre-tenant-resolution lookups against RLS-forced tables (API-key validation,
  proxy route/session/device/posture reads, Ziti startup, audit webhook
  bookkeeping) are bypass-wrapped so they no longer fail closed under the
  non-owner `openidx_app` role; WebAuthn login is org-scoped (P0-2, #254).
- OAuth token introspection now honors revocation — a revoked token reports
  `active:false` (#259).
- Removed the hardcoded APISIX admin key from the repo; templated from env
  (P0-4, #256). **Rotate the previously-committed key wherever deployed.**
- Enabled branch protection on `main` (Required Checks, enforce_admins) (P0-5).
- Production config validation now checks the *effective* DB sslmode (parsed from
  `DATABASE_URL`, not just the standalone field) (#263).
- Bumped auth/transport-critical dependencies (x/crypto, x/net, pgx/v5,
  go-webauthn, go-redis/v9); transitive advisories dropped 23→2 (#264).
- Platform-admin cross-org audit now records under RLS and logs failures;
  IP-threat DB errors are surfaced; dead runtime-DDL removed (P2, #265).

### Fixed
- 58 tables that existed only in `init-db.sql` are now created by migration
  **v54**, so managed-Postgres/RDS/Helm/`migrate` installs stop 500ing across
  MFA/SAML/social/lifecycle/ISPM/audit features; a parity test guards against
  recurrence (P0-3, #257).
- Split the deprovisioning policy-run log into `lifecycle_policy_executions`
  (migration **v55**) — it collided with the workflow `lifecycle_executions`
  schema, breaking deprovisioning execution records on every install (#258).
- Docs workflow no longer passes `latest latest` to `mike deploy` (#261).

### Changed
- Migrated off go-redis deprecated APIs (`SetEx`→`Set`, `GetSet`→`SetArgs`,
  `ZRevRange`→`ZRangeArgs`) (#264).
- `.gitignore` now excludes `*.zip` to prevent stray archive exports being
  committed (#266).

## [1.8.0] - 2026-06-29

### Added
- **Database-enforced tenant isolation (RLS activation)** — the v1.8 milestone of
  the multi-tenancy epic. The app now connects as a dedicated non-owner
  `openidx_app` role (`NOSUPERUSER NOBYPASSRLS`), so the `FORCE`'d row-level
  security policies (the predicate + FORCE shipped earlier in v37) finally
  enforce instead of being bypassed by a superuser connection. A no-GUC query on
  a scoped table now returns 0 rows; queries see only the request's org via the
  `app.org_id` GUC set at pool checkout; platform/cross-org paths opt in via
  `app.bypass_rls`. This is defense-in-depth *behind* the v1.7 app-layer `org_id`
  filtering. (#250)

### Changed
- **Migration v53** provisions `openidx_app` with blanket DML grants + default
  privileges (passwordless; the password is set out-of-band at deploy). Migrations
  and DDL continue to run as the owner role; services keep `AUTO_MIGRATE` off and
  the app `DATABASE_URL` points at `openidx_app`. `init-db.sql` provisions the
  same role for fresh installs. (#250)

## [1.7.2] - 2026-06-29

### Security
- **`github.com/jackc/pgx/v5` v5.5.4 → v5.9.2** — resolves GO-2026-5004.
  `govulncheck` now reports 0 affected vulnerabilities. (#248)

### Fixed
- **CI hard gates restored to green** (`Required Checks`). The org-scope, lint,
  and vulnerability gates had regressed:
  - **orgscope**: annotated the 19 org-unscoped queries the governance/devices
    work introduced (the Relations & Integrity Doctor's whole-install scans and
    queries keyed by globally-unique ids) with reviewed `//orgscope:ignore`
    directives. (#247)
  - **lint**: removed an unused var + orphaned import in `ziti_settings.go`;
    justified the deprecated, operator-supplied `google.CredentialsFromJSON` call
    in `play_integrity.go`; migrated the RLS pool hook `BeforeAcquire →
    PrepareConn` (deprecated by the pgx bump), preserving exact checkout
    semantics. (#247, #248)

## [1.7.1] - 2026-06-26

### Fixed
- **A fresh `apisix-edge` install can now stand up the full eight-service stack
  from a clean checkout.** The `gateway` service (`:8008`) is tracked as a
  systemd unit and added to the install's `enable --now` list (it had been
  running as an unmanaged `/tmp` process); the runbook now builds the service
  binaries into `~/oidx-runtime/bin` (the units' `ExecStart` targets); and the
  access-service launch wrapper ships as a sanitized `run-access.sh.example`
  (previously untracked, so a fresh install left the access-proxy with no start
  script). (#243, #244, #245)

## [1.7.0] - 2026-06-26

### Governance & devices: policies that enforce + real device trust (#234–#239)

Made the governance and devices domains actually work end-to-end. The policy
engine was a permissive no-op and device-trust signals were never populated, so
Zero-Trust controls silently passed everything; the device-trust approval
workflow existed but had no entry point; and a redundant policy engine sat
unwired. After this work: governance policies evaluate and enforce, device
posture and per-device trust flow into every access decision (forward-auth and
continuous re-verification), untrusted devices on trust-required routes file
approval requests that flip trust on approval, and the dead engine is gone.

#### Added
- **Device posture bridge** (D1): agent posture reports are written to
  `device_posture_results` so the access context evaluator enforces posture for
  the reporting device; migration v50 adds the upsert key. (#234)
- **Service-to-service auth for policy evaluation** (G1): a shared
  `INTERNAL_SERVICE_TOKEN`; the access-proxy presents it as `X-Internal-Token`
  (constant-time, scoped to governance `/evaluate`) so the policy call is
  authenticated instead of 401-failing-closed. (#235)
- **Device-trust request auto-creation** (D3): when an untrusted device hits a
  `require_device_trust` route, the proxy files a deduped pending
  `device_trust_requests` row — the missing entry point that feeds the existing
  approval queue. Approve/reject now notify the user, and new requests notify
  org admins, via the notifications service. (#238)
- **Migration v52**: reconcile the continuous-verify columns that existed only in
  `init-db.sql` (`proxy_sessions.{last_verified_at,verification_failures,geo_*,
  idp_id,device_trusted}`, `user_sessions.device_trusted`) onto migrate-based
  installs. (#239)

#### Changed
- **The governance policy engine actually enforces** (G1): `GetPolicy` /
  `ListPolicies` now load `policy_rules` (via a shared `loadPolicyRules`), so the
  per-type evaluators (separation-of-duty, risk, timebound, location,
  conditional-access) and the step-up loop run against real rules instead of an
  empty set. (#235)
- **`ProxySession.DeviceTrusted` is populated** from `known_devices.trusted`,
  matched by the request's device fingerprint (D2) — feeding the context checks,
  the inline policy DSL, and the governance `/evaluate` call. The continuous
  verifier re-derives it live each pass rather than reading a stale column.
  (#237, #239)

#### Fixed
- **Policy rule loading queried non-existent columns** (`condition/effect/
  priority` vs the real `rule_type/conditions/actions`); the error was swallowed,
  so rules silently never loaded — the true root cause behind "policies don't
  enforce." (#235)
- **The continuous session verifier errored every run** on migrate-based installs
  — its driver query referenced `proxy_sessions` columns present only in
  `init-db.sql`. (#239)

#### Removed
- **The dead `ZTPolicy` subsystem** (handler, store, model, tests; ~4,900 LOC)
  — never wired into any service, no table, no UI, its general-ABAC niche already
  served by the live `abac-policies` surface. Migration v51 drops the (never
  created) `zt_policies` / `zt_policy_versions` tables as a belt. (#236)

### Relations & Integrity Doctor — cross-domain health + referential integrity (#230, #231, #233)

A self-service "doctor" that scans the relationships *between* domains — proxy
routes, Applications tiles, OAuth clients, Ziti services, published apps,
identities — surfaces broken or orphaned wiring, and heals the safe cases
automatically; plus DB-level referential integrity so the most common orphans
can't form in the first place.

#### Added
- **Relations & Integrity Doctor** (`internal/access/health_engine.go`,
  `health_checks.go`): a check registry that scans cross-domain relations
  (route↔tile, app↔client, route↔Ziti, host uniqueness, published-app,
  identity↔Ziti, BrowZer-config dedup, domain presence, …), returns a structured
  report, auto-heals findings classified Safe, and leaves risky ones for an
  explicit fix. Exposed at `GET /api/v1/access/health/relations[?heal=safe]` and
  `POST /api/v1/access/health/fix/:checkId`, with a `HealRoute` after-mutation
  hook so a route change re-checks its own wiring. (#230)
- **Referential integrity** (migration v49): `applications.route_id →
  proxy_routes` and `applications.oauth_client_id → oauth_clients`, both
  `ON DELETE CASCADE`, backfilled from the existing id conventions — so deleting
  a route or client can no longer strand an Applications tile/app. (#231)

#### Changed
- Doctor check polish from review follow-ups: tightened classifications and
  counts (e.g. domain-presence counts `known_devices`, not a non-existent table).
  (#233)

### App, OAuth & clientless-publishing fixes (#223–#229, #232)

A run of fixes making OAuth client registration, the Applications view, and
clientless app publishing mutually consistent — registered clients are visible
and editable, and a published app maps cleanly to one host / one Ziti service.

#### Added
- **Applications tiles auto-sync for proxy routes**: creating/registering a
  client or proxy route surfaces a launcher tile without a manual step.
  (#224, #225)
- **App redirect_uris auto-register on the BrowZer OIDC client**, so a freshly
  published clientless app doesn't 400 on its first OAuth redirect. (#227)
- **One-app-per-host publishing**: an app publishes as a single host route → one
  Ziti service → one BrowZer target → one APISIX route, instead of exploding into
  one route per discovered path (which collided on the per-host BrowZer naming);
  discovered paths stay as advisory metadata. (#229)

#### Fixed
- **OAuth client registration 500** — new clients weren't assigned a UUID. (#223)
- **Registered clients didn't appear** in the Applications list. (#224)
- **Editing an application** now syncs its backing OAuth client (name/redirects),
  instead of drifting from it. (#226)
- **BrowZer config generators use the *effective* hosting mode** (fixing overlay
  error `1010` when a route's stored mode disagreed with its resolved mode).
  (#228)
- **`ziti_browzer_config` is a singleton** — the bootstrap reseed no longer
  appends a new row on every startup. (#232)

### Clientless edge on APISIX + console-managed publishing (#211–#221)

Moved the public `:443` edge from nginx to **Apache APISIX** as the single TLS
terminator, with the access-service pushing per-app BrowZer routes to it
dynamically; and hardened publishing so a clientless app can be created,
**edited, renamed, and deleted entirely from the admin console** without leaving
orphaned overlay/edge state. Resolves a class of failures hit while publishing
external HTTPS apps (`secops`, `es-dev`): BrowZer `1003`, OAuth/SAML 403s, and
stranded wiring after a rename/delete.

#### Added
- **APISIX edge** (`deployments/apisix-edge/`): a dedicated APISIX instance as
  the sole `:443` edge (TLS via the `*.tdv.org` wildcard), with `seed-edge-routes.sh`
  for the static routes (API fan-out, `/oauth`, `/scim`, `*.tdv.org` access-proxy)
  and systemd user units for the access + backend services. nginx is reduced to
  the admin-console SPA upstream. (#211, #213)
- **APISIX route reconciler** (`internal/access/apisix_reconciler.go`): the
  access-service pushes/prunes the per-app `browzer-<app>` edge routes from
  `proxy_routes` via the Admin API (gated by `APISIX_EDGE_ENABLED`). (#211)
- **Hosting-mode picker** in the proxy-route create/edit form — **Auto
  (recommended) / Hop — external·HTTPS / Direct — local·dark** — wired through the
  proxy-route CRUD (`hosting_mode`). (#220)
- **Edge routes for the oauth-service's management APIs**: `/api/v1/oauth/*` and
  `/api/v1/saml/*` now route to `:8006` (were missing, so they fell to the
  `/api/*` admin catch-all and 404'd). (#218, #219)
- **Router WSS config artifacts** (`deployments/apisix-edge/ziti-router/`): the
  edge router serves the clientless BrowZer overlay on `wss:3023` presenting the
  browser-trusted `*.tdv.org` cert via `transport.wss.identity`. (#214, #215)
- Docs: clientless edge architecture (`docs/OPENIDX_CLIENTLESS_EDGE_ARCHITECTURE.md`)
  and a publish-a-service guide with the full certificate matrix
  (`docs/PUBLISHING_A_SERVICE.md`). (#212, #217)

#### Changed
- **BrowZer routes auto-select their hosting mode** from the upstream:
  `EffectiveMode` promotes a BrowZer route off `identity` (never valid for the
  `#browzer-users` dial) and picks **hop** for external HTTPS / Host-routed
  upstreams, **direct** for local/HTTP — explicit hop/direct still honored. (#220)
- **OAuth client management and SAML SP management are now always authenticated**,
  not just outside `development` — the management groups get the auth middleware
  unconditionally while the interactive OIDC flow endpoints keep their env-gated
  behavior. (#218, #219)
- The external-IdP **OIDC `form_post` bypass is OFF by default**
  (`BROWZER_OIDC_CALLBACK_PATHS=""`): once the WSS overlay is healthy the service
  worker tunnels the callback, so a direct bypass splits the cookie context and
  loops the app back to login. (#216)

#### Fixed
- **BrowZer `1003` (service not dialable by the overlay)**: the reconciler now
  **converges** Bind/Dial service policies (upsert by name) instead of
  create-if-exists, so a route that transitions identity→router-hosted (e.g.
  BrowZer enabled after OpenZiti) has its stale `#access-proxy-clients` policies
  corrected to `#ziti-routers` / `#browzer-users`. (#220)
- **OAuth/SAML management 403/404 through the edge**: routing gap (mis-routed to
  admin-api) + dev-mode no-auth on the oauth-service. (#218, #219)
- **Route delete and rename left orphans**: deleting a route now tears down its
  Ziti service + policies + `host.v1` config + service-edge-router policy, and
  prunes the APISIX route + bootstrapper target; renaming re-keys the edge wiring
  to the new host instead of stranding it under the old one. (#221)
- **BrowZer `1007` (no WSS routers) / `1016` (WSS cert)** on the clientless path,
  and the **psm Entra login loop** caused by the direct OIDC bypass. (#214, #215, #216)

### Per-app BrowZer publishing via the OpenZiti reconciler (#201–#208)

Publish multiple apps clientlessly behind BrowZer — each as its own dark Ziti
service — and toggle them from the admin console without breaking the overlay.
Motivated by publishing a second BrowZer app (`psm.tdv.org`, an external HTTPS
IIS/.NET upstream) alongside `netgraph`: the BrowZer WASM runtime sends a fixed
`Host: unknown` and **no SNI** on every overlay request, so the old shared
`browzer-router` (which demuxed apps by Host) could only ever serve one app.

#### Added
- **OpenZiti reconciler** (`internal/access/ziti_reconciler.go`, gated by
  `ZITI_RECONCILER`): declaratively converges the controller to the desired
  state read from `proxy_routes` — per-app services, bind/dial/service-edge-router
  policies, `host.v1` configs, and router/SDK hosting — on boot, a 30s tick, and
  on demand. Replaces the imperative provisioning path as the single owner of all
  Ziti mutations. (#201)
- **Per-app BrowZer services**: each clientless app gets its own Ziti service
  hosted by the edge **router** via a fixed `host.v1` config (`{protocol,address,
  port}`), so there is no Host demux — removing the single-app limit of the shared
  router. (#201)
- **`hosting_mode = 'hop'`** for Host-routed / HTTPS upstreams (e.g. IIS/.NET):
  a per-app plain-HTTP hop (nginx) that listens on a deterministic `base+index`
  port, rewrites the `Host` header, and proxies to the real upstream; emits a
  per-route landing-path 302 so the post-OIDC `/` lands on the app's entry path.
  (#202, #203)
- **Public per-app nginx vhost generator** (`internal/access/browzer_vhosts.go`,
  `BROWZER_VHOST_CONFIG_PATH`): the access-service renders one TLS `server {}` per
  `ziti+browzer`-enabled route (`server_name <app>.tdv.org` → bootstrapper
  `:8445`), so publishing a clientless app needs **no** front-nginx hand-edit.
  Hop-mode routes additionally get an external-IdP **OIDC `form_post` callback
  bypass** (`location ~ /(signin-oidc|signout-callback-oidc)$` → the route's hop
  port). Config: `BROWZER_BOOTSTRAPPER_ADDR`, `BROWZER_VHOST_SSL_CERT/KEY`,
  `BROWZER_OIDC_CALLBACK_PATHS`. A poll-reload entrypoint
  (`deployments/docker/oidx-nginx-entrypoint.sh`, wildcard-`include`d from
  `nginx.conf`) reloads the front nginx when the generated file changes. (#208)

#### Changed
- **The admin-console one-click feature toggle defers to the reconciler** when
  `ZITI_RECONCILER` is on: enable/disable only write the `proxy_routes` flags
  (`ziti_enabled` / `browzer_enabled` / `ziti_service_name`) and enqueue a
  converge — no imperative service/policy creation or SDK hosting. Imperative
  behavior is unchanged when the reconciler is off. (#206)
- `RegenerateConfigs` (the toggle path) now also rewrites the hop and public
  vhost configs, not just the bootstrapper targets and router config — so a
  newly-toggled app gets its hop/public block live without a restart. (#208)

#### Fixed
- **`psm.tdv.org` 502 + feature-manager↔reconciler conflict**: with the
  reconciler on, the UI toggle still provisioned imperatively (SDK-hosting the
  service with an `edge` terminator and `#access-proxy-clients` policies, and
  renaming `ziti_service_name`), colliding with the reconciler's router-hosted
  `tunnel` terminator — the access-proxy then forwarded plain HTTP to the app's
  `:443`. Fixed by attaching the `host.v1` config to existing services
  (`EnsureServiceConfig`, #205) and by making the toggle defer (#206).
- **BrowZer hop leaked `unknown:<port>` on server redirects**: the hop set the
  upstream `Host`, so the app emitted a correct absolute `Location`, but nginx's
  **default `proxy_redirect`** rewrote it back to the proxy's own address — and
  since the runtime's `Host` is `unknown`, that became
  `http://unknown:<port>/…` (the psm Entra-login 302). Generated hop blocks now
  emit `proxy_redirect off;`. (#207)
- **Reconciler self-heals drifted `host.v1` configs** (create-or-PATCH on data
  drift) so per-app hop-port reshuffles converge automatically with no manual
  `ziti edge delete config`. (#204)

### Dark (loopback-bound) services behind BrowZer + native client (#196)

Publish a service that is **completely dark to the outside** — bound to host
loopback, reachable only over the OpenZiti overlay — while still serving it
clientlessly via BrowZer and/or a native client.

#### Added
- **`BROWZER_HOST_LOOPBACK_ALIAS`** (env, `browzer_targets.go` `browzerUpstream()`).
  In rootless deployments the native access-proxy (a host process) reaches a dark
  target at `127.0.0.1`, but the BrowZer router (a separate network namespace,
  e.g. slirp4netns) cannot. Since both upstreams derive from one route `to_url`,
  this knob rewrites a `127.0.0.1`/`localhost` `to_url` to the alias (e.g.
  `10.0.2.2` with `allow_host_loopback`) **for the BrowZer router config only**.
  Unset (the default, e.g. docker-compose where router and app share a bridge) →
  no rewrite, behavior unchanged.
- Admin console **Identities**: a **Download `.jwt`** button on the enrollment
  modal, so a one-time enrollment token can be fed straight to
  `ziti-edge-tunnel enroll --jwt` / Ziti Desktop Edge for native (no-browser)
  access to dark services.
- `docs/OPENIDX_ZITI_ARCHITECTURE.md`: full OpenIDX + OpenZiti architecture
  guide, including a "dark services + native client" recipe (and the rootless
  loopback-alias wrinkle).

### One-click OpenZiti/BrowZer toggles on proxy routes (#195)

#### Added
- `RouteFeatureToggles` — compact **OpenZiti** and **BrowZer** switches rendered
  directly in each HTTP proxy route's action bar on the Proxy Routes page, so
  putting a route behind the overlay (and publishing it clientlessly via BrowZer)
  is a single click. BrowZer is gated on OpenZiti, matching `ServiceFeaturePanel`.
  Reuses the existing `/services/:id/features/{ziti,browzer}/{enable,disable}`
  endpoints (no backend change) and shares the `['service-status', routeId]`
  query cache with the expand panel so both stay in sync.

### Admin console bug fixes (found via Playwright page sweep)

A headless logged-in sweep of all ~83 console pages surfaced four real bugs:

#### Fixed
- **Governance endpoints returned 401 for every valid token** — governance's
  JWKS key parser ran `ProbablyPrime()` on the RSA *modulus*, which is `p×q`
  (composite by definition), so it rejected every key. All governance pages
  (access-reviews/requests, policies, abac-policies, approval-policies,
  campaigns) were unusable. Replaced with the correct odd-modulus check.
- **`GET /users/me/consents` 500** — the query selected `rt.scope` without
  including it in `GROUP BY` (SQLSTATE 42803). Now aggregates with
  `string_agg(DISTINCT rt.scope, ' ')`.
- **Migration v39** — creates `device_trust_requests`, `device_trust_settings`,
  `trusted_browsers`, `risk_policies`, which existed only in `init-db.sql` (the
  same gap class as v38), so their handlers 500'd on RDS/Helm/`migrate` deploys.
  Also made `GetDeviceTrustSettings` return defaults on no-rows instead of 500.
  *(A wider audit found ~70 more tables only in `init-db.sql`; closing that whole
  gap — and reconciling init-db.sql's own duplicate `lifecycle_executions` — is
  tracked as follow-up.)*
- **`/users` client crash** — avatar initials read `user.username[0]` without a
  null guard (`Cannot read properties of undefined`). Now uses optional chaining
  with a `'?'` fallback.
- **`/users` showed blank names/emails + "Invalid Date"** — the admin users API
  speaks SCIM (`userName`, `name.givenName`, `emails[].value`, `createdAt`,
  `active`) per the identity models + SCIM integration tests, but the console is
  flat snake_case throughout. The console now adapts SCIM↔flat for the users
  endpoint (read and create/update) in `users.tsx`, leaving the rest of the page
  flat. (Backend left unchanged — its SCIM shape is the codified contract used by
  `/scim/v2/Users` and internal oauth/webauthn callers.)
- **`/groups` showed blank descriptions, wrong type, "Invalid Date"** — same
  SCIM↔flat mismatch (`displayName`, `attributes.{description,parentId}`,
  `createdAt`). `groups.tsx` now adapts read and create/update. (Member counts
  show 0 — the list endpoint doesn't return them; an API enhancement, not a
  console fix.)
- **Other SCIM-shaped consumers** (found by auditing every console call to the
  identity user/group endpoints): the group "add member" user-search dropdown
  (`/users/search`, SCIM) and the bulk-operations group selector
  (`/groups`, a bare SCIM array — the code expected `{data:[{id,name}]}`) now
  map SCIM→flat too. Audited as already-correct: group members, user roles,
  roles, and `/users/me` (camelCase, which `user-profile` already matches).

### One-click "open internal app" — published apps as launcher tiles

#### Added
- `POST /api/v1/access/apps/:id/publish-app` publishes a registered app as a
  one-click tile: it creates a single host-level proxy route, auto-creates a
  **My Apps** launcher tile (`applications` row, `base_url` = the gated public
  URL), and registers the per-host `…/access/.auth/callback` on the
  `access-proxy` OAuth client so SSO round-trips without a manual OAuth edit.
- `ACCESS_APPS_DOMAIN` config: bare-label hosts (e.g. `netgraph`) resolve to
  `<label>.<ACCESS_APPS_DOMAIN>` so every app lives under one wildcard domain
  with a single wildcard TLS cert.
- Migration **v41**: `published_apps.public_host` + `landing_path` (where the
  tile opens, default `/`, e.g. `/ui/` for apps not served at the site root).
- Admin console **App Publish → Publish App** dialog (public host + landing
  path). Docs: `docs/app-publishing.md` "One-Click Publishing" section.

### Access-proxy forward-auth: honor X-Forwarded-Proto

#### Fixed
- The access-service built its OAuth callback (`/access/.auth/callback`) as
  `http://` from `c.Request.Host`, ignoring `X-Forwarded-Proto`. Behind a
  TLS-terminating proxy (nginx/APISIX) the public URL is HTTPS, so the emitted
  `redirect_uri` didn't match the registered/public `https://` URL and the
  browser callback hit a non-TLS port. Added a `callbackScheme()` helper
  (X-Forwarded-Proto → request TLS → http) and applied it to all four callback
  builders (the built-in access-proxy login/exchange + the external-IDP paths).

### Access-proxy / App Publish schema fix (migration v40)

#### Fixed
- **App Publish was broken on every migrate-based / RDS / Helm deploy.**
  `GET /api/v1/access/apps` 500'd because `published_apps`, `discovered_paths`
  and `service_features` lived only in `init-db.sql`; `GET /api/v1/access/routes`
  500'd with `column "idp_id" does not exist` because the `proxy_routes` (and
  `proxy_sessions`) schema had drifted ~12 columns behind `init-db.sql`
  (`idp_id`, `route_type`, `remote_host/port`, posture/risk/guacamole/browzer …).
  Migration **v40** creates the missing tables and adds the missing columns
  (idempotent). Verified by registering→discovering→publishing an internal app
  end-to-end.

### gateway-service startup fixes

`gateway-service` panicked on startup under gin v1.11.0 and never began serving
(installs fronting it with APISIX wouldn't have noticed). Three stacked bugs,
each masked by the previous panic:

#### Fixed
- **Route catch-all conflict**: each service's route file registered ~dozens of
  explicit routes *plus* a `/*path` catch-all with the identical proxy handler;
  gin v1.11.0 rejects a catch-all alongside explicit siblings (`/users`).
  Collapsed each service to the single catch-all — behaviourally identical (one
  handler, no per-route middleware) and the correct shape for a pass-through.
- **Duplicate `/health` registration**: the gateway `Service`, the standardized
  `newhealth` service, and the routes package each registered `/health` (and
  `/ready`) on the same engine → `handlers are already registered for path
  '/health'`. The gateway now uses the `Service`'s health routes only (which is
  what the k8s probes and compose healthcheck hit at `/health`).
- **Wrong proxy targets**: `serviceURLProvider` hardcoded `localhost:8501–8506`
  (ignoring env), so the gateway proxied to non-existent/incorrect ports. Fixed
  the defaults to the services' real ports (`8001/8002/8004/8005/8006`) and added
  `<SERVICE>_SERVICE_URL` env overrides (e.g. `IDENTITY_SERVICE_URL`).

### CI green-up + GetUser NULL-name fix

#### Fixed
- **`GetUser` 404'd on users with no name**: `users.first_name`/`last_name` are
  nullable, but the read scanned them into non-pointer strings, so any name-less
  user (valid per SCIM) errored the scan and surfaced as 404. The read now
  `COALESCE`s both to `''`.
- **CI Lint**: removed an ineffectual `countArgCount++` in `internal/admin/service.go`.
- **CI Integration job**: set `DEFAULT_ORG_FALLBACK=true` for the suite. It is
  single-org (most tests log in the seeded admin without an `X-Org-Slug`/subdomain
  signal); the config default flipped to `false` in v1.7.0, which had been failing
  every admin-token-dependent test. The cross-org test still sends `X-Org-Slug`
  explicitly, so isolation is still validated.

### Tenant login branding + production hardening (v1.9.0)

Per-tenant branding on both login surfaces, plus production-readiness fixes —
three of which were surfaced by a prod-like local docker-compose smoke and would
otherwise only have failed in a real multi-tenant deploy.

#### Added
- **OAuth server-rendered login page branding** (`internal/oauth/service.go`):
  `renderLoginPage` now applies the resolved tenant's `tenant_branding` (logo,
  favicon, colors, titles, custom CSS, footer, powered-by toggle) with safe
  defaults on no-org/no-row; text/attrs escaped, `custom_css` treated as trusted
  admin input. Unit test `internal/oauth/branding_test.go`.
- **SPA login branding** (`web/admin-console/src/pages/login.tsx`): applies
  favicon, secondary color, page background (color/image), injected `custom_css`,
  custom footer, and powered-by visibility — on top of the existing
  logo/primary/title/message handling.
- **Migration v38**: creates `tenant_branding`, `tenant_domains` and
  `tenant_settings` in the versioned migration set. They previously existed only
  in `deployments/docker/init-db.sql` (docker-compose), so managed-RDS/Helm
  deploys never had them — branding could not be saved and domain-based tenant
  resolution silently returned defaults. DDL is idempotent.
- **`DATABASE_SSL_MODE` plumbed through deploy configs**: parametrized in
  docker-compose (`${DATABASE_SSL_MODE:-disable}`), the Helm DB-URL secret
  (`database.sslMode`), and documented in `.env.example`. (The Go config/pool
  side already honored it.)
- **`values-prod.yaml` + runbook**: production tenancy env (`TENANT_BASE_DOMAIN`,
  `DEFAULT_ORG_FALLBACK=false`), `database.sslMode: require`, and the tenancy/RLS
  sections + multi-tenancy post-deploy smoke in `docs/DEPLOYMENT.md`.

#### Fixed
- **Public login-branding endpoint blocked in multi-tenant deploys**: the
  fail-closed `TenantResolver` rejected `GET /api/v1/identity/branding` when
  `DEFAULT_ORG_FALLBACK=false`, so the login page could never load tenant
  branding. The endpoint (which self-resolves the tenant from `?org=`/`?domain=`)
  is now exempt from tenant resolution.
- **`TestRLSBelt` was inert under a superuser DB role**: PostgreSQL superusers
  (and `BYPASSRLS` roles) ignore RLS even with FORCE, so the belt test passed
  vacuously against the default `openidx` superuser used by the postgres image
  and CI. It now runs its assertions as a dedicated `NOSUPERUSER` role —
  mirroring how production connects to RDS — making the CI gate meaningful.
  Documented the non-superuser connection requirement in `docs/DEPLOYMENT.md`.

#### Tenancy env injection (Helm)
- The `-config` ConfigMap now carries `TENANT_BASE_DOMAIN`, `DEFAULT_ORG_FALLBACK`,
  `DEFAULT_ORG_ID` and `DATABASE_SSL_MODE`, and every backend deployment mounts it
  via `envFrom` so the settings actually reach the pods.

### Multi-tenancy — RLS belt + per-org primitives (v1.8.0)

Defense-in-depth: Postgres Row-Level Security so a missing app-layer org filter
still cannot leak across tenants, plus the per-org primitives.

#### Added
- Migration **v37**: activates RLS on all 68 org-scoped tables — policies
  rewritten to `app.bypass_rls='on' OR org_id = current_setting('app.org_id')`
  with `ENABLE` + `FORCE ROW LEVEL SECURITY` (fail-closed when the GUC is unset).
- Pool-checkout GUC injection (`internal/common/database/rls.go`): each
  connection is stamped with the request's tenant scope from `orgctx`; no query
  call-site changes. `orgctx.WithBypassRLS` is the explicit opt-in for
  background/cross-org jobs (wired into ~25 ticker/sweep entrypoints + the migrator).
- Two-tenant RLS ship-gate test (`test/integration/cross_org_test.go:TestRLSBelt`):
  a raw cross-org `SELECT` returns 0 rows even with the app filter "broken".
- Per-org rate-limit buckets; `compliance_reader` org-scoped read-only audit role;
  admin-console **Branding** page; `docs/multitenancy-upgrade-runbook.md`.

#### Changed
- **BREAKING (operational):** with RLS forced, direct SQL against org-scoped
  tables sees no rows unless the session sets `app.org_id` (or
  `app.bypass_rls='on'`). See the upgrade runbook.

### Multi-tenancy — App-layer enforcement (v1.7.0)

The v2.0 multi-tenancy epic's enforcement milestone. Every service query now
reads `org_id` from request context and filters/populates by it
(`orgscope ./internal` = 0), and tenant isolation is **activated**.

#### Added
- Cross-org integration test (`test/integration/cross_org_test.go`): a token
  scoped to org A gets **404** (not 403) reading org B's data; a platform admin
  (`super_admin`) may read cross-org via `X-Org-ID` and every such access writes
  an `audit_events` row (`platform_admin_cross_org_access`).
- Platform-admin bypass + mandatory audit, wired through the `TenantResolver`
  (`OnPlatformCrossOrg` hook + `auth.SuperAdminPredicate`).
- Per-tenant JWT `iss` and per-tenant OIDC discovery, derived from the org slug
  and `TENANT_BASE_DOMAIN`.
- Admin-console tenant selector (super_admin-only) that scopes requests via
  `X-Org-Slug`.
- `orgscope` is now a hard CI gate (`-fail`).

#### Changed
- **BREAKING (config):** `DEFAULT_ORG_FALLBACK` now defaults to **false** — a
  request that resolves no tenant is rejected (400) instead of being scoped to
  the default org. Single-tenant installs must set `DEFAULT_ORG_FALLBACK=true`.
- JWT `iss` is per-tenant when `TENANT_BASE_DOMAIN` is set (token-format change;
  global issuer otherwise, so single-tenant installs are unaffected).

## [1.6.0] - 2026-06-11

**Multi-tenancy Foundation milestone.** First of four releases in
the v2.0 multi-tenant SaaS isolation epic (`docs/v2-multitenancy-
design.md`). v1.6.0 lays the schema + plumbing groundwork **without
changing any behavior** for existing single-tenant installs — the
ship gate for this milestone is "existing functionality unchanged."

Multi-tenancy enforcement comes in v1.7.0 (service-layer query
scoping) and v1.8.0 (RLS belt + per-org primitives). v1.6.0 is the
foundation other releases build on.

### Added

- **`internal/common/orgctx` package** (#136). Pure-additive
  `context.Context` carrier for the resolved organization (UUID id
  + slug) and a platform-admin marker. The tenant-resolution
  middleware writes into it; v1.7.0 service code reads from it.
  `With` / `From` / `MustFrom` / `WithPlatformAdmin` /
  `IsPlatformAdmin` exposed with `ErrNoOrgContext` sentinel. 10
  unit tests.

- **`internal/common/middleware.TenantResolver`** (#140). The gin
  middleware that resolves the request's organization from
  `X-Org-Slug` header (gateway-set from subdomain), JWT `org_id`
  claim already attached by the Auth middleware, or `X-Org-ID`
  header (platform-admin only). Falls back to the install's
  default org so single-tenant installs keep working unchanged.
  Defines the `OrgLookup` interface and `ErrOrgNotFound`
  sentinel. 16 unit tests covering every resolution path.

- **`tools/orgscope` CLI** (#141). Static helper that walks
  `internal/` looking for SQL statements targeting a scoped
  table without an `org_id` reference. Filters out gin's
  `c.Query("client_id")`-style false positives by checking that
  the string literal starts with a SQL keyword. Mirrors v36's
  scoped-table list (68 tables, with documented install-wide
  exclusions). Wired into Go CI as an **informational job**
  ("Org-scope lint") that posts findings to the run summary but
  never gates a PR — v1.7.0 will promote to `-fail` once the
  service-layer refactors complete. Baseline on current `main`:
  ~1096 findings, each a concrete v1.7.0 refactor target. 28
  unit + fixture tests.

- **`docs/v2-multitenancy-design.md`** (#135). The architectural
  design doc the v1.0 plan called out as a v2 prerequisite.
  Captures three approved decisions (tenant resolution model,
  app-layer + Postgres RLS defense-in-depth, automatic `'default'`
  org backfill for existing installs), the four-milestone delivery
  plan (v1.6 → v2.0), out-of-scope items, risk register, sizing.

### Changed (schema)

- **Migration v34** (#137) — `org_id UUID NULL` column +
  `idx_<table>_org_id` index added to ~55 tables that migration
  v25 didn't reach (api_keys, mfa_*, oauth_*_tokens, ziti_*,
  scim_*, directory_*, privacy_*, posture_*, governance tables,
  …). Idempotent via `IF NOT EXISTS`. Six tables explicitly **not**
  scoped because they are install-wide rather than tenant-data:
  `organizations`, `permissions`, `system_settings`,
  `ip_threat_list`, `posture_check_types`, `policy_sync_state`.

- **Migration v35** (#138) — Backfills the default organization
  UUID (`00000000-0000-0000-0000-000000000010`, created by v25)
  into every NULL `org_id` row across v34's scoped set. Idempotent
  via `WHERE org_id IS NULL` guards. Down is narrower: only
  reverses rows currently holding the default UUID, so multi-org
  installs (none today) stay intact.

- **Migration v36** (#139) — Final foundation migration. For each
  of the 68 scoped tables, applies `SET DEFAULT '<default-org-
  uuid>'` (preserves ship gate — INSERTs that omit `org_id`
  silently land in default), `SET NOT NULL`, `ADD CONSTRAINT
  fk_<t>_org … REFERENCES organizations(id) ON DELETE RESTRICT`,
  and `CREATE POLICY pol_<t>_org_scope … PERMISSIVE … USING
  (true)`. **RLS is NOT enabled** on the tables — v1.8.0 owns
  activation by `ALTER POLICY` to a real org filter + `ALTER TABLE
  … ENABLE ROW LEVEL SECURITY`. v1.7.0's final PR will `DROP
  DEFAULT` once every INSERT path is org-context-aware.

### Notes for operators

- **No operator action required.** Migrations are
  forward-only-idempotent and `default` org is created
  automatically. The install behaves as a single-tenant install
  did before, just with the multi-tenancy plumbing ready
  underneath.
- **Migration v36 caveat:** `SET NOT NULL` on a table with very
  many rows (audit_events, login_history at scale) runs a
  validation scan. v35 backfilled every existing row so the scan
  succeeds, but for the largest installs we recommend the
  migration runs during a maintenance window.
- `tools/orgscope` baseline (~1096 unscoped queries) is **not**
  a regression — it documents the surface v1.7.0 will refactor.
  The CI job posts the count informationally; PRs are not gated.

### What's NOT in this release

- No enforcement of org scoping. Service code still ignores
  `orgctx`. Queries do not filter by `org_id` yet. RLS is not
  enabled. (v1.7.0 owns the app-layer enforcement; v1.8.0 owns
  RLS.)
- No tenant signup UI, billing, hard quotas, per-tenant signing
  keys, schema/db-per-tenant — those are explicitly out of scope
  for the entire v2.0 epic; see the design doc.

## [1.5.0] - 2026-06-11

A docs-only release that closes the last open P2 backlog item from
the v1.0 plan. No code change; safe to skip if you're already on
v1.4.0 and don't need the new operator-facing docs.

### Added
- **`docs/SECURITY-HARDENING.md`** (#133). Production-readiness
  checklist where every "hard requirement" row maps to a check in
  `Config.ValidateProduction()` — the in-process blocking startup
  gate that already refuses to bring up a misconfigured production
  deploy. Covers the secrets / transport / CSRF-CORS-audit-stream /
  debug-knob sections the validator gates on, plus an "outside the
  validator" section for the operational items that aren't config
  flags. The policy at the bottom nails down validator-first,
  doc-update-in-the-same-PR.
- **`docs/SECURITY-TENANCY.md`** (#133). Explicit, prose statement
  of the single-tenant assumption the v1.0 plan made and the v1.x
  releases preserved. Describes what is shared (data layer,
  identity, authorization, audit), what we do support (federation
  across IdPs, per-app authz, per-customer deployments), and what
  we don't (row-level tenant isolation, per-tenant signing keys,
  per-tenant rate limits, per-tenant audit isolation) — and why
  each is intentional, not a gap.

### Changed
- **`SECURITY.md`** Deployment section trimmed (#133). The previous
  generic OWASP-ish bullet list duplicated marketing copy from the
  README and overlapped with the new hardening doc by 90%. Replaced
  with two pointers to `SECURITY-HARDENING.md` and
  `SECURITY-TENANCY.md` plus the lock-step policy. Vuln reporting
  and supported-versions sections are unchanged.
- **`README.md`** Overview (#133). Adds a prominent blockquote that
  states the single-tenant assumption in one sentence and links to
  `docs/SECURITY-TENANCY.md`. First-impression accuracy for readers
  who would otherwise spend time evaluating us against a multi-
  tenant SaaS use case we don't support.
- **`docs/GETTING-STARTED.md`** "Initialize Database" step (#133).
  The old step told operators to run `\i migrations/001_create_tables.sql`
  — a pre-historic flow. Replaced with the supported path: build
  `cmd/migrate`, run `migrate up`, verify with `migrate status`.
  Plus a top-of-doc callout pointing readers at the new hardening
  and tenancy docs before any production deploy.

### Notes
- v1.4.0 deployments upgrade in place. The release tags the v1.5.0
  binaries identically to v1.4.0; if you don't pull the docs, the
  upgrade is a no-op.

## [1.4.0] - 2026-06-11

A short, focused security-hardening release. Three independent P1/P2
items the v1.0 plan called out, each landed as its own commit with
defense-in-depth tests:

### Changed
- **Dynamic UPDATE builders now run behind a column allow-list**
  (#129). Both `updateSAMLServiceProvider`
  (`internal/oauth/saml_sp.go`) and the
  `/access/paths/:pathID/classification` handler
  (`internal/access/app_publish.go`) used to build their SQL with
  `fmt.Sprintf("col = $%d", argIdx)` scattered through one if-block
  per column. The literals were hardcoded so the pattern was not
  actively exploitable, but the blast radius was wide: one refactor
  wiring a request-derived string into a Sprintf would have introduced
  a real SQL-injection vector. The new `buildUpdateClause` helper
  takes a per-caller column allow-list, validates each candidate
  against both that map and a strict identifier regex
  (`^[a-z_][a-z0-9_]{0,62}$`), and refuses to build the query when
  anything else slips through. Unit tests pin the rejection paths.
- **Migration lock acquisition retries up to 30 s before giving up**
  (#130). Previously `acquireLock` returned instantly on conflict —
  fine for a single admin-driven `cmd/migrate up`, but it raced in
  containerized environments where the migrate job and the
  identity-service / oauth-service replicas were all coming up against
  the same database at startup. Whichever migrator won the race ran
  the migrations; every other process exited with "lock is already
  held" and the orchestrator restarted them in a crash loop. The lock
  now retries every 500 ms for up to 30 s before reporting failure.
  Stale-lock recovery (15 min) is unchanged. A real DB error (not
  `errLockBusy`) still surfaces on the first try — only conflicts
  retry. Six unit tests pin the new behavior including
  context-cancellation handling.
- **CSRF protection is on by default** (#131). The
  `csrf_enabled` default flipped from `false` to `true`. The
  production gate (`ValidateProduction`) caught the old default
  anyway, but every non-prod environment had to remember to opt in.
  Operators now opt out (`CSRF_ENABLED=false`) only when they know
  they need to.

### Fixed
- **`internal/access/ziti.go` was hardcoding
  `tls.Config{InsecureSkipVerify: true}` unconditionally** (#131).
  The line ran before the CA-loading branch, which then bolted a
  `RootCAs` pool onto the TLS config — but `InsecureSkipVerify=true`
  nullifies every CA after it, so the verification path was doing
  nothing for security and the connection was insecure regardless of
  the operator's intent. Replaced with:
  - Load `ZitiIdentityDir/ca.pem` → use it for proper validation
    (the desired path).
  - Missing CA + `ZitiInsecureSkipVerify=true` → log a warning and
    use `InsecureSkipVerify` (the dev-loop escape hatch).
  - Missing CA + `ZitiInsecureSkipVerify=false` → refuse to start
    with a hint pointing at both knobs (the production refusal).

### Security
- **`ValidateProduction()` now rejects two new misconfigurations**
  (#131):
  - `redis_tls_skip_verify=true`
  - `ziti_insecure_skip_verify=true`
  Both are dev-loop escape hatches against self-signed certs in a
  local docker stack; in production they silently erase the trust
  chain on the link they cover. The blocking startup gate
  (`security_check.ValidateProductionConfig`) now ensures production
  deploys can't ship with either flag on.

### Notes
- All v1.3.0 deployments upgrade in place. The CSRF default flip and
  the new skip-verify production gates are the only behavioral
  changes most operators will see; the SQL builder and migration lock
  refactors are internal.

## [1.3.0] - 2026-06-11

A focused follow-on release driven by the P1.5 backend-test sweep —
which surfaced (and made us fix) two real OAuth-flow bugs and one
missing schema migration that production deployments had been
silently broken on since the QR-login feature shipped.

### Added
- **Backend unit-test coverage on previously untested seams** (#122):
  - `internal/oauth/authorize_handler_test.go` — the methods on
    `*AuthorizeHandler` (`validateRedirectURI`, `validateResponseType`,
    `validateScope`, `validatePKCEParameters`, `parseAuthorizeRequest`)
    were 0% covered; new file takes them to 100% without bringing up
    a Service / Redis / DB.
  - `internal/common/netutil/ssrf_test.go` — entire package was
    untested. `DefaultSSRFConfig`, `ValidateURL` (scheme / localhost /
    private-IP / no-hostname / allowlist-miss branches),
    `domainMatches`, `isPrivateIP` (RFC 1918 + RFC 4193 boundaries),
    `isLocalhostIP`, `IsPrivateURL`, `KnownPublicAPIs` sanity. Uses
    literal IPs so the test stays off DNS. **Package coverage
    0 % → 66.2 %**.
  - `internal/common/events/bus_test.go` — entire package was
    untested. `Event` constructor + fluent setters + `JSON`,
    `MemoryBus` subscribe / wildcard / all / with-filter / unsubscribe /
    publish-returns-last-error / close-rejects-publish /
    `PublishAsync`-delivers, and the package-level global-bus wrappers.
    **Package coverage 0 % → 100 %**.
- **Integration coverage for stepup + passwordless** (#123, #126,
  #127). Two new test files (`test/integration/stepup_test.go`,
  `test/integration/passwordless_test.go`) exercise 13 routes /
  ~25 cases. The stepup happy-path round-trip and the QR-login
  create / poll happy paths are now part of the gating integration
  suite.
- **Database migration v33: `qr_login_sessions`** (#127). The table
  `internal/identity/passwordless.go` has been `INSERT`-ing into since
  the QR-login feature shipped — but which no migration ever created.
  Every `POST /oauth/qr-login/create` therefore 500'd at the first
  `INSERT` against "relation does not exist". Surfaced by PR #126's
  integration tests; was previously masked by the broken-session-id
  validator (see Fixed below). Schema mirrors the column set the
  package already reads/writes (id, unique session_token, qr_code_data,
  status enum, nullable user_id, JSONB device blobs, IP, four
  lifecycle timestamps) plus indexes on `(status, created_at)` and a
  partial `user_id` index for the post-scan lookups.

### Fixed
- **`/oauth/stepup-*` returned 401 for every valid bearer token**
  (#126, closes #124). The three step-up routes were registered
  against the bare `/oauth` group with no auth middleware in front of
  them. The handlers read `user_id` and `session_id` from the gin
  context — but nothing populated them, because no middleware ran the
  JWT parse. The fix wraps the routes with `authMiddleware` the same
  way the `/oauth/authorize` consent endpoint already does. As a
  defense-in-depth follow-on, `handleAuthorizationCodeGrant` also now
  falls back to a DB lookup for the user's most-recent active session
  when the Redis `authcode_session:<code>` bridge is empty, so the
  access token always carries a usable `sid` claim.
- **`isValidSessionID` rejected every real `login_session`** (#126,
  closes #125). The validator required a strict 36-character UUID,
  but `/oauth/authorize` produces `login_session` via
  `GenerateRandomToken(32)` — a 44-character padded base64url token.
  The mismatch broke QR login, MFA OTP, passkey, and magic-link-verify
  end to end against the actual auth flow. `isValidSessionID` now
  accepts either form: a 36-character UUID, OR a 32..128-character
  base64url token with optional `=` padding. Both still exclude `:`,
  `/`, whitespace, and control bytes — Redis-key injection / path
  traversal stays blocked. Unit tests expanded to 23 cases covering
  the UUID happy path, the base64url happy path with and without
  padding, length boundaries, and the full injection-shaped rejection
  set.

### Notes
- All v1.2.0 deployments upgrade in place. Migration v33 applies on
  startup through the standard migration runner; the table is empty
  on first use and the OAuth service starts populating it
  immediately.

## [1.2.0] - 2026-06-10

A follow-on minor release closing the rest of the P1 and P2 backlog items
queued behind v1.1.0, plus a full sweep through the admin-console test
suite. Every admin-console page is now covered.

### Added
- **GDPR DSAR processor.** `Service.ExecuteDSAR` now actually fulfills
  data-subject access requests instead of marking them "received":
  - `export` (Article 15) compiles 12 categories of subject data (profile,
    consents, sessions, audit events, roles, groups, app assignments,
    access requests, MFA TOTP, MFA WebAuthn, MFA push, prior DSARs).
  - `delete` (Article 17) erases the subject's records.
  - `restrict` (Article 18) flags the subject for restricted processing.
  A background processor (`StartDSARProcessor`) auto-executes new `export`
  requests; `delete` and `restrict` stay manual on purpose. Backed by
  schema migration v32 (privacy tables) (#118).
- **Outbound resilience.** New `internal/common/resilience` package wraps
  external OAuth / SAML / OIDC discovery calls behind a circuit breaker
  (`ResilientHTTPClient` + per-host `Registry`). Long IdP outages no
  longer drag the whole login path down (#117).
- **Frontend test coverage: 100%.** Every page under
  `web/admin-console/src/pages/` (87 in total) now has a vitest suite.
  Suite is 114 files / 684 tests. Patterns established for fixtures with
  TanStack Query, Radix listeners, fetch-direct pages, route params, and
  `useAuth` mocks (#120).

### Changed
- **Application access requests are fulfilled end-to-end.** Approving an
  access request whose `resource_type == application` now provisions the
  application binding through `internal/provisioning`. Prior to this it
  marked the request approved and warned (#117).
- **Certification reviews now enforce decisions.** Reviewing an item
  with `decision == revoke` (whether per-item or via the campaign's
  `revokeUnreviewedItems`) actually revokes the underlying role / group /
  app assignment instead of just recording the decision (#117).

### Fixed
- **Session-cleanup race-detector flake.** `TestSessionService_Session-`
  `ExpirationCleanup` no longer relies on `miniredis.FastForward`, which
  raced the cleanup goroutine when `-race` was on. The test uses a real
  1 s TTL plus a 1.1 s sleep; the helper also closes its Redis client
  via `t.Cleanup` so leaked goroutines don't carry across tests (#119).

### Notes
- v1.1.0 deployments upgrade in place. The new privacy tables (migration
  v32) apply on startup through the standard migration runner.

## [1.1.0] - 2026-06-09

The first minor release after v1.0.0 — three weeks of post-release hardening
focused on real security gaps that integration tests surfaced, plus the
infrastructure to keep them from coming back.

### Added
- **`POST /api/v1/identity/users/:id/set-password`** — direct admin
  password-set endpoint. Hashes via `Service.SetPassword` so password-history
  and policy enforcement apply. Closes the "admin onboards a non-SSO user"
  gap that previously had no API path (#112).
- **`GET /api/v1/identity/users/me/sessions`** — the self-access counterpart
  of the existing admin-only `/users/:id/sessions`. Sources user id from the
  JWT (#114).
- **`GET /api/v1/identity/users/me/mfa/status`** — self-service MFA status
  endpoint. Returns the user's enabled primary factors as an array, distinct
  from the admin-console toggle map at `/mfa/methods`. Backup recovery codes
  are intentionally excluded — they're not a primary factor on their own
  (#114).
- **Integration test suite is now mandatory in CI**. The full 24-test suite
  (Postgres + Redis ephemeral services, real identity + oauth-service
  binaries) runs on every PR; any regression in identity / OAuth / MFA /
  WebAuthn / session flows blocks the merge (#115).

### Changed
- **Token revocation is now enforced at `/oauth/userinfo`.** PR #82 made
  `internal/auth.ValidateToken` fail-closed on revocation, but the OAuth
  service had its own JWT-parse path that never consulted the revocation
  store — `/oauth/revoke`, `/oauth/logout`, and `/oauth/logout-all` were
  redirect-theater. Now backed by two Redis-keyed mechanisms:
  - Per-token blacklist keyed by `sha256(token)`, TTL = remaining token
    lifetime. Used by `/oauth/revoke` and single-session `/oauth/logout`
    (when called with a Bearer).
  - Per-user revocation cutoff (`oauth:user_tokens_revoked_at:<userID>`).
    Used by `/oauth/logout-all` and by OIDC RP-initiated `/oauth/logout`
    when no Bearer is supplied — every token whose `iat ≤ cutoff` is
    rejected by `/oauth/userinfo` (#112, #114).
- **Refresh-token rotation now happens on every `grant_type=refresh_token`
  exchange** (RFC 6749 §6 / RFC 6819 §5.2.2.3). A new random refresh token
  is issued, the old one is deleted *after* the new one's INSERT succeeds,
  and the response carries the rotated token. Clients that don't store the
  rotated token will get `invalid_grant` on the next refresh — this is the
  intended security improvement (#114).
- **`Service.CreateUser` now mirrors the generated UUID back to the
  caller's struct**, so `c.JSON(201, user)` returns a usable `id` and the
  downstream "user.created" webhook + email-verification token insert see a
  real value instead of an empty string (#112).
- **SCIM `active` field now properly maps to the database `enabled` column**
  in `FromUser`. Previously, SCIM-conformant clients posting
  `{"active": true}` silently created users with `enabled=false`, and every
  admin handler queried `WHERE enabled = true` (#112).
- `handleAdminSetPassword` validates `:id` as a UUID up-front (#112).
- `handleRevoke` now signature-verifies the access token before blacklisting
  it (closes a CodeQL "missing JWT signature check" finding) (#112).

### Database
- **Migration v30**: `ALTER TABLE user_roles ADD COLUMN expires_at TIMESTAMPTZ`.
  The column was already referenced by `GenerateJWT` and the role-expiry
  cleaner, but never existed in the v1 schema — every JWT issuance returned
  an empty `roles` claim, which then 403'd the post-#79 admin-API authz gate
  (#105).
- **Migration v31**: `ALTER TABLE oauth_refresh_tokens ADD COLUMN session_id
  UUID`. The column was added when session-bound rotation landed but never
  made it into the schema migrations. Postgres rejected every INSERT, the
  error was swallowed in `handleAuthorizationCodeGrant`, and clients got
  refresh tokens that were never persisted — every `grant_type=refresh_token`
  then 400'd with `invalid_grant` (#114).

### Fixed
- `audit-service` registers the Redis health check it had been silently
  missing — every other service in the fleet was already checking Redis (#109).
- SAML SP metadata: corrected SA5008 XML tag conflicts on
  `Organization{Name,DisplayName,URL}` (#99).
- `internal/oauth/service.go` and `internal/identity/service.go` cleared
  CodeQL "log entries from user input" findings introduced by the new admin
  endpoints (#112).
- Ratelimit test window flake (#98).
- Frontend type-check and test command scripts (#88, #89).
- Race-condition CI job added (#91).
- CVE bumps: Go toolchain 1.25.11, `go-jose/v4` 4.1.4 (#104, #97).

### Test coverage
- `internal/migrations` unit tests for `allMigrations()` integrity (versions
  contiguous, no gaps, no empty SQL) and `splitSQL` behavior pins (#111).
- `internal/oauth.generateStepUpToken` sign/verify round-trip + claim
  shape (#111).
- `internal/oauth.isValidSessionID` regex-gate locked down across 15 cases
  including path traversal, separator injection, newline injection (#111).
- Frontend smoke coverage on top admin pages (#101).

### Docs
- `docs/PRODUCTION-READINESS.md` — end-to-end "can I deploy this?"
  assessment, 35-item pre-deployment checklist, full feature inventory,
  known-gaps register, deployment paths for Docker Compose / Helm /
  Terraform-EKS (#113).

### Upgrade notes
- **OAuth clients** with refresh tokens: after upgrade, the first
  `grant_type=refresh_token` exchange rotates the token. Persist the new
  `refresh_token` from the response; the old one is invalidated. Clients
  that ignore the rotated token will fail at the *second* refresh, not the
  first — make sure your client code stores the new value.
- **Browser SPAs** relying on the legacy "access token survives logout"
  bug: after upgrade, RP-initiated logout actually kills the access token.
  This is the desired behavior; UI flows that depended on the old leak
  should be reviewed.
- **Database**: two new migrations (v30, v31). Both are
  `ALTER TABLE ADD COLUMN IF NOT EXISTS` with nullable columns — backward
  compatible, fast on production-sized tables, no downtime required.

## [1.0.0] - 2026-05-22

The first tagged release: a hardened, single-tenant, self-hostable v1.

### Added
- Production deployment runbook (`docs/DEPLOYMENT.md`) anchored to the
  `ValidateProduction()` startup gate.
- Observability stack wired into the canonical compose file (Prometheus,
  Alertmanager, Grafana with provisioned dashboards, Loki/Promtail, Jaeger).
- GHCR image pipeline: multi-arch (amd64/arm64) images published to
  `ghcr.io/mhmtgngr/openidx/<service>` on every `main` push and `vX.Y.Z` tag,
  now version-stamped (the tag or commit SHA) and surfaced at `/health`.
- Helm `values-prod.yaml` (pinned tags, autoscaling, NetworkPolicies, external
  secrets, managed datastores) and a Helm chart CI workflow.
- Terraform remote-state backend bootstrap (`deployments/terraform/bootstrap/`)
  and a Terraform fmt/validate CI workflow.
- Compile gate for the build-tagged integration test suite, plus an ephemeral
  Postgres/Redis integration-test CI job.
- Backup/restore: real S3 upload and restore-from-S3 wired through the
  `Storage` interface (the previously-unused `S3Storage` backend), with a
  corrected disaster-recovery runbook.

### Changed
- Project status / feature docs rewritten to reflect the real (much more
  complete) state of the codebase.
- Adopted golangci-lint v2 and cleared the lint backlog: enforced `gofmt`,
  `govet`, `ineffassign`, `unconvert`, `bodyclose`, `staticcheck` (SA bug-class)
  and `unused`; removed dead code. `errcheck` remains intentionally deferred
  (dominated by intentional fire-and-forget calls and optional request-body
  binds).

### Fixed
- Frontend `eslint` configuration repaired; 18 stale frontend tests fixed
  (full suite green).
- Security Scanning workflow no longer reports false-red (image-scan gating;
  Semgrep SARIF upload made non-blocking).
- Backup storage: removed misleading "not initialized" panic placeholders and
  added the package's first tests.
- Schema migrations recover a stale advisory lock (from a crashed holder)
  instead of deadlocking on startup.

### Security
- **Identity admin API now enforces authorization.** The `/api/v1/identity`
  routes are deny-by-default: self-service paths (`/users/me`, MFA enrollment,
  trusted browsers, risk assessment, resend-verification) remain available to
  the authenticated user, but every other identity route now requires the
  `admin`/`super_admin` role. Previously these routes were authenticated but
  not authorized.
- **Token revocation is now enforced.** `RevokeUserTokens` previously wrote a
  per-user revocation marker that was never consulted; tokens issued before a
  revocation are now rejected. Added opt-in fail-closed validation
  (`WithRevocationRequired`) for production.
- **Auth endpoints fail closed under load-shedding.** The distributed rate
  limiter now rejects auth-sensitive requests (login, token, OTP, magic-link,
  password-reset, step-up) when its Redis backend is unavailable, instead of
  silently failing open, and covers more sensitive paths.

### Known limitations (v1)
- **Single-tenant.** One organization per deployment; multi-tenant SaaS
  isolation is not implemented.
- OAuth token introspection does not yet reflect revocation; access-token
  revocation propagates within the access-token TTL (15 min).
- Several built-but-unwired features remain (flagged `TODO(unwired)` in code):
  session idle/absolute-timeout enforcement, SAML SLO session tracking,
  reverse-proxy hop-by-hop header stripping, and audit-stream SIEM config
  endpoints.

[Unreleased]: https://github.com/mhmtgngr/openidx/compare/v1.17.0...HEAD
[1.17.0]: https://github.com/mhmtgngr/openidx/compare/v1.16.1...v1.17.0
[1.16.1]: https://github.com/mhmtgngr/openidx/compare/v1.16.0...v1.16.1
[1.16.0]: https://github.com/mhmtgngr/openidx/compare/v1.15.0...v1.16.0
[1.15.0]: https://github.com/mhmtgngr/openidx/compare/v1.14.1...v1.15.0
[1.14.1]: https://github.com/mhmtgngr/openidx/compare/v1.14.0...v1.14.1
[1.14.0]: https://github.com/mhmtgngr/openidx/compare/v1.13.1...v1.14.0
[1.13.1]: https://github.com/mhmtgngr/openidx/compare/v1.13.0...v1.13.1
[1.13.0]: https://github.com/mhmtgngr/openidx/compare/v1.12.0...v1.13.0
[1.12.0]: https://github.com/mhmtgngr/openidx/compare/v1.11.0...v1.12.0
[1.11.0]: https://github.com/mhmtgngr/openidx/compare/v1.10.1...v1.11.0
[1.10.1]: https://github.com/mhmtgngr/openidx/compare/v1.10.0...v1.10.1
[1.10.0]: https://github.com/mhmtgngr/openidx/compare/v1.9.1...v1.10.0
[1.9.1]: https://github.com/mhmtgngr/openidx/compare/v1.9.0...v1.9.1
[1.9.0]: https://github.com/mhmtgngr/openidx/compare/v1.8.2...v1.9.0
[1.8.2]: https://github.com/mhmtgngr/openidx/compare/v1.8.1...v1.8.2
[1.8.1]: https://github.com/mhmtgngr/openidx/compare/v1.8.0...v1.8.1
[1.8.0]: https://github.com/mhmtgngr/openidx/compare/v1.7.2...v1.8.0
[1.7.2]: https://github.com/mhmtgngr/openidx/compare/v1.7.1...v1.7.2
[1.7.1]: https://github.com/mhmtgngr/openidx/compare/v1.7.0...v1.7.1
[1.7.0]: https://github.com/mhmtgngr/openidx/compare/v1.6.0...v1.7.0
[1.0.0]: https://github.com/mhmtgngr/openidx/releases/tag/v1.0.0
