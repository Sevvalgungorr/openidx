# OpenIDX Production Readiness

**Refreshed:** 2026-06-08 (commit `bd2faa4`, branch `main`)
**Released version:** v1.0.0 (2026-05-22)
**Verdict:** **Ready to deploy as a hardened, self-hosted IAM/ZTNA platform — single- or multi-tenant.** Multi-tenancy (app-layer `org_id` scoping + Postgres RLS belt) landed in v1.6–v1.8; see [DEPLOYMENT.md §4b](./DEPLOYMENT.md#step-4b--multi-tenancy-and-row-level-security-v16). A handful of integration-test failures track real but narrow product gaps (documented in §6) — they do not block a production install, but the affected flows should be exercised manually until follow-up PRs land.

---

## 1. TL;DR — Can I deploy this?

| Scenario | Ready? | Notes |
|---|---|---|
| **Self-host one org on Kubernetes (production)** | ✅ Yes | Helm chart with `values-prod.yaml`, pinned tags, NetworkPolicies, autoscaling. Run through §5 first. |
| **Self-host on a single VM via Docker Compose** | ✅ Yes | `deployments/docker/docker-compose.yml` — convenient for staging or small deployments. |
| **Multi-tenant SaaS** | ✅ Yes (v1.6+) | App-layer `org_id` scoping (`orgctx` + `TenantResolver`) **and** a Postgres RLS belt (migration v37, FORCE RLS on org-scoped tables). Set `TENANT_BASE_DOMAIN`, `DEFAULT_ORG_FALLBACK=false`. See [DEPLOYMENT.md §4b](./DEPLOYMENT.md#step-4b--multi-tenancy-and-row-level-security-v16) and `v2-multitenancy-design.md`. |
| **Cloud deploy via Terraform (AWS EKS)** | ✅ Yes | `deployments/terraform/` is wired with remote-state bootstrap. |
| **Production with PII / regulated data** | ⚠️ Yes, with the hardening checklist (§5) | The `ValidateProduction()` startup gate enforces TLS, real secrets, CSRF, no debug OTP, etc. — refuse to start in prod with insecure defaults. |

**One-line rule of thumb:** if `cmd/identity-service --config production.yaml` starts cleanly past `ValidateProduction()`, you've cleared the security floor.

---

## 2. What's actually in the box

```
~158 KLOC Go (production)   +   ~99 KLOC Go (tests)        →  176 _test.go files
8 backend services          +   3 supporting CLIs          →  ~1,099 HTTP endpoints
87 admin-console pages      +   30 schema migrations       →  React 18 + Vite + Radix/Tailwind
```

### 2.1 Backend services (all built, tested, containerized)

| Service | Port | Endpoints | Responsibility |
|---|---|---|---|
| `identity-service` | 8001 | 192 | Users, groups, roles, sessions, WebAuthn, TOTP, push MFA, federation (OIDC + SAML), passwordless |
| `governance-service` | 8002 | 48 | Access reviews, ABAC policies (SoD / risk / time-bound), OPA integration, certification campaigns |
| `provisioning-service` | 8003 | 21 | SCIM 2.0 users/groups, provisioning rules |
| `audit-service` | 8004 | 32 | Unified audit events, real-time WS streaming, Elasticsearch indexing, compliance reports (SOC2 / HIPAA / GDPR / PCI DSS) |
| `admin-api` | 8005 | 272 | Aggregated admin surface (dashboard stats, settings, applications, API keys, webhooks, notifications) |
| `oauth-service` | 8006 | 55 | OAuth 2.0 + OIDC IdP — PKCE, JWKS (RS256), refresh-token rotation, revocation, step-up, RP-initiated logout |
| `gateway-service` | 8088 | 211 | APISIX integration, proxy routes, OpenZiti tunneling, app publishing |
| `access-service` | — | 177 | Zero-Trust access control, OpenZiti enrollment, posture checks, Android agent / MDM / kiosk / remote support |

Supporting binaries: `cmd/migrate` (schema migrations), `cmd/backup` (backup + restore CLI; S3 / local), `cmd/profiler`, `cmd/demo-app`.

### 2.2 Identity & Authentication

- **User management**: CRUD + bulk operations, CSV import/export, soft delete, lock/unlock, email verification, password history + policy.
- **MFA**: TOTP (RFC 6238, pquerna/otp), WebAuthn / FIDO2 (go-webauthn), push MFA, SMS / Email OTP, recovery codes, step-up authentication.
- **Passwordless**: Magic-link, QR-code device login, passkeys.
- **Federation**: External OIDC providers, SAML SP/IdP (signed metadata, JIT provisioning, attribute mapping).
- **Sessions**: Idle + absolute timeouts, session listing per user, revoke single / revoke-all, distributed session policy.
- **Account recovery**: Password reset (email-token), admin-set password (`POST /users/:id/set-password`, added in PR #112).

### 2.3 OAuth 2.0 / OpenID Connect Provider

- Grants: `authorization_code` (with PKCE S256, required for public clients), `refresh_token`, `client_credentials`.
- Discovery endpoint, JWKS (RS256, key rotation supported via `internal/oauth/keys.go`).
- Token revocation (RFC 7009) — access + refresh tokens, with per-token blacklist *and* per-user "revoke everything before now" marker enforced at `/oauth/userinfo` (PR #112).
- OIDC RP-initiated logout (`/oauth/logout?id_token_hint=…`), logout-all.
- Refresh-token rotation + replay detection (token family revocation).
- Step-up authentication (`/oauth/stepup-challenge` → time-bounded re-auth claim).
- Consent screen + scope management.

### 2.4 SCIM 2.0 Provisioning

- Users + Groups CRUD per RFC 7644.
- ServiceProviderConfig + ResourceTypes discovery endpoints.
- ETag concurrency, filter expressions, attribute-projection.
- Provisioning rules (auto-assign roles/groups on attribute match).

### 2.5 Access Governance

- **Access reviews / certification campaigns** — assign reviewers, item-level decisions, escalation, audit trail.
- **ABAC policies** — Open Policy Agent (OPA) integration; policy authoring UI; admission and runtime evaluation.
- **Separation of Duties** (SoD) detection.
- **Risk-based & time-bounded role assignments** — `user_roles.expires_at` (migration v30), background expiry sweep.
- **Access requests** — submit / approve / reject / fulfill (role and group fulfillment fully wired; application fulfillment is the noted P1.1 gap, called out in `iterative-whistling-shell.md`).
- **Approval policies** — per-app, per-resource workflows.

### 2.6 Zero-Trust Network Access (ZTNA)

- **OpenZiti integration** — service enrollment, posture binding, identity-bound tunnels.
- **BrowZer** — clientless browser-based access for HTTP/HTTPS apps.
- **Posture checks** — 10 built-in checks (OS version, disk encryption, screen lock, AV/EDR, jailbreak, etc.), per-app posture policies.
- **Conditional access** — risk-scored, context-aware rules (`internal/risk/`): brute-force detection, impossible-travel, anomalous-IP, new-device.
- **App publishing** — register an internal app, classify discovered paths, publish with policy.

### 2.7 Android Unified Agent (shipped in PR #59)

- Native Android client (`agent-android/`).
- MDM + kiosk + remote support over Ziti.
- Enrollment via QR + OAuth, Play Integrity verification, BYOD work-profile mode.
- WebRTC remote control with recording — encryption-at-rest, key rotation, retention + legal-hold, S3 + filesystem backends.
- Server side under `internal/access/`: `agent_api.go`, `kiosk_api.go`, `remote_support*.go`, `play_integrity.go`, `turn_credentials.go`, `recording_crypto.go`.

### 2.8 Admin Console (frontend)

- React 18 + Vite + TanStack Query + Radix UI + Tailwind.
- 87 pages — users / groups / roles / sessions / MFA / governance / policies / applications / Ziti / agent fleet / kiosk policies / remote support / audit / analytics / API explorer / branding / certificates / consent / DSAR / compliance dashboard / etc.
- OAuth PKCE login (admin-console client, public, S256 required).
- Real-time updates (WebSocket for audit stream, session changes).
- Vitest smoke tests for top admin pages.

### 2.9 Auditing & Compliance

- Unified audit log across services (writes to `audit_events`, replicated to Elasticsearch when configured). MFA bypass additionally keeps a dedicated `mfa_bypass_audit` row, and is mirrored into `audit_events` so the unified view, the compliance reports and the SIEM forwarder all see it.
- WebSocket streaming endpoint (`/api/v1/audit/stream`) with origin allow-list and message-size cap.
- Audit archival to S3 / cold storage.
- Compliance reports — SOC2, HIPAA, GDPR (consent + DSAR), PCI DSS.
- Retention + legal-hold metadata at the storage layer.

### 2.10 Operational

- **Health endpoints** — `/health`, `/health/live`, `/health/ready` registered on every service. All 8 services check Postgres + Redis (audit-service also checks Elasticsearch when configured). Health responses include service version (`-ldflags -X main.Version=...`).
- **Metrics** — Prometheus scrape on every service; default Grafana dashboards provisioned via `deployments/docker/grafana/`.
- **Tracing** — OpenTelemetry-ready (`internal/common/tracing/`), Jaeger wired in compose.
- **Structured logging** — Zap, correlation-id middleware, optional JSON output for log aggregation.
- **Graceful shutdown** — per-service shutdown manager drains in-flight requests, closes DB / Redis / WebSocket connections in dependency order.

### 2.11 Backup & Disaster Recovery

- `internal/backup/` — `Manager` routes through the `Storage` interface; both `LocalStorage` and `S3Storage` are wired (S3 was unwired pre-v1; fixed and verified end-to-end before tag).
- `cmd/backup` CLI — `backup create` / `backup restore` / `backup list` against either backend.
- Encryption at rest for backups; integrity verification on restore.
- Helm `CronJob` template included for scheduled backups.
- `docs/disaster-recovery.md` — verified runbook including restore drill steps.

### 2.12 API gateway / ingress

- Apache APISIX configuration in `deployments/docker/apisix/` (routes, plugins, rate limits, OIDC auth).
- Per-route rate-limiting (sliding-window via Redis; default 100/min per IP, **strict 5–10/min per auth endpoint** fail-closed).
- CORS and security-header middleware applied service-wide.

---

## 3. CI / quality posture

| Gate | Status | Notes |
|---|---|---|
| `gofmt` / `govet` | Required | Enforced by `golangci-lint v2` |
| `ineffassign` / `unconvert` / `bodyclose` | Required | Same |
| `staticcheck` (SA bug-class) | Required | Same |
| `unused` | Required | Same |
| Race detector (`go test -race`) | Required | 5 real data races already fixed |
| `govulncheck` | Required | Zero criticals at tag time |
| Trivy (image + filesystem) | Informational | Allowlist tracked in `.trivyignore` |
| CodeQL | Required | Failures here block Required Checks |
| Unit tests (per-package matrix) | Required | 176 `_test.go` files |
| Integration tests (Postgres + Redis ephemeral services) | **Informational (`|| true`)** | **21 / 24 top-level tests passing on `main`.** Promotion gated on §6 follow-ups. |
| Frontend tests (vitest) | Required when frontend changed | Smoke coverage on top pages |
| Coverage report (codecov) | Informational | |
| `errcheck` | Intentionally deferred | Dominated by fire-and-forget calls + optional body close. Documented decision. |

**Required Checks aggregate** is the merge gate. Skip-on-no-change is in place — docs-only PRs don't get blocked by Go-side checks.

---

## 4. Security posture (what's enforced today)

- **Token revocation** is authoritative — Redis-backed per-token blacklist + per-user cutoff marker, enforced at `/oauth/userinfo` with fail-closed semantics (PR #82 + #112).
- **Brute-force protection** — `internal/risk/anomaly.go::DetectBruteForce` is wired to throttling/lockout; auth endpoints fail-closed on Redis outage (PR #74-ish).
- **Admin authz** — admin-only routes deny-by-default (`roles` claim from JWT) since PR #79. SECURITY.md documents the single-tenant trust model.
- **CSRF** — disabled by default for dev, **`ValidateProduction()` refuses to start** without `csrf_enabled=true`.
- **`DEBUG_OTP_IN_RESPONSE`** — false by default, hard-blocked in production.
- **TLS** — production gate requires real (non-`localhost`) issuer/redirect URIs, real DB / Redis credentials, real secret key material.
- **Insecure dev-only knobs** — `ziti_insecure_skip_verify`, `redis_tls_skip_verify` default false; require explicit opt-in.
- **Dynamic SQL** — every `UPDATE … SET %s WHERE id=$N` Sprintf site has been audited; columns are hardcoded string literals from `if req.X != nil { sets = append(sets, "x=$N") }` blocks. No request-derived column names.
- **CVE bumps** — Go toolchain 1.25.11 (fixes GO-2026-5037/5038/5039); 5 dependency-CVE bumps as part of the v1 hardening pass.
- **Audit logging** — sensitive IAM actions land in `audit_events` with actor, actor IP, target and outcome: login success / failure / denial, role assignment, removal and wholesale replacement (which records the roles lost as well as gained), role and group lifecycle, group membership changes, TOTP enrolment and disablement, backup-code generation, MFA bypass issue and use, identity-provider create / update / delete, user create / update / delete, and password change vs. admin-set password. Emission sits *after* each operation's error check, so a rejected attempt never appears as a change. This is deliberately a named list, not "everything": the section previously claimed every admin action was covered, and named a table (`audit_logs`) that does not exist. Governance and PAM keep their own emission paths.
- **HTTP server timeouts** — `ReadTimeout`, `WriteTimeout`, `IdleTimeout` set on every service's `http.Server` (slow-client / Slowloris-style DoS protection).
- **Outbound HTTP timeouts** — every SAML metadata / social-login client carries an explicit `Timeout`.

---

## 5. Pre-deployment checklist

Before flipping any production switch, walk through this:

### 5.1 Secrets and configuration

- [ ] `JWT_SIGNING_KEY` (or KMS reference) generated, ≥ 4096-bit RSA, rotated from any seeded dev key.
- [ ] `DATABASE_URL` / `REDIS_URL` point at managed instances with TLS.
- [ ] All `*_PASSWORD` and `*_SECRET` env vars sourced from a secrets manager (External Secrets Operator + Vault / AWS Secrets Manager). No literals in Helm `values.yaml`.
- [ ] `APP_ENV=production` set. Confirm the service refuses to start if you flip any insecure knob (smoke test the gate).
- [ ] `OAUTH_JWKS_URL` and the issuer point at the public hostname, not `localhost`.

### 5.2 Identity bootstrap

- [ ] Default admin password (`Admin@123` from seed migration v10) **rotated** before exposing the admin console.
- [ ] At least one second admin account created (avoid single-account lockout).
- [ ] MFA enrolled on every admin account (TOTP + a hardware key as backup).

### 5.3 Datastores

- [ ] Postgres: `cmd/migrate up` run once, replication / PITR enabled.
- [ ] Redis: persistence on (AOF / RDB) for revocation lists you don't want to lose on restart; *or* accept a small-window risk window.
- [ ] Elasticsearch (optional, for audit search): index lifecycle policy in place.

### 5.4 Backup

- [ ] `cmd/backup` CronJob deployed (Helm template available), target = S3 bucket with versioning + object-lock.
- [ ] **Restore drill performed** — verified you can restore an audit-log-affecting backup to a side-by-side cluster and queries match expected counts. `docs/disaster-recovery.md` walks this.

### 5.5 Networking

- [ ] APISIX (or your gateway of choice) terminates TLS; internal mesh runs mTLS or sits behind a private network.
- [ ] Kubernetes `NetworkPolicy` allows only the documented inter-service flows.
- [ ] Rate limits set per environment (`RATE_LIMIT_AUTH_REQUESTS`, `RATE_LIMIT_REQUESTS`) — defaults are tuned for prod, not load tests.

### 5.6 Observability

- [ ] Prometheus scrape jobs configured against all 8 services.
- [ ] Grafana dashboards loaded from `deployments/docker/grafana/dashboards/`.
- [ ] Alertmanager routes set for the supplied alert rules.
- [ ] Loki / your log aggregator pointed at structured JSON output.
- [ ] On-call runbook(s) hooked to your paging system.

### 5.7 Compliance

- [ ] Audit-log retention configured (DB partition by month + S3 archival pipeline).
- [ ] Legal-hold workflow tested (set / clear / list).
- [ ] Privacy / DSAR submission endpoints reachable; manual DSAR fulfillment process documented (automated fulfillment is a P2.3 follow-up, not in v1).

### 5.8 Release hygiene

- [ ] Image digests pinned in `values-prod.yaml` (not just tags).
- [ ] `kubectl rollout` strategy = `RollingUpdate` with `maxUnavailable: 0`.
- [ ] You've verified `/health` returns `version: 1.0.0` after the rollout.

---

## 6. Known gaps (do not block deploy, do not silently ignore)

Every entry below was re-verified against the code before being written down. The
previous version of this section was wrong in both directions — it listed five
gaps that had all since been closed, while omitting the security findings the
IAM audit turned up. A gap list that is not re-checked stops being a plan and
becomes a rumour, so entries here cite the file that settles them.

### 6.1 Closed since the last revision — no longer gaps

The five items previously listed (from the v1 integration-test push, PRs #110
and #112) are all implemented. Kept here, briefly, because they were quoted
elsewhere as open:

| Previously listed as a gap | Actually |
|---|---|
| `GET /users/me/sessions` not implemented | Routed to `handleGetMySessions` (`internal/identity/service.go`) |
| `GET /users/me/mfa/status` returns 404 | Routed to `handleGetMyMFAStatus` (same route block) |
| `handleRefreshTokenGrant` 400s for the public admin-console client | Fixed in #633; `clientCredentials` accepts form and Basic auth, and a client registered with `token_endpoint_auth_method=none` carries no secret to mismatch (`internal/oauth/client_auth.go`, `dcr.go`) |
| WebAuthn enrollment paths don't match the integration test | They do: the test calls `/api/v1/identity/mfa/webauthn/register/begin`, which is a registered route (`test/integration/auth_flows_test.go`) |
| Application provisioning for approved access requests is a no-op | `case "application"` grants the assignment, and the `default` branch now fails loudly rather than marking a request fulfilled without granting anything (`internal/governance/workflows.go`) |

The paragraph that used to follow — "after these land, the integration suite's
`|| true` will be dropped and `test-integration` added to Required Checks" — is
also done. Neither the integration job nor the unit-test matrix carries `|| true`
any more, and `test-integration` is in the Required Checks `needs:` list
(`.github/workflows/ci.yml`).

### 6.2 Actually open

| Gap | Affected | Mitigation |
|---|---|---|
| The Ziti controller admin password uses a local AES-256-GCM encrypter rather than `internal/common/secretcrypt` | No KEK rotation for that one secret | Format is authenticated and test-pinned (`internal/access/secret_cipher.go`). Consolidating needs the stored value re-encrypted under a tagged format first — a data migration, not a refactor; `secretcrypt` passes untagged input through unchanged and would otherwise hand the base64 blob to a controller login as the password. |
| Password hashing is bcrypt (cost 12), not Argon2id | Offline-cracking cost is lower than a memory-hard KDF's | One policy and one cost throughout (`internal/identity/passwords.go`). Adopting Argon2id needs bcrypt verification plus rehash-on-login; the unreachable Argon2id service that could not verify a single real bcrypt hash was deleted in #637 rather than left looking like coverage. |
| `internal/oauth/oidc.go`'s `OIDCProvider` is unreachable | Nothing at runtime — `/userinfo` routes to `Service.handleUserInfo` | Dead, not wrong. Removing it also removes ~950 lines of tests and touches the shared OIDC test harness, so it is its own change. |
| RFC 8628 device authorization grant not implemented | CLI / TV / input-constrained clients | Not advertised in discovery, so no client negotiates it. |
| LDAP referral chasing absent | Multi-domain AD forests where the search base returns referrals | Point the connector at a global catalog, or configure one directory per domain. |

### 6.3 Out of scope for v1 (large epics, not blockers)

- Billing / quotas / self-service onboarding.
- SOC2 Type II / ISO 27001 certification audits.

Multi-tenant SaaS isolation was previously listed here as "would require a
data-layer retrofit". That retrofit has happened: tenant isolation is enforced
at the database with `FORCE ROW LEVEL SECURITY`, the GUCs are set at pool
checkout (`internal/common/database/rls.go`), and `tools/orgscope` runs as a
hard CI gate that fails the build on a query touching a tenant-scoped table
without an `org_id` predicate. It is not an open epic.

---

## 7. Deploying — fastest paths

### 7.1 Docker Compose (single VM / staging)

```bash
git clone https://github.com/mhmtgngr/openidx
cd openidx
cp .env.example .env       # then edit JWT_SIGNING_KEY, DB password, etc.
make dev-infra             # Postgres + Redis + (optional) Elasticsearch + observability stack
docker compose -f deployments/docker/docker-compose.yml up -d
make migrate-up            # apply 30 migrations
# admin-console at http://localhost:3000
# default login: admin / Admin@123  ← rotate this immediately
```

### 7.2 Kubernetes (production)

```bash
helm install openidx ./deployments/kubernetes/helm/openidx \
  -f deployments/kubernetes/helm/openidx/values-prod.yaml \
  --set image.tag=v1.0.0 \
  --set externalSecrets.enabled=true \
  --set ingress.host=auth.example.com
```

Pre-flight: ensure the `External Secrets Operator` and a backing secret store (Vault / AWS Secrets Manager / GCP Secret Manager) are installed in the cluster, and that the documented secret keys (`openidx/jwt-key`, `openidx/db-password`, etc.) exist.

### 7.3 AWS EKS via Terraform

```bash
cd deployments/terraform/bootstrap   # one-time: provisions the remote-state S3 bucket + DynamoDB lock
terraform init && terraform apply
cd ../environments/prod
terraform init
terraform apply                       # provisions EKS, RDS, ElastiCache, S3 buckets, IRSA
helm install openidx ../../kubernetes/helm/openidx -f values-prod.yaml
```

Modules under `deployments/terraform/modules/` cover EKS, networking, RDS Postgres, ElastiCache Redis, ALB, and IAM (IRSA for backup S3 access).

---

## 8. Where to look in the code

| You want to… | Read |
|---|---|
| Understand the architecture | `README.md` + `docs/PROJECT-STATUS.md` |
| Stand up locally | `docs/GETTING-STARTED.md` |
| Plan a production deploy | `docs/DEPLOYMENT.md` + this document |
| Verify the security posture before going live | `SECURITY.md` (trust model, vulnerability reporting) + §5 above |
| Understand the OAuth/OIDC flows | `docs/OAUTH-OIDC.md` |
| Wire up MFA | `docs/MFA_IMPLEMENTATION_GUIDE.md`, `docs/PASSWORDLESS_AND_PUSH_MFA_IMPLEMENTATION.md` |
| Use SCIM | `docs/SCIM.md`, `docs/SCIM-FEATURES-LOCATION.md` |
| Restore from a backup | `docs/disaster-recovery.md` |
| Cut a release | `docs/RELEASING.md` |
| See what changed in v1.0.0 | `CHANGELOG.md` |

---

## 9. Bottom line

You can deploy this to a real organization today as a hardened single-tenant IAM + ZTNA platform. The security floor is enforced at startup; the operational story (Helm, Terraform, observability, backup, runbooks) is genuine, not aspirational. The remaining gaps in §6 are real and worth tracking — but each affects a narrow flow, none touches the security boundary, and each has a documented workaround. If you'd hesitate to deploy Okta or Entra ID without your own pre-flight checklist, walk through §5 here and you're at parity.
