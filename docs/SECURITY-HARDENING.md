# OpenIDX Production Hardening Checklist

This is the production-readiness checklist for OpenIDX deployments. It is
**grounded in the code** — every required item below corresponds to a
check in `Config.ValidateProduction()`
(`internal/common/config/config.go`), which runs as a blocking startup
gate. If a knob is misset, the service refuses to start. If a knob is in
the "should-set" section, the service starts but emits a warning in
the logs.

You can use this file in two ways:

1. As a deployment checklist for a single-tenant production install.
2. As a reference for what the validator already enforces, so you don't
   have to re-derive it from the source.

For the threat model and the boundaries this list assumes, see
[SECURITY-TENANCY.md](./SECURITY-TENANCY.md).

---

## Hard requirements (validator refuses to start otherwise)

Set `OPENIDX_ENVIRONMENT=production` (or `APP_ENV=production`) to
activate the gate. Every item below is a critical issue the validator
returns as an error — you cannot bring the service up in production
without satisfying it.

### Secrets

| Knob | Required value | Notes |
|---|---|---|
| `JWT_SECRET` | random ≥ 32 bytes; must not contain "change" (case-insensitive) | Used to sign access + ID tokens. Rotate together with `OAUTH_JWKS_URL` cache invalidation. |
| `ACCESS_SESSION_SECRET` | random ≥ 32 bytes; must not match `change-me` | Used by the access-service for session cookies. |
| `ENCRYPTION_KEY` | random ≥ 32 bytes; must not contain "change" (case-insensitive) | Encrypts sensitive at-rest fields (SMTP creds, identity-provider client secrets, etc). |

The validator does **not** check rotation cadence — that's an
operational policy. We recommend 90-day rotation for JWT-signing keys.

### TLS / transport encryption

| Knob | Required value | What goes plaintext if you skip it |
|---|---|---|
| `DATABASE_SSL_MODE` | `require`, `verify-ca`, or `verify-full` (not `disable`) | The entire PostgreSQL wire protocol — including password hashes, MFA secrets, audit events. |
| `REDIS_TLS_ENABLED` | `true` | Session IDs, OAuth login_session bridges, MFA challenge tokens. |
| `TLS_ENABLED` | `true` | Inter-service HTTP between identity / oauth / governance / etc. |
| `REDIS_TLS_SKIP_VERIFY` | **must be `false`** | Setting this to `true` disables Redis server-cert validation, which silently undoes `REDIS_TLS_ENABLED`. Closed in v1.4.0. |
| `ZITI_INSECURE_SKIP_VERIFY` | **must be `false`** | Setting this to `true` disables Ziti controller TLS validation. Closed in v1.4.0. |

Both skip-verify flags exist as dev-loop escape hatches against
self-signed certs in a local docker stack. In production they erase the
trust chain on the link they cover, which is why the validator hard-
refuses them.

### CSRF + CORS + audit stream

| Knob | Required value | Notes |
|---|---|---|
| `CSRF_ENABLED` | `true` | Defaults to `true` since v1.4.0; was `false` before. |
| `CORS_ALLOWED_ORIGINS` | not `*` | Must enumerate the admin-console + first-party SPA origins. |
| `AUDIT_STREAM_ALLOWED_ORIGINS` | not empty, not `*` | WebSocket origin allow-list for the audit-stream endpoint. |

### Debug knobs

| Knob | Required value | Notes |
|---|---|---|
| `DEBUG_OTP_IN_RESPONSE` | `false` | Setting this to `true` returns OTP codes in API responses; **never** acceptable in production. |

---

## Soft requirements (validator warns but allows startup)

The same code path also emits warnings for the following. The service
still starts, but every warning should be triaged before declaring an
install production-ready.

- Default values for any of the three secrets above (caught as critical
  if explicitly default; warned if structurally suspicious).
- `cors_allowed_origins is wildcard` (also a critical issue).
- `tls.enabled is false` (also a critical issue).

There is no item below that is "warn-only" — the v1.3.0 / v1.4.0
sweeps promoted everything material to a critical issue.

---

## Hardening that lives outside the config validator

The validator only catches what is expressible as a config flag. The
items below are operational; the project does not check them at
startup.

### Database

- Run PostgreSQL with `log_statement = 'ddl'` so schema changes leave
  a trail.
- Migrations land through `cmd/migrate up`, not auto-migrated by
  application services — this is enforced by the entry-point design;
  no service binary calls `Migrate()` directly.
- Apply pg_hba rules so OpenIDX service accounts can only connect from
  the application subnet, not from the operator workstations.
- Take encrypted backups via the same `internal/backup` path the
  v1.1.0 release wired up (see [disaster-recovery.md](./disaster-recovery.md)).

### Redis

- Pin the Redis version (do not track `:latest`). The session-cleanup
  flake the v1.1.0 / v1.2.0 cycle hit was sensitive to a Redis client
  behavior change.
- Bind Redis to `127.0.0.1` unless remote access is genuinely
  required. See `docs/host-firewall-baseline.md`.
- Use a non-default `REQUIREPASS`. Do not skip this on the assumption
  that the wire is TLS-protected: that assumption fails the moment
  Redis is published on a non-loopback address, and Redis holds
  session and rate-limit state. A leaked DSN is far more dangerous
  when the password is empty.
- Consider Redis Sentinel if a single-node failure would page someone;
  the project already supports it (see the `redis_sentinel_*`
  config fields).

### Container / runtime

- Run all services as non-root. The Docker images already drop to a
  non-root user; if you re-roll images, preserve this.
- Use read-only root filesystems where possible.
- Set CPU + memory limits — the rate-limit middleware fails closed on
  Redis disconnect (as of PR #82), but an OOM-killed pod still drops
  in-flight requests.

### Networking

- Put the API gateway (APISIX or an equivalent) in front of all
  external traffic. Direct exposure of any service binary is a
  misconfiguration.
- Apply Kubernetes NetworkPolicies (or VPC security groups) to
  restrict service-to-service traffic to known peers.

### Observability

- Forward audit events out of the database to a SIEM. The audit table
  is durable but not append-only; assume you'll want offsite copies.
- Set alerts on the brute-force / impossible-travel events the risk
  engine emits.
- Track the JWT key-rotation cadence with a dashboard or a calendar
  reminder; nothing in the code reminds you.

---

## When this file is wrong

The validator is the source of truth. If you add or remove a critical
issue in `Config.ValidateProduction()`, update the corresponding row in
the "Hard requirements" table above in the same PR.

If you discover an item that **should** be enforced at startup but
isn't, the policy is: harden the validator first (defense in depth at
launch), then update this file. Doc-only hardening leaves the next
operator one config-typo away from a regression.
