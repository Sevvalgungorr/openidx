# Going dark: taking the OpenIDX API off the public internet

Goal: no data API reachable from the internet. Services bind loopback-only and
are reachable **only over the OpenZiti overlay**; the sole public doors are the
Tier-0 bootstrap surface (login/JWKS, `POST /api/v1/access/enroll`, agent
enroll/report, APK download) and the admin console.

This is enforced by two merged changes:

- **Hard auth on the data API** (`ACCESS_API_REQUIRE_AUTH=true`, PR #558): even in
  `APP_ENV=development` the `/api/v1/access` group rejects anonymous callers.
- **Dark-mode bind guard** (`ValidateDarkModeBind`, PR #559): when a
  `DARK_MODE_TIER{1,2}` flag is set, the service refuses to start unless
  `SERVICE_BIND_ADDR` is loopback. A "dark" service can never silently stay
  public.

## Staged proof (already run, no live impact)

A throwaway access-service was started on `127.0.0.1:18077` with
`SERVICE_BIND_ADDR=127.0.0.1 DARK_MODE_TIER1=true ACCESS_API_REQUIRE_AUTH=true`:

| Check | Result |
|---|---|
| `127.0.0.1:18077/access/health` (on-box / overlay) | **200** |
| `<SERVER_IP>:18077` (public IP, off-box) | **connection refused** |
| `no-token /api/v1/access/pam/entries` | **401** |
| `with-token /api/v1/access/pam/entries` | **200** |
| `POST /api/v1/access/enroll` | **401** (needs a credential, reachable) |
| Negative control: `DARK_MODE_TIER1=true` + `SERVICE_BIND_ADDR=0.0.0.0` | **FATAL, refuses to start** |

## Rollout checklist (per service)

For each data service (access, governance, identity, audit, provisioning; oauth
is Tier-0-ish — keep its public login/JWKS/enroll surface reachable):

1. In the service's `run-*.sh` / unit env, set:
   - `SERVICE_BIND_ADDR=127.0.0.1`
   - `DARK_MODE_TIER1=true` (or `TIER2` for device-trust-required services)
   - `ACCESS_API_REQUIRE_AUTH=true` (access-service)
2. Restart the service. It will `log.Fatal` if the bind is not loopback (guard).
3. Confirm bind: `ss -tlnp | grep :<port>` shows `127.0.0.1:<port>`, not `0.0.0.0`.
4. Confirm off-box refusal: from another host, the service port must refuse.

## Edge (nginx + APISIX) — keep only Tier-0 public

Trim the public edge so the internet can reach only:

- `POST /api/v1/access/enroll`, agent enroll/report, APK download (bootstrap)
- `/oauth/*`, `/.well-known/*` (login, JWKS, discovery)
- the admin console SPA

Everything else under `/api/v1/*` should be served only to overlay clients (the
loopback upstreams), i.e. dropped from the public `location /api/v1/` block or
gated so only the overlay-terminated path reaches them.

## Prerequisites still open

- **Z1 (controller FQDN):** advertise the Ziti controller under a
  phone/off-box-resolvable name (`ctrl.tdv.org`) instead of `localtest.me`
  (which resolves to 127.0.0.1 everywhere), plus the DNS record. Without this,
  remote overlay clients cannot reach the controller to enroll/dial.
- **Z3 (PAM over Ziti):** the PAM ziti-broker/tunnel must be running on the box
  (`/api/v1/access/pam/broker/status` currently reports `ziti_broker:false`)
  before PAM entries can move to `reach_mode:ziti`.
