# OpenIDX + OpenZiti — Architecture & Operations Guide

> A full view of how OpenIDX and OpenZiti fit together, how to use them, and
> where the "Ziti client" actually lives. Reflects the running deployment on
> this box (`<SERVER_IP>`, podman, native Go services) as of 2026-06-23.
>
> Just want to get the fabric running? See
> [ZITI_EASY_DEPLOYMENT.md](./ZITI_EASY_DEPLOYMENT.md) — `make ziti-quickstart`
> brings up the controller (with the bundled ZAC console) and a router in one
> command.

---

## 1. The 60-second mental model

OpenIDX is a Zero Trust Access Platform: identity (who you are), policy (what
you may reach), and a **reverse proxy** (the enforcement point) for web/SSH/RDP
apps. OpenZiti is the **encrypted overlay network** that carries traffic so the
target app is never exposed on the LAN/Internet — it has *no open inbound port*;
it only makes an outbound connection to the overlay.

Three things cooperate:

1. **OpenIDX services** — identity, OAuth/OIDC, audit, and the **access-service**
   (the Zero Trust proxy + Ziti orchestrator).
2. **OpenZiti control plane** — a **controller** (issues identities/certs, holds
   policy) and an **edge router** (moves the encrypted data).
3. **BrowZer** — makes a Ziti-protected web app reachable from an *unmodified
   browser* (no client install), by injecting a JS runtime that speaks Ziti.

```
                         ┌──────────────────────────────────────────────┐
        Browser /        │                  oidx-nginx :443              │
        SSH client  ───► │      (TLS terminator, *.tdv.org real cert)    │
                         └───────┬───────────────┬──────────────┬────────┘
                                 │               │              │
              openidx.tdv.org ───┘   netgraph.tdv.org    browzer.tdv.org / ctrl.tdv.org
              (admin console +       (published app)      (BrowZer bootstrap +
               API, :8001-8007)             │              controller front)
                                 ┌───────────▼───────────┐
                                 │  access-service :8007  │  ◄── the Zero Trust proxy
                                 │  (embeds Ziti Go SDK)  │      AND Ziti orchestrator
                                 └───────────┬───────────┘
                          hosts/binds Ziti   │   manages (REST mgmt API)
                          services via SDK   │
                                 ┌───────────▼────────────────────────────┐
                                 │            OpenZiti overlay             │
                                 │  controller :1280   router :3022/:3023  │
                                 └───────────┬────────────────────────────┘
                                             │ terminator forwards to upstream
                                 ┌───────────▼───────────┐
                                 │  Target app (netgraph │
                                 │  <SERVER_IP>:8088)  │  ◄── never directly exposed
                                 └───────────────────────┘
```

---

## 2. Where is the "Ziti client"? (read this first)

This is the most common point of confusion. There is **no single Ziti client** —
there are three roles, and which one applies depends on *how* you reach the app.

| Role | What it is | Where it lives here | Install needed? |
|------|-----------|---------------------|-----------------|
| **Hosting side (the "server")** | OpenIDX's access-service **embeds the OpenZiti Go SDK** (`sdk-golang v1.7.0`). It enrolls as a Ziti identity called **`access-proxy`** and *hosts/binds* the services (it is the terminator that forwards to the real app). | `internal/access/ziti.go` (the `ZitiManager`); identity file `/tmp/oidx-ziti/identity/access-proxy.json` | Already built into OpenIDX — nothing to install |
| **Clientless browser (BrowZer)** | The **browser itself becomes the client**. The BrowZer bootstrapper injects a JS runtime (`ziti-browzer-runtime-*.js`) into the page; that runtime opens a **WebSocket (WSS)** to the edge router and tunnels HTTP over the overlay. | bootstrapper container `oidx-browzer` (:8445), runtime served via `browzer.tdv.org` | **None** — any modern browser |
| **Native endpoint client (optional)** | For non-browser apps (or always-on access), an OS-level tunneler — **Ziti Desktop Edge** (Windows/macOS) or **`ziti-edge-tunnel`** (Linux) — enrolls a per-device identity and captures traffic to Ziti services. | *Not deployed on this box.* You'd enroll a device identity from the controller and run the tunneler on the user's machine. | Yes — install the tunneler |

**Bottom line for this deployment:** users reach `netgraph.tdv.org` **clientlessly via BrowZer** — there is nothing for them to install. The only "Ziti client" present on the box is the **SDK embedded in the access-service** (the hosting side), whose identity is `access-proxy.json`. A native tunneler is supported by OpenZiti but is not set up here.

---

## 3. Component inventory (live on this box)

### 3.1 OpenIDX microservices (native Go, run via `/tmp/run-access.sh` and friends)

| Service | Port | Entry point | Responsibility |
|---------|------|-------------|----------------|
| identity-service | 8001 | `cmd/identity-service/main.go` | Users, SSO, identity management |
| governance-service | 8002 | `cmd/governance-service/main.go` | Access reviews, certifications, policies |
| provisioning-service | 8003 | `cmd/provisioning-service/main.go` | SCIM 2.0, user lifecycle, directory sync |
| audit-service | 8004 | `cmd/audit-service/main.go` | Audit log, compliance reports, SIEM |
| admin-api | 8005 | `cmd/admin-api/main.go` | Admin console REST API, dashboard |
| oauth-service | 8006 | `cmd/oauth-service/main.go` | OAuth 2.0 / OIDC, JWKS (the IdP) |
| **access-service** | **8007** | `cmd/access-service/main.go` | **Zero Trust proxy + Ziti orchestration** |
| gateway-service | 8008 | `cmd/gateway-service/main.go` | Unified API gateway, JWT validation |

Backing stores: **PostgreSQL** `oidx-pg` (`:55432`), **Redis** `oidx-redis` (`:56379`).

### 3.2 OpenZiti + BrowZer (podman containers)

| Container | Image | Ports | Role |
|-----------|-------|-------|------|
| `oidx-ziti-controller` | `openziti/ziti-controller` (**v1.6.12**) | mgmt/edge API `:1280` | Issues identities & certs, stores policy, fabric brain |
| `oidx-ziti-router` | `openziti/ziti-router` | link `:3022`, **WSS `:3023`** | Moves encrypted data; WSS port serves the browser |
| `oidx-browzer` | `ziti-browzer-bootstrapper` | `:8445` | Serves + injects the BrowZer JS runtime; OIDC bounce |
| `oidx-browzer-router` | `nginx:alpine` | `:8094` | Per-vhost demux of BrowZer traffic to the target app |
| `oidx-nginx` | `nginx:alpine` | `:443` | TLS terminator / front door for all `*.tdv.org` |

### 3.3 nginx front door (`/tmp/oidx-tls/nginx.conf`)

| Hostname | Upstream | Purpose |
|----------|----------|---------|
| `openidx.tdv.org` | `:8001`–`:8007`, `:8005` (admin), `:8006` (oauth) | Admin console + all OpenIDX APIs |
| `netgraph.tdv.org` | `https://:8445` (bootstrapper) | The **published app**, reached clientlessly via BrowZer |
| `browzer.tdv.org` | `https://:8445` | BrowZer runtime + WSS bootstrap |
| `ctrl.tdv.org` | `https://:1280` | Fronts the Ziti controller with the real `*.tdv.org` cert |
| `*.tdv.org` | `http://:8007` | Wildcard → access-proxy (default reverse-proxy path) |

> **DNS / hosts requirement:** `*.tdv.org` is **private LAN only**. Any machine
> using this stack (incl. the browser) must map these names to `<SERVER_IP>`
> in its hosts file:
> ```
> <SERVER_IP>  openidx.tdv.org netgraph.tdv.org browzer.tdv.org ctrl.tdv.org
> ```

---

## 4. How OpenIDX and Ziti are wired together

### 4.1 The access-service is the integration point

`internal/access/` is where OpenIDX speaks Ziti. The key pieces:

| File | Purpose |
|------|---------|
| `ziti.go` | **`ZitiManager`** — wraps the Go SDK `ziti.Context` (loaded from `access-proxy.json`), hosts services via SDK `Listen`, and calls the controller's REST management API. `NewZitiManagerWithConn()` allows runtime reconnect. |
| `ziti_provider.go` | **`ZitiProvider`** — a lock-free `atomic.Pointer` slot so the manager can be swapped at runtime (admin connect/disconnect) without a restart and without data races. |
| `ziti_settings.go` / `ziti_settings_handlers.go` | Admin-panel-managed controller connection (URL, admin creds **AES-256-GCM encrypted at rest**, enable flag). Connect/disconnect with no restart. |
| `ziti_user_sync.go` | Syncs OpenIDX **users → Ziti identities** (see §4.3). |
| `ziti_browzer.go` | `BootstrapBrowZer()` — provisions the BrowZer control objects (see §4.4). |
| `browzer_targets.go` | Generates the bootstrapper `config.json` (vhost→service map) and the `browzer-router.conf` nginx config. |
| `feature_manager.go` / `feature_handlers.go` | The **per-route feature toggle** engine (ziti / browzer / guacamole) — see §4.2. |
| `ziti_reconciler.go` | **Desired-state reconciler** (DB = source of truth; converges Ziti). **Default ON**; `ZITI_RECONCILER=false` reverts to the legacy imperative path. Per-route `hosting_mode` (`identity`\|`direct`). |
| `ziti_fabric.go`, `ziti_handlers.go`, `ziti_*_handlers.go` | Health monitoring + CRUD endpoints for services, identities, policies, terminators, sessions. |

On startup the access-service: loads `access-proxy.json` → initializes the SDK
context → `BootstrapBrowZer` → hosts all enabled services (binds terminators) →
starts the health, certificate, and user-sync monitors.

### 4.2 Feature toggles — what "enable Ziti / BrowZer on a route" does

A **proxy route** (e.g. `netgraph.tdv.org` → `<SERVER_IP>:8088`) is the unit
of publishing. Each route has independent features, stored in the
`service_features` table and orchestrated by `FeatureManager`:

- **Enable `ziti`** → creates a Ziti **service** for the route, grants the
  bind/dial **policies**, and **hosts** it (the access-proxy binds a terminator
  that forwards to the upstream). Sets `proxy_routes.ziti_enabled = true`.
- **Enable `browzer`** (requires ziti) → marks the service `#browzer-enabled`,
  sets `hosting_mode`, and regenerates the BrowZer target + router config so the
  bootstrapper will demux that vhost. Sets `proxy_routes.browzer_enabled = true`.
- **Enable `guacamole`** (SSH/RDP/VNC routes) → clientless remote-desktop via
  Apache Guacamole.

Endpoints: `POST /api/v1/access/services/:id/features/{ziti|browzer|guacamole}/{enable|disable}`.

### 4.3 User → Ziti identity sync (`ziti_user_sync.go`)

A background poller (`StartUserSyncPoller`) keeps every OpenIDX user mirrored as
a Ziti identity (1:1, keyed by user id):

- **`externalId` = the user's UUID** — this is the OIDC `sub` claim BrowZer maps
  the browser's JWT to, so the overlay knows *which identity* the browser is.
- **`#browzer-users`** role attribute + group attributes → drive the dial policies.
- **auth-policy** — external-JWT (BrowZer) when enabled.
- Last group sync tracked in `ziti_identities.group_attrs_synced_at` (migration v46).

This is what lets a user log in to OpenIDX (OIDC) and have the *same identity*
authorize their overlay access — no separate Ziti enrollment step for BrowZer.

### 4.4 BrowZer bootstrap (`ziti_browzer.go`)

`BootstrapBrowZer()` provisions (idempotently) the control-plane objects that
make clientless browser access trust OpenIDX as the IdP:

1. **External JWT Signer** — trusts OpenIDX's OIDC issuer + JWKS (`sub` = user UUID).
2. **Auth Policy** — allows that external JWT as primary auth.
3. **Dial Policy** — `#browzer-users` may dial `#browzer-enabled` services.
4. **Edge-Router Policy** — `#browzer-users` may use the routers.

Config persisted in the `ziti_browzer_config` table (migration v45).

---

## 5. How a user reaches a service (the three data paths)

### Path A — Plain reverse proxy (no Ziti)
`Browser → nginx (TLS) → access-service :8007 → upstream app`.
Auth enforced by OpenIDX (OIDC). The app is reachable on the LAN through nginx.
This is the `*.tdv.org → :8007` wildcard path.

### Path B — Clientless via BrowZer (this box's published `netgraph.tdv.org`)
```
Browser ──TLS──► nginx (netgraph.tdv.org:443)
        ──────► bootstrapper :8445   (injects ziti-browzer-runtime JS, bounces to OIDC login)
Browser ──WSS──► edge router :3023   (the injected runtime now speaks Ziti)
        ──────► overlay ──► access-proxy terminator ──► browzer-router :8094 (vhost demux)
        ──────► target app <SERVER_IP>:8088
```
**No client install.** The browser authenticates to OpenIDX (OIDC), gets a JWT,
and the BrowZer runtime uses it as the overlay identity (matched via `externalId`).

### Path C — Native overlay client (optional, not deployed)
Install **Ziti Desktop Edge** / `ziti-edge-tunnel` on the endpoint, enroll a
device identity from the controller, and the OS tunnels traffic to the Ziti
service directly — works for any TCP app, not just browsers.

---

## 6. How to use it — operator workflow

### 6.1 Open the admin console
Browse to **`https://openidx.tdv.org`** (after the hosts-file entry), log in.

### 6.2 Connect OpenIDX to the Ziti controller (one-time, runtime, no restart)
**Ziti Network → Connection** tab: set controller URL (`https://ctrl.tdv.org:443`
or the internal `https://ziti-controller.localtest.me:1280`), admin user/password,
→ **Test**, then **Save & Connect**. Status badge turns *Connected*.
(On this box it's also pre-wired via env in `/tmp/run-access.sh`.)

### 6.3 Publish a route behind Ziti / BrowZer — one click
**Proxy Routes** page → each HTTP route row has two switches in its action bar:

- **OpenZiti** — flip on to put the route on the overlay (auto-creates the
  service, policies, and hosting).
- **BrowZer** — flip on (enabled once OpenZiti is on) for clientless browser
  access.

> These switches were added in PR #195 (`RouteFeatureToggles`). The same controls
> also live in the route's expandable **Features** panel (with health badges and
> a config dialog), and per-service under **Ziti Network → Remote Access**.

### 6.4 Reach the published app
From a machine with the hosts entries, browse to the app's hostname
(`https://netgraph.tdv.org`) → OpenIDX login → the app loads over the overlay.

### 6.5 Teardown (documented)
`POST /api/v1/access/ziti/disconnect` → `podman rm -f oidx-browzer oidx-browzer-router
oidx-ziti-router oidx-ziti-controller` → remove `ZITI_*`/`BROWZER_*` from
`run-access.sh` → revert the nginx `netgraph.tdv.org` block to the access-proxy.

---

## 7. Data model (Ziti-relevant tables & migrations)

| Table | Key columns | Added in |
|-------|------------|----------|
| `proxy_routes` | `ziti_enabled`, `ziti_service_name`, `browzer_enabled`, `hosting_mode`, `guacamole_connection_id` | v40 (+ `browzer_enabled`), v47 (`hosting_mode`) |
| `service_features` | `route_id`, `feature_name`, `enabled`, `config`, `resource_ids`, `status` (UNIQUE route+feature) | v40 |
| `ziti_services` | `ziti_id`, `name`, `protocol`, `host`, `port`, `route_id` | (access schema) |
| `ziti_identities` | `ziti_id`, `user_id`, `externalId`, `attributes`, `group_attrs_synced_at` | v46 (sync timestamp) |
| `ziti_browzer_config` | `external_jwt_signer_id`, `auth_policy_id`, `dial_policy_id`, `oidc_issuer`, `oidc_client_id` | v45 |
| `ziti_config_types` / `ziti_config_data` | management-API resource cache | v42 |
| `enrolled_agents` | `ziti_identity_id`, posture results, enrollment tokens | v43 |

`hosting_mode`: `identity` = access-proxy hosts the terminator and injects
identity headers (default); `direct` = edge router hosts via `host.v1` (used for
BrowZer routes; this is the path the reconciler's Phase 2 targets).

---

## 8. Key environment variables (`/tmp/run-access.sh`)

```sh
ZITI_ENABLED=true
ZITI_CTRL_URL=https://ziti-controller.localtest.me:1280
ZITI_ADMIN_USER=admin
ZITI_ADMIN_PASSWORD=***            # admin creds (also storable encrypted in DB)
ZITI_IDENTITY_DIR=/tmp/oidx-ziti/identity   # holds access-proxy.json (the SDK identity)
ZITI_INSECURE_SKIP_VERIFY=true     # DEV ONLY — skips controller cert verification
BROWZER_ENABLED=true
BROWZER_CLIENT_ID=browzer-client
BROWZER_TARGETS_PATH=/tmp/oidx-ziti/browzer-config/config.json
BROWZER_ROUTER_CONFIG_PATH=/tmp/oidx-ziti/browzer-config/browzer-router.conf
BROWZER_ROUTER_HOST=127.0.0.1
BROWZER_ROUTER_PORT=8094
```

> `ZITI_RECONCILER` (default ON) gates the desired-state reconciler. Set it to
> `false` to fall back to the legacy imperative hosting path on startup.

---

## 9. Known limitations & gotchas (this deployment)

- **BrowZer WSS last-mile is not fully proven end-to-end.** TLS-ingress dials to
  the overlay work; the *browser's* WSS path (`:3023 → router → access-proxy
  terminator`) has faulted with `no destination for circuit` in testing. The
  page loads and bootstraps, but content rendering over WSS may hang. This is
  the open item the reconciler's Phase 2 (router `host.v1` per-app hosting) is
  meant to resolve. Native (tunneler/TLS) access is unaffected.
- **SDK ↔ controller version compatibility matters.** `sdk-golang` must be
  protocol-compatible with the controller image (a v1.3 SDK vs v1.6 controller
  bound terminators but didn't service dials). Currently `sdk-golang v1.7.0` ↔
  controller `v1.6.12`. Re-check if you bump the container image.
- **nginx config is a bind-mounted single file.** Editing
  `/tmp/oidx-tls/nginx.conf` with a tool that replaces the inode requires a
  `podman restart oidx-nginx` (not just `nginx -s reload`) for the container to
  see the change.
- **`browzer-router-zt` bind race on cold start.** The first start after the
  service is (re)created can log "identity does not have permission to bind …";
  the access-service's "Waiting for Ziti SDK to discover …" step resolves it on
  the next pass once the service pre-exists.
- **`ZITI_INSECURE_SKIP_VERIFY=true` is dev-only.** Production must use a
  controller cert the access-service trusts.

---

## 10. Glossary

- **Controller** — the Ziti brain: issues identities/certs, stores policy.
- **Edge router** — the data mover; endpoints/SDK connect to it (TLS `:3022`, WSS `:3023`).
- **Identity** — an enrolled principal on the overlay (a user, a device, or the access-proxy).
- **Service** — a named overlay endpoint (e.g. `openidx-Netgraph`).
- **Terminator** — the registered "this identity hosts that service here" record;
  the host side of a service.
- **Bind / Dial policy** — who may *host* (bind) vs *consume* (dial) a service.
- **host.v1 config** — tells a router how to forward a hosted service to a real address.
- **BrowZer** — clientless browser access: injects a JS Ziti runtime, no install.
- **access-proxy** — OpenIDX's own Ziti identity (the embedded SDK), the hosting side.

---

## 11. Where to look in the code

```
cmd/access-service/main.go        # boots the proxy + Ziti orchestration
internal/access/
  ziti.go                         # ZitiManager — the embedded SDK "client"/host
  ziti_provider.go                # runtime-swappable manager (atomic pointer)
  ziti_settings*.go               # admin-managed controller connection
  ziti_user_sync.go               # users -> Ziti identities (externalId, browzer auth)
  ziti_browzer.go                 # BrowZer control-plane bootstrap
  browzer_targets.go              # bootstrapper config.json + router nginx config
  feature_manager.go / feature_handlers.go   # per-route ziti/browzer/guacamole toggles
  ziti_reconciler.go              # desired-state reconciler (flag-gated)
web/admin-console/src/
  pages/proxy-routes.tsx          # routes list + one-click toggles
  components/RouteFeatureToggles.tsx          # the inline OpenZiti/BrowZer switches
  components/ServiceFeaturePanel.tsx          # expandable feature panel
  pages/ziti-network.tsx          # connection / fabric / services / identities / remote-access
internal/migrations/sql_v4{0,2,3,5,6,7}.go    # ziti/browzer schema
```

---

## 12. Dark services + native client

"Dark" means the target app has **zero inbound exposure** — it is not reachable
from the LAN/Internet at all, only over the OpenZiti overlay. This is the
strongest posture and it's fully supported.

### 12.1 Making a service dark (worked example: netgraph)

netgraph is its own compose stack (`/home/cmit/infra`, project `infra_team`).
The steps that made it dark on this box:

1. **Bind the app to host loopback only** — in `/home/cmit/infra/compose.yaml`,
   change the port from `"8088:8088"` (all interfaces) to `"127.0.0.1:8088:8088"`,
   then `podman-compose -p infra_team ... up -d --force-recreate api`. Now the LAN
   gets connection-refused on `<SERVER_IP>:8088`; only the host can reach it.
2. **Point the Ziti service target at loopback** — set the route's `to_url` to
   `http://127.0.0.1:8088`. The native access-proxy (a host process) hosts
   `openidx-Netgraph` and dials `127.0.0.1:8088`, so the dark app is reachable
   over the overlay.

**Verify dark:** `curl http://<SERVER_IP>:8088/` → connection refused (000);
`curl http://127.0.0.1:8088/` → responds. The app is now overlay-only.

### 12.2 The rootless-topology wrinkle (why the BrowZer router needs an alias)

On this box the two overlay-hosting components have **different views of "the
host"**:

- The **native access-proxy** runs as a host process → it reaches the dark app at
  `127.0.0.1:8088`.
- `oidx-browzer-router` runs in a **rootless slirp4netns** container → its
  `127.0.0.1` is the *container's* loopback, not the host's. It cannot reach a
  host-loopback service unless started with `--network
  slirp4netns:allow_host_loopback=true`, which exposes the host loopback at
  `10.0.2.2`.

Both consumers derive their upstream from the single route `to_url`, so a new,
portable knob bridges the gap:

- **`BROWZER_HOST_LOOPBACK_ALIAS`** (env, read in `browzer_targets.go`
  `browzerUpstream()`): when set, any `to_url` pointing at `127.0.0.1`/`localhost`
  is rewritten **for the BrowZer router config only** to use this alias. On this
  box it is `10.0.2.2`. Unset (the default, e.g. docker-compose where the router
  shares a bridge with the app) → no rewrite, behavior unchanged.
- `oidx-browzer-router` is run with `allow_host_loopback=true` so `10.0.2.2:8088`
  forwards to the host's dark netgraph.

Result: the native path uses `127.0.0.1:8088`, the BrowZer router uses
`10.0.2.2:8088`, both reach the same dark app. (In a Kubernetes/bridge
deployment you'd instead put the router and app on one network and skip the
alias entirely.)

### 12.3 Native client (Ziti Desktop Edge / ziti-edge-tunnel)

For non-browser apps or a locked-down posture, enroll a native client. OpenIDX
already mints the enrollment token:

1. **Get a token** — Admin console → **Ziti Network → Identities**. Either create
   an identity, or use an existing one (the user→Ziti sync auto-creates one per
   OpenIDX user). Open its menu → **Get Enrollment JWT** → **Download** the `.jwt`
   (or copy it). One-time use.
2. **Install the tunneler** on the endpoint:
   - Linux: `ziti-edge-tunnel` (OpenZiti releases).
   - Windows/macOS: **Ziti Desktop Edge**.
3. **Enroll**: `ziti-edge-tunnel enroll --jwt <downloaded>.jwt --identity me.json`,
   then run the tunneler with that identity.
4. **Reach the dark service** — the tunneler intercepts traffic to the Ziti
   service (e.g. `openidx-Netgraph`) and carries it over the overlay to the
   access-proxy → `127.0.0.1:8088`. No host port, no browser, no BrowZer
   bootstrapper involved.

The native client is the **maximally-dark** option: only the edge router's
listener needs to be reachable, and only by enrolled endpoints.

### 12.4 BrowZer router config delivery (dir-mount, not file-mount)

The access-service regenerates `browzer-router.conf` with an **atomic write**
(temp file + rename), so every regeneration produces a **new inode**. The BrowZer
router must therefore consume the config the way docker-compose does — **dir-mount**
the shared config directory and run `browzer-router-entrypoint.sh`, which copies
the file into nginx and polls + `nginx -s reload`s on change:

```sh
podman run -d --name oidx-browzer-router \
  --network slirp4netns:allow_host_loopback=true --restart unless-stopped \
  -p 127.0.0.1:8094:80 \
  -v /tmp/oidx-ziti/browzer-config:/shared-config:ro \
  -v <repo>/deployments/docker/browzer-router-entrypoint.sh:/browzer-router-entrypoint.sh:ro \
  --entrypoint /bin/sh nginx:alpine /browzer-router-entrypoint.sh
```

**Do NOT bind-mount the config FILE directly** (e.g. as `/etc/nginx/conf.d/default.conf`):
the atomic rename gives the file a new inode that a *file* bind-mount never sees, so
a regenerated config (a newly enabled/toggled BrowZer route) silently never reaches
the running router. With the dir-mount + entrypoint, a route toggle propagates within
the poll interval (~5 s) and nginx reloads automatically — no container recreate.
(Verified: an atomic-rename write to the shared config is reflected in the container
and reloaded within ~5 s.)

### 12.5 Caveats

- The **BrowZer browser WSS last-mile now works** end-to-end — verified in a real
  headless browser: the full netgraph SPA (HTML + JS + cytoscape + a 1.5 MB graph
  payload) renders clientlessly over the overlay against the dark app. What made the
  published site render was marking the primary app the router `default_server`
  (§12.4), because the WASM runtime's overlay request Host does not reliably match
  the vhost name.
- netgraph serves its UI at `/ui/` and 404s at `/`, and the OIDC `redirect_uri`
  returns to `/`; a per-route landing path (or a `/ → /ui/` redirect at the router)
  would make browsing the bare host land on the app.
- `allow_host_loopback=true` widens the slirp container's reach to the host
  loopback; acceptable here (the router only proxies overlay-delivered traffic)
  but note it for hardening.

---

*Generated from the live deployment and source on 2026-06-23. Identity files,
ports, and hostnames are specific to this box (`<SERVER_IP>`).*

---

# Dark platform cutover (staged, verify-before-cutover)

> Spec: `docs/superpowers/specs/2026-07-17-dark-platform-ziti-first-design.md`.
> Plan: `docs/superpowers/plans/2026-07-17-dark-platform-ziti-first.md`.
>
> **Everything below is opt-in.** With all flags at their defaults the platform
> behaves exactly as it does today (full public route set, all-interfaces bind).
> Going dark is an explicit, staged **operator** action, gated at every step by
> `make dark-drill` and `scripts/dark-mode.sh --verify`. Never drop a public
> route until `--verify` proves the overlay path works.

## Tier model

| Tier | Surfaces | Ziti dial attribute | Public in `DARK_MODE=off` | Public after cutover |
|---|---|---|---|---|
| **0 (bootstrap)** | `enroll`, `oauth`, `.well-known`/jwks | (public, never darked) | yes | **yes (always)** |
| **1 (self-service + shell)** | identity self-service API, console SPA | `#enrolled-users` | yes | dark in `tier1` |
| **2 (management + data)** | admin-api, governance, audit, provisioning, scim, access | `#device-trusted` | yes | dark in `tier2` and `tier1` |

Tier 0 is **always** seeded. Darking it bricks enrollment and login and makes
the platform unrecoverable without break-glass. The invariant test
`TestNoTier0SurfaceIsDarked` and the seeder both enforce this.

## The two enforcement planes

Going dark requires **both** planes to move together, or you get a false-secure
state (edge route dropped but backend still bound to a routable interface, or
vice versa):

1. **Edge (what the internet can reach):** `DARK_MODE={off|tier2|tier1}` selects
   which APISIX routes get seeded — `deployments/apisix-edge/seed-edge-routes.sh`.
2. **Backend bind (what a routable interface can reach):**
   `SERVICE_BIND_ADDR=127.0.0.1` on each darked service makes it loopback-only,
   so the edge router (and only it) can host it onto the overlay. Combined with
   `DARK_MODE_TIER1`/`DARK_MODE_TIER2=true` on the access-service, the reconciler
   models each surface as a tier'd dark Ziti service (`defaultDarkServices()`).

## Runbook — do these IN ORDER. Do not skip a verify.

### 1. Enroll the admin fleet FIRST

Before darking anything, every operator who needs the management plane must be
enrolled and (for Tier 2) device-trusted, or you will lock yourself out.

- Enroll each admin via native tunneler or BrowZer. The public enroll door is
  `POST /api/v1/access/enroll` (Tier 0, rate-limited, audited) — it exchanges a
  valid session/token for a Ziti enrollment JWT.
- Confirm device-trust: `GET /api/v1/access/my-devices` must show the device as
  trusted (this is what grants `#device-trusted` → Tier-2 dial).
- Register the console dark app: `bash scripts/register-console-dark-app.sh`
  (idempotent; the reconciler converges `openidx-console` + its BrowZer route).

### 2. Deploy Phases 1-5 with all flags OFF

Ship the code. `DARK_MODE=off`, no `SERVICE_BIND_ADDR` override, no
`DARK_MODE_TIER*`. **No behavior change** — this is a safe, reversible deploy.
Confirm the fleet is enrolled and healthy on the still-public platform.

### 3. Drill in staging (offline + live)

```bash
make dark-drill                 # offline: route-set + tier invariants + self-test
```
Then a **live staging drill**, Tier 2 first:
```bash
# On admin/governance/audit/provisioning/scim/access services:
export SERVICE_BIND_ADDR=127.0.0.1
export DARK_MODE_TIER2=true            # access-service: model surfaces as dark
# Re-seed the edge to drop the Tier-2 routes:
DARK_MODE=tier2 bash deployments/apisix-edge/seed-edge-routes.sh
# Prove the invariant against the LIVE staging deployment:
scripts/dark-mode.sh --verify \
  --public-url  https://<staging-host>/api/v1/admin/health \
  --overlay-url https://<overlay-path-to-admin>/health
```
`--verify` must prove all three: **public refused** + **overlay reachable** +
**tier gate holds** (a Tier-1-only identity is refused the Tier-2 surface). If
any check fails, STOP — do not proceed to prod.

### 4. Cut over prod, Tier 2 then Tier 1

Only after staging `--verify` is green: repeat step 3 against prod for `tier2`.
Once Tier 2 is stable and verified, repeat for `tier1` (adds self-service + SPA
to the dark set; only the Tier-0 bootstrap stays public).

### 5. Break-glass (rehearse this in staging as part of the drill)

If a cutover locks out operators or the overlay is impaired:

```bash
scripts/dark-mode.sh --undark          # re-seeds DARK_MODE=off (public routes back)
```
`--undark` restores the full public edge route set and prints the
`SERVICE_BIND_ADDR` revert (unset it and restart the affected services to
re-bind all interfaces). Keep a **sealed, out-of-band enroll token** so a fresh
admin device can enroll even if the console is unreachable. The undark path is
part of `make dark-drill` — rehearse it so the muscle memory exists before you
need it at 3am.

## Invariants (enforced in CI via `make dark-drill`)

- Tier-2 surfaces carry `#device-trusted`, never merely `#enrolled-users`
  (`TestTier2ServicesRequireDeviceTrust`).
- No Tier-0 surface is ever a dark service (`TestNoTier0SurfaceIsDarked`).
- Every dark upstream is loopback (`TestDarkServiceUpstreamsAreLoopback`).
- `scripts/dark-mode.sh --self-test` proves public-refused + overlay-200 +
  tier-gate on every run, so a cutover can't be green-lit on a false positive.

## Live cutover result (this deployment, Tier 1+2 dark)

Verified on this box: 5 services loopback-bound (dark on the external host IP,
still served via the local edge + overlay):

| Service | Port | External host-IP | Via edge |
|---|---|---|---|
| identity | 8001 | refused (dark) | reachable |
| governance | 8002 | refused (dark) | reachable |
| provisioning | 8003 | refused (dark) | reachable |
| audit | 8004 | refused (dark) | reachable |
| admin-api | 8005 | refused (dark) | reachable |
| oauth | 8006 | public (Tier 0) | reachable |
| access | 8007 | public (Tier 0) | reachable |

**Key finding — darking `identity` does NOT break login.** The oauth service
holds `identityService *identity.Service` as an **in-process embedded library**
(`internal/oauth/service.go`), and `handleLogin` calls
`s.identityService.AuthenticateUser(...)` directly against the DB — not over
HTTP to `:8001`. So loopback-binding identity's network port has zero effect on
credential verification. Proven live with identity dark: full auth-code+PKCE
login issued a real `access_token` (873 chars) + `id_token`.

Cutover tooling: `scripts/service-dark-bind.sh` (per-service loopback bind via a
systemd drop-in; drill by default, `KEEP=1` persists) and
`scripts/service-undark.sh` (break-glass revert). Requires binaries that honor
`SERVICE_BIND_ADDR` (Phase 1); the pre-Phase-1 binaries silently ignored it.
