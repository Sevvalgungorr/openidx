# Easy OpenZiti Deployment & Management

> How to get the OpenZiti fabric behind OpenIDX running with the least effort,
> and how to manage it once it's up. Complements
> [OPENIDX_ZITI_ARCHITECTURE.md](./OPENIDX_ZITI_ARCHITECTURE.md), which explains
> *how* the integration works internally.

---

## TL;DR — one command

```bash
make ziti-quickstart        # controller + ZAC console + edge router
make ziti-quickstart HA=1   # …plus a second router (redundant data plane)
```

> For full redundancy (controller quorum, failover, runbook) see
> [ZITI_HA_DEPLOYMENT.md](./ZITI_HA_DEPLOYMENT.md).

This starts the Ziti controller (with the **bundled ZAC admin console**) and a
self-enrolling WSS-capable edge router from the dev compose stack, waits for
health, and prints the console URL and credentials:

| What | Where |
|---|---|
| ZAC admin console | `https://ziti-controller.localtest.me:11280/zac/` |
| Login | `admin` / `$ZITI_PWD` (from `.env`) |
| Stop (state kept) | `make ziti-down` |

Then start OpenIDX (`make dev`) — the access-service auto-connects to the
controller from env (`ZITI_CTRL_URL`, `ZITI_ADMIN_PASSWORD`) and the admin
console's **Network Setup** page walks through the rest.

---

## The ZAC console is built in — no extra service

The official `openziti/ziti-controller` Docker image **ships the Ziti Admin
Console (ZAC) inside the controller** since console 3.x became a SPA: the image
copies the `openziti/ziti-console-assets` build to `/ziti-console` and the
bootstrap enables it (`ZITI_BOOTSTRAP_CONSOLE=true`), serving it at
`https://<controller>:<port>/zac/`. OpenIDX's compose files enable this
explicitly, so there is **no separate ZAC container, npm build, or Node server
to run**.

OpenIDX surfaces the console everywhere it matters:

- **Ziti Network** and **Network Setup** admin pages show an **"Ziti Console"**
  button (from the `console_url` field of `GET /api/v1/access/ziti/status` and
  `GET /api/v1/access/ziti/setup/status`).
- The URL is derived from the controller URL (`<ZITI_CTRL_URL>/zac/`) and can be
  overridden with `ZITI_CONSOLE_URL` when the browser reaches the controller on
  a mapped host/port (the dev compose maps host `11280` → container `1280`).

Use ZAC for raw fabric surgery (routers, terminators, sessions, low-level
policies); use OpenIDX's own pages for the day-to-day flows (publish a route,
sync users, BrowZer). Day-to-day you should rarely need ZAC — the per-route
**OpenZiti / BrowZer toggles** on Proxy Routes do the service + policy plumbing
automatically.

## Division of labor: what OpenIDX automates for you

You should never need to hand-create Ziti objects for the standard flows:

| Task | Where it's automated |
|---|---|
| Create Ziti service + bind/dial policies for an app | Proxy Routes → **OpenZiti** toggle |
| Publish an app to unmodified browsers (no client) | Proxy Routes → **BrowZer** toggle |
| Mirror users → Ziti identities (OIDC `sub` as externalId) | background user-sync poller |
| External-JWT signer / auth policy trusting OpenIDX as IdP | BrowZer bootstrap (automatic) |
| Router enrollment (compose) | `ziti-router-init` one-shot container |
| Drift repair (services, policies, configs) | reconciler (`ZITI_RECONCILER=true`) |

End users need **no certificate enrollment** for browser apps: BrowZer uses
their OpenIDX OIDC login as the overlay identity (Ziti *external JWT signers*).
Only native tunneler users (Ziti Desktop Edge, `ziti-edge-tunnel`) download a
one-time `.jwt` from **My Devices**. The endpoint agent enrolls its own Ziti
identity automatically during `agent enroll` — no operator step.

## Defaults that keep the fabric healthy

- **Reconciler is on by default** (`ZITI_RECONCILER=false` reverts to the
  legacy imperative path): the DB is the source of truth and a serialized loop
  continuously converges the controller, so crashed bootstrappers, stale
  terminators, and half-applied toggles self-heal instead of drifting.
- **Pinned Ziti images**: compose pins `openziti/ziti-controller` and
  `openziti/ziti-router` to a version verified against the embedded
  sdk-golang (override with `ZITI_VERSION`). SDK↔controller skew has caused
  silent dial failures before — bump the tag and the SDK together.
- **Version-controlled router config**: the dev router runs from
  `deployments/docker/ziti-router/config.yml` (WSS listener, BrowZer alt
  certs, CSR SANs all declared) instead of a config generated in the container
  and patched with sed/awk at startup.

---

## Deployment options, easiest → most control

### 1. Dev / lab: `make ziti-quickstart` (recommended start)

What it does under the hood: `docker compose up -d ziti-controller
ziti-router-init ziti-router` with generated secrets. Everything persists in
named volumes; `make dev-clean` resets.

### 2. Full local stack: `make dev`

The dev compose brings up the whole platform including the Ziti fabric, the
BrowZer bootstrapper, and the access-service pre-wired to the controller.

### 3. Throwaway upstream sandbox (no OpenIDX)

To experiment with Ziti itself, upstream's all-in-one quickstart is the
simplest thing that exists — a single container running `ziti edge quickstart`
(controller + router + console in one process):

```bash
wget https://get.openziti.io/dock/all-in-one/compose.yml
ZITI_PWD=admin docker compose up
# console at https://localhost:1280/zac/
```

The same exists as a bare command (`ziti edge quickstart --home ./ziti-home`)
if you have the `ziti` binary — one process, persistent when `--home` is set.

### 4. Production, single host (compose)

`docker-compose.prod.yml --profile ziti` runs the same controller (+ZAC) and
router hardened variants. Requirements that the config validation enforces:

- unique `ZITI_PWD` (the default `openidx_ziti_admin` is rejected in prod),
- `ZITI_INSECURE_SKIP_VERIFY=false`,
- a stable DNS name for the controller (`ZITI_CTRL_ADVERTISED_ADDRESS`) —
  **certificates embed it; it cannot change later**.

### 5. Production, Kubernetes (Helm)

The OpenIDX chart deliberately does *not* deploy the fabric; use upstream's
charts next to it:

```bash
helm repo add openziti https://openziti.io/helm-charts
helm install ziti-controller openziti/ziti-controller ...   # TLS passthrough required
helm install ziti-router openziti/ziti-router --set-file enrollmentJwt=router1.jwt ...
```

Then point the access-service at it (`ZITI_CTRL_URL`, or the admin console's
**Ziti Network → Connection** form — settings are stored encrypted in the DB
and applied without restarts). Note the controller's TLS ports need
**passthrough** (client-cert auth), not HTTP-level ingress termination.

---

## Management surfaces, quick reference

| Surface | Use for |
|---|---|
| **OpenIDX Network Setup page** | guided checklist: what's up, what's missing, what to install |
| **OpenIDX Proxy Routes toggles** | publishing/unpublishing apps on the overlay |
| **OpenIDX Ziti Network page** | connection settings, services, identities, fabric health, enrollment JWTs |
| **ZAC console** (`…/zac/`) | raw controller administration, debugging terminators/sessions |
| `ziti` CLI (`docker exec openidx-ziti-controller ziti …`) | scripting/automation against the mgmt API |

## Troubleshooting in one place

- Controller logs: `docker logs openidx-ziti-controller`
- Router logs: `docker logs openidx-ziti-router`
- Access-service ↔ controller status: **Ziti Network** header badge, or
  `GET /api/v1/access/ziti/status`
- Full checklist with remediation hints: **Network Setup** page

## Sources / further reading

- [All-in-one quickstart (compose)](https://github.com/openziti/ziti/blob/main/quickstart/docker/all-in-one/README.md)
- [Console deployment guide](https://openziti.io/docs/guides/deployments/docker/console)
- [ziti-console (ZAC) repository](https://github.com/openziti/ziti-console)
- [Kubernetes controller install](https://openziti.io/docs/guides/deployments/kubernetes/kubernetes-controller/)
- [Kubernetes router install](https://openziti.io/docs/guides/deployments/kubernetes/kubernetes-router/)
- [Helm charts](https://github.com/openziti/helm-charts)
- [External JWT signers (clientless auth)](https://openziti.io/docs/learn/core-concepts/security/authentication/external-jwt-signers/)
- [BrowZer introduction](https://blog.openziti.io/introducing-openziti-browzer)
- [BrowZer OIDC configuration](https://openziti.io/docs/guides/external-auth/browzer/)
