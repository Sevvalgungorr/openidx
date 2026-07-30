# Ziti High Availability — Simple, Redundant, Always-On

This guide makes the OpenZiti overlay a **fully redundant, continuously
available** network layer — on-prem (Docker Compose) or cloud (Kubernetes/
Helm) — without adding operational complexity. It complements
[ZITI_EASY_DEPLOYMENT.md](ZITI_EASY_DEPLOYMENT.md) (single-node quickstart)
and [OPENIDX_ZITI_ARCHITECTURE.md](OPENIDX_ZITI_ARCHITECTURE.md) (full
architecture).

## What fails, and what that costs

Understanding the two planes tells you where redundancy pays off:

| Plane | Component | If it dies… |
|---|---|---|
| **Data** | Edge router(s) | With ONE router, every overlay session drops and nothing can dial until it's back. With TWO+, the fabric re-paths around the dead router — users don't notice. |
| **Control** | Controller | Established sessions **keep flowing** (routers forward autonomously), but new dials/enrollments and OpenIDX management (identity sync, kill-switch severs, PAM Ziti provisioning) stall until it returns. |

So the priority order is: **(1) redundant routers, (2) auto-restarting
controller, (3) controller quorum** — in that order of effort and payoff.

## On-prem: Docker Compose

### One command, redundant data plane

```bash
make ziti-quickstart HA=1
```

This brings up the controller plus **two edge routers**
(`openidx-router`, `openidx-router-2`, overlay file
`deployments/docker/docker-compose.ziti-ha.yml`). Because the bootstrap
edge-router policies are role-based on `#all`, the second router serves every
service with **zero policy changes**. Kill either router and existing sessions
re-path; patch/restart them one at a time for zero-downtime maintenance.

Both routers (and the controller) carry `ziti agent stats` healthchecks, so
`docker ps` shows real health, not just "Up".

### Production compose posture

`docker-compose.prod.yml` now sets `restart: unless-stopped` on every
long-running Ziti-plane service (controller, routers, BrowZer, Guacamole
brokers) — a crashed container comes back without operator action. Only the
one-shot init jobs (`ziti-router-init`, `browzer-cert-init`) stay
`restart: "no"`.

### Controller redundancy on-prem

A Raft controller quorum needs stable per-member identity and storage, which
compose does not model well — if you need controller HA on-prem, run the
fabric via the Helm chart on any small k8s (k3s works) and keep the app stack
in compose. For most on-prem installs, `restart: unless-stopped` + the fact
that the data plane survives controller downtime is the right trade.

## Cloud: Kubernetes / Helm

Enable the fabric with a Raft quorum and a redundant data plane:

```yaml
# values-prod.yaml
zitiFabric:
  enabled: true
  controller:
    replicas: 3          # odd number → Raft quorum; survives 1 member loss
  router:
    replicas: 2          # redundant data plane
```

What the chart does automatically at those replica counts:

- **Raft** — `ZITI_CTRL_RAFT_ENABLED=true` when `controller.replicas > 1`;
  each member gets its own PVC (StatefulSet `volumeClaimTemplates`).
- **PodDisruptionBudgets** — controller `maxUnavailable: 1` (a node drain can
  never break the quorum majority), router `minAvailable: 1`.
- **Anti-affinity** — soft node anti-affinity spreads quorum members and
  routers across nodes.
- **Probes** — readiness + liveness (`ziti agent stats`) on controller and
  router pods, so Kubernetes restarts a wedged process and never routes to a
  not-ready member.
- **Pinned images** — `openziti/{ziti-controller,ziti-router}:1.6.12`, the
  version the embedded `sdk-golang` is verified against (see
  OPENIDX_ZITI_ARCHITECTURE.md §9 on version skew). Never float to `:latest`.

Terraform users: `deployments/terraform/modules/openziti` exposes
`controller_replicas` / `router_replicas` and drives the same chart.

## Management-API failover (the OpenIDX side)

Running a controller cluster only helps if OpenIDX can *use* the surviving
members. `ZITI_CTRL_URLS` (comma-separated, additional members of the same
cluster — same PKI and admin credentials) turns the access-service's
management client into a failover pool:

```bash
ZITI_CTRL_URL=https://openidx-ziti-controller-0.openidx-ziti-controller:1280
ZITI_CTRL_URLS=https://openidx-ziti-controller-1.openidx-ziti-controller:1280,https://openidx-ziti-controller-2.openidx-ziti-controller:1280
```

Behavior (implemented in `internal/access/ziti_endpoints.go`):

- A member that fails (network error, 502/503/504) goes into a **30s
  cooldown**; the next healthy member takes over after a fresh auth
  (zt-session tokens are per controller).
- Selection is **sticky** — no failback churn; a recovered member serves
  again when the active one next fails.
- Single-endpoint installs behave exactly as before — the pool degenerates to
  today's behavior, and errors surface unchanged.
- The state is visible in **Admin Console → Ziti Network → Connection**
  ("HA controller cluster: n/m healthy") and on
  `GET /api/v1/access/ziti/status` (`ha`, `controller_endpoints`).

The SDK data plane needs no such list: an enrolled identity file carries every
controller address and `sdk-golang` fails over on its own.

## IAM ⇄ PAM ⇄ Ziti: how the pillars stay consistent (review)

The three pillars share **one Postgres** — cross-pillar consistency is scoped
SQL, not service-to-service calls (see
[IAM_PAM_ZITI_INTERRELATION.md](IAM_PAM_ZITI_INTERRELATION.md)). The
relationship was reviewed as part of this hardening; what stands, and what
was tightened:

**Stands (no re-implementation needed):**
- **IAM → Ziti**: users/groups mirror to Ziti identities with org-scoped role
  attributes (`ziti_user_sync.go`, 30s poller + reconciler); disabling a user
  deprovisions their identity within ≤30s.
- **PAM ⇄ Ziti**: a PAM entry in `reach_mode='ziti'` gets a per-entry Ziti
  service; the Guacamole broker reaches the target over the overlay and the
  target exposes **no inbound port** (`pam_ziti.go`). Access 360 and the
  kill-switch fuse all three pillars per user.
- **Honesty rule**: nothing is reported severed unless the controller
  confirmed it — kill-switch warnings surface partial failures.

**Tightened in this pass:**
- **Device-trust approval → overlay, ≤30s**: approving a device trust request
  (manual or auto) now marks the user's Ziti identity attributes stale, so
  the `#device-trusted` attribute lands on the next 30s sync tick instead of
  the previous ≤5-minute window — and it no longer depends on the admin using
  the console page that happened to trigger the sync client-side.
- **Device revoke → overlay, immediate**: revoking a device recomputes the
  user's `#device-trusted` attribute in the same request, so dial policies
  keyed on device trust stop matching as soon as the last trusted device is
  gone.
- **Control-plane continuity**: every one of these sync paths rides the
  management-API failover pool above, so a single controller failure no
  longer stalls IAM/PAM enforcement into the overlay.

## Runbook: verifying your redundancy

```bash
# 1. Data plane: kill a router mid-session — traffic must survive
docker stop openidx-ziti-router     # (or delete one router pod)
# expected: overlay sessions re-path via router-2; Admin Console →
# Ziti Network → Overview still shows routers online ≥ 1

# 2. Control plane: kill the active controller member (k8s quorum)
kubectl delete pod openidx-ziti-controller-0
# expected: /api/v1/access/ziti/status flips the failed endpoint to
# healthy:false, another member becomes active, identity sync continues

# 3. Recovery: restart what you killed
# expected: it rejoins (router: re-links; controller: rejoins quorum),
# endpoints return to healthy:true — no manual steps
```
