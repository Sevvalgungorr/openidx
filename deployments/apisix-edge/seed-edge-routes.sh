#!/usr/bin/env bash
# Seeds the STATIC OpenIDX edge routes into the fresh APISIX (oidx-apisix, :9280,
# etcd prefix /apisix-oidx). Idempotent (PUT = upsert). Re-run only if the etcd
# store is reset — these routes normally persist in etcd across reboots.
#
# NOTE: the per-app BrowZer routes (browzer-<app>-tdv-org[-oidc]) are NOT here —
# the access-service's APISIX reconciler manages those off proxy_routes.
set -euo pipefail
ADMIN=${APISIX_ADMIN_URL:-http://127.0.0.1:9280}
KEY=${APISIX_ADMIN_KEY:-CHANGE_ME_ADMIN_KEY}
CERT=${TDV_CERT:-/home/cmit/oidx-runtime/oidx-tls/tdv-fullchain.pem}
KEYF=${TDV_KEY:-/home/cmit/oidx-runtime/oidx-tls/tdv-key.pem}

# Management API allow-list -- SITE SPECIFIC, override per deployment.
# When the edge is published through a NAT this MUST exclude the LAN gateway
# address: a router doing source NAT (masquerade) rewrites every external
# request to its own LAN IP, so if that IP falls inside the allow-list the
# restriction silently becomes a no-op and the audit trail (actor_ip) collapses
# to a single address. Only destination NAT (port forwarding) should be used.
# See docs/ziti-nat-firewall-requirements.md.
MGMT_ALLOW_CIDRS=${MGMT_ALLOW_CIDRS:-'"127.0.0.0/8","10.0.0.0/8","172.16.0.0/12","192.168.0.0/16"'}

# DARK_MODE controls how much of the platform is reachable at the public edge
# (see docs/superpowers/specs/2026-07-17-dark-platform-ziti-first-design.md):
#   off   (default) — today's full public route set.
#   tier2 — drop the management routes (admin, governance, audit, provisioning,
#           scim, access-except-enroll); Tier-0 (enroll, oauth-auth subset,
#           well-known, identity self-service, SPA) stays.
#   tier1 — additionally drop self-service + SPA; only the Tier-0 bootstrap
#           (enroll, oauth-auth subset, well-known) stays public.
# Tier 0 is ALWAYS seeded — darking it would brick bootstrap.
DARK_MODE=${DARK_MODE:-off}
# DRY_RUN=1 prints the route names that WOULD be seeded (for tests) without
# touching APISIX.
DRY_RUN=${DRY_RUN:-0}

_put_real() { curl -fsS -o /dev/null -w "  route %-26s -> %{http_code}\n" "$1" \
        -X PUT -H "X-API-KEY: $KEY" "$ADMIN/apisix/admin/routes/$1" -d "$2"; }
put() { if [ "$DRY_RUN" = "1" ]; then echo "put $1"; else _put_real "$1" "$2"; fi; }

# --- TLS (wildcard *.tdv.org) ---
if [ "$DRY_RUN" != "1" ]; then
python3 - "$ADMIN" "$KEY" "$CERT" "$KEYF" <<'PY'
import json,sys,urllib.request
admin,key,certf,keyf=sys.argv[1:5]
body=json.dumps({"cert":open(certf).read(),"key":open(keyf).read(),"snis":["*.tdv.org","tdv.org"]}).encode()
r=urllib.request.Request(f"{admin}/apisix/admin/ssls/tdv-wildcard",data=body,method="PUT",
  headers={"X-API-KEY":key,"Content-Type":"application/json"})
print("  ssl  tdv-wildcard            ->",urllib.request.urlopen(r).status)
PY
fi

H='"hosts":["openidx.tdv.org"]'

# ===========================================================================
# TIER 0 — always public (the bootstrap gate; darking it bricks enrollment).
# ===========================================================================
# The enroll door: the ONLY /api/v1/access/* path public in dark mode. Higher
# priority than the (off-mode) /api/v1/access/* catch-all so it always wins.
put openidx-api-enroll       "{$H,\"uri\":\"/api/v1/access/enroll\",\"priority\":45,\"upstream\":{\"type\":\"roundrobin\",\"nodes\":{\"127.0.0.1:8007\":1}}}"
# OAuth login/token/JWKS surface — required to obtain a token / for BrowZer login.
put openidx-oauth            "{$H,\"uri\":\"/oauth/*\",\"priority\":30,\"upstream\":{\"type\":\"roundrobin\",\"nodes\":{\"127.0.0.1:8006\":1}}}"
put openidx-wellknown        "{$H,\"uri\":\"/.well-known/*\",\"priority\":30,\"upstream\":{\"type\":\"roundrobin\",\"nodes\":{\"127.0.0.1:8006\":1}}}"

# ===========================================================================
# TIER 1 — self-service + SPA (public in off/tier2, dark in tier1).
# ===========================================================================
if [ "$DARK_MODE" = "off" ] || [ "$DARK_MODE" = "tier2" ]; then
  put openidx-api-identity     "{$H,\"uri\":\"/api/v1/identity/*\",\"priority\":30,\"upstream\":{\"type\":\"roundrobin\",\"nodes\":{\"127.0.0.1:8001\":1}}}"
  # enable_websocket: this /* catch-all fronts nginx :8443, which serves the
  # Guacamole PAM console at /guacamole/*. Guacamole's session tunnel is a
  # WebSocket; without this APISIX drops the Upgrade and the browser authenticates
  # but the tunnel to guacd never establishes (session won't open).
  put openidx-spa              "{$H,\"uri\":\"/*\",\"priority\":10,\"enable_websocket\":true,\"upstream\":{\"type\":\"roundrobin\",\"scheme\":\"https\",\"pass_host\":\"pass\",\"nodes\":{\"127.0.0.1:8443\":1},\"tls\":{\"verify\":false}}}"
fi

# ===========================================================================
# TIER 2 — management/data planes (public only in off; dark in tier2 + tier1).
# ===========================================================================
if [ "$DARK_MODE" = "off" ]; then
  put openidx-api-governance   "{$H,\"uri\":\"/api/v1/governance/*\",\"priority\":30,\"upstream\":{\"type\":\"roundrobin\",\"nodes\":{\"127.0.0.1:8002\":1}}}"
  put openidx-api-provisioning "{$H,\"uri\":\"/api/v1/provisioning/*\",\"priority\":30,\"upstream\":{\"type\":\"roundrobin\",\"nodes\":{\"127.0.0.1:8003\":1}}}"
  put openidx-api-audit        "{$H,\"uri\":\"/api/v1/audit/*\",\"priority\":30,\"enable_websocket\":true,\"upstream\":{\"type\":\"roundrobin\",\"nodes\":{\"127.0.0.1:8004\":1}}}"
  put openidx-api-access       "{$H,\"uri\":\"/api/v1/access/*\",\"priority\":30,\"enable_websocket\":true,\"upstream\":{\"type\":\"roundrobin\",\"nodes\":{\"127.0.0.1:8007\":1}}}"
  # /api/v1/oauth/* (OAuth client management) is owned by the oauth-service :8006,
  # NOT admin-api — it must out-prioritize the /api/* admin catch-all below.
  put openidx-api-oauth        "{$H,\"uri\":\"/api/v1/oauth/*\",\"priority\":30,\"upstream\":{\"type\":\"roundrobin\",\"nodes\":{\"127.0.0.1:8006\":1}}}"
  # /api/v1/saml/* (SAML SP management) is also oauth-service :8006.
  put openidx-api-saml         "{$H,\"uri\":\"/api/v1/saml/*\",\"priority\":30,\"upstream\":{\"type\":\"roundrobin\",\"nodes\":{\"127.0.0.1:8006\":1}}}"
  put openidx-api-admin        "{$H,\"uri\":\"/api/*\",\"priority\":20,\"upstream\":{\"type\":\"roundrobin\",\"nodes\":{\"127.0.0.1:8005\":1}}}"
  put openidx-scim             "{$H,\"uri\":\"/scim/*\",\"priority\":30,\"upstream\":{\"type\":\"roundrobin\",\"nodes\":{\"127.0.0.1:8003\":1}}}"
fi

# --- infra hosts ---
put browzer-host '{"hosts":["browzer.tdv.org"],"uri":"/*","priority":20,"enable_websocket":true,"upstream":{"type":"roundrobin","scheme":"https","pass_host":"rewrite","upstream_host":"browzer.tdv.org","nodes":{"127.0.0.1:8445":1},"tls":{"verify":false},"timeout":{"connect":60,"send":86400,"read":86400}}}'
put ctrl-host    '{"hosts":["ctrl.tdv.org"],"uri":"/*","priority":20,"enable_websocket":true,"upstream":{"type":"roundrobin","scheme":"https","pass_host":"pass","nodes":{"127.0.0.1:1280":1},"tls":{"verify":false},"timeout":{"connect":60,"send":86400,"read":86400}}}'

# Ziti management/console/fabric API: internal networks only.
#
# The controller must be reachable from the internet for clients to enrol and
# open sessions — that is the whole point of an overlay. The MANAGEMENT plane is
# a different matter: creating identities, editing policies and enrolling
# routers all live under /edge/management/v1, the ZAC admin console under /zac
# + /ziti-console, and fabric ops under /fabric/v1. Each demands credentials
# (401 without them), but an authenticated endpoint exposed to the internet is
# still a credential-guessing surface on the control plane of the whole network.
#
# DEFENCE IN DEPTH — two independent layers, because APISIX alone is bypassable:
#   1. Controller config.yml splits the single :1280 web listener into
#      `client-public` (0.0.0.0:1280 — edge-client + edge-oidc only) and
#      `management-local` (127.0.0.1:1281 — edge-management + fabric + zac).
#      So even if someone port-forwards the public edge STRAIGHT to :1280
#      (bypassing APISIX entirely, as observed 2026-08-17), the management APIs
#      simply are not served there — measured: DIRECT :1280 /edge/management ->
#      404, DIRECT :1281 -> 200. See deployments/apisix-edge/ziti-controller/.
#   2. These APISIX routes ip-restrict the management plane on the :443 path and
#      point at the loopback-only :1281 listener.
#
# Higher priority than ctrl-host so they win for these path prefixes; the
# catch-all above is left untouched, so client and enrolment traffic is
# unaffected.
#
# ip-restriction matches on the real TCP source (remote_addr), not on
# X-Forwarded-For, so it cannot be bypassed by forging a header.
put ctrl-mgmt-restricted '{"hosts":["ctrl.tdv.org"],"uri":"/edge/management/v1/*","priority":70,"enable_websocket":true,"plugins":{"ip-restriction":{"whitelist":['"${MGMT_ALLOW_CIDRS}"']}},"upstream":{"type":"roundrobin","scheme":"https","pass_host":"pass","nodes":{"127.0.0.1:1281":1},"tls":{"verify":false},"timeout":{"connect":60,"send":86400,"read":86400}}}'
put ctrl-zac-restricted '{"hosts":["ctrl.tdv.org"],"uris":["/zac","/zac/*","/ziti-console","/ziti-console/*"],"priority":70,"enable_websocket":true,"plugins":{"ip-restriction":{"whitelist":['"${MGMT_ALLOW_CIDRS}"']}},"upstream":{"type":"roundrobin","scheme":"https","pass_host":"pass","nodes":{"127.0.0.1:1281":1},"tls":{"verify":false},"timeout":{"connect":60,"send":86400,"read":86400}}}'
put ctrl-fabric-restricted '{"hosts":["ctrl.tdv.org"],"uri":"/fabric/v1/*","priority":70,"enable_websocket":true,"plugins":{"ip-restriction":{"whitelist":['"${MGMT_ALLOW_CIDRS}"']}},"upstream":{"type":"roundrobin","scheme":"https","pass_host":"pass","nodes":{"127.0.0.1:1281":1},"tls":{"verify":false},"timeout":{"connect":60,"send":86400,"read":86400}}}'

# --- *.tdv.org one-click apps -> access-proxy (auth enforced by the proxy itself) ---
put access-proxy-wildcard '{"hosts":["*.tdv.org"],"uri":"/*","priority":-50,"enable_websocket":true,"upstream":{"type":"roundrobin","scheme":"http","pass_host":"pass","nodes":{"127.0.0.1:8007":1},"timeout":{"connect":60,"send":86400,"read":86400}}}'

echo "Edge routes seeded."
