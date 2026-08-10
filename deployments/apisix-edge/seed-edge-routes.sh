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
  put openidx-spa              "{$H,\"uri\":\"/*\",\"priority\":10,\"upstream\":{\"type\":\"roundrobin\",\"scheme\":\"https\",\"pass_host\":\"pass\",\"nodes\":{\"127.0.0.1:8443\":1},\"tls\":{\"verify\":false}}}"
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

# Ziti management API: internal networks only.
#
# The controller must be reachable from the internet for clients to enrol and
# open sessions — that is the whole point of an overlay. The MANAGEMENT API is
# a different matter: creating identities, editing policies and enrolling
# routers all live under /edge/management/v1. It already demands credentials
# (401 without them), but an authenticated endpoint exposed to the internet is
# still a credential-guessing surface on the control plane of the whole
# network.
#
# Higher priority than ctrl-host so it wins for this path prefix; the catch-all
# above is left untouched, so client and enrolment traffic is unaffected.
#
# ip-restriction matches on the real TCP source (remote_addr), not on
# X-Forwarded-For, so it cannot be bypassed by forging a header.
put ctrl-mgmt-restricted '{"hosts":["ctrl.tdv.org"],"uri":"/edge/management/v1/*","priority":70,"enable_websocket":true,"plugins":{"ip-restriction":{"whitelist":["127.0.0.0/8","10.0.0.0/8","172.16.0.0/12","192.168.0.0/16"]}},"upstream":{"type":"roundrobin","scheme":"https","pass_host":"pass","nodes":{"127.0.0.1:1280":1},"tls":{"verify":false},"timeout":{"connect":60,"send":86400,"read":86400}}}'

# --- *.tdv.org one-click apps -> access-proxy (auth enforced by the proxy itself) ---
put access-proxy-wildcard '{"hosts":["*.tdv.org"],"uri":"/*","priority":-50,"enable_websocket":true,"upstream":{"type":"roundrobin","scheme":"http","pass_host":"pass","nodes":{"127.0.0.1:8007":1},"timeout":{"connect":60,"send":86400,"read":86400}}}'

echo "Edge routes seeded."
