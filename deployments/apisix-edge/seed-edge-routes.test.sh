#!/usr/bin/env bash
# Route-set assertions for the DARK_MODE variants of seed-edge-routes.sh, using
# DRY_RUN=1 so nothing touches APISIX. Run from deployments/apisix-edge/.
set -euo pipefail
cd "$(dirname "$0")"

fail() { echo "FAIL: $1"; exit 1; }
# Match the whole route name (anchored) so e.g. "openidx-oauth" never matches
# "openidx-api-oauth".
has()  { echo "$1" | grep -qx "put $2"; }
hasnt(){ echo "$1" | grep -qx "put $2" && return 1 || return 0; }

# --- off (default): full public set ---
off=$(DARK_MODE=off DRY_RUN=1 bash seed-edge-routes.sh 2>&1)
has "$off" openidx-api-admin      || fail "off: admin route missing"
has "$off" openidx-api-enroll     || fail "off: enroll route missing"
has "$off" openidx-spa            || fail "off: SPA route missing"
echo "OK off (full set)"

# --- tier2: management dropped, Tier-0 + Tier-1 kept ---
t2=$(DARK_MODE=tier2 DRY_RUN=1 bash seed-edge-routes.sh 2>&1)
hasnt "$t2" openidx-api-admin       || fail "tier2: admin route MUST be dropped"
hasnt "$t2" openidx-api-governance  || fail "tier2: governance route MUST be dropped"
hasnt "$t2" openidx-api-audit       || fail "tier2: audit route MUST be dropped"
hasnt "$t2" openidx-scim            || fail "tier2: scim route MUST be dropped"
hasnt "$t2" openidx-api-access      || fail "tier2: /api/v1/access/* catch-all MUST be dropped"
has   "$t2" openidx-api-enroll      || fail "tier2: enroll route MUST stay (Tier 0)"
has   "$t2" openidx-wellknown       || fail "tier2: well-known MUST stay (Tier 0)"
has   "$t2" openidx-oauth           || fail "tier2: oauth auth surface MUST stay (Tier 0)"
has   "$t2" openidx-api-identity    || fail "tier2: identity self-service stays (Tier 1)"
has   "$t2" openidx-spa             || fail "tier2: SPA stays (Tier 1)"
echo "OK tier2 (management dropped)"

# --- tier1: only Tier-0 bootstrap ---
t1=$(DARK_MODE=tier1 DRY_RUN=1 bash seed-edge-routes.sh 2>&1)
hasnt "$t1" openidx-api-admin       || fail "tier1: admin route MUST be dropped"
hasnt "$t1" openidx-api-identity    || fail "tier1: identity self-service MUST be dropped"
hasnt "$t1" openidx-spa             || fail "tier1: SPA MUST be dropped"
has   "$t1" openidx-api-enroll      || fail "tier1: enroll route MUST stay (Tier 0)"
has   "$t1" openidx-wellknown       || fail "tier1: well-known MUST stay (Tier 0)"
has   "$t1" openidx-oauth           || fail "tier1: oauth auth surface MUST stay (Tier 0)"
echo "OK tier1 (Tier-0 bootstrap only)"

# --- ziti control plane: management API must stay internal-only ---
#
# The controller is reachable from the internet by design (clients enrol and
# open sessions there). /edge/management/v1 is not: it creates identities,
# edits policies and enrols routers. It already requires credentials, but an
# authenticated management endpoint on the public internet is still a
# credential-guessing surface on the control plane of the entire network.
#
# These assertions pin the decision, not the wording: a restricted route must
# exist, it must carry an IP allow-list, and it must outrank the catch-all —
# a lower priority would silently make it dead configuration.
z=$(DRY_RUN=1 bash seed-edge-routes.sh 2>&1)
has "$z" ctrl-host              || fail "ziti: client/enrolment route MUST stay reachable"
has "$z" ctrl-mgmt-restricted   || fail "ziti: management API MUST have a restricted route"
has "$z" ctrl-zac-restricted    || fail "ziti: ZAC admin console MUST have a restricted route"
has "$z" ctrl-fabric-restricted || fail "ziti: fabric API MUST have a restricted route"
# DRY_RUN prints route names only, so the body is asserted against the script
# source itself. Without these two checks the route could exist and still be
# useless: no allow-list means it restricts nothing, and a priority at or below
# ctrl-host (20) means the catch-all wins and this route never matches.
grep -q 'ctrl-mgmt-restricted.*ip-restriction' seed-edge-routes.sh \
  || fail "ziti: management route MUST carry an IP allow-list"
grep -q 'ctrl-mgmt-restricted.*"uri":"/edge/management/v1/\*","priority":70' seed-edge-routes.sh \
  || fail "ziti: management route MUST outrank ctrl-host (priority 20), else it never matches"
# The management/console/fabric plane must point at the loopback-only listener
# (:1281), NOT the public :1280. If a direct port-forward bypasses APISIX, the
# controller's client-public listener on :1280 does not serve these APIs at all;
# routing them back to :1280 here would reopen that exact hole (measured
# 2026-08-17: DIRECT :1280 mgmt -> 404 after the split, 200 before). These pin
# both the allow-list AND the loopback upstream for every management-plane route.
for r in ctrl-mgmt-restricted ctrl-zac-restricted ctrl-fabric-restricted; do
  grep -q "$r.*ip-restriction" seed-edge-routes.sh \
    || fail "ziti: $r MUST carry an IP allow-list"
  grep -q "$r.*127.0.0.1:1281" seed-edge-routes.sh \
    || fail "ziti: $r MUST target the loopback-only :1281 listener, not public :1280"
  grep -q "$r.*127.0.0.1:1280" seed-edge-routes.sh \
    && fail "ziti: $r MUST NOT target public :1280 (management plane leaks past APISIX bypass)"
  grep -q "$r.*\"priority\":70" seed-edge-routes.sh \
    || fail "ziti: $r MUST outrank ctrl-host (priority 20), else it never matches"
done

# Source-NAT trap: if the allow-list covers the source IP of a NAT router doing
# masquerade, every external request looks internal and the restriction silently
# becomes a no-op. The gateway address is site-specific, so this check runs only
# when EDGE_GATEWAY_IP is supplied; it is SKIPPED loudly rather than passing
# quietly, because a silent pass here would be a false green.
if [ -n "${EDGE_GATEWAY_IP:-}" ]; then
  # Effective allow-list: env override wins, otherwise the script default.
  effective="${MGMT_ALLOW_CIDRS:-$(sed -n "s/^MGMT_ALLOW_CIDRS=\${MGMT_ALLOW_CIDRS:-'\(.*\)'}$/\1/p" seed-edge-routes.sh)}"
  [ -n "$effective" ] || fail "ziti: could not determine the management allow-list"
  python3 - "$effective" "$EDGE_GATEWAY_IP" <<'PYEOF' || fail "ziti: allow-list MUST NOT cover the LAN gateway (source NAT would bypass the restriction)"
import sys, json, ipaddress
nets = json.loads("[" + sys.argv[1] + "]")
gw = ipaddress.ip_address(sys.argv[2])
sys.exit(1 if any(gw in ipaddress.ip_network(n) for n in nets) else 0)
PYEOF
  echo "OK ziti management allow-list excludes the gateway"
else
  echo "SKIP gateway/allow-list check (set EDGE_GATEWAY_IP to enable)"
fi
echo "OK ziti control plane (management API internal-only)"

echo "ALL PASS"
