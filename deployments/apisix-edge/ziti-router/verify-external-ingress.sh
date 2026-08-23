#!/usr/bin/env bash
# Verify the Ziti external-ingress forwarding matrix from off-box perspective.
# Probes the public gateway the CI/browser clients resolve to and checks the
# ports the SDK data-path (:3022), enroll/auth (:1280), APISIX web edge (:443)
# and in-browser BrowZer (:3023) require. See EXTERNAL-INGRESS.md.
#
# Usage: ./verify-external-ingress.sh [gateway_ip]
#   gateway_ip defaults to the A record of browzer.tdv.org (via 8.8.8.8).
set -uo pipefail

RESOLVER="${DNS_RESOLVER:-8.8.8.8}"
NAMES=(ctrl.tdv.org browzer.tdv.org openidx.tdv.org)

echo "== public DNS (@${RESOLVER}) =="
declare -A IPS
for h in "${NAMES[@]}"; do
  ip="$(dig +short "@${RESOLVER}" "$h" 2>/dev/null | grep -E '^[0-9]' | head -1)"
  IPS[$h]="$ip"
  printf '  %-18s -> %s\n' "$h" "${ip:-<none>}"
done

GW="${1:-${IPS[browzer.tdv.org]}}"
if [[ -z "$GW" ]]; then
  echo "ERROR: could not determine gateway IP (pass it as arg 1)" >&2
  exit 2
fi

echo
echo "== forwarding matrix on gateway ${GW} =="
# port -> "who needs it | required?(1=required)"
declare -A NEED=(
  [443]="APISIX web edge|1"
  [1280]="controller enroll/auth (CI/SDK, BrowZer)|1"
  [3022]="router tls edge (CI/SDK data-path)|1"
  [3023]="router wss edge (in-browser BrowZer only)|0"
)
fail=0
for p in 443 1280 3022 3023; do
  who="${NEED[$p]%%|*}"; req="${NEED[$p]##*|}"
  if timeout 5 bash -c "echo > /dev/tcp/${GW}/${p}" 2>/dev/null; then
    printf '  :%-5s OPEN    (%s)\n' "$p" "$who"
  else
    if [[ "$req" == "1" ]]; then
      printf '  :%-5s CLOSED  REQUIRED (%s)\n' "$p" "$who"
      fail=1
    else
      printf '  :%-5s closed  optional (%s)\n' "$p" "$who"
    fi
  fi
done

echo
if [[ "$fail" == "1" ]]; then
  echo "RESULT: FAIL — a required forward is closed on ${GW}."
  echo "        CI will enroll but hang on the data channel if :3022 is closed."
  echo "        Fix on the NAT gateway (DNAT :3022 -> this host), not on the router."
  exit 1
fi
echo "RESULT: OK — all required forwards open on ${GW}."
