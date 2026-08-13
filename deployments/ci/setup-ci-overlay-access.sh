#!/usr/bin/env bash
# Grants a CI runner access to an internal HTTPS service over the Ziti overlay.
#
# Idempotent: every object is created only if missing, so re-running is safe and
# the second run reports no changes. Nothing existing is renamed or deleted.
#
# Why each object is needed (each one alone is a silent dead end):
#   service + intercept.v1  a service carrying only host.v1 is reachable by
#                           BrowZer but offers a tunneller no address to
#                           intercept, so the CI DNS lookup just times out
#   host.v1                 where the router forwards to (the real app:port)
#   Bind policy             lets the router terminate the service; without a
#                           terminator the dial fails with "no terminators"
#   Dial policy             lets the CI identity role reach the service
#   edge-router policy      lets the identity USE a router at all
#   service-edge-router     lets the service BE OFFERED on that router; missing
#                           this, the identity authenticates and then sees
#                           "service not found", which reads like a permissions
#                           bug but is a routing one
#
# Usage:
#   ./setup-ci-overlay-access.sh                 # apply (idempotent)
#   DRY_RUN=1 ./setup-ci-overlay-access.sh       # show what would change
#   ./setup-ci-overlay-access.sh --identity NAME # also mint an identity + JWT
#   ./setup-ci-overlay-access.sh --rollback      # remove ONLY what this created
set -euo pipefail

SERVICE="${SERVICE:-secops}"
INTERCEPT_DNS="${INTERCEPT_DNS:-secops.ziti}"
TARGET_HOST="${TARGET_HOST:?set TARGET_HOST to the internal app address}"
TARGET_PORT="${TARGET_PORT:-443}"
CI_ROLE="${CI_ROLE:-ci-clients}"
CONTAINER="${ZITI_CONTAINER:-oidx-ziti-controller}"
DRY_RUN="${DRY_RUN:-0}"

z() { docker exec "$CONTAINER" sh -c \
  'ziti edge login localhost:1280 -u admin -p "$ZITI_PWD" -y >/dev/null 2>&1; '"$1" 2>/dev/null \
  | grep -v 'Emulate Docker CLI'; }

# Existence checks are name-exact. NOTE: `ziti edge list` returns only 10 rows
# by default; a substring/paged check silently misses objects and would make
# this script recreate things that already exist.
exists() { z "ziti edge list $1 'limit 200' -j" \
  | python3 -c "import json,sys
try: d=json.load(sys.stdin)
except Exception: sys.exit(1)
sys.exit(0 if any(o.get('name')=='$2' for o in d.get('data',[])) else 1)"; }

step() {
  local kind="$1" name="$2" cmd="$3"
  if exists "$kind" "$name"; then echo "  ok      $kind/$name (already present)"; return; fi
  if [ "$DRY_RUN" = 1 ]; then echo "  WOULD   $kind/$name"; return; fi
  z "$cmd" >/dev/null && echo "  created $kind/$name"
}

if [ "${1:-}" = "--rollback" ]; then
  # SERVICE-SCOPED ONLY. The edge-router policy is deliberately NOT removed:
  # it is keyed on the CI ROLE, not on this service, so other CI identities
  # share it. An earlier version did delete it and instantly cut off an
  # unrelated, already-enrolled CI identity's access to every router -- the
  # rollback of one service broke a different consumer. Shared objects are
  # only ever created here, never destroyed.
  echo "Removing objects scoped to service '${SERVICE}' (shared role/router"
  echo "policies and identities are left alone):"
  for c in "service-edge-router-policies openidx-serp-${SERVICE}" \
           "service-policies openidx-dial-${SERVICE}" \
           "service-policies openidx-bind-${SERVICE}" \
           "services ${SERVICE}" \
           "configs ${SERVICE}-intercept" \
           "configs ${SERVICE}-host"; do
    set -- $c
    exists "$1" "$2" && { z "ziti edge delete $1 '$2'" >/dev/null; echo "  deleted $1/$2"; } \
                     || echo "  absent  $1/$2"
  done
  echo "  kept    edge-router-policies/${CI_ROLE}-erp (shared by all #${CI_ROLE} identities)"
  exit 0
fi

echo "Service '${SERVICE}' -> ${TARGET_HOST}:${TARGET_PORT}, dialable at ${INTERCEPT_DNS} by #${CI_ROLE}"

step configs "${SERVICE}-intercept" \
  "ziti edge create config '${SERVICE}-intercept' intercept.v1 '{\"protocols\":[\"tcp\"],\"addresses\":[\"${INTERCEPT_DNS}\"],\"portRanges\":[{\"low\":${TARGET_PORT},\"high\":${TARGET_PORT}}]}'"

step configs "${SERVICE}-host" \
  "ziti edge create config '${SERVICE}-host' host.v1 '{\"protocol\":\"tcp\",\"address\":\"${TARGET_HOST}\",\"port\":${TARGET_PORT}}'"

step services "${SERVICE}" \
  "ziti edge create service '${SERVICE}' -a '${SERVICE}' --configs '${SERVICE}-intercept,${SERVICE}-host'"

step service-policies "openidx-bind-${SERVICE}" \
  "ziti edge create service-policy 'openidx-bind-${SERVICE}' Bind --service-roles '#${SERVICE}' --identity-roles '#ziti-routers'"

step service-policies "openidx-dial-${SERVICE}" \
  "ziti edge create service-policy 'openidx-dial-${SERVICE}' Dial --service-roles '#${SERVICE}' --identity-roles '#${CI_ROLE}'"

step service-edge-router-policies "openidx-serp-${SERVICE}" \
  "ziti edge create service-edge-router-policy 'openidx-serp-${SERVICE}' --service-roles '#${SERVICE}' --edge-router-roles '#all'"

step edge-router-policies "${CI_ROLE}-erp" \
  "ziti edge create edge-router-policy '${CI_ROLE}-erp' --identity-roles '#${CI_ROLE}' --edge-router-roles '#all'"

if [ "${1:-}" = "--identity" ] && [ -n "${2:-}" ]; then
  ident="$2"
  if exists identities "$ident"; then
    echo "  ok      identities/$ident (already present; not re-enrolled)"
  elif [ "$DRY_RUN" = 1 ]; then
    echo "  WOULD   identities/$ident"
  else
    z "ziti edge create identity '$ident' -a '${CI_ROLE}' -o '/persistent/${ident}.jwt'" >/dev/null
    docker cp "$CONTAINER:/persistent/${ident}.jwt" "./${ident}.jwt" >/dev/null 2>&1
    docker exec "$CONTAINER" sh -c "rm -f '/persistent/${ident}.jwt'" 2>/dev/null || true
    echo "  created identities/$ident -> ./${ident}.jwt"
    cat <<EOF

  Enrol once, then store the RESULT as a secret. The JWT is one-time and
  short-lived; the enrolled JSON is the long-lived credential.

    ziti-edge-tunnel enroll --jwt ./${ident}.jwt --identity ./${ident}.json
    base64 -w0 ./${ident}.json    # -> pipeline SECRET variable ZITI_CI_IDENTITY_B64
    shred -u ./${ident}.json ./${ident}.jwt

  Never commit either file.
EOF
  fi
fi

echo "Done. Verify with:"
echo "  ziti edge list services 'limit 200' | grep ${SERVICE}"
echo "  ziti fabric list terminators 'limit 200' | grep ${SERVICE}   # must be non-empty"
