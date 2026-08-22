#!/usr/bin/env bash
# Collector: public-edge reachability through APISIX :443. Each path has an
# allowed set of HTTP codes; anything else is an ops finding. `/` returning 403
# is exactly the frontend-mount outage class, so its suggested action is
# restart_nginx. The probe is injectable (SH_EDGE_PROBE) for testing.
set -uo pipefail
cd "$(dirname "$0")"; . ./lib.sh

# path|allowed-codes(csv)|suggested_action
CHECKS='/|200,301,302|restart_nginx
/.well-known/openid-configuration|200|
/api/v1/access/ziti/status|200,401|
/downloads/agent-manifest.json|200|'

_default_probe() { # <path> -> http code
  curl -s -o /dev/null -w '%{http_code}' -k --max-time 6 \
    --resolve openidx.tdv.org:443:127.0.0.1 "https://openidx.tdv.org$1" 2>/dev/null || echo 000
}
PROBE="${SH_EDGE_PROBE:-_default_probe}"

printf '%s\n' "$CHECKS" | while IFS='|' read -r path allowed action; do
  [ -z "$path" ] && continue
  code=$($PROBE "$path")
  if ! echo ",$allowed," | grep -q ",$code,"; then
    sh_finding ops high "ops:edge-bad:$path" system "edge $path returned $code (allowed: $allowed)" \
      "{\"path\":\"$path\",\"code\":$code}" "$action"
  fi
done
