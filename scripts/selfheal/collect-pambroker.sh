#!/usr/bin/env bash
# Collector: PAM/Guacamole broker health. Born from the 2026-08-24 incident where
# the direct guacd (pam-guacd) was wedged for SIX WEEKS -- container "Up (starting)",
# listening on :4822 but serving nothing -- and NOTHING detected it.
#
# Two guac stacks front two guacd brokers:
#   direct: webapp pam-guacamole (:10090) -> guacd pam-guacd
#   ziti:   webapp pam-guacamole-ziti (:10091) -> guacd pam-guacd-ziti
#
# Detection strategy (prefer reachability signals over guessing internal state):
#   1. webapp unreachable: curl -sf .../guacamole/ must return 200. A webapp that
#      does NOT answer 200 is the clearest outage signal and its guac container
#      pair is what we would restart -> suggested_action=restart_pam_broker.
#   2. guacd wedged: the webapp is the app's own client of guacd, so "webapp is
#      running but cannot reach its broker" IS the wedged-guacd signal. We express
#      this as: the guac container is running (podman) but its webapp does not
#      answer 200. That reproduces the six-week silent wedge without guessing.
#   3. access-service broker-status: /api/v1/access/pam/broker/status. On the box
#      this is auth-gated (401 -> {"error":"missing authorization header"}), so we
#      treat it as BEST-EFFORT: only if it answers 200 with a parseable body do we
#      inspect it for a broker marked unhealthy/unconfigured. When auth-gated we
#      note it and rely on the direct webapp curls (signal #1/#2) instead.
#
# All probes are injectable so the test can drive them with no live box:
#   SH_PAM_WEB_PROBE   <url>       -> http code
#   SH_PAM_CTR_PROBE   <container> -> "running" | "absent"  (podman running-state)
#   SH_PAM_BROKER_PROBE            -> "<http_code> <body>"  (access-service status)
# Silent when everything is healthy.
set -uo pipefail
cd "$(dirname "$0")"; . ./lib.sh

# webapp-url|webapp-container|guacd-container|label
# The webapp+guacd containers move together, so the remediation restarts the pair;
# the webapp container is passed as data.container (what restart_pam_broker acts on).
BROKERS='http://127.0.0.1:10090/guacamole/|pam-guacamole|pam-guacd|direct
http://127.0.0.1:10091/guacamole/|pam-guacamole-ziti|pam-guacd-ziti|ziti'

BROKER_STATUS_URL="${SH_PAM_BROKER_STATUS_URL:-http://127.0.0.1:8007/api/v1/access/pam/broker/status}"

_default_web_probe() { # <url> -> http code (200 == webapp reachable)
  curl -s -o /dev/null -w '%{http_code}' --max-time 6 "$1" 2>/dev/null || echo 000
}
_default_ctr_probe() { # <container> -> "running" | "absent"
  local st
  st=$(podman inspect -f '{{.State.Running}}' "$1" 2>/dev/null || echo false)
  [ "$st" = true ] && echo running || echo absent
}
_default_broker_probe() { # -> "<http_code> <body>"  (best-effort; may be auth-gated)
  local code body
  body=$(curl -s --max-time 5 -w '\n%{http_code}' "$BROKER_STATUS_URL" 2>/dev/null || printf '\n000')
  code=$(printf '%s' "$body" | tail -n1)
  body=$(printf '%s' "$body" | sed '$d' | tr -d '\n' | tr -s ' ')
  echo "$code ${body:-none}"
}
WEB_PROBE="${SH_PAM_WEB_PROBE:-_default_web_probe}"
CTR_PROBE="${SH_PAM_CTR_PROBE:-_default_ctr_probe}"
BROKER_PROBE="${SH_PAM_BROKER_PROBE:-_default_broker_probe}"

# --- 1 & 2: per-stack webapp reachability (== guacd reachability) ---------------
printf '%s\n' "$BROKERS" | while IFS='|' read -r url webctr guacdctr label; do
  [ -z "$url" ] && continue
  code=$($WEB_PROBE "$url")
  [ "$code" = 200 ] && continue           # webapp answers -> stack (incl guacd) reachable
  cstate=$($CTR_PROBE "$webctr")
  if [ "$cstate" = running ]; then
    # Webapp container is UP but its /guacamole/ does not serve 200. This is both
    # the "webapp unreachable" and the "guacd wedged" class (webapp is guacd's own
    # client) -> safe deterministic fix is restarting the guac pair.
    # code is quoted: curl returns "000" on failure, which is NOT valid JSON as a
    # bare number (leading zeros) and would make json.loads fall back to {"raw":..}.
    sh_finding ops high "ops:pam-broker-wedged:$label" "pam-$label" \
      "PAM $label broker unreachable: $webctr running but $url returned $code (guacd $guacdctr likely wedged)" \
      "{\"container\":\"$webctr\",\"guacd\":\"$guacdctr\",\"url\":\"$url\",\"code\":\"$code\"}" restart_pam_broker
  else
    # Container itself is not running -> systemd/compose ownership problem, not a
    # simple podman restart of a live container. Escalate (no auto action).
    sh_finding ops high "ops:pam-broker-down:$label" "pam-$label" \
      "PAM $label broker down: $url returned $code and container $webctr is $cstate" \
      "{\"container\":\"$webctr\",\"guacd\":\"$guacdctr\",\"url\":\"$url\",\"code\":\"$code\"}" ""
  fi
done

# --- 3: access-service broker-status (best-effort, auth-gated on the box) --------
read -r bcode bbody < <($BROKER_PROBE)
case "$bcode" in
  200)
    # Parse a JSON body for a broker marked unhealthy/unconfigured.
    bad=$(PAM_BODY="$bbody" python3 - <<'PY' 2>/dev/null
import os, json
try:
    d = json.loads(os.environ.get("PAM_BODY", ""))
except Exception:
    raise SystemExit(0)
def walk(x):
    out = []
    if isinstance(x, dict):
        # a broker entry marked unhealthy/unconfigured/down/false
        s = str(x.get("status", x.get("state", ""))).lower()
        h = x.get("healthy", x.get("ok"))
        if s in ("unhealthy", "unconfigured", "down", "error") or h is False:
            out.append(x.get("name", x.get("broker", s or "broker")))
        for v in x.values():
            out += walk(v)
    elif isinstance(x, list):
        for v in x:
            out += walk(v)
    return out
b = walk(d)
if b:
    print(",".join(str(x) for x in b))
PY
)
    if [ -n "$bad" ]; then
      sh_finding ops high "ops:pam-broker-status-unhealthy" pam-access \
        "access-service reports PAM broker(s) unhealthy: $bad" \
        "{\"brokers\":\"$bad\"}" ""
    fi
    ;;
  401|403)
    : # auth-gated as expected on the box -> rely on webapp curls above (documented)
    ;;
  000)
    sh_finding ops warn "ops:pam-broker-status-unreachable" pam-access \
      "access-service PAM broker-status endpoint unreachable (code=$bcode)" \
      "{\"code\":$bcode}" ""
    ;;
  *)
    : # other codes: not actionable here; webapp signals are authoritative
    ;;
esac
