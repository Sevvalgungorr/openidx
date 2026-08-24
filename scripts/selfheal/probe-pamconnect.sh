#!/usr/bin/env bash
# Synthetic connect probe (read-only, SAFE): proves the PAM broker control-plane
# chain is alive END-TO-END without opening a real privileged session. It does
# NOT call /api/tokens with credentials or start a guacd tunnel -- it only proves
# the pieces that must be healthy for /api/tokens auth to work at all:
#   1. guac webapp answers 200 on /guacamole/ (the servlet that fronts /api/tokens)
#   2. its guacd container process is running (podman)  -- the wedged-for-6-weeks class
#   3. access-service PAM broker-status is healthy (or documented auth-gated 401/403)
#
# Emits ONE health line to stdout (and $SELFHEAL_STATE_DIR/pamconnect.json) that
# the loop and a dashboard can consume:
#   {"probe":"pamconnect","ts":"...","status":"pass|fail","checks":[...]}
# Exit 0 on PASS, 1 on FAIL. Probes injectable (same seams as the collector).
set -uo pipefail
cd "$(dirname "$0")"; . ./lib.sh

# webapp-url|webapp-container|guacd-container|label
BROKERS='http://127.0.0.1:10090/guacamole/|pam-guacamole|pam-guacd|direct
http://127.0.0.1:10091/guacamole/|pam-guacamole-ziti|pam-guacd-ziti|ziti'
BROKER_STATUS_URL="${SH_PAM_BROKER_STATUS_URL:-http://127.0.0.1:8007/api/v1/access/pam/broker/status}"

_default_web_probe() { curl -s -o /dev/null -w '%{http_code}' --max-time 6 "$1" 2>/dev/null || echo 000; }
_default_ctr_probe() { local st; st=$(podman inspect -f '{{.State.Running}}' "$1" 2>/dev/null || echo false); [ "$st" = true ] && echo running || echo absent; }
_default_broker_probe() { curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$BROKER_STATUS_URL" 2>/dev/null || echo 000; }
WEB_PROBE="${SH_PAM_WEB_PROBE:-_default_web_probe}"
CTR_PROBE="${SH_PAM_CTR_PROBE:-_default_ctr_probe}"
BROKER_PROBE="${SH_PAM_BROKER_STATUS_PROBE:-_default_broker_probe}"

# Collect check results as "name=ok|bad detail" lines, then let python emit JSON.
checks=$(mktemp)
overall=pass

printf '%s\n' "$BROKERS" | while IFS='|' read -r url webctr guacdctr label; do
  [ -z "$url" ] && continue
  wc=$($WEB_PROBE "$url")
  [ "$wc" = 200 ] && echo "webapp-$label ok code=$wc" || echo "webapp-$label bad code=$wc"
  gs=$($CTR_PROBE "$guacdctr")
  [ "$gs" = running ] && echo "guacd-$label ok state=$gs" || echo "guacd-$label bad state=$gs"
done > "$checks"

bc=$($BROKER_PROBE)
case "$bc" in
  200)      echo "broker-status ok code=$bc" >> "$checks" ;;
  401|403)  echo "broker-status ok code=$bc(auth-gated)" >> "$checks" ;;  # expected on box
  *)        echo "broker-status bad code=$bc" >> "$checks" ;;
esac

grep -q ' bad ' "$checks" && overall=fail

ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
out=$(SF_TS="$ts" SF_STATUS="$overall" python3 - "$checks" <<'PY'
import sys, os, json
checks=[]
for line in open(sys.argv[1]):
    line=line.strip()
    if not line: continue
    parts=line.split(" ",2)
    name=parts[0]; state=parts[1] if len(parts)>1 else "bad"
    detail=parts[2] if len(parts)>2 else ""
    checks.append({"name":name,"ok":state=="ok","detail":detail})
print(json.dumps({"probe":"pamconnect","ts":os.environ["SF_TS"],
                  "status":os.environ["SF_STATUS"],"checks":checks},
                 separators=(",",":")))
PY
)
rm -f "$checks"

printf '%s\n' "$out" > "$SELFHEAL_STATE_DIR/pamconnect.json" 2>/dev/null || true
printf '%s\n' "$out"
[ "$overall" = pass ]
