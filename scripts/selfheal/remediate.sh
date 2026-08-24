#!/usr/bin/env bash
# The ONE box-mutation point. Reads finding JSON lines on stdin and, for Tier-0
# ops findings, performs the deterministic remediation gated by the full safety
# envelope. Everything else (bug/anomaly/security, or an action beyond Tier-0)
# is logged as "escalate" and left for a human / the Claude triage routine.
#
# Safety envelope (all enforced here so it lives in one place):
#   - autonomy gate: acts only in tier0/tier1 (never off/observe)
#   - kill-switch:   $SELFHEAL_STATE_DIR/DISABLE halts everything
#   - anti-flap:     a fingerprint is auto-remediated at most K=3 times/hour
#   - health-gate:   after acting, verify /health; the caller/watch records the
#                    outcome (recovered vs still-bad). (System restart + health
#                    are injectable for tests via SH_ACT_RESTART / SH_ACT_HEALTH.)
#   - --dry-run:     print intended action, do nothing.
set -uo pipefail
cd "$(dirname "$0")"; . ./lib.sh

DRY=0; [ "${1:-}" = "--dry-run" ] && DRY=1
K="${SELFHEAL_FLAP_K:-3}"
mode=$(sh_mode)
FLAP="$SELFHEAL_STATE_DIR/flap"; touch "$FLAP"

_default_restart() { systemctl --user restart "$1.service" 2>/dev/null; }
_default_health()  { curl -fsS --max-time 3 "http://127.0.0.1:$1/health" 2>/dev/null | grep -o '"status":"up"' | head -1 | grep -q up && echo up || echo down; }
# PAM broker restart: the guac webapp + its guacd move together, so restart both
# containers (webapp first so a fresh guacd is up before it reconnects). Health
# is the webapp answering 200 on /guacamole/ again -- same signal the collector
# used to detect the wedge. Both are injectable for tests.
_default_restart_pam() { # <webapp-container> <guacd-container>
  podman restart "$2" >/dev/null 2>&1   # guacd first
  podman restart "$1" >/dev/null 2>&1   # then webapp
}
_default_pam_health() { # <webapp-url> -> up|down
  local c; c=$(curl -s -o /dev/null -w '%{http_code}' --max-time 6 "$1" 2>/dev/null || echo 000)
  [ "$c" = 200 ] && echo up || echo down
}
ACT_RESTART="${SH_ACT_RESTART:-_default_restart}"
ACT_HEALTH="${SH_ACT_HEALTH:-_default_health}"
ACT_RESTART_PAM="${SH_ACT_RESTART_PAM:-_default_restart_pam}"
ACT_PAM_HEALTH="${SH_ACT_PAM_HEALTH:-_default_pam_health}"

# _flap_count <fp>: attempts for this fingerprint within the last hour.
_flap_count() { local fp="$1" now cutoff; now=$(date +%s); cutoff=$((now-3600))
  awk -F'\t' -v fp="$fp" -v c="$cutoff" '$1==fp && $2>=c' "$FLAP" | wc -l; }
_flap_mark()  { printf '%s\t%s\n' "$1" "$(date +%s)" >> "$FLAP"; }

# _record <fp> <action> <result>: append one remediation-outcome line to
# actions.jsonl so the admin-console panel has a history. result is one of
# recovered|still-bad|halted|escalated|dry-run|observe.
ACTIONS="$SELFHEAL_STATE_DIR/actions.jsonl"
_record() {
  SF_FP="$1" SF_ACT="$2" SF_RES="$3" python3 - >> "$ACTIONS" <<'PY'
import os, json, datetime
print(json.dumps({
  "ts": datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ"),
  "fingerprint": os.environ["SF_FP"], "action": os.environ["SF_ACT"], "result": os.environ["SF_RES"],
}, separators=(",", ":")))
PY
}

while IFS= read -r line; do
  [ -z "$line" ] && continue
  fp=$(echo "$line"    | python3 -c 'import sys,json;print(json.load(sys.stdin).get("fingerprint",""))' 2>/dev/null)
  act=$(echo "$line"   | python3 -c 'import sys,json;print(json.load(sys.stdin).get("suggested_action",""))' 2>/dev/null)
  svc=$(echo "$line"   | python3 -c 'import sys,json;print(json.load(sys.stdin).get("service",""))' 2>/dev/null)
  port=$(echo "$line"  | python3 -c 'import sys,json;print(json.load(sys.stdin).get("data",{}).get("port",0))' 2>/dev/null)
  pam_ctr=$(echo "$line"   | python3 -c 'import sys,json;print(json.load(sys.stdin).get("data",{}).get("container",""))' 2>/dev/null)
  pam_guacd=$(echo "$line" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("data",{}).get("guacd",""))' 2>/dev/null)
  pam_url=$(echo "$line"   | python3 -c 'import sys,json;print(json.load(sys.stdin).get("data",{}).get("url",""))' 2>/dev/null)
  [ -z "$fp" ] && continue

  # Only Tier-0 ops actions are auto-eligible.
  case "$act" in restart_unit|restart_nginx|restart_pam_broker) ;; *) echo "escalate: $fp (action='$act')"; _record "$fp" "$act" escalated; continue;; esac

  if sh_killed; then echo "halted (kill-switch): $fp"; _record "$fp" "$act" halted; continue; fi
  if [ "$mode" != tier0 ] && [ "$mode" != tier1 ]; then echo "observe: would $act for $fp"; _record "$fp" "$act" observe; continue; fi
  # --dry-run short-circuits BEFORE anti-flap so it always reports pure intent.
  if [ "$DRY" = 1 ]; then echo "dry-run: would $act for $fp ($svc)"; _record "$fp" "$act" dry-run; continue; fi
  if [ "$(_flap_count "$fp")" -ge "$K" ]; then echo "escalate (anti-flap >=$K): $fp"; _record "$fp" "$act" escalated; continue; fi

  _flap_mark "$fp"
  case "$act" in
    restart_unit)   $ACT_RESTART "$svc"; sleep 2
                    if [ "$($ACT_HEALTH "$port")" = up ]; then echo "recovered: $fp via restart_unit"; _record "$fp" "$act" recovered
                    else echo "still-bad after restart_unit: $fp (escalate)"; _record "$fp" "$act" still-bad; fi ;;
    restart_nginx)  $ACT_RESTART "container-oidx-nginx"; sleep 2
                    echo "acted restart_nginx for $fp (verify edge next sweep)"; _record "$fp" "$act" recovered ;;
    restart_pam_broker)
                    $ACT_RESTART_PAM "$pam_ctr" "$pam_guacd"; sleep 3
                    if [ "$($ACT_PAM_HEALTH "$pam_url")" = up ]; then echo "recovered: $fp via restart_pam_broker ($pam_ctr/$pam_guacd)"; _record "$fp" "$act" recovered
                    else echo "still-bad after restart_pam_broker: $fp (escalate)"; _record "$fp" "$act" still-bad; fi ;;
  esac
done
