#!/usr/bin/env bash
# Collector: per-service health. Emits an ops finding for any oidx-* service
# whose /health is not "up", whose systemd unit is not active, or that is in a
# restart loop (>=3 restarts). Silent when everything is healthy.
#
# The actual probe is injectable via SH_HEALTH_PROBE so the test can drive it
# without a live box. Default probe hits /health + systemctl.
set -uo pipefail
cd "$(dirname "$0")"; . ./lib.sh

SERVICES="oidx-identity:8001 oidx-governance:8002 oidx-provisioning:8003 oidx-audit:8004 oidx-admin-api:8005 oidx-oauth:8006 oidx-access:8007"

_default_probe() { # <unit> <port> -> "up|down active|dead <restarts>"
  local unit="$1" port="$2" h u r
  h=$(curl -fsS --max-time 3 "http://127.0.0.1:$port/health" 2>/dev/null | grep -o '"status":"up"' | head -1)
  [ -n "$h" ] && h=up || h=down
  u=$(systemctl --user is-active "$unit.service" 2>/dev/null); [ "$u" = active ] || u=dead
  r=$(systemctl --user show "$unit.service" -p NRestarts --value 2>/dev/null); [ -z "$r" ] && r=0
  echo "$h $u $r"
}
PROBE="${SH_HEALTH_PROBE:-_default_probe}"

for pair in $SERVICES; do
  unit="${pair%%:*}"; port="${pair##*:}"
  read -r health unit_state restarts < <($PROBE "$unit" "$port")
  if [ "$health" != up ] || [ "$unit_state" != active ]; then
    sh_finding ops high "ops:unit-down:$unit" "$unit" "$unit not healthy (health=$health unit=$unit_state)" \
      "{\"port\":$port,\"restarts\":$restarts}" restart_unit
  elif [ "${restarts:-0}" -ge 3 ]; then
    sh_finding ops warn "ops:restart-loop:$unit" "$unit" "$unit restart loop ($restarts restarts)" \
      "{\"port\":$port,\"restarts\":$restarts}" ""
  fi
done
