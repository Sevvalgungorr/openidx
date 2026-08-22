#!/usr/bin/env bash
# Collector: log liveness. A service log not written to within
# SH_LOG_STALE_SECS (default 600) is a fault — the service may be wedged and
# silent (the failure mode a health check alone can miss). Emits an ops finding
# per stale log. Only checks the 7 service logs (build/stage logs are ignored).
set -uo pipefail
cd "$(dirname "$0")"; . ./lib.sh

LOG_DIR="${SH_LOG_DIR:-/tmp/oidx-logs}"
STALE="${SH_LOG_STALE_SECS:-600}"
SVCS="access admin audit governance identity oauth provisioning"
now=$(date +%s)

for svc in $SVCS; do
  f="$LOG_DIR/$svc.log"
  [ -f "$f" ] || { sh_finding ops warn "ops:log-missing:$svc" "$svc" "log file missing" "{\"path\":\"$f\"}" ""; continue; }
  mtime=$(stat -c %Y "$f" 2>/dev/null || echo 0)
  age=$(( now - mtime ))
  if [ "$age" -gt "$STALE" ]; then
    sh_finding ops warn "ops:log-stale:$svc" "$svc" "log stale ${age}s (>${STALE}s) — service may be silent" \
      "{\"path\":\"$f\",\"age_secs\":$age}" ""
  fi
done
