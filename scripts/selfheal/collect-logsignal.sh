#!/usr/bin/env bash
# Collector: error/panic mining. Scans the tail of each service log for
# error/fatal/panic lines, groups them by fingerprint (so one recurring error
# = one finding, not one per occurrence), and emits a bug finding per group
# with an occurrence count. severity: panic/fatal -> crit, else warn.
set -uo pipefail
cd "$(dirname "$0")"; . ./lib.sh

LOG_DIR="${SH_LOG_DIR:-/tmp/oidx-logs}"
TAIL="${SH_LOG_TAIL:-500}"
SVCS="access admin audit governance identity oauth provisioning"

for svc in $SVCS; do
  f="$LOG_DIR/$svc.log"; [ -f "$f" ] || continue
  # Extract error-ish messages from the tail. Handle zap JSON ("msg":"...") and
  # plaintext; fall back to the whole line. Group by fingerprint: the same error
  # with volatile ids collapses to one entry (rep msg = first seen, count = N).
  tail -n "$TAIL" "$f" 2>/dev/null \
    | grep -iE '"level":"(error|fatal|dpanic|panic)"|\[ERROR\]|\bpanic\b|\bfatal\b' \
    | sed -E 's/.*"msg":"([^"]*)".*/\1/' \
    | while IFS= read -r msg; do
        [ -z "$msg" ] && continue
        printf '%s\t%s\n' "$(sh_fingerprint bug "$msg")" "$msg"
      done \
    | awk -F'\t' '{cnt[$1]++; if(!($1 in rep)) rep[$1]=$2} END{for(k in cnt) printf "%d\t%s\t%s\n", cnt[k], k, rep[k]}' \
    | while IFS=$'\t' read -r count fp msg; do
        [ -z "$fp" ] && continue
        sev=warn; echo "$msg" | grep -qiE 'panic|fatal' && sev=crit
        sh_finding bug "$sev" "$fp" "$svc" "$msg" "{\"count\":$count}" ""
      done
done
