#!/usr/bin/env bash
# Collector: security signals from logs. Emits security findings for a 403
# spike (>= SH_SEC_403_THRESHOLD in the tail) and for injection/traversal
# markers in request paths. Security findings are NEVER auto-remediated
# (suggested_action stays empty) — they alert a human / the security routine.
set -uo pipefail
cd "$(dirname "$0")"; . ./lib.sh

LOG_DIR="${SH_LOG_DIR:-/tmp/oidx-logs}"
TAIL="${SH_LOG_TAIL:-1000}"
THRESH="${SH_SEC_403_THRESHOLD:-30}"
SVCS="access admin audit governance identity oauth provisioning"

for svc in $SVCS; do
  f="$LOG_DIR/$svc.log"; [ -f "$f" ] || continue
  body=$(tail -n "$TAIL" "$f" 2>/dev/null)

  # 403/401 spike (forbidden/unauthorized bursts = probing / privilege attempts).
  c403=$(printf '%s\n' "$body" | grep -cE '"status":403|" 403 |\bforbidden\b' || true)
  if [ "$c403" -ge "$THRESH" ]; then
    sh_finding security high "security:forbidden-spike:$svc" "$svc" "403 spike: $c403 in last $TAIL lines" \
      "{\"count\":$c403}" ""
  fi

  # Injection / path traversal markers.
  if printf '%s\n' "$body" | grep -qE '\.\./\.\./|/etc/passwd|union[[:space:]]+select|<script>|\x27[[:space:]]*or[[:space:]]*\x27'; then
    sh_finding security high "security:path-traversal:$svc" "$svc" "injection/traversal marker in requests" "{}" ""
  fi
done
