#!/usr/bin/env bash
# Verify: a burst of 403s from one principal is flagged (auth abuse), an
# injection/traversal marker is flagged, and normal traffic is silent.
set -uo pipefail
cd "$(dirname "$0")"
export SELFHEAL_STATE_DIR="$(mktemp -d)"; export SH_LOG_DIR="$(mktemp -d)"
export SH_SEC_403_THRESHOLD=5
fails=0; ok(){ echo "  OK  $1"; }; bad(){ echo "  FAIL  $1"; fails=$((fails+1)); }

# 6x 403 for the same path + one traversal attempt.
{ for i in $(seq 1 6); do echo '{"level":"warn","status":403,"path":"/api/v1/settings"}'; done
  echo '{"path":"/downloads/../../etc/passwd"}'
  echo '{"level":"info","status":200,"path":"/dashboard"}'; } > "$SH_LOG_DIR/admin.log"

out=$(bash ./collect-security.sh)
echo "$out" | grep -q '"class":"security"' && ok "emits security findings" || bad "no security finding"
echo "$out" | grep -q 'forbidden-spike' && ok "flags 403 spike" || bad "missed 403 spike"
echo "$out" | grep -q 'path-traversal' && ok "flags traversal" || bad "missed traversal"

: > "$SH_LOG_DIR/admin.log"; echo '{"status":200,"path":"/ok"}' > "$SH_LOG_DIR/admin.log"
[ -z "$(bash ./collect-security.sh)" ] && ok "silent on clean traffic" || bad "noise on clean"

rm -rf "$SELFHEAL_STATE_DIR" "$SH_LOG_DIR"
[ "$fails" -eq 0 ] && echo "collect-security PASS" || { echo "FAIL ($fails)"; exit 1; }
