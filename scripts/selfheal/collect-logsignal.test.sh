#!/usr/bin/env bash
# Verify errors/panics in the tail are surfaced as bug findings, grouped so the
# SAME error with different ids collapses to one fingerprint, and info lines are
# ignored.
set -uo pipefail
cd "$(dirname "$0")"
export SELFHEAL_STATE_DIR="$(mktemp -d)"; export SH_LOG_DIR="$(mktemp -d)"
export SH_LOG_TAIL=50
fails=0; ok(){ echo "  OK  $1"; }; bad(){ echo "  FAIL  $1"; fails=$((fails+1)); }

cat > "$SH_LOG_DIR/access.log" <<LOG
{"level":"info","msg":"started"}
{"level":"error","msg":"failed to query delivery aaaaaaaa-0000-4000-8000-000000000001"}
{"level":"error","msg":"failed to query delivery bbbbbbbb-0000-4000-8000-000000000002"}
{"level":"info","msg":"ok"}
LOG
out=$(bash ./collect-logsignal.sh)
echo "$out" | grep -q '"class":"bug"' && ok "surfaces error as bug" || bad "no bug finding"
n=$(echo "$out" | grep -c 'failed to query delivery' || true)
[ "$n" -eq 1 ] && ok "grouped duplicate errors to one" || bad "did not group ($n lines)"
echo "$out" | python3 -c 'import sys,json;[json.loads(l) for l in sys.stdin if l.strip()]' && ok "valid json lines" || bad "bad json"

rm -rf "$SELFHEAL_STATE_DIR" "$SH_LOG_DIR"
[ "$fails" -eq 0 ] && echo "collect-logsignal PASS" || { echo "FAIL ($fails)"; exit 1; }
