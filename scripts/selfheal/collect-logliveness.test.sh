#!/usr/bin/env bash
# A log that has not been written to within the freshness window is itself a
# fault (service wedged / not logging). Verify a stale log is flagged and a
# fresh one is not.
set -uo pipefail
cd "$(dirname "$0")"
export SELFHEAL_STATE_DIR="$(mktemp -d)"; export SH_LOG_DIR="$(mktemp -d)"
export SH_LOG_STALE_SECS=60
fails=0; ok(){ echo "  OK  $1"; }; bad(){ echo "  FAIL  $1"; fails=$((fails+1)); }

echo x > "$SH_LOG_DIR/oauth.log"           # fresh (just now)
echo x > "$SH_LOG_DIR/identity.log"; touch -d '10 minutes ago' "$SH_LOG_DIR/identity.log"  # stale
out=$(bash ./collect-logliveness.sh)
echo "$out" | grep -q '"fingerprint":"ops:log-stale:identity"' && ok "flags stale log" || bad "missed stale"
echo "$out" | grep -q 'oauth' && bad "flagged fresh log" || ok "silent on fresh"

rm -rf "$SELFHEAL_STATE_DIR" "$SH_LOG_DIR"
[ "$fails" -eq 0 ] && echo "collect-logliveness PASS" || { echo "FAIL ($fails)"; exit 1; }
