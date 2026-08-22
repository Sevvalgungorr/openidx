#!/usr/bin/env bash
# Verifies scripts/selfheal/lib.sh helpers: finding emission is valid JSON,
# fingerprints are stable + normalized, mode/kill-switch read correctly.
set -uo pipefail
cd "$(dirname "$0")"
export SELFHEAL_STATE_DIR="$(mktemp -d)"
# shellcheck disable=SC1091
. ./lib.sh
fails=0
ok(){ echo "  OK    $1"; }
bad(){ echo "  FAIL  $1"; fails=$((fails+1)); }

# sh_finding emits one valid JSON object with the required keys.
line=$(sh_finding ops warn "ops:unit-down:oidx-oauth" oidx-oauth "unit down" '{"port":8006}' restart_unit)
echo "$line" | python3 -c 'import sys,json; d=json.load(sys.stdin); assert d["class"]=="ops" and d["severity"]=="warn" and d["fingerprint"]=="ops:unit-down:oidx-oauth" and d["service"]=="oidx-oauth" and d["suggested_action"]=="restart_unit" and d["data"]["port"]==8006' \
  && ok "sh_finding valid json" || bad "sh_finding json"

# fingerprints normalize volatile tokens (uuids, timestamps, hex) to a stable sig.
a=$(sh_fingerprint bug "failed to query delivery bbbbbbbb-0000-4000-8000-0000000000ff")
b=$(sh_fingerprint bug "failed to query delivery 11111111-2222-3333-4444-555555555555")
[ "$a" = "$b" ] && ok "fingerprint stable across ids" || bad "fingerprint differs: $a vs $b"

# mode defaults to observe; kill-switch detected.
[ "$(sh_mode)" = "observe" ] && ok "mode defaults observe" || bad "mode default"
touch "$SELFHEAL_STATE_DIR/DISABLE"
sh_killed && ok "kill-switch detected" || bad "kill-switch"
rm -f "$SELFHEAL_STATE_DIR/DISABLE"
sh_killed && bad "kill-switch stuck on" || ok "kill-switch clears"

rm -rf "$SELFHEAL_STATE_DIR"
[ "$fails" -eq 0 ] && echo "lib.test.sh PASS" || { echo "lib.test.sh FAIL ($fails)"; exit 1; }
