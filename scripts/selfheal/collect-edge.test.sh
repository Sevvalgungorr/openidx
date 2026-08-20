#!/usr/bin/env bash
# The edge probe must flag a path whose HTTP code is outside its allowed set
# (e.g. SPA / returning 403 = the yesterday incident) and stay silent when codes
# are acceptable. HTTP codes are injected so no live edge is needed.
set -uo pipefail
cd "$(dirname "$0")"
export SELFHEAL_STATE_DIR="$(mktemp -d)"
fails=0; ok(){ echo "  OK  $1"; }; bad(){ echo "  FAIL  $1"; fails=$((fails+1)); }

# Fake curl: SPA / returns 403 (bad), everything else 200.
export SH_EDGE_PROBE='_edge'; _edge(){ case "$1" in /) echo 403;; *) echo 200;; esac; }
export -f _edge
out=$(bash ./collect-edge.sh)
echo "$out" | grep -q '"fingerprint":"ops:edge-bad:/"' && ok "flags SPA 403" || bad "missed SPA 403"
echo "$out" | grep -q '"suggested_action":"restart_nginx"' && ok "suggests nginx restart for /" || bad "no nginx action"

export SH_EDGE_PROBE='_allok'; _allok(){ case "$1" in /api/*) echo 401;; *) echo 200;; esac; }; export -f _allok
[ -z "$(bash ./collect-edge.sh)" ] && ok "silent when codes acceptable (401 on api ok)" || bad "noise on acceptable"

rm -rf "$SELFHEAL_STATE_DIR"
[ "$fails" -eq 0 ] && echo "collect-edge PASS" || { echo "FAIL ($fails)"; exit 1; }
