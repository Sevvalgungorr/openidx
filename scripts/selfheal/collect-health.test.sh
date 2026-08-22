#!/usr/bin/env bash
# Verifies collect-health emits a finding when a probe reports DOWN and stays
# silent when everything is up. Uses injected fake probes (no real box needed).
set -uo pipefail
cd "$(dirname "$0")"
export SELFHEAL_STATE_DIR="$(mktemp -d)"
fails=0; ok(){ echo "  OK  $1"; }; bad(){ echo "  FAIL  $1"; fails=$((fails+1)); }

# Fake probe: oidx-oauth down, all else up. The collector calls SH_HEALTH_PROBE.
export SH_HEALTH_PROBE='_fake'; _fake(){ # <unit> <port> -> prints "up|down active|dead <restarts>"
  case "$1" in oidx-oauth) echo "down dead 4";; *) echo "up active 0";; esac; }
export -f _fake
out=$(bash ./collect-health.sh)
echo "$out" | grep -q '"fingerprint":"ops:unit-down:oidx-oauth"' && ok "flags down unit" || bad "missing down finding"
echo "$out" | grep -q 'oidx-identity' && bad "reported healthy unit" || ok "silent on healthy"
echo "$out" | grep -q '"suggested_action":"restart_unit"' && ok "suggests restart" || bad "no action"

# All up -> no findings.
export SH_HEALTH_PROBE='_allup'; _allup(){ echo "up active 0"; }; export -f _allup
[ -z "$(bash ./collect-health.sh)" ] && ok "no findings when healthy" || bad "noise when healthy"

rm -rf "$SELFHEAL_STATE_DIR"
[ "$fails" -eq 0 ] && echo "collect-health PASS" || { echo "collect-health FAIL ($fails)"; exit 1; }
