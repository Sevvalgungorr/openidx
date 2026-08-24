#!/usr/bin/env bash
# Verifies the synthetic connect probe emits a single JSON health line with
# status=pass when the chain is healthy (webapps 200, guacd running, broker-status
# 401 auth-gated == OK) and status=fail when any link is broken. All probes
# injected -- read-only, never opens a session.
set -uo pipefail
cd "$(dirname "$0")"
export SELFHEAL_STATE_DIR="$(mktemp -d)"
fails=0; ok(){ echo "  OK  $1"; }; bad(){ echo "  FAIL  $1"; fails=$((fails+1)); }

# healthy chain
export SH_PAM_WEB_PROBE='_web'; _web(){ echo 200; }
export SH_PAM_CTR_PROBE='_ctr'; _ctr(){ echo running; }
export SH_PAM_BROKER_STATUS_PROBE='_brk'; _brk(){ echo 401; }   # auth-gated == OK
export -f _web _ctr _brk
out=$(bash ./probe-pamconnect.sh); rc=$?
echo "$out" | grep -q '"probe":"pamconnect"' && ok "emits pamconnect health line" || bad "no health line"
echo "$out" | grep -q '"status":"pass"' && ok "status=pass on healthy chain" || bad "not pass on healthy chain"
[ "$rc" -eq 0 ] && ok "exit 0 on pass" || bad "nonzero exit on pass"
[ -f "$SELFHEAL_STATE_DIR/pamconnect.json" ] && ok "writes pamconnect.json for dashboard" || bad "no pamconnect.json"

# wedged guacd -> fail
export SH_PAM_CTR_PROBE='_absent'; _absent(){ echo absent; }; export -f _absent
out2=$(bash ./probe-pamconnect.sh); rc2=$?
echo "$out2" | grep -q '"status":"fail"' && ok "status=fail when guacd not running" || bad "not fail on wedged guacd"
[ "$rc2" -ne 0 ] && ok "nonzero exit on fail" || bad "exit 0 despite fail"

# webapp down -> fail
export SH_PAM_CTR_PROBE='_ctr'; export SH_PAM_WEB_PROBE='_down'; _down(){ echo 000; }; export -f _down
out3=$(bash ./probe-pamconnect.sh)
echo "$out3" | grep -q '"status":"fail"' && ok "status=fail when webapp unreachable" || bad "not fail on webapp down"

rm -rf "$SELFHEAL_STATE_DIR"
[ "$fails" -eq 0 ] && echo "probe-pamconnect PASS" || { echo "probe-pamconnect FAIL ($fails)"; exit 1; }
