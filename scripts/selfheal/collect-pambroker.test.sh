#!/usr/bin/env bash
# Verifies collect-pambroker flags a wedged broker (webapp !=200 but container
# running -> restart_pam_broker), a fully-down broker (container absent ->
# escalate/no action), stays silent when webapps are 200, and treats an
# auth-gated (401) access-service broker-status as OK. All probes injected.
set -uo pipefail
cd "$(dirname "$0")"
export SELFHEAL_STATE_DIR="$(mktemp -d)"
fails=0; ok(){ echo "  OK  $1"; }; bad(){ echo "  FAIL  $1"; fails=$((fails+1)); }

# --- wedged direct broker: webapp 000, container running; ziti healthy 200 ---
export SH_PAM_WEB_PROBE='_web'; _web(){ case "$1" in *10090*) echo 000;; *) echo 200;; esac; }
export SH_PAM_CTR_PROBE='_ctr'; _ctr(){ echo running; }
export SH_PAM_BROKER_PROBE='_brk'; _brk(){ echo "401 {\"error\":\"missing authorization header\"}"; }
export -f _web _ctr _brk
out=$(bash ./collect-pambroker.sh)
echo "$out" | grep -q '"fingerprint":"ops:pam-broker-wedged:direct"' && ok "flags wedged direct broker" || bad "missed wedged direct broker"
echo "$out" | grep -q '"suggested_action":"restart_pam_broker"' && ok "suggests restart_pam_broker" || bad "no restart_pam_broker action"
echo "$out" | grep -q '"container":"pam-guacamole"' && ok "carries webapp container in data" || bad "missing container in data"
echo "$out" | grep -q 'ziti' && bad "reported healthy ziti stack" || ok "silent on healthy ziti"
# auth-gated 401 must NOT raise a broker-status finding
echo "$out" | grep -q 'pam-broker-status' && bad "raised finding on auth-gated 401" || ok "401 broker-status treated as OK"

# --- broker fully down: webapp 000 AND container absent -> down (no auto action) ---
export SH_PAM_CTR_PROBE='_absent'; _absent(){ echo absent; }; export -f _absent
out2=$(bash ./collect-pambroker.sh)
echo "$out2" | grep -q '"fingerprint":"ops:pam-broker-down:direct"' && ok "flags fully-down broker" || bad "missed fully-down broker"
echo "$out2" | grep -q '"fingerprint":"ops:pam-broker-down:direct".*"suggested_action":""' && ok "down broker escalates (no action)" || bad "down broker should have empty action"

# --- all webapps 200 + 401 broker-status -> silent ---
export SH_PAM_WEB_PROBE='_allup'; _allup(){ echo 200; }; export -f _allup
export SH_PAM_CTR_PROBE='_ctr'
[ -z "$(bash ./collect-pambroker.sh)" ] && ok "silent when all brokers healthy" || bad "noise when healthy"

# --- access-service reports an unhealthy broker (200 body) -> finding ---
export SH_PAM_BROKER_PROBE='_brkbad'; _brkbad(){ echo '200 {"brokers":[{"name":"direct","status":"unhealthy"}]}'; }; export -f _brkbad
out3=$(bash ./collect-pambroker.sh)
echo "$out3" | grep -q '"fingerprint":"ops:pam-broker-status-unhealthy"' && ok "flags access-service unhealthy broker" || bad "missed access-service unhealthy broker"

rm -rf "$SELFHEAL_STATE_DIR"
[ "$fails" -eq 0 ] && echo "collect-pambroker PASS" || { echo "collect-pambroker FAIL ($fails)"; exit 1; }
