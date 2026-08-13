#!/usr/bin/env bash
# Fault matrix: for each origin failure mode, assert the pipeline's REACTION.
#
# The real OpenSecOps origin belongs to another team and currently flaps: on
# 2026-08-13 it answered /api correctly on only 4 of 60 tries. Waiting for
# someone else to fix that is not a measurable loop, and testing against a
# moving target gives results that cannot be reproduced. So the outage is
# treated as an INPUT and reproduced locally, while the metric is our own
# reaction to it.
#
# NOT DETERMINISTIC BY DESIGN: the flapping case models the measured 7%
# success rate, and 40 retries still miss ~5% of the time (0.93^40). Measured
# 11/12 over repeated runs. A single 3/4 result is therefore expected noise,
# not a regression -- re-run before concluding anything. Making it pass 100%
# would mean retrying forever, which hides a genuinely dead backend.
# Repo root, so the script works from any checkout (it parses the pipeline YAML).
cd "$(dirname "$0")/../../.." || exit 1
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PORT=19311
extract(){ python3 - "$1" <<'PY'
import yaml,sys
d=yaml.safe_load(open('deployments/ci/azure-pipelines-ziti.yml'))
want=sys.argv[1]
def st(o):
    if isinstance(o,dict):
        if 'script' in o and want in str(o.get('displayName','')): yield o
        for v in o.values(): yield from st(v)
    elif isinstance(o,list):
        for v in o: yield from st(v)
s=list(st(d))[0]['script']
s=s.replace('ip="$(getent hosts "$ZITI_INTERCEPT_DNS" | awk \'{print $1}\' | head -1)"','ip=127.0.0.1')
print('SECOPS_HOST=localhost\nSECOPS_PORT='+__import__('os').environ['PORT']+'\nZITI_INTERCEPT_DNS=secops.ziti')
print(s)
PY
}
# the step uses https; the fake origin is http, so rewrite the scheme
prep(){ extract "$1" | sed 's#https://\${SECOPS_HOST}#http://${SECOPS_HOST}#g; s#--resolve [^ ]*##g' ; }

run(){ # mode expected_rc must_contain
  local mode="$1" exp="$2" needle="$3"
  MODE=$mode python3 "$(dirname "$0")/fake-origin.py" $PORT & local pid=$!
  sleep 0.6
  PORT=$PORT prep connectivity > "$WORK/step.sh"
  bash "$WORK/step.sh" >"$WORK/out.txt" 2>&1; local rc=$?
  kill $pid 2>/dev/null; wait $pid 2>/dev/null
  local okrc=0 okmsg=0
  [ "$rc" = "$exp" ] && okrc=1
  grep -qi "$needle" "$WORK/out.txt" && okmsg=1
  printf "%-10s rc=%s(bekl %s)%s  mesaj[%s]%s\n" "$mode" "$rc" "$exp" \
    "$([ $okrc = 1 ] && echo ' OK' || echo ' HATA')" "$needle" \
    "$([ $okmsg = 1 ] && echo ' OK' || echo ' HATA')"
  [ $okrc = 1 ] && [ $okmsg = 1 ] && return 0 || { sed 's/^/      /' "$WORK/out.txt"|tail -4; return 1; }
}
pass=0; tot=0
for spec in "healthy|0|reachable over the overlay" \
            "dead_api|1|APPLICATION PROBLEM" \
            "flapping|0|API routed" \
            "no_route|1|OVERLAY PROBLEM"; do
  IFS='|' read -r m e n <<<"$spec"; tot=$((tot+1))
  if [ "$m" = no_route ]; then
    PORT=$PORT prep connectivity > "$WORK/step.sh"   # nothing listening
    bash "$WORK/step.sh" >"$WORK/out.txt" 2>&1; rc=$?
    if [ "$rc" = 1 ] && grep -qi "OVERLAY PROBLEM" "$WORK/out.txt"; then
      echo "no_route   rc=1(bekl 1) OK  mesaj[OVERLAY PROBLEM] OK"; pass=$((pass+1))
    else echo "no_route   HATA rc=$rc"; tail -3 "$WORK/out.txt"|sed 's/^/      /'; fi
    continue
  fi
  run "$m" "$e" "$n" && pass=$((pass+1))
done
echo "FAULT_MATRIX=$pass/$tot"
