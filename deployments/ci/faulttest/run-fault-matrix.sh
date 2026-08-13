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
# THIS GATE IS DETERMINISTIC. It was not at first: the flapping case used the
# measured 7% success rate directly, so the matrix itself failed ~5% of runs
# (0.93^40) and reported 5/6 with nothing broken. I hit that live. A gate that
# cries wolf one run in twenty teaches people to ignore it, which is worse than
# having no gate, and "just re-run it" is how real regressions get waved through.
#
# Fixed by separating the two questions. The GATE asks a yes/no question -- does
# the loop survive a backend that only answers after many failures -- and uses a
# deterministic stand-in (success on exactly every 20th request; 20 > the old 12,
# so it still catches that defect, and < 40, so a correct loop always passes).
# The STATISTICAL question -- is 40 retries enough at the real 7% rate -- is a
# separate run and is not a pass/fail gate:
#
#   bash deployments/ci/faulttest/run-fault-matrix.sh --stat 12
#
# Nothing in the PIPELINE changed for this; the retry count stays 40. Only the
# test stopped being a coin toss.
# Repo root, so the script works from any checkout (it parses the pipeline YAML).
cd "$(dirname "$0")/../../.." || exit 1
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PORT=19311
# A minimal but realistic Semgrep report: one finding WITHOUT extra.metadata,
# which is the shape that makes a strict importer raise.
SCAN_FILE="$WORK/semgrep.json"
cat > "$SCAN_FILE" <<'JSON'
{"version":"1.173.0","results":[{"check_id":"local.rule.a","extra":{"severity":"ERROR"}}],"errors":[],"paths":{},"time":{}}
JSON
export SCAN_FILE
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
import os
# The upload step needs a report, a product id and a key. The key is a real
# secret in Azure and is NOT available here, which is exactly why the live
# import could never be verified from this box: the fake origin supplies one
# so the pipeline's REACTION to 500 is still measurable.
print('SECOPS_HOST=localhost\nSECOPS_PORT='+os.environ['PORT']+'\nZITI_INTERCEPT_DNS=secops.ziti')
print('SCAN_FILE='+os.environ.get('SCAN_FILE','/dev/null'))
print('SECOPS_PRODUCT_ID=1\nOPENSECOPS_API_KEY=fake-key-for-local-fault-injection')
print('SCAN_TYPE=semgrep\nFAIL_ON_ZERO_FINDINGS=false')
print(s)
PY
}
# the step uses https; the fake origin is http, so rewrite the scheme
prep(){ extract "$1" | sed 's#https://\${SECOPS_HOST}#http://${SECOPS_HOST}#g; s#--resolve [^ ]*##g' ; }

run(){ # mode expected_rc must_contain [step]
  local mode="$1" exp="$2" needle="$3" step="${4:-connectivity}"
  MODE=$mode python3 "$(dirname "$0")/fake-origin.py" $PORT & local pid=$!
  sleep 0.6
  PORT=$PORT prep "$step" > "$WORK/step.sh"
  bash "$WORK/step.sh" >"$WORK/out.txt" 2>&1; local rc=$?
  kill $pid 2>/dev/null; wait $pid 2>/dev/null
  local okrc=0 okmsg=0
  [ "$rc" = "$exp" ] && okrc=1
  grep -qi "$needle" "$WORK/out.txt" && okmsg=1
  printf "%-10s rc=%s(bekl %s)%s  mesaj[%s]%s\n" "$mode${4:+/$4}" "$rc" "$exp" \
    "$([ $okrc = 1 ] && echo ' OK' || echo ' HATA')" "$needle" \
    "$([ $okmsg = 1 ] && echo ' OK' || echo ' HATA')"
  [ $okrc = 1 ] && [ $okmsg = 1 ] && return 0 || { sed 's/^/      /' "$WORK/out.txt"|tail -4; return 1; }
}
# --stat N: run only the random-rate flapping case N times and report the
# miss rate. Informational; does not gate.
if [ "${1:-}" = --stat ]; then
  n="${2:-12}"; ok=0
  for i in $(seq 1 "$n"); do
    MODE=flapstat python3 "$(dirname "$0")/fake-origin.py" $PORT & pid=$!
    sleep 0.6
    PORT=$PORT prep connectivity > "$WORK/step.sh"
    if bash "$WORK/step.sh" >/dev/null 2>&1; then ok=$((ok+1)); fi
    kill $pid 2>/dev/null; wait $pid 2>/dev/null
  done
  echo "FLAP_STAT=$ok/$n (random 7% origin, 40 retries; ~5% miss is expected)"
  exit 0
fi

pass=0; tot=0
for spec in "healthy|0|reachable over the overlay" \
            "dead_api|1|APPLICATION PROBLEM" \
            "flapping|0|API routed" \
            "no_route|1|OVERLAY PROBLEM" \
            "api_500|1|SERVER-side exception|upload" \
            "healthy|0|findings parsed|upload"; do
  IFS='|' read -r m e n st <<<"$spec"; tot=$((tot+1))
  if [ "$m" = no_route ]; then
    PORT=$PORT prep connectivity > "$WORK/step.sh"   # nothing listening
    bash "$WORK/step.sh" >"$WORK/out.txt" 2>&1; rc=$?
    if [ "$rc" = 1 ] && grep -qi "OVERLAY PROBLEM" "$WORK/out.txt"; then
      echo "no_route   rc=1(bekl 1) OK  mesaj[OVERLAY PROBLEM] OK"; pass=$((pass+1))
    else echo "no_route   HATA rc=$rc"; tail -3 "$WORK/out.txt"|sed 's/^/      /'; fi
    continue
  fi
  run "$m" "$e" "$n" "$st" && pass=$((pass+1))
done
echo "FAULT_MATRIX=$pass/$tot"
# Record the result so a scoreboard can read it WITHOUT re-running a 3-minute
# matrix on every pass. Three deliberate choices:
#  - a TIMESTAMP, because a stale pass is a false green and the reader must
#    age it out rather than trust it forever;
#  - the COMMIT, because a pass proves nothing about a different tree;
#  - a FIXED /tmp path, not $TMPDIR. The first version honoured TMPDIR, which
#    is set in some shells, so writer and reader silently disagreed and the
#    scoreboard saw no evidence at all. It failed CLOSED (0, not a pass), so
#    the aging rule did its job -- but a metric that depends on the caller''"'"'s
#    environment is not a metric. FAULT_MATRIX_RESULT still overrides.
RESULT_FILE="${FAULT_MATRIX_RESULT:-/tmp/cifault/last-result}"
# The stamp is the hash of the INPUTS this matrix actually exercises, not
# HEAD. Keying on HEAD looked stricter but was wrong in a way that would have
# eroded the gate: every unrelated commit invalidated a still-valid result, so
# a 3-minute matrix had to be re-run to prove something no change had touched.
# A check that demands busywork for nothing gets skipped, and then the aging
# rule protects nothing. Keying on the inputs stays correct in both
# directions: touch the pipeline or the harness and the evidence expires
# immediately; touch anything else and it does not.
INPUT_SHA="$( { cat deployments/ci/azure-pipelines-ziti.yml \
                    deployments/ci/faulttest/fake-origin.py \
                    "$0"; } 2>/dev/null | sha256sum | cut -c1-7)"
mkdir -p "$(dirname "$RESULT_FILE")" 2>/dev/null \
  && printf '%s %s/%s %s\n' "$(date -u +%FT%TZ)" "$pass" "$tot" "$INPUT_SHA" \
     > "$RESULT_FILE"
[ "$pass" = "$tot" ]
