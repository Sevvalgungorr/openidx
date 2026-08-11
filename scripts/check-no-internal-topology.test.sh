#!/usr/bin/env bash
# Verifies scripts/check-no-internal-topology.sh actually detects what it claims.
#
# This test exists because the first version of that script used an invalid
# grep flag (-N). Every invocation errored out and matched NOTHING, so the
# check reported success on a repository that DID contain internal addresses.
# A guard that cannot fail is worse than no guard: it manufactures confidence.
# So the cases below assert BOTH directions -- real leaks must be caught, and
# documentation ranges must not be.
set -uo pipefail
cd "$(dirname "$0")"
CHECK="./check-no-internal-topology.sh"
fails=0

run_on() { # <content> -> 0 if the script WOULD flag this line
  local pat allow found
  pat=$(sed -n "s/^PATTERN='\(.*\)'$/\1/p" "$CHECK")
  allow=$(sed -n "s/^ALLOW='\(.*\)'$/\1/p" "$CHECK")
  [ -n "$pat" ] && [ -n "$allow" ] || { echo "could not extract PATTERN/ALLOW"; return 2; }
  # Same two stages the script applies: match private addresses, then drop the
  # conventional examples. Testing only stage 1 would misreport every result.
  found=$(printf '%s' "$1" | grep -Po "$pat" 2>/dev/null | grep -Pv "($allow)" || true)
  [ -n "$found" ]
}

must_catch() {
  if run_on "$1"; then echo "  catch  OK    $1"
  else echo "  catch  FAIL  $1  <-- real internal address slipped through"; fails=$((fails+1)); fi
}

must_ignore() {
  if run_on "$1"; then echo "  ignore FAIL  $1  <-- false positive"; fails=$((fails+1))
  else echo "  ignore OK    $1"; fi
}

echo "must be caught (these are the values actually leaked into this repo):"
# These are the exact values that leaked into this repo today. They live here
# on purpose, as fixtures proving the checker catches them, so each line is
# marked topology-ok -- otherwise the checker would flag its own test.
must_catch 'gw = ipaddress.ip_address("192.168.31.1")'   # topology-ok
must_catch 'req.Header.Set("X-Forwarded-For", "10.10.2.22")'  # topology-ok
must_catch "target_host: '192.168.31.100'"               # topology-ok
must_catch '"192.168.31.64/26","192.168.31.128/25"'      # topology-ok
must_catch 'proxy: 172.20.5.8'                           # topology-ok

echo "must be ignored (documentation ranges and generic CIDRs):"
must_ignore 'real remote is 203.0.113.9'
must_ignore 'expected 198.51.100.7'
must_ignore 'example 192.0.2.1'
must_ignore '"whitelist":["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16"]'
must_ignore 'listen 127.0.0.1:8080'
must_ignore 'version 1.10.2.22 of the library'

echo "the ALLOW filter must not swallow a real leak (both stages together):"
for v in '192.168.31.1' '10.10.2.22' '172.20.5.8'; do   # topology-ok
  if printf '%s' "$v" | grep -Pq "$(sed -n "s/^PATTERN='\(.*\)'$/\1/p" "$CHECK")" \
     && ! printf '%s' "$v" | grep -Pq "$(sed -n "s/^ALLOW='\(.*\)'$/\1/p" "$CHECK")"; then
    echo "  2stage OK    $v"
  else echo "  2stage FAIL  $v  <-- ALLOW filter swallowed a real address"; fails=$((fails+1)); fi
done
for v in '192.168.1.1' '10.0.0.5' '10.0.2.2' '172.17.0.1'; do
  if printf '%s' "$v" | grep -Pq "$(sed -n "s/^ALLOW='\(.*\)'$/\1/p" "$CHECK")"; then
    echo "  2stage OK    $v (conventional, allowed)"
  else echo "  2stage FAIL  $v  <-- conventional example would be flagged"; fails=$((fails+1)); fi
done

# A guard that reports success while doing nothing is the exact failure this
# file was written for, so prove the check can still go red.
echo "the script must be able to FAIL (guard against a silent no-op):"
canary="../scripts/.topology-canary-$$.txt"
printf 'gateway 192.168.31.1\n' > "$canary"   # topology-ok
# --all sweeps tracked+untracked working tree; --staged only sees the index,
# so the canary is checked in the mode that can actually observe it.
if $CHECK --all >/dev/null 2>&1; then
  echo "  canary FAIL  <-- check passed with a planted internal address"; fails=$((fails+1))
else
  echo "  canary OK    (planted address made it go red)"
fi
rm -f "$canary"

if [ "$fails" -ne 0 ]; then echo "FAILURES: $fails"; exit 1; fi
echo "ALL PASS"
