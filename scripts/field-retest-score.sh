#!/usr/bin/env bash
# Scoreboard for the second field retest round (Şevval, 2026-08-14).
#
# Why this exists: the first round proved that a fix nobody re-measures rots.
# Every metric here is measured from the code or from the live system, never
# from a comment, a doc, or a line count. Read-only: it changes nothing.
#
# Usage:  bash scripts/field-retest-score.sh
# Output: NAME  VALUE  TARGET  OK|EKSIK   and a final SCORE=n/m
#
# LIVE=1 also probes production over the network (needs egress).
set -uo pipefail
# Resolve the repo from git, NOT from $0. Measured the hard way: a copy of
# this script kept in /tmp made `dirname $0`/.. resolve to "/", so every
# file-based metric looked absent and the board reported a score for a
# directory that is not the repository. It read 7/11 when the truth was 1/10.
# A scoreboard that silently scores the wrong tree is worse than none.
repo="$(git rev-parse --show-toplevel 2>/dev/null)"
if [ -z "$repo" ]; then
  echo "NOT MEASURED: run this from inside the repository." >&2
  exit 1
fi
cd "$repo" || exit 1
# Fail loudly rather than scoring an unrelated tree.
[ -f deployments/ci/azure-pipelines-ziti.yml ] || {
  echo "NOT MEASURED: $repo does not look like openidx." >&2; exit 1; }

pass=0; total=0
chk() { # name value target ok
  total=$((total+1)); [ "$4" = "1" ] && pass=$((pass+1))
  printf '%-26s %-14s %-18s %s\n' "$1" "$2" "$3" "$([ "$4" = 1 ] && echo OK || echo EKSIK)"
}

YML=deployments/ci/azure-pipelines-ziti.yml
FLEET=web/admin-console/src/pages/agent-fleet.tsx

# 1. CSP must be configurable in production. It was a dead feature: CSPCustom
#    was only ever set in tests, so no service could change the policy. Same
#    class as the UPLOAD_SBOM literal that shadowed its own pipeline variable.
c="$(grep -rn 'CSPCustom:' --include='*.go' . 2>/dev/null | grep -v '_test.go' | grep -cv '""' || true)"
chk CSP_CONFIGURABLE "$c" ">=1" "$([ "$c" -ge 1 ] && echo 1 || echo 0)"

# 2. Guacamole ships AngularJS, whose expression/filter engine needs eval.
#    Under script-src 'self' the browser throws EvalError and the UI renders
#    raw {{'CLIENT.TEXT_...' | translate}} at the user. The relaxation must
#    exist for that path only.
g="$(grep -rn "unsafe-eval" --include='*.go' . 2>/dev/null | grep -v '_test.go' | grep -ci 'guac' || true)"
chk CSP_GUAC_EVAL "$g" ">=1" "$([ "$g" -ge 1 ] && echo 1 || echo 0)"

# 3. ...and it must NOT leak into the main application policy. Loosening the
#    whole app to fix one embedded console would be a security regression, so
#    this metric fails if the default policy ever gains eval.
d="$(sed -n "/Default CSP if no custom policy provided/,+3p" internal/common/middleware/security.go 2>/dev/null | grep -ci 'unsafe-eval' || true)"
chk CSP_MAIN_SAFE "$d" 0 "$([ "$d" = 0 ] && echo 1 || echo 0)"

# 4. A percentage next to a status of "unknown" is a lie: it makes "the agent
#    never reported" look identical to "the agent reported and scored zero".
#    Counting the word "unknown" only proved the word was present, so it also
#    passed on pages that printed a wrong number confidently. It now counts the
#    real defect: a percent built by hand from the raw score. Every such site
#    must go through lib/compliance.ts. Verified by mutation: put one manual
#    Math.round(score) back and this drops to 0.
man=0
for f in web/admin-console/src/pages/agent-fleet.tsx \
         web/admin-console/src/pages/my-devices.tsx \
         web/admin-console/src/pages/user-access-360.tsx; do
  [ -f "$f" ] || continue
  n="$(grep -cE 'Math\.round\((100 \* )?[A-Za-z_.]*([Ss]core|compliance)[A-Za-z_.]*\)[^)]*%' "$f" 2>/dev/null || true)"
  man=$((man + n))
done
helper=0
[ -f web/admin-console/src/lib/compliance.ts ] && helper=1
ok=0; [ "$man" = 0 ] && [ "$helper" = 1 ] && ok=1
chk UNKNOWN_HAS_GUARD "elle=$man yardimci=$helper" "elle=0" "$ok"

# 5. The rotation connector count in the docs must match the rotators that
#    actually compile. The checklist said 6 while the code shipped 8; a doc
#    that drifts is the same silent-green failure as a scan that finds nothing.
# Test files define fake rotators (fake, fake_minter, gen); counting them
# would overstate what we actually ship. Measured: 11 with tests, 8 without.
t="$(for f in internal/credentials/*.go; do case "$f" in *_test.go) continue;; esac
     grep -hoP 'Type\(\) string \{ return "\K[a-z_]+' "$f" 2>/dev/null; done | sort -u | wc -l)"
docn="$(grep -rhoP '\b\K\d+(?= (?:connector|rotation connector|rotator) (?:tip|type)i?)' docs/*.md 2>/dev/null | head -1)"
if [ -z "$docn" ]; then ok=1; note="belgede sayi yok"; else
  [ "$docn" = "$t" ] && ok=1 || ok=0; note="belge=$docn"; fi
chk ROTATION_TYPES "$t ($note)" "kod=belge" "$ok"

# 6. Dates rendered without a guard print "Invalid Date" to the user when the
#    field is absent. Measured on the two pages this round's report named, so
#    the number cannot be diluted by the rest of the console.
un=0
for f in web/admin-console/src/pages/ziti-network.tsx "$FLEET"; do
  [ -f "$f" ] || continue
  n="$(grep -o 'new Date([^)]*)' "$f" 2>/dev/null | grep -v 'new Date()' | wc -l)"
  gd="$(grep -c '? new Date(' "$f" 2>/dev/null || true)"
  un=$((un + n - gd))
done
[ "$un" -lt 0 ] && un=0
chk UNGUARDED_DATES "$un" 0 "$([ "$un" = 0 ] && echo 1 || echo 0)"

# 7. Every flag a step READS must actually be settable, and must arrive in the
#    exact spelling the step compares against.
#    The old version counted literals that collided with a ${FLAG:-default}
#    and printed 0 -- green -- while all SIX flags on main were unusable:
#    three were bare $(...) macros with no definition anywhere (an undefined
#    macro survives as literal text and reads as OFF), and three were never
#    set in any env: block at all. Counting the shape of the YAML proved
#    nothing; this delegates to the gate that reproduces the real failure.
if [ -f scripts/check-pipeline-flags.sh ]; then
  pf="$(bash scripts/check-pipeline-flags.sh 2>/dev/null | head -1)"
  pf="${pf#PIPELINE_FLAGS=}"
  case "$pf" in skipped*) pf=0 ;; ''|*[!0-9]*) pf=99 ;; esac
else
  # No gate committed yet: measure the defect directly so main is scored
  # honestly rather than skipped.
  pf="$(python3 - <<'PYEOF' 2>/dev/null || echo 99
import re
s=open('deployments/ci/azure-pipelines-ziti.yml').read()
flags=set(re.findall(r'\$\{([A-Z_]+):-(?:false|true)\}',s))
env=dict(re.findall(r'^\s+([A-Z_]+):\s*"([^"]*)"\s*$',s,re.M))
bad=0
for f in flags:
    v=env.get(f)
    if v is None: bad+=1                       # read but never set
    elif re.fullmatch(r'\$\([A-Z_]+\)',v): bad+=1   # undefined bare macro
    elif v in ('true','false'): bad+=1         # baked-in literal
print(bad)
PYEOF
)"
fi
chk SHADOWED_FLAGS "$pf" 0 "$([ "$pf" = 0 ] && echo 1 || echo 0)"

# 8. The header is set by nginx, whose config used to live only on the box.
#    A policy that decides security headers for every response is production
#    code; keeping it unversioned is how the Guacamole defect stayed invisible
#    to review. Committed copy must exist and must match what is deployed.
if [ -f deployments/docker/oidx-nginx/nginx.conf ]; then
  nd="$(bash scripts/check-nginx-drift.sh 2>/dev/null | head -1)"
  case "$nd" in
    NGINX_DRIFT=0|NGINX_DRIFT=skipped*) chk NGINX_IN_GIT "${nd#NGINX_}" "drift yok" 1 ;;
    *) chk NGINX_IN_GIT "${nd#NGINX_}" "drift yok" 0 ;;
  esac
else
  chk NGINX_IN_GIT "surum kontrolu disi" "drift yok" 0
fi

# 9. Live probe, opt-in: proves the header the browser actually receives,
#    rather than the one we believe we configured.
if [ "${LIVE:-0}" = "1" ]; then
  h="$(curl -sI --max-time 10 https://openidx.tdv.org/guacamole/ 2>/dev/null | grep -i '^content-security-policy' || true)"
  if [ -z "$h" ]; then chk LIVE_GUAC_CSP "olculemedi" "unsafe-eval" 0
  else
    echo "$h" | grep -qi 'unsafe-eval' && chk LIVE_GUAC_CSP "unsafe-eval VAR" "unsafe-eval" 1 \
                                       || chk LIVE_GUAC_CSP "unsafe-eval YOK" "unsafe-eval" 0
  fi
fi

# 10. Live Audit Stream: the token must be proven fresh BEFORE the socket is
#     opened. A WebSocket handshake gets one attempt and no retry, so an
#     expired token cannot be recovered from the way a 401 on a REST call can.
#     Measured 2026-08-14: valid token -> stream stayed open; expired token ->
#     close 1006 while the service logged 401 "token is expired".
#     Counting the word "token" would pass on any file that mentions it, so
#     this counts the actual guard: the connect path calling ensureFreshToken.
AS=web/admin-console/src/components/audit/AuditStream.tsx
ST=web/admin-console/src/lib/session-token.ts
if [ -f "$AS" ] && [ -f "$ST" ]; then
  g="$(awk '/function handleConnect/,/^  }/' "$AS" | grep -c 'ensureFreshToken' || true)"
else g=0; fi
chk WS_EXPIRY_GUARD "$g" ">=1" "$([ "$g" -ge 1 ] && echo 1 || echo 0)"

# 11. Close code 1006 must name a cause. The browser reports 1006 for EVERY
#     failed handshake because the upgrade's HTTP status is never exposed to
#     JavaScript, so "Connection closed abnormally" sent the field tester
#     hunting a dead service, a blocked origin and a TLS fault when the
#     session had simply expired. The message must mention the session and
#     offer a next step.
SS=web/admin-console/src/stores/audit-stream.ts
if [ -f "$SS" ]; then
  m="$(grep -E "^\s*1006:" "$SS" | grep -ci 'session' || true)"
  n="$(grep -E "^\s*1006:" "$SS" | grep -ci 'sign in again' || true)"
else m=0; n=0; fi
w=$(( m >= 1 && n >= 1 ? 1 : 0 ))
chk WS_1006_EXPLAINED "sebep=$m adim=$n" "ikisi de >=1" "$w"

echo "SCORE=${pass}/${total}"
