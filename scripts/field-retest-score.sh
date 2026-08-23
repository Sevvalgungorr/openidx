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
cd "$(dirname "$0")/.." || exit 1

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
#    Counted as a defect while the badge prints a percent unconditionally.
if [ -f "$FLEET" ]; then
  u="$(awk '/function ComplianceBadge/,/^}/' "$FLEET" | grep -c "unknown" || true)"
else u=0; fi
chk UNKNOWN_HAS_GUARD "$u" ">=1" "$([ "$u" -ge 1 ] && echo 1 || echo 0)"

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

# 7. Flags the step body treats as switchable must be passed as macros, or the
#    documented switch silently does nothing (the UPLOAD_SBOM defect).
s="$(python3 - <<'PYEOF' 2>/dev/null || echo 99
import re
s=open('deployments/ci/azure-pipelines-ziti.yml').read()
lit=set(re.findall(r'^\s{6}([A-Z_]+):\s*"(?:true|false)"\s*$',s,re.M))
flags=set(re.findall(r'\$\{([A-Z_]+):-(?:false|true)\}',s))
print(len([k for k in lit if k in flags]))
PYEOF
)"
chk SHADOWED_FLAGS "$s" 0 "$([ "$s" = 0 ] && echo 1 || echo 0)"

# 8. Live probe, opt-in: proves the header the browser actually receives,
#    rather than the one we believe we configured.
if [ "${LIVE:-0}" = "1" ]; then
  h="$(curl -sI --max-time 10 https://openidx.tdv.org/guacamole/ 2>/dev/null | grep -i '^content-security-policy' || true)"
  if [ -z "$h" ]; then chk LIVE_GUAC_CSP "olculemedi" "unsafe-eval" 0
  else
    echo "$h" | grep -qi 'unsafe-eval' && chk LIVE_GUAC_CSP "unsafe-eval VAR" "unsafe-eval" 1 \
                                       || chk LIVE_GUAC_CSP "unsafe-eval YOK" "unsafe-eval" 0
  fi
fi

echo "SCORE=${pass}/${total}"
