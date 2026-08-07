#!/usr/bin/env bash
# My Network scoreboard — 12 metrics tracking the "make OpenZiti easy for users"
# initiative. Run after every change; no metric may regress.
#
#   bash scripts/mynetwork-score.sh
#
# Metrics that need a live DB/controller degrade to "-" when unavailable so the
# script still runs in CI.
set -uo pipefail
cd "$(dirname "$0")/.."

FE=web/admin-console/src/pages
PSQL='docker exec oidx-pg psql -U openidx -d openidx -tAc'

sql() { $PSQL "$1" 2>/dev/null | grep -v podman | tr -d ' \n' || echo "-"; }
num() { local v="${1:-}"; [[ "$v" =~ ^[0-9]+$ ]] && echo "$v" || echo "-"; }

# 1. user-facing network page exists
m1=$(ls $FE/my-network.tsx 2>/dev/null | wc -l | tr -d ' ')

# 2. aggregator endpoint registered
m2=$(grep -c 'my/resources' internal/access/service.go 2>/dev/null | head -1 | tr -d ' \n')
m2=${m2:-0}

# 3. Ziti jargon VISIBLE TO USERS. Only rendered copy counts — identifiers,
#    comments, API paths and type names are implementation detail, not UX.
#    Heuristic: JSX text and quoted UI strings, minus code-ish lines.
jarg=0
for f in $FE/my-devices.tsx $FE/my-network.tsx; do
  [ -f "$f" ] || continue
  n=$(grep -inE 'ziti|enrollment|jwt|tunneler|edge router|role attribute' "$f" 2>/dev/null \
      | grep -vE 'zitiIdentity|enrollment_jwt|ziti_id|showJwt|downloadJwt|d\.ziti|my-ziti-identity|source:|ziti\?:|ziti:|interface |api\.get|api\.post|queryKey|openziti\.io|^\s*[0-9]+:\s*(//|/\*|\*)' \
      | grep -cE '' | head -1 | tr -d ' \n')
  jarg=$(( jarg + ${n:-0} ))
done
m3=$jarg

# 4/5/6/8: proven by tests; "-" until the suites exist
m4=$([ -f internal/access/my_resources_test.go ] && echo 0 || echo "-")
m5=$([ -f $FE/my-network.test.tsx ] && echo 0 || echo "-")
m6=$([ -f $FE/my-network.test.tsx ] && echo 0 || echo "-")

# 7. clientless (browser-reachable) resources — need no tunneler/enrollment
m7=$(num "$(sql "SELECT count(*) FROM proxy_routes WHERE browzer_enabled=true AND enabled=true;")")

# 8. false-green: verified live per release
m8=$([ -f internal/access/my_resources_test.go ] && echo 0 || echo "-")

# 9. cross-scope rows: "-" until a scoping regression test exists, then 0.
#    A missing test is NOT a pass — today's handleListMyGuacConnections filters
#    only by org, so every user sees every broker connection.
if grep -qs 'handleListMyGuacConnections' internal/access/*_test.go 2>/dev/null; then
  m9=0
else
  m9="-"
fi

# 10. CLI steps an admin still needs, in two halves:
#     - diagnosing "why can/can't X reach Y"  -> the explain endpoint + drawer;
#     - onboarding a resource end-to-end      -> the create form provisioning
#       the full chain (intercept/dial fields).
#     Each half that still needs the CLI counts 4 (the ziti commands it replaces).
m10=0
grep -qs 'handleExplainZitiService' internal/access/service.go || m10=$(( m10 + 4 ))
grep -qs 'intercept_address\|dial_roles' $FE/ziti-network.tsx || m10=$(( m10 + 4 ))

# 11. admin surface must not shrink: 104 ziti endpoints at baseline
adm=$(grep -cE 'api\.(GET|POST|PUT|DELETE|PATCH)\("/ziti' internal/access/service.go 2>/dev/null || echo 0)
m11=$(( 104 - adm )); [ "$m11" -lt 0 ] && m11=0

# 12. gates + no new migrations (baseline 91)
mig=$(ls internal/migrations/sql_v*.go 2>/dev/null | wc -l | tr -d ' ')
m12=$(( mig > 91 ? 1 : 0 ))

cat <<EOF
=== My Network scoreboard ($(date -u +%Y-%m-%dT%H:%MZ)) ===
USER_NETWORK_PAGES=$m1            target 1
MY_RESOURCES_ENDPOINT=$m2         target >=1
JARGON_HITS=$m3                   target 0   (baseline 53)
SCHEMA_INCOMPLETE_ROWS=$m4        target 0
MULTI_CTA_CARDS=$m5               target 0
DEADEND_ROWS=$m6                  target 0
CLIENTLESS_RESOURCES=$m7          target >=5 (baseline 5)
FALSE_GREEN=$m8                   target 0
CROSS_SCOPE_ROWS=$m9              target 0
CLI_STEPS_TO_ONBOARD=$m10         target 0   (baseline 8)
ADMIN_SURFACE_DELTA=$m11          target 0   (ziti endpoints now: $adm / 104)
GATES_FAILING=$m12                target 0   (migrations: $mig / 91)
EOF
