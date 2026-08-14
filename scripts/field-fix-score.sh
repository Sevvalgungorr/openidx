#!/usr/bin/env bash
# Scoreboard for the field-bug + CI-coverage loop.
#
# Prints KEY=VALUE lines and one scalar SCORE=n/9. Re-run after every change
# and paste into the PR body. A metric that cannot be measured prints
# UNKNOWN and counts as NOT at target -- never as a pass.
set -uo pipefail
cd "$(dirname "$0")/.."
ok=0; tot=0
chk(){ # name value target pass
  tot=$((tot+1)); [ "$4" = 1 ] && ok=$((ok+1))
  printf '%-26s %-14s hedef %-12s %s\n' "$1" "$2" "$3" "$([ "$4" = 1 ] && echo OK || echo EKSIK)"
}

# 1. Fault matrix: a RATIO, so adding a case is never punished.
m="$(bash deployments/ci/faulttest/run-fault-matrix.sh 2>/dev/null | grep -o 'FAULT_MATRIX=[0-9]*/[0-9]*' | cut -d= -f2)"
if [ -n "$m" ] && [ "${m%/*}" = "${m#*/}" ] && [ "${m%/*}" -gt 0 ]; then mo=1; else mo=0; m="${m:-UNKNOWN}"; fi
chk FAULT_MATRIX "$m" "n/n, n>0" $mo

# 2. Coverage must not shrink: cases measured today.
# Count the specs the matrix actually RUNS, so coverage can never shrink
# unnoticed. Reading the dispatch table would over/under-count: several
# specs share one branch, and some branches are helpers.
# UNIQUE specs, because duplicating an existing case keeps the count up
# while real coverage silently drops.
cases="$(sed -n '/^for spec in /,/; do$/p' deployments/ci/faulttest/run-fault-matrix.sh \
  | grep -oE '"[a-z0-9_]+\|[0-9]+\|[^"]*"' | sort -u | wc -l)"
chk MATRIX_CASES "$cases" ">=14" "$([ "$cases" -ge 14 ] && echo 1 || echo 0)"

# 3. Prose that would run as shell.
p="$(bash scripts/check-shell-prose.sh 2>/dev/null | grep -o '[0-9]*$')"
chk PROSE_IN_SHELL "${p:-UNKNOWN}" 0 "$([ "${p:-1}" = 0 ] && echo 1 || echo 0)"

# 4. Every network step must name the cause when the overlay name fails,
#    instead of dying silently under `set -e`.
# Only lookups that ASSIGN a result can die silently (empty ip -> confusing
# downstream error). The retry loop reports its own failure, so it is excluded.
g="$(grep -c 'ip="$(getent hosts' deployments/ci/azure-pipelines-ziti.yml || true)"
r="$(grep -c 'OVERLAY NAME DID NOT RESOLVE' deployments/ci/azure-pipelines-ziti.yml || true)"
chk RESOLVE_GUARDS "$r/$g" "hepsi" "$([ "$g" -gt 0 ] && [ "$r" = "$g" ] && echo 1 || echo 0)"

# 5. Tool installs must not die numerically. Under `set -euo pipefail` a
#    failed download exits with curl's code and prints nothing at all.
#    Every tool this pipeline installs must say so by name when it is
#    missing, otherwise a scan that never ran is indistinguishable from a
#    clean one. Counting distinct tools, not messages: adding a second
#    message for one tool must not paper over a tool with none.
i="$(grep -oE '(SYFT|SEMGREP|TUNNELLER) NOT INSTALLED' deployments/ci/azure-pipelines-ziti.yml \
  | sort -u | wc -l)"
chk INSTALL_GUARDS "$i" ">=3" "$([ "$i" -ge 3 ] && echo 1 || echo 0)"

#    Scanners installed with `pip install --user` break on modern images
#    (PEP 668 refuses it outright). Measured on python3.12 in this box.
v="$(grep -c 'pip install --quiet --user' deployments/ci/azure-pipelines-ziti.yml || true)"
chk PEP668_UNSAFE_PIP "$v" 0 "$([ "$v" = 0 ] && echo 1 || echo 0)"

#    A documented switch that a pipeline variable cannot actually set is a
#    feature that silently does not exist. UPLOAD_SBOM was pinned to a
#    literal "false" in the step's env while its own message said "set
#    UPLOAD_SBOM=true to enable"; the literal shadows the variable, so the
#    upload could never be turned on and looked deliberate every run.
#    Rule: if the step body reads a flag as ${FLAG:-false}, i.e. treats it as
#    switchable, then env must pass it as a macro, not bake in a constant.
#    Measured generically so the next flag cannot repeat it.
u="$(python3 - <<'PYEOF'
import re
s=open('deployments/ci/azure-pipelines-ziti.yml').read()
lit=set(re.findall(r'^\s{6}([A-Z_]+):\s*"(?:true|false)"\s*$',s,re.M))
flags=set(re.findall(r'\$\{([A-Z_]+):-(?:false|true)\}',s))
print(len([k for k in lit if k in flags]))
PYEOF
)"
chk SHADOWED_FLAGS "$u" 0 "$([ "$u" = 0 ] && echo 1 || echo 0)"

# 6. A scan of zero files must be fatal (it looks exactly like clean code).
z="$(grep -c 'NOT SCANNED' deployments/ci/azure-pipelines-ziti.yml || true)"
chk EMPTY_SCAN_FATAL "$z" ">=1" "$([ "$z" -ge 1 ] && echo 1 || echo 0)"

# 6. Only endpoints proven to exist may be wired up.
a="$(grep -c 'imports/archive"' deployments/ci/azure-pipelines-ziti.yml || true)"
chk UNPROVEN_ENDPOINTS "$a" 0 "$([ "$a" = 0 ] && echo 1 || echo 0)"

# 7/8. Contract tests that pin the JSON the console actually reads.
if go test ./internal/oauth/ -run 'SAMLServiceProvider|EnabledDefaults' >/dev/null 2>&1; then s=PASS; so=1; else s=FAIL; so=0; fi
chk SAML_CONTRACT_TESTS "$s" PASS $so

# 9. Docs must not teach a stale count.
d="$(grep -c '11/11\|13/13' docs/ci-over-ziti-overlay.md || true)"
chk DOCS_STALE_COUNTS "$d" 0 "$([ "$d" = 0 ] && echo 1 || echo 0)"

# 10. Toolchain must carry the CVE fix.
# Read the toolchain DIRECTIVE; a comment mentioning a version is not a build.
t="$(awk '$1=="toolchain"{print $2}' go.mod)"
tp="${t#go1.25.}"
chk GO_TOOLCHAIN "${t:-UNKNOWN}" ">=go1.25.13" "$([ -n "$t" ] && [ "${tp:-0}" -ge 13 ] 2>/dev/null && echo 1 || echo 0)"

echo "SCORE=$ok/$tot"
