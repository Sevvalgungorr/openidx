#!/usr/bin/env bash
# One self-heal run: sweep collectors -> update ledger -> feed Tier-0 findings
# to the remediator -> print a compact summary. This is what the /selfheal-watch
# Claude routine invokes each cycle; the Claude side reads the summary + ledger
# and only does deep analysis / opens a triage when a finding is new or unhealed.
set -uo pipefail
cd "$(dirname "$0")"; . ./lib.sh

findings=$(bash ./sweep.sh)                 # writes latest.json, echoes finding lines
printf '%s\n' "$findings" | grep -q . && printf '%s\n' "$findings" | bash ./ledger.sh
rem=$(printf '%s\n' "$findings" | bash ./remediate.sh)

n=$(printf '%s\n' "$findings" | grep -c . || true)
crit=$(printf '%s\n' "$findings" | grep -c '"severity":"crit"' || true)
echo "selfheal-watch: mode=$(sh_mode) findings=$n crit=$crit"
[ -n "$rem" ] && printf '%s\n' "$rem" | sed 's/^/  remediate: /'
echo "  ledger: $SELFHEAL_STATE_DIR/ledger.jsonl"
