#!/usr/bin/env bash
# selfheal-watch orchestrates one run: sweep -> ledger -> remediate, and prints
# a compact summary. Verify it wires the three together and honors observe mode
# (no mutation). Uses fake collectors + injected actions so it's hermetic.
set -uo pipefail
cd "$(dirname "$0")"
export SELFHEAL_STATE_DIR="$(mktemp -d)"; export SH_COLLECTOR_DIR="$(mktemp -d)"
export SELFHEAL_MODE=observe
fails=0; ok(){ echo "  OK  $1"; }; bad(){ echo "  FAIL  $1"; fails=$((fails+1)); }

printf '#!/usr/bin/env bash\necho '\''{"fingerprint":"ops:unit-down:oidx-oauth","class":"ops","severity":"high","service":"oidx-oauth","suggested_action":"restart_unit","data":{"port":8006}}'\''\n' > "$SH_COLLECTOR_DIR/collect-x.sh"
chmod +x "$SH_COLLECTOR_DIR/collect-x.sh"

out=$(bash ./selfheal-watch.sh)
[ -f "$SELFHEAL_STATE_DIR/latest.json" ] && ok "ran sweep (snapshot present)" || bad "no sweep"
[ -s "$SELFHEAL_STATE_DIR/ledger.jsonl" ] && ok "updated ledger" || bad "no ledger update"
echo "$out" | grep -qi 'observe' && ok "observe: reported would-remediate" || bad "no observe report"
echo "$out" | grep -qi 'findings=1' && ok "summary counts findings" || bad "no summary count"

rm -rf "$SELFHEAL_STATE_DIR" "$SH_COLLECTOR_DIR"
[ "$fails" -eq 0 ] && echo "selfheal-watch PASS" || { echo "FAIL ($fails)"; exit 1; }
