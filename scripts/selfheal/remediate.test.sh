#!/usr/bin/env bash
# The remediator is the ONLY mutation point, so its safety envelope is the most
# important thing to test: mode gate, kill-switch, dry-run, anti-flap, and
# health-verify-with-rollback. The actual system actions are injected
# (SH_ACT_RESTART / SH_ACT_HEALTH) so nothing real is touched.
set -uo pipefail
cd "$(dirname "$0")"
export SELFHEAL_STATE_DIR="$(mktemp -d)"
fails=0; ok(){ echo "  OK  $1"; }; bad(){ echo "  FAIL  $1"; fails=$((fails+1)); }
FIND='{"fingerprint":"ops:unit-down:oidx-oauth","class":"ops","severity":"high","service":"oidx-oauth","suggested_action":"restart_unit","data":{"port":8006}}'

# Injected actions record calls; health returns from a file we control.
export SH_ACT_RESTART='_r'; _r(){ echo "restart:$1" >> "$SELFHEAL_STATE_DIR/acts"; }
export SH_ACT_HEALTH='_h';  _h(){ cat "$SELFHEAL_STATE_DIR/healthret" 2>/dev/null || echo up; }
export -f _r _h

# observe mode -> records intent, never acts.
echo "$FIND" | SELFHEAL_MODE=observe bash ./remediate.sh > /tmp/o1
[ ! -f "$SELFHEAL_STATE_DIR/acts" ] && ok "observe: no action" || bad "observe acted"

# kill-switch -> no action even in tier0.
touch "$SELFHEAL_STATE_DIR/DISABLE"
echo "$FIND" | SELFHEAL_MODE=tier0 bash ./remediate.sh > /tmp/o2
[ ! -f "$SELFHEAL_STATE_DIR/acts" ] && ok "kill-switch: no action" || bad "acted despite kill-switch"
rm -f "$SELFHEAL_STATE_DIR/DISABLE"

# tier0 + healthy-after -> restart happens once, recovery recorded.
echo up > "$SELFHEAL_STATE_DIR/healthret"
echo "$FIND" | SELFHEAL_MODE=tier0 bash ./remediate.sh > /tmp/o3
grep -q 'restart:oidx-oauth' "$SELFHEAL_STATE_DIR/acts" && ok "tier0 restarted unit" || bad "no restart in tier0"
# actions.jsonl gets a "recovered" history line for the panel.
grep -q '"result":"recovered"' "$SELFHEAL_STATE_DIR/actions.jsonl" && ok "recorded recovered action" || bad "no actions.jsonl recovered line"

# kill-switch path records a "halted" action.
: > "$SELFHEAL_STATE_DIR/actions.jsonl"
touch "$SELFHEAL_STATE_DIR/DISABLE"
echo "$FIND" | SELFHEAL_MODE=tier0 bash ./remediate.sh >/dev/null
grep -q '"result":"halted"' "$SELFHEAL_STATE_DIR/actions.jsonl" && ok "recorded halted action" || bad "no halted action line"
rm -f "$SELFHEAL_STATE_DIR/DISABLE"

# anti-flap: exceed K=3 -> further attempts escalate (no more restarts).
: > "$SELFHEAL_STATE_DIR/acts"
for i in 1 2 3 4 5; do echo "$FIND" | SELFHEAL_MODE=tier0 bash ./remediate.sh >/dev/null; done
rc=$(grep -c 'restart:oidx-oauth' "$SELFHEAL_STATE_DIR/acts" || true)
[ "$rc" -le 3 ] && ok "anti-flap capped restarts at K=3 ($rc)" || bad "anti-flap failed ($rc)"

# dry-run -> prints intent, never calls the action.
: > "$SELFHEAL_STATE_DIR/acts"
echo "$FIND" | SELFHEAL_MODE=tier0 bash ./remediate.sh --dry-run > /tmp/o5
grep -qi 'would' /tmp/o5 && [ ! -s "$SELFHEAL_STATE_DIR/acts" ] && ok "dry-run: intent only" || bad "dry-run acted"

rm -rf "$SELFHEAL_STATE_DIR"
[ "$fails" -eq 0 ] && echo "remediate PASS" || { echo "FAIL ($fails)"; exit 1; }
