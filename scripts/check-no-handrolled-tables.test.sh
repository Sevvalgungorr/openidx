#!/usr/bin/env bash
# Mutation test for the hand-rolled-tables guard: a page with a raw <table> must
# be flagged; a page using the <Table> component must not. The last case proves
# --enforce actually goes red on an offender, so the guard can never be a
# silent no-op.
set -uo pipefail
cd "$(dirname "$0")/.."
fails=0; ok(){ echo "  OK  $1"; }; bad(){ echo "  FAIL  $1"; fails=$((fails+1)); }
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

cat > "$tmp/bad.tsx" <<'TSX'
export default function Bad() {
  return <table><tbody><tr><td>x</td></tr></tbody></table>
}
TSX
cat > "$tmp/good.tsx" <<'TSX'
import { Table, TableBody, TableRow, TableCell } from '@/components/ui/table'
export default function Good() {
  return <Table><TableBody><TableRow><TableCell>x</TableCell></TableRow></TableBody></Table>
}
TSX

out=$(SH_PAGES_DIR="$tmp" bash scripts/check-no-handrolled-tables.sh)
echo "$out" | grep -q 'bad.tsx' && ok "flags a hand-rolled <table>" || bad "missed the bad page"
echo "$out" | grep -q 'good.tsx' && bad "flagged a <Table> component page" || ok "ignores a <Table> page"
echo "$out" | grep -q 'handrolled-tables offenders: 1' && ok "reports the offender count" || bad "wrong offender count"

SH_PAGES_DIR="$tmp" bash scripts/check-no-handrolled-tables.sh --enforce >/dev/null 2>&1 \
  && bad "enforce did not fail" || ok "enforce fails on offender"

[ "$fails" -eq 0 ] && echo "check-no-handrolled-tables PASS" || { echo "FAIL ($fails)"; exit 1; }
