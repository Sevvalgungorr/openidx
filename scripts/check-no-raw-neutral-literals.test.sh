#!/usr/bin/env bash
# Mutation test for the raw-neutral-literals guard: a page using bg-white /
# text-gray-500 must be flagged; a page using bg-background /
# text-muted-foreground must not. A guard that cannot go red is worthless, so
# the last case proves --enforce actually exits non-zero on an offender.
set -uo pipefail
cd "$(dirname "$0")/.."
fails=0; ok(){ echo "  OK  $1"; }; bad(){ echo "  FAIL  $1"; fails=$((fails+1)); }
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

cat > "$tmp/bad.tsx" <<'TSX'
export default function Bad() {
  return <div className="bg-white text-gray-500">hello</div>
}
TSX
cat > "$tmp/good.tsx" <<'TSX'
export default function Good() {
  return <div className="bg-background text-muted-foreground">hello</div>
}
TSX

out=$(SH_PAGES_DIR="$tmp" bash scripts/check-no-raw-neutral-literals.sh)
echo "$out" | grep -q 'bad.tsx' && ok "flags a page with raw neutral literals" || bad "missed the bad page"
echo "$out" | grep -q 'good.tsx' && bad "flagged a token-only page" || ok "ignores a token-only page"
echo "$out" | grep -q 'raw-neutral-literals offenders: 1' && ok "reports the offender count" || bad "wrong offender count"

SH_PAGES_DIR="$tmp" bash scripts/check-no-raw-neutral-literals.sh --enforce >/dev/null 2>&1 \
  && bad "enforce did not fail" || ok "enforce fails on offender"

[ "$fails" -eq 0 ] && echo "check-no-raw-neutral-literals PASS" || { echo "FAIL ($fails)"; exit 1; }
