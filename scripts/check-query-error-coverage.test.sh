#!/usr/bin/env bash
# Mutation test for the query-error coverage guard: it must FLAG a page that
# fetches with useQuery but never renders QueryError/QueryGate, and IGNORE a page
# that does. A guard that can't go red (or that flags good code) is worse than none.
set -uo pipefail
cd "$(dirname "$0")/.."
fails=0; ok(){ echo "  OK  $1"; }; bad(){ echo "  FAIL  $1"; fails=$((fails+1)); }
tmp=$(mktemp -d)
cat > "$tmp/bad.tsx" <<'TSX'
const q = useQuery({ queryKey: ['x'], queryFn: () => api.get('/x') })
return <div>{q.data?.length ?? 'No items found'}</div>
TSX
cat > "$tmp/good.tsx" <<'TSX'
const q = useQuery({ queryKey: ['x'], queryFn: () => api.get('/x') })
return <QueryGate query={q} resource="x">{(d) => <div>{d.length}</div>}</QueryGate>
TSX
out=$(SH_PAGES_DIR="$tmp" bash scripts/check-query-error-coverage.sh)
echo "$out" | grep -q 'bad.tsx' && ok "flags a page with no QueryError" || bad "missed the bad page"
echo "$out" | grep -q 'good.tsx' && bad "flagged a good page" || ok "ignores a compliant page"
SH_PAGES_DIR="$tmp" bash scripts/check-query-error-coverage.sh --enforce >/dev/null 2>&1 && bad "enforce did not fail on offender" || ok "enforce fails on offender"
rm -rf "$tmp"
[ "$fails" -eq 0 ] && echo "check-query-error-coverage PASS" || { echo "FAIL ($fails)"; exit 1; }
