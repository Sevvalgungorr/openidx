#!/usr/bin/env bash
# Mutation test for the destructive-confirm guard: a page whose mutation is named
# with a destructive verb must gate it behind ConfirmAction/AlertDialog. Flag the
# bad page, ignore the good one.
set -uo pipefail
cd "$(dirname "$0")/.."
fails=0; ok(){ echo "  OK  $1"; }; bad(){ echo "  FAIL  $1"; fails=$((fails+1)); }
tmp=$(mktemp -d)
cat > "$tmp/bad.tsx" <<'TSX'
const deleteMutation = useMutation({ mutationFn: (id) => api.delete(`/x/${id}`) })
return <button onClick={() => deleteMutation.mutate(id)}>Delete</button>
TSX
cat > "$tmp/good.tsx" <<'TSX'
const deleteMutation = useMutation({ mutationFn: (id) => api.delete(`/x/${id}`) })
return <ConfirmAction title="Delete?" description="." onConfirm={() => deleteMutation.mutate(id)}>{(open)=><button onClick={open}>Delete</button>}</ConfirmAction>
TSX
out=$(SH_PAGES_DIR="$tmp" bash scripts/check-destructive-confirm.sh)
echo "$out" | grep -q 'bad.tsx' && ok "flags unconfirmed destructive mutation" || bad "missed the bad page"
echo "$out" | grep -q 'good.tsx' && bad "flagged a confirmed page" || ok "ignores a confirmed page"
SH_PAGES_DIR="$tmp" bash scripts/check-destructive-confirm.sh --enforce >/dev/null 2>&1 && bad "enforce did not fail" || ok "enforce fails on offender"
rm -rf "$tmp"
[ "$fails" -eq 0 ] && echo "check-destructive-confirm PASS" || { echo "FAIL ($fails)"; exit 1; }
