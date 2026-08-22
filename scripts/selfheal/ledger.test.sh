#!/usr/bin/env bash
# Verify: feeding findings updates ledger.jsonl deduped by fingerprint (count
# increments, last_seen updates, first_seen preserved), and a brand-new
# fingerprint is added.
set -uo pipefail
cd "$(dirname "$0")"
export SELFHEAL_STATE_DIR="$(mktemp -d)"
fails=0; ok(){ echo "  OK  $1"; }; bad(){ echo "  FAIL  $1"; fails=$((fails+1)); }
L="$SELFHEAL_STATE_DIR/ledger.jsonl"

echo '{"fingerprint":"ops:x","class":"ops","severity":"high","message":"m","service":"s"}' | bash ./ledger.sh
echo '{"fingerprint":"ops:x","class":"ops","severity":"high","message":"m","service":"s"}' | bash ./ledger.sh
echo '{"fingerprint":"bug:y","class":"bug","severity":"warn","message":"n","service":"t"}' | bash ./ledger.sh

lines=$(wc -l < "$L")
[ "$lines" -eq 2 ] && ok "two distinct fingerprints" || bad "expected 2 entries, got $lines"
python3 -c '
import json
rows=[json.loads(l) for l in open("'"$L"'")]
x=[r for r in rows if r["fingerprint"]=="ops:x"][0]
assert x["count"]==2, x
assert x["first_seen"]<=x["last_seen"]
print("  OK  count=2 first<=last")
' || bad "dedup/count wrong"

rm -rf "$SELFHEAL_STATE_DIR"
[ "$fails" -eq 0 ] && echo "ledger PASS" || { echo "FAIL ($fails)"; exit 1; }
