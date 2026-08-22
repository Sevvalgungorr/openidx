#!/usr/bin/env bash
# sweep runs every collect-*.sh, concatenates their finding lines, and writes a
# snapshot JSON {ts, findings:[...]}. Verify it aggregates + writes latest.json.
set -uo pipefail
cd "$(dirname "$0")"
export SELFHEAL_STATE_DIR="$(mktemp -d)"
fails=0; ok(){ echo "  OK  $1"; }; bad(){ echo "  FAIL  $1"; fails=$((fails+1)); }

# Point sweep at a dir of two fake collectors so the test is hermetic.
export SH_COLLECTOR_DIR="$(mktemp -d)"
printf '#!/usr/bin/env bash\necho '\''{"fingerprint":"a","class":"ops"}'\''\n' > "$SH_COLLECTOR_DIR/collect-a.sh"
printf '#!/usr/bin/env bash\necho '\''{"fingerprint":"b","class":"bug"}'\''\n' > "$SH_COLLECTOR_DIR/collect-b.sh"
chmod +x "$SH_COLLECTOR_DIR"/collect-*.sh

out=$(bash ./sweep.sh)
[ -f "$SELFHEAL_STATE_DIR/latest.json" ] && ok "wrote latest.json" || bad "no latest.json"
python3 -c 'import json;d=json.load(open("'"$SELFHEAL_STATE_DIR"'/latest.json"));assert len(d["findings"])==2 and "ts" in d' \
  && ok "snapshot has 2 findings + ts" || bad "snapshot shape wrong"

rm -rf "$SELFHEAL_STATE_DIR" "$SH_COLLECTOR_DIR"
[ "$fails" -eq 0 ] && echo "sweep PASS" || { echo "FAIL ($fails)"; exit 1; }
