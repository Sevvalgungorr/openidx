#!/usr/bin/env bash
# Aggregator: run every collect-*.sh, gather their finding lines, and write one
# snapshot to $SELFHEAL_STATE_DIR/{latest.json, snapshot-<ts>.json}. Prints the
# finding lines to stdout too (so callers can pipe to the ledger). A collector
# that errors does not abort the sweep — its stderr is logged, others continue.
set -uo pipefail
cd "$(dirname "$0")"; . ./lib.sh

COLLECTOR_DIR="${SH_COLLECTOR_DIR:-$(dirname "$0")}"
tmp=$(mktemp)
for c in "$COLLECTOR_DIR"/collect-*.sh; do
  [ -e "$c" ] || continue
  bash "$c" >> "$tmp" 2>>"$SELFHEAL_STATE_DIR/sweep.err" || \
    echo "collector failed: $c" >> "$SELFHEAL_STATE_DIR/sweep.err"
done

ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
SF_TS="$ts" python3 - "$tmp" "$SELFHEAL_STATE_DIR" <<'PY'
import sys, json, os
findings=[]
with open(sys.argv[1]) as fh:
    for line in fh:
        line=line.strip()
        if not line: continue
        try: findings.append(json.loads(line))
        except Exception: pass
snap={"ts":os.environ["SF_TS"],"findings":findings}
state=sys.argv[2]
with open(os.path.join(state,"latest.json"),"w") as o: json.dump(snap,o,separators=(",",":"))
with open(os.path.join(state,f"snapshot-{os.environ['SF_TS']}.json"),"w") as o: json.dump(snap,o,separators=(",",":"))
PY
cat "$tmp"; rm -f "$tmp"
