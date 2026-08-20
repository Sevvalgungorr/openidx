#!/usr/bin/env bash
# Ledger: reads finding JSON lines on stdin and upserts them into
# $SELFHEAL_STATE_DIR/ledger.jsonl keyed by fingerprint. New fingerprint ->
# appended with count=1, first_seen=last_seen=now, status=open. Existing ->
# count++, last_seen=now, severity/message refreshed, first_seen + status
# preserved. This dedup is what powers self-improvement (recurring == high
# count) and prevents the same problem spamming remediation every run.
set -uo pipefail
cd "$(dirname "$0")"; . ./lib.sh

L="$SELFHEAL_STATE_DIR/ledger.jsonl"; touch "$L"
now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
# Buffer stdin to a file: `python3 - <<PY` uses stdin for the PROGRAM, so the
# findings must reach python by another channel (argv path), not sys.stdin.
in=$(mktemp); cat > "$in"
SF_NOW="$now" python3 - "$L" "$in" <<'PY'
import sys, json, os
path=sys.argv[1]; src=sys.argv[2]; now=os.environ["SF_NOW"]
rows={}
for line in open(path):
    line=line.strip()
    if not line: continue
    r=json.loads(line); rows[r["fingerprint"]]=r
for line in open(src):
    line=line.strip()
    if not line: continue
    try: f=json.loads(line)
    except Exception: continue
    fp=f.get("fingerprint")
    if not fp: continue
    if fp in rows:
        r=rows[fp]; r["count"]=r.get("count",1)+1; r["last_seen"]=now
        r["severity"]=f.get("severity",r.get("severity")); r["message"]=f.get("message",r.get("message"))
    else:
        rows[fp]={**f,"count":1,"first_seen":now,"last_seen":now,"status":"open"}
with open(path,"w") as o:
    for r in rows.values(): o.write(json.dumps(r,separators=(",",":"))+"\n")
PY
rm -f "$in"
