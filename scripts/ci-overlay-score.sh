#!/usr/bin/env bash
# CI-over-overlay skorbordu. Salt-okunur; hicbir sey degistirmez.
#
# NEDEN REPODA: bu betik oturum boyunca /tmp'de yasadi, yani onu yalnizca onu
# yazan makine calistirabiliyordu. Baskasinin tekrarlayamadigi bir olcum,
# olcum degil iddiadir. Repoya alindi, saha degerleri parametre oldu.
#
# Kullanim:
#   bash scripts/ci-overlay-score.sh
#   APP_HOST=app.example.org ZITI_CONTAINER=my-controller bash scripts/ci-overlay-score.sh
#
# Kural: hicbir metrik geriye gitmez. OLCULEMEYEN = OK=0, asla basari degil.
#
# OLCUM HATASI DUZELTILDI: 'ziti edge list' VARSAYILAN LIMIT 10 doner. Ilk
# surumde bu yuzden 16 servisin 10'u gorunuyordu ve "secops servisi yok"
# sonucuna varmistim -- YANLISTI. Tum sorgular artik 'limit 100' kullanir.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Saha degerleri. Varsayilanlar bu kurulumdan; baska kurulumda override edin.
APP_HOST="${APP_HOST:-secops.tdv.org}"
ZITI_CONTAINER="${ZITI_CONTAINER:-oidx-ziti-controller}"
SERVICE="${SERVICE:-secops}"
# Tunneler kaniti gibi ucuz olmayan olcumlerin birakildigi yer.
EVID="${CI_OVERLAY_EVIDENCE:-/tmp/ciziti}"
Z() { timeout 60 docker exec "$ZITI_CONTAINER" sh -c \
  'ziti edge login localhost:1280 -u admin -p "$ZITI_PWD" -y >/dev/null 2>&1; '"$1" 2>/dev/null | grep -v Emulate; }
ok(){ [ "$2" = "$3" ] && echo 1 || echo 0; }
ge(){ [ "$2" -ge "$3" ] 2>/dev/null && echo 1 || echo 0; }
J(){ python3 -c "import json,sys
try: d=json.load(sys.stdin)
except Exception: print(-1); raise SystemExit
$1" 2>/dev/null || echo -1; }

SVC=$(Z 'ziti edge list services "limit 100" -j')
IDS=$(Z 'ziti edge list identities "limit 200" -j')
POL=$(Z 'ziti edge list service-policies "limit 100" -j')
TRM=$(Z 'ziti fabric list terminators "limit 100" -j')

svc=$(echo "$SVC"|J "print(len(d['data']))")
# secops: intercept.v1 TASIYAN servis (dial edilebilir olan). host.v1-only olan
# openidx-SecOps BrowZer icindir, tunneler ondan DNS adi alamaz.
secsvc=$(echo "$SVC"|SVCNAME="$SERVICE" J "import os
n=os.environ['SVCNAME']
print(sum(1 for s in d['data'] if s['name']==n))")
term=$(echo "$TRM"|SVCNAME="$SERVICE" J "import os
n=os.environ['SVCNAME']
print(sum(1 for t in d['data'] if (t.get('service') or {}).get('name')==n))")
# ci kimligi: KAYITLI olmali; sadece var olmasi yetmez (kayitsiz kimlik kullanilamaz)
# KAYIT GOSTERGESI: bu controller surumunde liste ciktisinda isEnrolled HER
# ZAMAN None (104/104). Ona bakan bir kontrol her kimligi 'kayitsiz' sayar --
# sessiz yanlis-kirmizi. Gercek gosterge cert authenticator'un varligi
# (olculdu: 104 kimligin 5'inde var, bekleyen enrollment 97).
ciid=$(echo "$IDS"|J "
ci=[i for i in d['data'] if 'ci-clients' in (i.get('roleAttributes') or [])]
print(sum(1 for i in ci if (i.get('authenticators') or {}).get('cert')))")
cipol=$(echo "$POL"|SVCNAME="$SERVICE" J "import os
n='#'+os.environ['SVCNAME']
print(sum(1 for p in d['data'] if p.get('type')=='Dial' and n in (p.get('serviceRoles') or []) and '#ci-clients' in (p.get('identityRoles') or [])))")

# These two come from a real tunneller run, which cannot be re-run cheaply on
# every scoring pass. They were cached as bare "1", so a result from hours ago
# kept reading as a pass -- a false green. Age them out: a proof older than
# 6 hours is UNKNOWN (0), never a success.
fresh(){ [ -f "$1" ] && [ -z "$(find "$1" -mmin +360)" ] && cat "$1" || echo 0; }
reach=$(fresh "$EVID/reach.ok")
deny=$(fresh "$EVID/deny.ok")

P="$ROOT/deployments/ci/azure-pipelines-ziti.yml"
pdns=""; pport=""; pver=""
# Read the values by PARSING the YAML, not by grepping. A grep for
# 'NAME: "value"' silently returns nothing once the file switches to the
# list form (- name: X / value: Y) that a variable group requires -- which
# read as a regression when only the syntax had changed.
if [ -f "$P" ]; then
  read -r pdns pport pver <<<"$(python3 - "$P" <<'PYEOF'
import sys, yaml
v = yaml.safe_load(open(sys.argv[1]))["variables"]
d = v if isinstance(v, dict) else {i["name"]: i["value"] for i in v if "name" in i}
print(d.get("ZITI_INTERCEPT_DNS",""), d.get("SECOPS_PORT",""), d.get("ZITI_TUNNELER_VERSION",""))
PYEOF
)"
fi
CFG=$(Z 'ziti edge list configs "limit 100" -j')
ldns=$(echo "$CFG"|SVCNAME="$SERVICE" J "
import os
n=os.environ['SVCNAME']+'-intercept'
for c in d['data']:
    if c['name']==n: print(c['data']['addresses'][0]); break")
lport=$(echo "$CFG"|SVCNAME="$SERVICE" J "
import os
n=os.environ['SVCNAME']+'-intercept'
for c in d['data']:
    if c['name']==n: print(c['data']['portRanges'][0]['low']); break")
vok=0
[ -n "$pver" ] && { code=$(timeout 25 curl -s -o /dev/null -w '%{http_code}' -L \
  "https://github.com/openziti/ziti-tunnel-sdk-c/releases/download/v${pver}/ziti-edge-tunnel-Linux_x86_64.zip"); \
  [ "$code" = 200 ] && vok=1; }

# A single probe is not a measurement. secops answered 200 once and 502 on the
# next seven tries; one lucky request read as healthy. Probe 5 times and report
# the WORST result, so intermittent failure cannot show up as green.
prod=200
for _ in 1 2 3 4 5; do
  c=$(timeout 8 curl -sk -o /dev/null -w '%{http_code}' "https://${APP_HOST}/health")
  [ "$c" = 200 ] || { prod="$c"; break; }
done
rtr=$(Z 'ziti edge list edge-routers "limit 100" -j'|J "print(sum(1 for r in d['data'] if r.get('isOnline')))")
docs=$([ -f "$ROOT/docs/ci-over-ziti-overlay.md" ] && echo 1 || echo 0)
scr=$([ -f "$ROOT/deployments/ci/setup-ci-overlay-access.sh" ] && echo 1 || echo 0)

r=0
p(){ printf "%-24s=%-14s | %-11s | OK=%s\n" "$1" "$2" "$3" "$4"; [ "$4" = 1 ] && r=$((r+1)); }
p SECOPS_DIALABLE_SVC "$secsvc" "1"    "$(ok x "$secsvc" 1)"
p SECOPS_TERMINATOR   "$term"   ">=1"  "$(ge x "$term" 1)"
p CI_DIAL_POLICY      "$cipol"  ">=1"  "$(ge x "$cipol" 1)"
p CI_IDENTITY_ENROLLED "$ciid"  ">=1"  "$(ge x "$ciid" 1)"
p OVERLAY_REACH_200   "$reach"  "1"    "$(ok x "$reach" 1)"
p UNAUTH_DENIED       "$deny"   "1"    "$(ok x "$deny" 1)"
p PIPE_DNS_MATCHES    "${pdns:-none}" "$ldns" "$(ok x "${pdns:-none}" "$ldns")"
p PIPE_PORT_MATCHES   "${pport:-none}" "$lport" "$(ok x "${pport:-none}" "$lport")"
p PIPE_VERSION_EXISTS "$vok"    "1"    "$(ok x "$vok" 1)"
p SETUP_SCRIPT        "$scr"    "1"    "$(ok x "$scr" 1)"
p DOC                 "$docs"   "1"    "$(ok x "$docs" 1)"
p PROD_SECOPS_OK      "$prod"   "200"  "$(ok x "$prod" 200)"
p ROUTER_ONLINE       "$rtr"    ">=1"  "$(ge x "$rtr" 1)"
p TOTAL_SERVICES      "$svc"    ">=16" "$(ge x "$svc" 16)"
# ARIZA TEPKISI. Bu skorbord altyapiyi olcuyordu ama boru hattinin ariza
# davranisini hic gormuyordu; iki betigi ayri tutmak "sadece score.sh
# kostum, yesil" demeye izin veriyordu. Matris 3 dakika surer, o yuzden
# burada yeniden kosulmaz: sonucu dosyadan okunur. BAYAT SONUC SAHTE
# YESILDIR -- 6 saatten eskisi ya da HEAD ile eslesmeyeni UNKNOWN(0).
fm=0; fmv="none"
FMF="${FAULT_MATRIX_RESULT:-/tmp/cifault/last-result}"
if [ -f "$FMF" ]; then
  read -r fmts fmres fmsha < "$FMF"
  age=$(( $(date -u +%s) - $(date -u -d "$fmts" +%s 2>/dev/null || echo 0) ))
  # Must match the stamp the matrix writes: a hash of the files the matrix
  # exercises, NOT HEAD. See run-fault-matrix.sh for why.
  head_sha=$( { cat "$ROOT/deployments/ci/azure-pipelines-ziti.yml" \
                    "$ROOT/deployments/ci/faulttest/fake-origin.py" \
                    "$ROOT/deployments/ci/faulttest/run-fault-matrix.sh"; } \
              2>/dev/null | sha256sum | cut -c1-7)
  if [ "$age" -gt 21600 ]; then fmv="STALE($fmres)"
  elif [ -n "$head_sha" ] && [ "$fmsha" != "$head_sha" ]; then fmv="OTHER_SHA($fmres)"
  else fmv="$fmres"; [ "$fmres" = "6/6" ] && fm=1; fi
fi
p FAULT_MATRIX        "$fmv"    "6/6"  "$fm"
echo "SCORE=$r/15"
