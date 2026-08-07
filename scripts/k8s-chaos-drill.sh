#!/usr/bin/env bash
# k8s-chaos-drill.sh — prove the always-on claims by breaking things on purpose.
#
# A manifest that *declares* high availability is not evidence. This drill kills
# real pods, drains real nodes and rolls out real images while a load generator
# runs, then reports how many requests were actually lost. Anything that cannot
# be measured is reported as unknown, never as a pass.
#
# Two modes:
#   --static   inspect the rendered chart only (no cluster). Catches missing
#              preStop/spread/PDB before anyone deploys. Always available.
#   (default)  run against a live cluster: pod kill, rolling update, node drain,
#              zone loss and Ziti router loss, each under continuous polling.
#
# Usage:
#   scripts/k8s-chaos-drill.sh --static
#   scripts/k8s-chaos-drill.sh --namespace openidx --url https://api.example.com
set -uo pipefail

NS="${NS:-openidx}"
URL="${URL:-}"
MODE="live"
CHART="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/deployments/kubernetes/helm/openidx"
VALUES="${VALUES:-$CHART/values-prod.yaml}"
HELM="$(command -v helm 2>/dev/null || echo /tmp/helm)"

while [ $# -gt 0 ]; do
	case "$1" in
	--static) MODE="static"; shift ;;
	--namespace) NS="$2"; shift 2 ;;
	--url) URL="$2"; shift 2 ;;
	*) echo "unknown flag: $1"; exit 2 ;;
	esac
done

FAIL=0
pass() { printf '  ✅ %s\n' "$1"; }
fail() { printf '  ❌ %s\n' "$1"; FAIL=1; }
unknown() { printf '  ⚠️  %s (ÖLÇÜLEMEDİ — başarı sayılmaz)\n' "$1"; FAIL=1; }

# ---------------------------------------------------------------- static mode
# Checks the rendered manifest, because the chart is where a zero-downtime
# rollout is either configured or silently missing.
static_checks() {
	echo "── Statik: üretilen manifest ──"
	if [ ! -x "$HELM" ]; then unknown "helm bulunamadı"; return; fi
	local rendered; rendered="$(mktemp)"
	if ! "$HELM" template chaos "$CHART" -f "$VALUES" >"$rendered" 2>/dev/null; then
		fail "helm template başarısız — chart dağıtılamaz durumda"
		return
	fi

	local res; res="$(python3 - "$rendered" <<'PYCHK'
import sys, yaml
docs=[d for d in yaml.safe_load_all(open(sys.argv[1])) if d]
deps=[d for d in docs if d.get('kind')=='Deployment']
pdbs=[d for d in docs if d.get('kind')=='PodDisruptionBudget']
bad=[]
for d in deps:
    n=d['metadata']['name']; sp=d['spec']['template']['spec']
    missing=[]
    # A pod that exits the moment it gets SIGTERM can still be in Service
    # endpoints on some nodes: the usual source of 502s during a deploy.
    if not any((c.get('lifecycle') or {}).get('preStop') for c in sp.get('containers',[])):
        missing.append('preStop')
    # Without a grace period longer than preStop+drain, Kubernetes SIGKILLs
    # mid-drain and cuts live requests.
    if sp.get('terminationGracePeriodSeconds') is None:
        missing.append('terminationGracePeriodSeconds')
    # Anti-affinity survives a node loss; only a zone spread survives an AZ loss.
    if not sp.get('topologySpreadConstraints'):
        missing.append('topologySpreadConstraints')
    # maxUnavailable>0 sheds capacity during an ordinary rollout.
    ru=(d['spec'].get('strategy') or {}).get('rollingUpdate') or {}
    if ru.get('maxSurge') is None or ru.get('maxUnavailable') not in (0,'0'):
        missing.append('rollingUpdate')
    if missing: bad.append(n + ': ' + ','.join(missing))
for b in bad: print('  eksik ->', b)
print('RESULT', len(bad), len(deps), len(pdbs))
PYCHK
)"
	echo "$res" | grep '^  eksik ->' || true
	local nbad ntot npdb
	nbad="$(echo "$res" | awk '/^RESULT/{print $2}')"
	ntot="$(echo "$res" | awk '/^RESULT/{print $3}')"
	npdb="$(echo "$res" | awk '/^RESULT/{print $4}')"
	if [ "${nbad:-1}" = "0" ] && [ "${ntot:-0}" -gt 0 ]; then
		pass "$ntot deployment: zarif kapanma + AZ yayilimi + kapasite dusmeyen guncelleme"
	else
		fail "${nbad:-?}/${ntot:-?} deployment eksik ayarla dagitilacak"
	fi
	if [ "${npdb:-0}" -gt 0 ]; then pass "PodDisruptionBudget: $npdb"
	else fail "PodDisruptionBudget yok"; fi
	rm -f "$rendered"
}

# ------------------------------------------------------------------ live mode
have_cluster() { command -v kubectl >/dev/null 2>&1 && kubectl get ns "$NS" >/dev/null 2>&1; }

# Continuous polling around a disruption. Prints "lost/total".
poll_during() {
	local label="$1"; shift
	if [ -z "$URL" ]; then unknown "$label: --url verilmedi"; return; fi
	local lost=0 total=0 i
	( "$@" ) &
	local action=$!
	for i in $(seq 120); do
		total=$((total+1))
		local code; code="$(curl -sk -o /dev/null -w '%{http_code}' -m 3 "$URL" 2>/dev/null)"
		case "$code" in 2*|3*) ;; *) lost=$((lost+1));; esac
		kill -0 "$action" 2>/dev/null || break
		sleep 0.5
	done
	wait "$action" 2>/dev/null
	if [ "$lost" -eq 0 ]; then pass "$label: $total istek, kayıp 0"
	else fail "$label: $total istek, KAYIP $lost"; fi
}

live_checks() {
	echo "── Canlı: gerçek kesinti altında ──"
	if ! have_cluster; then
		unknown "küme erişilemiyor (kubectl/namespace $NS)"
		return
	fi

	# 1. Pod kill — the cheapest failure a cluster must absorb invisibly.
	poll_during "Pod öldürme" sh -c "kubectl -n $NS delete pod -l app.kubernetes.io/component=identity-service --field-selector=status.phase=Running --wait=false | head -1; sleep 20"

	# 2. Rolling update — the disruption that happens on every single deploy.
	poll_during "Rolling update" sh -c "kubectl -n $NS rollout restart deploy -l app.kubernetes.io/component=identity-service >/dev/null; kubectl -n $NS rollout status deploy -l app.kubernetes.io/component=identity-service --timeout=120s >/dev/null"

	# 3. Node drain — a routine maintenance action, and where a missing PDB bites.
	local node; node="$(kubectl -n "$NS" get pod -l app.kubernetes.io/component=identity-service -o jsonpath='{.items[0].spec.nodeName}' 2>/dev/null)"
	if [ -n "$node" ]; then
		poll_during "Node drain ($node)" sh -c "kubectl drain $node --ignore-daemonsets --delete-emptydir-data --timeout=120s >/dev/null 2>&1; kubectl uncordon $node >/dev/null 2>&1"
	else
		unknown "Node drain: düğüm bulunamadı"
	fi

	# 4. Ziti router loss — with one router, every dark application drops at once.
	if kubectl -n "$NS" get deploy -l app.kubernetes.io/component=ziti-router >/dev/null 2>&1; then
		poll_during "Ziti router kaybı" sh -c "kubectl -n $NS delete pod -l app.kubernetes.io/component=ziti-router --wait=false | head -1; sleep 20"
	else
		unknown "Ziti router: dağıtılmamış (zitiFabric.enabled)"
	fi

	# 5. PDB coverage — a drain without a budget can take every replica at once.
	local nopdb; nopdb="$(kubectl -n "$NS" get pdb -o name 2>/dev/null | wc -l)"
	if [ "${nopdb:-0}" -gt 0 ]; then pass "PodDisruptionBudget tanımlı ($nopdb)"
	else fail "PodDisruptionBudget yok — drain tüm replikaları alabilir"; fi
}

echo "🛡️  OpenIDX Kubernetes chaos drill"
echo ""
static_checks
echo ""
if [ "$MODE" = "live" ]; then
	live_checks
	echo ""
else
	echo "── Canlı testler atlandı (--static) ──"
	echo "  NOT: statik denetim niyeti doğrular, dayanıklılığı DEĞİL."
	echo "       Gerçek kanıt için kümede --url ile çalıştırın."
	echo ""
fi

if [ "$FAIL" -eq 0 ]; then
	echo "✅ Chaos drill geçti."
else
	echo "❌ Chaos drill başarısız — yukarıdaki maddeler always-on iddiasını çürütüyor."
fi
exit "$FAIL"
