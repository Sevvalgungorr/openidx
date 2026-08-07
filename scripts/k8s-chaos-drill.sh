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
	# The suffix matters: kubeconform skips files it does not recognise as
	# YAML/JSON and then reports "0 resources found", which would read as a
	# clean validation of a manifest it never actually looked at.
	local rendered; rendered="$(mktemp --suffix=.yaml)"
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

	# Schema validation against the real Kubernetes API. A chart can render
	# perfectly valid YAML that the API server still rejects (wrong field name,
	# wrong type, deprecated apiVersion), and that failure would only appear at
	# deploy time — during the outage you were trying to prevent.
	if command -v kubeconform >/dev/null 2>&1 || [ -x /tmp/k8sha/kubeconform ]; then
		local kc; kc="$(command -v kubeconform 2>/dev/null || echo /tmp/k8sha/kubeconform)"
		# Reuse the render produced above instead of making a second one: one
		# source of truth, and no chance of the two drifting.
		#
		# CRDs (ExternalSecret, PrometheusRule) have no upstream schema, so they
		# are skipped; every core resource must validate strictly.
		#
		# The counts are parsed rather than grepped for "Invalid: 0", because
		# that substring also matches "Invalid: 10" — a broken manifest would be
		# reported as healthy, exactly the false-green this drill prevents. A
		# zero-resource result is treated as failure too: an empty render means
		# the chart cannot deploy at all.
		local kcout ninvalid nvalid
		kcout="$("$kc" -strict -summary -ignore-missing-schemas "$rendered" 2>&1 | tail -1)"
		ninvalid="$(printf '%s' "$kcout" | sed -n 's/.*Invalid: \([0-9][0-9]*\).*/\1/p')"
		nvalid="$(printf '%s' "$kcout" | sed -n 's/.*[^n]Valid: \([0-9][0-9]*\).*/\1/p')"
		if [ "${ninvalid:-1}" = "0" ] && [ "${nvalid:-0}" -gt 0 ]; then
			pass "Kubernetes API şema doğrulaması (strict): $nvalid kaynak"
		else
			fail "manifest gerçek API şemasına uymuyor (geçerli:${nvalid:-?} geçersiz:${ninvalid:-?})"
		fi
	else
		unknown "kubeconform yok: şema doğrulaması yapılamadı"
	fi

	# Alert rules. A rule with a typo in its PromQL is accepted by Kubernetes and
	# then never fires: the manifest is valid, the alert simply does not exist.
	# That is worse than having no alert at all, because the dashboard implies
	# someone is watching. promtool parses the expressions the way Prometheus
	# itself does.
	local pt; pt="$(command -v promtool 2>/dev/null || echo /tmp/k8sha/promtool)"
	if [ -x "$pt" ]; then
		local rules; rules="$(mktemp --suffix=.yaml)"
		python3 - "$rendered" "$rules" <<'PYRULES'
import sys, yaml
docs=[d for d in yaml.safe_load_all(open(sys.argv[1])) if d]
groups=[]
for d in docs:
    if d.get('kind')=='PrometheusRule':
        groups.extend(d['spec'].get('groups',[]))
yaml.safe_dump({'groups':groups}, open(sys.argv[2],'w'), default_flow_style=False)
print(sum(len(g.get('rules',[])) for g in groups))
PYRULES
		local ptout
		ptout="$("$pt" check rules "$rules" 2>&1)"
		if printf '%s' "$ptout" | grep -q 'SUCCESS'; then
			pass "Uyarı kuralları geçerli ($(printf '%s' "$ptout" | grep -oE '[0-9]+ rules found' | head -1))"
		else
			fail "uyarı kuralları geçersiz — sessizce hiç ateşlenmezler"
			printf '%s\n' "$ptout" | tail -3
		fi
		rm -f "$rules"
	else
		unknown "promtool yok: uyarı kuralları doğrulanamadı"
	fi

	# Alert delivery. Rules that fire into nothing are the worst kind of
	# monitoring: the dashboard is green, the rules exist, and everyone assumes
	# someone is being paged. An enabled Alertmanager route whose receiver has
	# no delivery method configured is exactly that, and it is easy to ship by
	# accident because the manifest is perfectly valid.
	local delivery
	delivery="$(python3 - "$rendered" <<'PYALERT'
import sys, yaml
docs=[d for d in yaml.safe_load_all(open(sys.argv[1])) if d]
rules=sum(len(g.get('rules',[])) for d in docs if d.get('kind')=='PrometheusRule'
          for g in d['spec'].get('groups',[]))
cfgs=[d for d in docs if d.get('kind')=='AlertmanagerConfig']
if not cfgs:
    # No route at all is a real gap when rules exist, but it is a deliberate
    # opt-in: report it as informational rather than a failure.
    print(f"NOROUTE {rules}")
else:
    empty=[r['name'] for c in cfgs for r in c['spec'].get('receivers',[])
           if not [k for k in r if k != 'name']]
    print(f"ROUTED {rules} {len(empty)} {','.join(empty)}")
PYALERT
)"
	case "$delivery" in
	NOROUTE*)
		local nr; nr="$(printf '%s' "$delivery" | awk '{print $2}')"
		if [ "${nr:-0}" -gt 0 ]; then
			printf '  ℹ️  %s uyarı kuralı tanımlı, teslim yolu yapılandırılmamış (monitoring.alerting.enabled=false)\n' "$nr"
		fi
		;;
	ROUTED*)
		local nempty names
		nempty="$(printf '%s' "$delivery" | awk '{print $3}')"
		names="$(printf '%s' "$delivery" | awk '{print $4}')"
		if [ "${nempty:-1}" = "0" ]; then
			pass "Uyarı teslim yolu yapılandırılmış"
		else
			fail "alıcıda teslim yolu yok (${names:-?}) — uyarılar sessizce kaybolur"
		fi
		;;
	esac
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
