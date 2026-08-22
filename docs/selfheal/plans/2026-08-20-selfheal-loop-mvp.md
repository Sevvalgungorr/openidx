# OpenIDX Self-Heal Loop (MVP) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the MVP of a Claude-driven self-healing ops loop for OpenIDX — deterministic collectors that emit findings, a deduping ledger, a Tier-0 remediator with a safety envelope + dry-run, and a `/selfheal-watch` entry that runs it in `observe` mode.

**Architecture:** Cheap bash collectors each emit JSON "finding" lines → `sweep.sh` aggregates into a snapshot + feeds the ledger (dedup by fingerprint) → `remediate.sh` is the single box-mutation point (Tier-0 ops actions, gated by `SELFHEAL_MODE` + kill-switch + anti-flap, with `--dry-run`) → `selfheal-watch.sh` orchestrates a run for the Claude routine. Design principle: intelligence lives in the Claude routine; collectors/ledger are deterministic; only the remediator mutates the box.

**Tech Stack:** Bash (`set -uo pipefail`), `python3` (JSON escaping/merge, always present on the box), `curl`, `systemctl --user`, `docker`/podman. Follows the repo's `check-*.sh ↔ *.test.sh` convention (tests assert both directions, run via `bash scripts/<name>.test.sh`).

**Spec:** `docs/selfheal/2026-08-20-selfheal-loop-design.md`

**Box facts used throughout:**
- Services (unit:port): `oidx-identity:8001 oidx-governance:8002 oidx-provisioning:8003 oidx-audit:8004 oidx-admin-api:8005 oidx-oauth:8006 oidx-access:8007`
- Logs: `/tmp/oidx-logs/{access,admin,audit,governance,identity,oauth,provisioning}.log` (zap JSON lines)
- State dir: `/home/cmit/oidx-runtime/selfheal/` (created by `lib.sh`)
- Edge: APISIX `:443`, host `openidx.tdv.org` (resolve to `127.0.0.1` in probes)
- nginx SPA container: `oidx-nginx` (systemd unit `container-oidx-nginx.service`)

**Finding JSON schema** (one per line, emitted by collectors):
```json
{"ts":"<rfc3339>","class":"ops|bug|anomaly|security","severity":"info|warn|high|crit","fingerprint":"<class>:<stable-sig>","service":"<name-or-'system'>","message":"<human>","data":{...},"suggested_action":"<remediator-op-or-''>"}
```

---

### Task 1: `lib.sh` — shared helpers (paths, mode, kill-switch, finding emit, fingerprint)

**Files:**
- Create: `scripts/selfheal/lib.sh`
- Test: `scripts/selfheal/lib.test.sh`

- [ ] **Step 1: Write the failing test**

```bash
cat > scripts/selfheal/lib.test.sh <<'EOF'
#!/usr/bin/env bash
# Verifies scripts/selfheal/lib.sh helpers: finding emission is valid JSON,
# fingerprints are stable + normalized, mode/kill-switch read correctly.
set -uo pipefail
cd "$(dirname "$0")"
export SELFHEAL_STATE_DIR="$(mktemp -d)"
# shellcheck disable=SC1091
. ./lib.sh
fails=0
ok(){ echo "  OK    $1"; }
bad(){ echo "  FAIL  $1"; fails=$((fails+1)); }

# sh_finding emits one valid JSON object with the required keys.
line=$(sh_finding ops warn "ops:unit-down:oidx-oauth" oidx-oauth "unit down" '{"port":8006}' restart_unit)
echo "$line" | python3 -c 'import sys,json; d=json.load(sys.stdin); assert d["class"]=="ops" and d["severity"]=="warn" and d["fingerprint"]=="ops:unit-down:oidx-oauth" and d["service"]=="oidx-oauth" and d["suggested_action"]=="restart_unit" and d["data"]["port"]==8006' \
  && ok "sh_finding valid json" || bad "sh_finding json"

# fingerprints normalize volatile tokens (uuids, timestamps, hex) to a stable sig.
a=$(sh_fingerprint bug "failed to query delivery bbbbbbbb-0000-4000-8000-0000000000ff")
b=$(sh_fingerprint bug "failed to query delivery 11111111-2222-3333-4444-555555555555")
[ "$a" = "$b" ] && ok "fingerprint stable across ids" || bad "fingerprint differs: $a vs $b"

# mode defaults to observe; kill-switch detected.
[ "$(sh_mode)" = "observe" ] && ok "mode defaults observe" || bad "mode default"
touch "$SELFHEAL_STATE_DIR/DISABLE"
sh_killed && ok "kill-switch detected" || bad "kill-switch"
rm -f "$SELFHEAL_STATE_DIR/DISABLE"
sh_killed && bad "kill-switch stuck on" || ok "kill-switch clears"

rm -rf "$SELFHEAL_STATE_DIR"
[ "$fails" -eq 0 ] && echo "lib.test.sh PASS" || { echo "lib.test.sh FAIL ($fails)"; exit 1; }
EOF
chmod +x scripts/selfheal/lib.test.sh
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bash scripts/selfheal/lib.test.sh`
Expected: FAIL — `./lib.sh: No such file or directory`

- [ ] **Step 3: Write minimal implementation**

```bash
mkdir -p scripts/selfheal
cat > scripts/selfheal/lib.sh <<'EOF'
#!/usr/bin/env bash
# Shared helpers for the OpenIDX self-heal loop. Sourced by every collector,
# the sweep aggregator, the ledger, and the remediator.
#
# Why a lib: findings must be uniform JSON (so the ledger + Claude routine can
# parse them), fingerprints must be STABLE across volatile ids (so the same
# recurring problem dedups to one ledger entry), and the autonomy gate +
# kill-switch must be read identically everywhere. Divergence here silently
# breaks dedup or, worse, the safety envelope.
set -uo pipefail

SELFHEAL_STATE_DIR="${SELFHEAL_STATE_DIR:-/home/cmit/oidx-runtime/selfheal}"
mkdir -p "$SELFHEAL_STATE_DIR" 2>/dev/null || true

# sh_mode: off | observe | tier0 | tier1  (default observe). Read from env or
# the state-dir MODE file so an operator can change it without editing scripts.
sh_mode() {
  local m="${SELFHEAL_MODE:-}"
  [ -z "$m" ] && [ -f "$SELFHEAL_STATE_DIR/MODE" ] && m=$(tr -d '[:space:]' < "$SELFHEAL_STATE_DIR/MODE")
  case "$m" in off|observe|tier0|tier1) echo "$m";; *) echo "observe";; esac
}

# sh_killed: true (0) when the kill-switch file exists — halts ALL autonomy.
sh_killed() { [ -f "$SELFHEAL_STATE_DIR/DISABLE" ]; }

# sh_fingerprint <class> <message>: stable signature. Normalize volatile tokens
# (uuids, hex blobs, ip:port, numbers, iso timestamps) so the same problem with
# different ids maps to ONE fingerprint.
sh_fingerprint() {
  local class="$1" msg="$2" sig
  sig=$(printf '%s' "$msg" \
    | sed -E 's/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/UUID/g' \
    | sed -E 's/[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.Z+-]+/TS/g' \
    | sed -E 's/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(:[0-9]+)?/IP/g' \
    | sed -E 's/\b[0-9a-fA-F]{16,}\b/HEX/g' \
    | sed -E 's/[0-9]+/N/g' \
    | tr -s ' ' | cut -c1-80)
  printf '%s:%s' "$class" "$sig"
}

# sh_finding <class> <severity> <fingerprint> <service> <message> [data-json] [suggested_action]
# Emits ONE JSON line. python3 does the escaping so arbitrary messages are safe.
sh_finding() {
  SF_CLASS="$1" SF_SEV="$2" SF_FP="$3" SF_SVC="$4" SF_MSG="$5" \
  SF_DATA="${6:-{}}" SF_ACT="${7:-}" python3 - <<'PY'
import json, os, datetime
data = os.environ["SF_DATA"]
try: data = json.loads(data)
except Exception: data = {"raw": data}
print(json.dumps({
  "ts": datetime.datetime.utcnow().replace(microsecond=0).isoformat()+"Z",
  "class": os.environ["SF_CLASS"], "severity": os.environ["SF_SEV"],
  "fingerprint": os.environ["SF_FP"], "service": os.environ["SF_SVC"],
  "message": os.environ["SF_MSG"], "data": data,
  "suggested_action": os.environ["SF_ACT"],
}, separators=(",", ":")))
PY
}
EOF
chmod +x scripts/selfheal/lib.sh
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bash scripts/selfheal/lib.test.sh`
Expected: PASS — `lib.test.sh PASS`

- [ ] **Step 5: Commit**

```bash
git add scripts/selfheal/lib.sh scripts/selfheal/lib.test.sh
git commit -m "feat(selfheal): shared lib (finding emit, stable fingerprint, mode/kill-switch)"
```

---

### Task 2: `collect-health.sh` — service health / unit state / restart-loop

**Files:**
- Create: `scripts/selfheal/collect-health.sh`
- Test: `scripts/selfheal/collect-health.test.sh`

- [ ] **Step 1: Write the failing test**

```bash
cat > scripts/selfheal/collect-health.test.sh <<'EOF'
#!/usr/bin/env bash
# Verifies collect-health emits a finding when a probe reports DOWN and stays
# silent when everything is up. Uses injected fake probes (no real box needed).
set -uo pipefail
cd "$(dirname "$0")"
export SELFHEAL_STATE_DIR="$(mktemp -d)"
fails=0; ok(){ echo "  OK  $1"; }; bad(){ echo "  FAIL  $1"; fails=$((fails+1)); }

# Fake probe: oidx-oauth down, all else up. The collector calls SH_HEALTH_PROBE.
export SH_HEALTH_PROBE='_fake'; _fake(){ # <unit> <port> -> prints "up|down active|dead <restarts>"
  case "$1" in oidx-oauth) echo "down dead 4";; *) echo "up active 0";; esac; }
export -f _fake
out=$(bash ./collect-health.sh)
echo "$out" | grep -q '"fingerprint":"ops:unit-down:oidx-oauth"' && ok "flags down unit" || bad "missing down finding"
echo "$out" | grep -q 'oidx-identity' && bad "reported healthy unit" || ok "silent on healthy"
echo "$out" | grep -q '"suggested_action":"restart_unit"' && ok "suggests restart" || bad "no action"

# All up -> no findings.
export SH_HEALTH_PROBE='_allup'; _allup(){ echo "up active 0"; }; export -f _allup
[ -z "$(bash ./collect-health.sh)" ] && ok "no findings when healthy" || bad "noise when healthy"

rm -rf "$SELFHEAL_STATE_DIR"
[ "$fails" -eq 0 ] && echo "collect-health PASS" || { echo "collect-health FAIL ($fails)"; exit 1; }
EOF
chmod +x scripts/selfheal/collect-health.test.sh
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bash scripts/selfheal/collect-health.test.sh`
Expected: FAIL — `./collect-health.sh: No such file or directory`

- [ ] **Step 3: Write minimal implementation**

```bash
cat > scripts/selfheal/collect-health.sh <<'EOF'
#!/usr/bin/env bash
# Collector: per-service health. Emits an ops finding for any oidx-* service
# whose /health is not "up", whose systemd unit is not active, or that is in a
# restart loop (>=3 restarts). Silent when everything is healthy.
#
# The actual probe is injectable via SH_HEALTH_PROBE so the test can drive it
# without a live box. Default probe hits /health + systemctl.
set -uo pipefail
cd "$(dirname "$0")"; . ./lib.sh

SERVICES="oidx-identity:8001 oidx-governance:8002 oidx-provisioning:8003 oidx-audit:8004 oidx-admin-api:8005 oidx-oauth:8006 oidx-access:8007"

_default_probe() { # <unit> <port> -> "up|down active|dead <restarts>"
  local unit="$1" port="$2" h u r
  h=$(curl -fsS --max-time 3 "http://127.0.0.1:$port/health" 2>/dev/null | grep -o '"status":"up"' | head -1)
  [ -n "$h" ] && h=up || h=down
  u=$(systemctl --user is-active "$unit.service" 2>/dev/null); [ "$u" = active ] || u=dead
  r=$(systemctl --user show "$unit.service" -p NRestarts --value 2>/dev/null); [ -z "$r" ] && r=0
  echo "$h $u $r"
}
PROBE="${SH_HEALTH_PROBE:-_default_probe}"

for pair in $SERVICES; do
  unit="${pair%%:*}"; port="${pair##*:}"
  read -r health unit_state restarts < <($PROBE "$unit" "$port")
  if [ "$health" != up ] || [ "$unit_state" != active ]; then
    sh_finding ops high "ops:unit-down:$unit" "$unit" "$unit not healthy (health=$health unit=$unit_state)" \
      "{\"port\":$port,\"restarts\":$restarts}" restart_unit
  elif [ "${restarts:-0}" -ge 3 ]; then
    sh_finding ops warn "ops:restart-loop:$unit" "$unit" "$unit restart loop ($restarts restarts)" \
      "{\"port\":$port,\"restarts\":$restarts}" ""
  fi
done
EOF
chmod +x scripts/selfheal/collect-health.sh
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bash scripts/selfheal/collect-health.test.sh`
Expected: PASS — `collect-health PASS`

- [ ] **Step 5: Commit**

```bash
git add scripts/selfheal/collect-health.sh scripts/selfheal/collect-health.test.sh
git commit -m "feat(selfheal): collect-health (down unit / restart-loop findings)"
```

---

### Task 3: `collect-logliveness.sh` — stale-log detection

**Files:**
- Create: `scripts/selfheal/collect-logliveness.sh`
- Test: `scripts/selfheal/collect-logliveness.test.sh`

- [ ] **Step 1: Write the failing test**

```bash
cat > scripts/selfheal/collect-logliveness.test.sh <<'EOF'
#!/usr/bin/env bash
# A log that has not been written to within the freshness window is itself a
# fault (service wedged / not logging). Verify a stale log is flagged and a
# fresh one is not.
set -uo pipefail
cd "$(dirname "$0")"
export SELFHEAL_STATE_DIR="$(mktemp -d)"; export SH_LOG_DIR="$(mktemp -d)"
export SH_LOG_STALE_SECS=60
fails=0; ok(){ echo "  OK  $1"; }; bad(){ echo "  FAIL  $1"; fails=$((fails+1)); }

echo x > "$SH_LOG_DIR/oauth.log"           # fresh (just now)
echo x > "$SH_LOG_DIR/identity.log"; touch -d '10 minutes ago' "$SH_LOG_DIR/identity.log"  # stale
out=$(bash ./collect-logliveness.sh)
echo "$out" | grep -q '"fingerprint":"ops:log-stale:identity"' && ok "flags stale log" || bad "missed stale"
echo "$out" | grep -q 'oauth' && bad "flagged fresh log" || ok "silent on fresh"

rm -rf "$SELFHEAL_STATE_DIR" "$SH_LOG_DIR"
[ "$fails" -eq 0 ] && echo "collect-logliveness PASS" || { echo "FAIL ($fails)"; exit 1; }
EOF
chmod +x scripts/selfheal/collect-logliveness.test.sh
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bash scripts/selfheal/collect-logliveness.test.sh`
Expected: FAIL — `No such file or directory`

- [ ] **Step 3: Write minimal implementation**

```bash
cat > scripts/selfheal/collect-logliveness.sh <<'EOF'
#!/usr/bin/env bash
# Collector: log liveness. A service log not written to within
# SH_LOG_STALE_SECS (default 600) is a fault — the service may be wedged and
# silent (the failure mode a health check alone can miss). Emits an ops finding
# per stale log. Only checks the 7 service logs (build/stage logs are ignored).
set -uo pipefail
cd "$(dirname "$0")"; . ./lib.sh

LOG_DIR="${SH_LOG_DIR:-/tmp/oidx-logs}"
STALE="${SH_LOG_STALE_SECS:-600}"
SVCS="access admin audit governance identity oauth provisioning"
now=$(date +%s)

for svc in $SVCS; do
  f="$LOG_DIR/$svc.log"
  [ -f "$f" ] || { sh_finding ops warn "ops:log-missing:$svc" "$svc" "log file missing" "{\"path\":\"$f\"}" ""; continue; }
  mtime=$(stat -c %Y "$f" 2>/dev/null || echo 0)
  age=$(( now - mtime ))
  if [ "$age" -gt "$STALE" ]; then
    sh_finding ops warn "ops:log-stale:$svc" "$svc" "log stale ${age}s (>${STALE}s) — service may be silent" \
      "{\"path\":\"$f\",\"age_secs\":$age}" ""
  fi
done
EOF
chmod +x scripts/selfheal/collect-logliveness.sh
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bash scripts/selfheal/collect-logliveness.test.sh`
Expected: PASS — `collect-logliveness PASS`

- [ ] **Step 5: Commit**

```bash
git add scripts/selfheal/collect-logliveness.sh scripts/selfheal/collect-logliveness.test.sh
git commit -m "feat(selfheal): collect-logliveness (stale/missing service log findings)"
```

---

### Task 4: `collect-logsignal.sh` — error/panic mining with grouped fingerprints

**Files:**
- Create: `scripts/selfheal/collect-logsignal.sh`
- Test: `scripts/selfheal/collect-logsignal.test.sh`

- [ ] **Step 1: Write the failing test**

```bash
cat > scripts/selfheal/collect-logsignal.test.sh <<'EOF'
#!/usr/bin/env bash
# Verify errors/panics in the tail are surfaced as bug findings, grouped so the
# SAME error with different ids collapses to one fingerprint, and info lines are
# ignored.
set -uo pipefail
cd "$(dirname "$0")"
export SELFHEAL_STATE_DIR="$(mktemp -d)"; export SH_LOG_DIR="$(mktemp -d)"
export SH_LOG_TAIL=50
fails=0; ok(){ echo "  OK  $1"; }; bad(){ echo "  FAIL  $1"; fails=$((fails+1)); }

cat > "$SH_LOG_DIR/access.log" <<LOG
{"level":"info","msg":"started"}
{"level":"error","msg":"failed to query delivery aaaaaaaa-0000-4000-8000-000000000001"}
{"level":"error","msg":"failed to query delivery bbbbbbbb-0000-4000-8000-000000000002"}
{"level":"info","msg":"ok"}
LOG
out=$(bash ./collect-logsignal.sh)
echo "$out" | grep -q '"class":"bug"' && ok "surfaces error as bug" || bad "no bug finding"
n=$(echo "$out" | grep -c 'failed to query delivery' || true)
[ "$n" -eq 1 ] && ok "grouped duplicate errors to one" || bad "did not group ($n lines)"
echo "$out" | python3 -c 'import sys,json;[json.loads(l) for l in sys.stdin if l.strip()]' && ok "valid json lines" || bad "bad json"

rm -rf "$SELFHEAL_STATE_DIR" "$SH_LOG_DIR"
[ "$fails" -eq 0 ] && echo "collect-logsignal PASS" || { echo "FAIL ($fails)"; exit 1; }
EOF
chmod +x scripts/selfheal/collect-logsignal.test.sh
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bash scripts/selfheal/collect-logsignal.test.sh`
Expected: FAIL — `No such file or directory`

- [ ] **Step 3: Write minimal implementation**

```bash
cat > scripts/selfheal/collect-logsignal.sh <<'EOF'
#!/usr/bin/env bash
# Collector: error/panic mining. Scans the tail of each service log for
# error/fatal/panic lines, groups them by fingerprint (so one recurring error
# = one finding, not one per occurrence), and emits a bug finding per group
# with an occurrence count. severity: panic/fatal -> crit, else warn.
set -uo pipefail
cd "$(dirname "$0")"; . ./lib.sh

LOG_DIR="${SH_LOG_DIR:-/tmp/oidx-logs}"
TAIL="${SH_LOG_TAIL:-500}"
SVCS="access admin audit governance identity oauth provisioning"

for svc in $SVCS; do
  f="$LOG_DIR/$svc.log"; [ -f "$f" ] || continue
  # Extract error-ish messages from the tail. Handle zap JSON ("msg":"...") and
  # plaintext; fall back to the whole line. Group by fingerprint via awk.
  tail -n "$TAIL" "$f" 2>/dev/null \
    | grep -iE '"level":"(error|fatal|dpanic|panic)"|\[ERROR\]|\bpanic\b|\bfatal\b' \
    | sed -E 's/.*"msg":"([^"]*)".*/\1/' \
    | while IFS= read -r msg; do
        [ -z "$msg" ] && continue
        fp=$(sh_fingerprint bug "$msg")
        echo "$fp"$'\t'"$msg"
      done \
    | sort | uniq -c | sort -rn \
    | while read -r count rest; do
        fp="${rest%%$'\t'*}"; msg="${rest#*$'\t'}"
        sev=warn; echo "$msg" | grep -qiE 'panic|fatal' && sev=crit
        sh_finding bug "$sev" "$fp" "$svc" "$msg" "{\"count\":$count}" ""
      done
done
EOF
chmod +x scripts/selfheal/collect-logsignal.sh
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bash scripts/selfheal/collect-logsignal.test.sh`
Expected: PASS — `collect-logsignal PASS`

- [ ] **Step 5: Commit**

```bash
git add scripts/selfheal/collect-logsignal.sh scripts/selfheal/collect-logsignal.test.sh
git commit -m "feat(selfheal): collect-logsignal (grouped error/panic bug findings)"
```

---

### Task 5: `collect-edge.sh` — public-edge reachability

**Files:**
- Create: `scripts/selfheal/collect-edge.sh`
- Test: `scripts/selfheal/collect-edge.test.sh`

- [ ] **Step 1: Write the failing test**

```bash
cat > scripts/selfheal/collect-edge.test.sh <<'EOF'
#!/usr/bin/env bash
# The edge probe must flag a path whose HTTP code is outside its allowed set
# (e.g. SPA / returning 403 = the yesterday incident) and stay silent when codes
# are acceptable. HTTP codes are injected so no live edge is needed.
set -uo pipefail
cd "$(dirname "$0")"
export SELFHEAL_STATE_DIR="$(mktemp -d)"
fails=0; ok(){ echo "  OK  $1"; }; bad(){ echo "  FAIL  $1"; fails=$((fails+1)); }

# Fake curl: SPA / returns 403 (bad), everything else 200.
export SH_EDGE_PROBE='_edge'; _edge(){ case "$1" in /) echo 403;; *) echo 200;; esac; }
export -f _edge
out=$(bash ./collect-edge.sh)
echo "$out" | grep -q '"fingerprint":"ops:edge-bad:/"' && ok "flags SPA 403" || bad "missed SPA 403"
echo "$out" | grep -q '"suggested_action":"restart_nginx"' && ok "suggests nginx restart for /" || bad "no nginx action"

export SH_EDGE_PROBE='_allok'; _allok(){ case "$1" in /api/*) echo 401;; *) echo 200;; esac; }; export -f _allok
[ -z "$(bash ./collect-edge.sh)" ] && ok "silent when codes acceptable (401 on api ok)" || bad "noise on acceptable"

rm -rf "$SELFHEAL_STATE_DIR"
[ "$fails" -eq 0 ] && echo "collect-edge PASS" || { echo "FAIL ($fails)"; exit 1; }
EOF
chmod +x scripts/selfheal/collect-edge.test.sh
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bash scripts/selfheal/collect-edge.test.sh`
Expected: FAIL — `No such file or directory`

- [ ] **Step 3: Write minimal implementation**

```bash
cat > scripts/selfheal/collect-edge.sh <<'EOF'
#!/usr/bin/env bash
# Collector: public-edge reachability through APISIX :443. Each path has an
# allowed set of HTTP codes; anything else is an ops finding. `/` returning 403
# is exactly the frontend-mount outage class, so its suggested action is
# restart_nginx. The probe is injectable (SH_EDGE_PROBE) for testing.
set -uo pipefail
cd "$(dirname "$0")"; . ./lib.sh

# path|allowed-codes(csv)|suggested_action
CHECKS='/|200,301,302|restart_nginx
/.well-known/openid-configuration|200|
/api/v1/access/ziti/status|200,401|
/downloads/agent-manifest.json|200|'

_default_probe() { # <path> -> http code
  curl -s -o /dev/null -w '%{http_code}' -k --max-time 6 \
    --resolve openidx.tdv.org:443:127.0.0.1 "https://openidx.tdv.org$1" 2>/dev/null || echo 000
}
PROBE="${SH_EDGE_PROBE:-_default_probe}"

printf '%s\n' "$CHECKS" | while IFS='|' read -r path allowed action; do
  [ -z "$path" ] && continue
  code=$($PROBE "$path")
  if ! echo ",$allowed," | grep -q ",$code,"; then
    sh_finding ops high "ops:edge-bad:$path" system "edge $path returned $code (allowed: $allowed)" \
      "{\"path\":\"$path\",\"code\":$code}" "$action"
  fi
done
EOF
chmod +x scripts/selfheal/collect-edge.sh
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bash scripts/selfheal/collect-edge.test.sh`
Expected: PASS — `collect-edge PASS`

- [ ] **Step 5: Commit**

```bash
git add scripts/selfheal/collect-edge.sh scripts/selfheal/collect-edge.test.sh
git commit -m "feat(selfheal): collect-edge (APISIX :443 reachability; SPA-403 -> restart_nginx)"
```

---

### Task 6: `collect-security.sh` — auth-abuse / config-drift from logs

**Files:**
- Create: `scripts/selfheal/collect-security.sh`
- Test: `scripts/selfheal/collect-security.test.sh`

- [ ] **Step 1: Write the failing test**

```bash
cat > scripts/selfheal/collect-security.test.sh <<'EOF'
#!/usr/bin/env bash
# Verify: a burst of 403s from one principal is flagged (auth abuse), an
# injection/traversal marker is flagged, and normal traffic is silent.
set -uo pipefail
cd "$(dirname "$0")"
export SELFHEAL_STATE_DIR="$(mktemp -d)"; export SH_LOG_DIR="$(mktemp -d)"
export SH_SEC_403_THRESHOLD=5
fails=0; ok(){ echo "  OK  $1"; }; bad(){ echo "  FAIL  $1"; fails=$((fails+1)); }

# 6x 403 for the same path + one traversal attempt.
{ for i in $(seq 1 6); do echo '{"level":"warn","status":403,"path":"/api/v1/settings"}'; done
  echo '{"path":"/downloads/../../etc/passwd"}'
  echo '{"level":"info","status":200,"path":"/dashboard"}'; } > "$SH_LOG_DIR/admin.log"

out=$(bash ./collect-security.sh)
echo "$out" | grep -q '"class":"security"' && ok "emits security findings" || bad "no security finding"
echo "$out" | grep -q 'forbidden-spike' && ok "flags 403 spike" || bad "missed 403 spike"
echo "$out" | grep -q 'path-traversal' && ok "flags traversal" || bad "missed traversal"

: > "$SH_LOG_DIR/admin.log"; echo '{"status":200,"path":"/ok"}' > "$SH_LOG_DIR/admin.log"
[ -z "$(bash ./collect-security.sh)" ] && ok "silent on clean traffic" || bad "noise on clean"

rm -rf "$SELFHEAL_STATE_DIR" "$SH_LOG_DIR"
[ "$fails" -eq 0 ] && echo "collect-security PASS" || { echo "FAIL ($fails)"; exit 1; }
EOF
chmod +x scripts/selfheal/collect-security.test.sh
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bash scripts/selfheal/collect-security.test.sh`
Expected: FAIL — `No such file or directory`

- [ ] **Step 3: Write minimal implementation**

```bash
cat > scripts/selfheal/collect-security.sh <<'EOF'
#!/usr/bin/env bash
# Collector: security signals from logs. Emits security findings for a 403
# spike (>= SH_SEC_403_THRESHOLD in the tail) and for injection/traversal
# markers in request paths. Security findings are NEVER auto-remediated
# (suggested_action stays empty) — they alert a human / the security routine.
set -uo pipefail
cd "$(dirname "$0")"; . ./lib.sh

LOG_DIR="${SH_LOG_DIR:-/tmp/oidx-logs}"
TAIL="${SH_LOG_TAIL:-1000}"
THRESH="${SH_SEC_403_THRESHOLD:-30}"
SVCS="access admin audit governance identity oauth provisioning"

for svc in $SVCS; do
  f="$LOG_DIR/$svc.log"; [ -f "$f" ] || continue
  body=$(tail -n "$TAIL" "$f" 2>/dev/null)

  # 403/401 spike (forbidden/unauthorized bursts = probing / privilege attempts).
  c403=$(printf '%s\n' "$body" | grep -cE '"status":403|" 403 |\bforbidden\b' || true)
  if [ "$c403" -ge "$THRESH" ]; then
    sh_finding security high "security:forbidden-spike:$svc" "$svc" "403 spike: $c403 in last $TAIL lines" \
      "{\"count\":$c403}" ""
  fi

  # Injection / path traversal markers.
  if printf '%s\n' "$body" | grep -qE '\.\./\.\./|/etc/passwd|union[[:space:]]+select|<script>|\x27[[:space:]]*or[[:space:]]*\x27'; then
    sh_finding security high "security:path-traversal:$svc" "$svc" "injection/traversal marker in requests" "{}" ""
  fi
done
EOF
chmod +x scripts/selfheal/collect-security.sh
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bash scripts/selfheal/collect-security.test.sh`
Expected: PASS — `collect-security PASS`

- [ ] **Step 5: Commit**

```bash
git add scripts/selfheal/collect-security.sh scripts/selfheal/collect-security.test.sh
git commit -m "feat(selfheal): collect-security (403 spike + injection/traversal findings)"
```

---

### Task 7: `sweep.sh` — run all collectors → snapshot

**Files:**
- Create: `scripts/selfheal/sweep.sh`
- Test: `scripts/selfheal/sweep.test.sh`

- [ ] **Step 1: Write the failing test**

```bash
cat > scripts/selfheal/sweep.test.sh <<'EOF'
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
EOF
chmod +x scripts/selfheal/sweep.test.sh
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bash scripts/selfheal/sweep.test.sh`
Expected: FAIL — `No such file or directory`

- [ ] **Step 3: Write minimal implementation**

```bash
cat > scripts/selfheal/sweep.sh <<'EOF'
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
EOF
chmod +x scripts/selfheal/sweep.sh
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bash scripts/selfheal/sweep.test.sh`
Expected: PASS — `sweep PASS`

- [ ] **Step 5: Commit**

```bash
git add scripts/selfheal/sweep.sh scripts/selfheal/sweep.test.sh
git commit -m "feat(selfheal): sweep (run collectors -> snapshot latest.json)"
```

---

### Task 8: `ledger.sh` — dedup findings by fingerprint

**Files:**
- Create: `scripts/selfheal/ledger.sh`
- Test: `scripts/selfheal/ledger.test.sh`

- [ ] **Step 1: Write the failing test**

```bash
cat > scripts/selfheal/ledger.test.sh <<'EOF'
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
EOF
chmod +x scripts/selfheal/ledger.test.sh
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bash scripts/selfheal/ledger.test.sh`
Expected: FAIL — `No such file or directory`

- [ ] **Step 3: Write minimal implementation**

```bash
cat > scripts/selfheal/ledger.sh <<'EOF'
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
SF_NOW="$now" python3 - "$L" <<'PY'
import sys, json, os
path=sys.argv[1]; now=os.environ["SF_NOW"]
rows={}
for line in open(path):
    line=line.strip()
    if not line: continue
    r=json.loads(line); rows[r["fingerprint"]]=r
for line in sys.stdin:
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
EOF
chmod +x scripts/selfheal/ledger.sh
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bash scripts/selfheal/ledger.test.sh`
Expected: PASS — `ledger PASS`

- [ ] **Step 5: Commit**

```bash
git add scripts/selfheal/ledger.sh scripts/selfheal/ledger.test.sh
git commit -m "feat(selfheal): ledger (fingerprint-deduped findings store)"
```

---

### Task 9: `remediate.sh` — Tier-0 remediator + safety envelope + `--dry-run`

**Files:**
- Create: `scripts/selfheal/remediate.sh`
- Test: `scripts/selfheal/remediate.test.sh`

- [ ] **Step 1: Write the failing test**

```bash
cat > scripts/selfheal/remediate.test.sh <<'EOF'
#!/usr/bin/env bash
# The remediator is the ONLY mutation point, so its safety envelope is the most
# important thing to test: mode gate, kill-switch, dry-run, anti-flap, and
# health-verify-with-rollback. The actual system actions are injected
# (SH_ACT_RESTART / SH_ACT_HEALTH) so nothing real is touched.
set -uo pipefail
cd "$(dirname "$0")"
export SELFHEAL_STATE_DIR="$(mktemp -d)"
fails=0; ok(){ echo "  OK  $1"; }; bad(){ echo "  FAIL  $1"; fails=$((fails+1)); }
FIND='{"fingerprint":"ops:unit-down:oidx-oauth","class":"ops","severity":"high","service":"oidx-oauth","suggested_action":"restart_unit","data":{"port":8006}}'

# Injected actions record calls; health returns from a file we control.
export SH_ACT_RESTART='_r'; _r(){ echo "restart:$1" >> "$SELFHEAL_STATE_DIR/acts"; }
export SH_ACT_HEALTH='_h';  _h(){ cat "$SELFHEAL_STATE_DIR/healthret" 2>/dev/null || echo up; }
export -f _r _h

# observe mode -> records intent, never acts.
SELFHEAL_MODE=observe; echo "$FIND" | bash ./remediate.sh > /tmp/o1
[ ! -f "$SELFHEAL_STATE_DIR/acts" ] && ok "observe: no action" || bad "observe acted"

# kill-switch -> no action even in tier0.
touch "$SELFHEAL_STATE_DIR/DISABLE"
SELFHEAL_MODE=tier0; echo "$FIND" | bash ./remediate.sh > /tmp/o2
[ ! -f "$SELFHEAL_STATE_DIR/acts" ] && ok "kill-switch: no action" || bad "acted despite kill-switch"
rm -f "$SELFHEAL_STATE_DIR/DISABLE"

# tier0 + healthy-after -> restart happens once, recovery recorded.
echo up > "$SELFHEAL_STATE_DIR/healthret"
SELFHEAL_MODE=tier0; echo "$FIND" | bash ./remediate.sh > /tmp/o3
grep -q 'restart:oidx-oauth' "$SELFHEAL_STATE_DIR/acts" && ok "tier0 restarted unit" || bad "no restart in tier0"

# anti-flap: exceed K=3 -> further attempts escalate (no more restarts).
: > "$SELFHEAL_STATE_DIR/acts"
for i in 1 2 3 4 5; do echo "$FIND" | bash ./remediate.sh >/dev/null; done
rc=$(grep -c 'restart:oidx-oauth' "$SELFHEAL_STATE_DIR/acts" || true)
[ "$rc" -le 3 ] && ok "anti-flap capped restarts at K=3 ($rc)" || bad "anti-flap failed ($rc)"

# dry-run -> prints intent, never calls the action.
: > "$SELFHEAL_STATE_DIR/acts"
SELFHEAL_MODE=tier0; echo "$FIND" | bash ./remediate.sh --dry-run > /tmp/o5
grep -qi 'would' /tmp/o5 && [ ! -s "$SELFHEAL_STATE_DIR/acts" ] && ok "dry-run: intent only" || bad "dry-run acted"

rm -rf "$SELFHEAL_STATE_DIR"
[ "$fails" -eq 0 ] && echo "remediate PASS" || { echo "FAIL ($fails)"; exit 1; }
EOF
chmod +x scripts/selfheal/remediate.test.sh
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bash scripts/selfheal/remediate.test.sh`
Expected: FAIL — `No such file or directory`

- [ ] **Step 3: Write minimal implementation**

```bash
cat > scripts/selfheal/remediate.sh <<'EOF'
#!/usr/bin/env bash
# The ONE box-mutation point. Reads finding JSON lines on stdin and, for Tier-0
# ops findings, performs the deterministic remediation gated by the full safety
# envelope. Everything else (bug/anomaly/security, or an action beyond Tier-0)
# is logged as "escalate" and left for a human / the Claude triage routine.
#
# Safety envelope (all enforced here so it lives in one place):
#   - autonomy gate: acts only in tier0/tier1 (never off/observe)
#   - kill-switch:   $SELFHEAL_STATE_DIR/DISABLE halts everything
#   - anti-flap:     a fingerprint is auto-remediated at most K=3 times/hour
#   - health-gate:   after acting, verify /health; the caller/watch records the
#                    outcome (recovered vs still-bad). (System restart + health
#                    are injectable for tests via SH_ACT_RESTART / SH_ACT_HEALTH.)
#   - --dry-run:     print intended action, do nothing.
set -uo pipefail
cd "$(dirname "$0")"; . ./lib.sh

DRY=0; [ "${1:-}" = "--dry-run" ] && DRY=1
K="${SELFHEAL_FLAP_K:-3}"
mode=$(sh_mode)
FLAP="$SELFHEAL_STATE_DIR/flap"; touch "$FLAP"

_default_restart() { systemctl --user restart "$1.service" 2>/dev/null; }
_default_health()  { curl -fsS --max-time 3 "http://127.0.0.1:$1/health" 2>/dev/null | grep -o '"status":"up"' | head -1 | grep -q up && echo up || echo down; }
ACT_RESTART="${SH_ACT_RESTART:-_default_restart}"
ACT_HEALTH="${SH_ACT_HEALTH:-_default_health}"

# _flap_count <fp>: attempts for this fingerprint within the last hour.
_flap_count() { local fp="$1" now cutoff; now=$(date +%s); cutoff=$((now-3600))
  awk -F'\t' -v fp="$fp" -v c="$cutoff" '$1==fp && $2>=c' "$FLAP" | wc -l; }
_flap_mark()  { printf '%s\t%s\n' "$1" "$(date +%s)" >> "$FLAP"; }

while IFS= read -r line; do
  [ -z "$line" ] && continue
  fp=$(echo "$line"    | python3 -c 'import sys,json;print(json.load(sys.stdin).get("fingerprint",""))' 2>/dev/null)
  act=$(echo "$line"   | python3 -c 'import sys,json;print(json.load(sys.stdin).get("suggested_action",""))' 2>/dev/null)
  svc=$(echo "$line"   | python3 -c 'import sys,json;print(json.load(sys.stdin).get("service",""))' 2>/dev/null)
  port=$(echo "$line"  | python3 -c 'import sys,json;print(json.load(sys.stdin).get("data",{}).get("port",0))' 2>/dev/null)
  [ -z "$fp" ] && continue

  # Only Tier-0 ops actions are auto-eligible.
  case "$act" in restart_unit|restart_nginx) ;; *) echo "escalate: $fp (action='$act')"; continue;; esac

  if sh_killed; then echo "halted (kill-switch): $fp"; continue; fi
  if [ "$mode" != tier0 ] && [ "$mode" != tier1 ]; then echo "observe: would $act for $fp"; continue; fi
  if [ "$(_flap_count "$fp")" -ge "$K" ]; then echo "escalate (anti-flap >=$K): $fp"; continue; fi
  if [ "$DRY" = 1 ]; then echo "dry-run: would $act for $fp ($svc)"; continue; fi

  _flap_mark "$fp"
  case "$act" in
    restart_unit)   $ACT_RESTART "$svc"; sleep 2
                    if [ "$($ACT_HEALTH "$port")" = up ]; then echo "recovered: $fp via restart_unit"
                    else echo "still-bad after restart_unit: $fp (escalate)"; fi ;;
    restart_nginx)  $ACT_RESTART "container-oidx-nginx"; sleep 2
                    echo "acted restart_nginx for $fp (verify edge next sweep)" ;;
  esac
done
EOF
chmod +x scripts/selfheal/remediate.sh
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bash scripts/selfheal/remediate.test.sh`
Expected: PASS — `remediate PASS`

- [ ] **Step 5: Commit**

```bash
git add scripts/selfheal/remediate.sh scripts/selfheal/remediate.test.sh
git commit -m "feat(selfheal): remediate (Tier-0 + safety envelope: mode/kill-switch/anti-flap/dry-run)"
```

---

### Task 10: `selfheal-watch.sh` + Claude skill + runbook

**Files:**
- Create: `scripts/selfheal/selfheal-watch.sh`
- Create: `.claude/commands/selfheal-watch.md`
- Create: `docs/selfheal/runbook.md`
- Test: `scripts/selfheal/selfheal-watch.test.sh`

- [ ] **Step 1: Write the failing test**

```bash
cat > scripts/selfheal/selfheal-watch.test.sh <<'EOF'
#!/usr/bin/env bash
# selfheal-watch orchestrates one run: sweep -> ledger -> remediate, and prints
# a compact summary. Verify it wires the three together and honors observe mode
# (no mutation). Uses fake collectors + injected actions so it's hermetic.
set -uo pipefail
cd "$(dirname "$0")"
export SELFHEAL_STATE_DIR="$(mktemp -d)"; export SH_COLLECTOR_DIR="$(mktemp -d)"
export SELFHEAL_MODE=observe
fails=0; ok(){ echo "  OK  $1"; }; bad(){ echo "  FAIL  $1"; fails=$((fails+1)); }

printf '#!/usr/bin/env bash\necho '\''{"fingerprint":"ops:unit-down:oidx-oauth","class":"ops","severity":"high","service":"oidx-oauth","suggested_action":"restart_unit","data":{"port":8006}}'\''\n' > "$SH_COLLECTOR_DIR/collect-x.sh"
chmod +x "$SH_COLLECTOR_DIR/collect-x.sh"

out=$(bash ./selfheal-watch.sh)
[ -f "$SELFHEAL_STATE_DIR/latest.json" ] && ok "ran sweep (snapshot present)" || bad "no sweep"
[ -s "$SELFHEAL_STATE_DIR/ledger.jsonl" ] && ok "updated ledger" || bad "no ledger update"
echo "$out" | grep -qi 'observe' && ok "observe: reported would-remediate" || bad "no observe report"
echo "$out" | grep -qi 'findings=1' && ok "summary counts findings" || bad "no summary count"

rm -rf "$SELFHEAL_STATE_DIR" "$SH_COLLECTOR_DIR"
[ "$fails" -eq 0 ] && echo "selfheal-watch PASS" || { echo "FAIL ($fails)"; exit 1; }
EOF
chmod +x scripts/selfheal/selfheal-watch.test.sh
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bash scripts/selfheal/selfheal-watch.test.sh`
Expected: FAIL — `No such file or directory`

- [ ] **Step 3: Write minimal implementation**

```bash
cat > scripts/selfheal/selfheal-watch.sh <<'EOF'
#!/usr/bin/env bash
# One self-heal run: sweep collectors -> update ledger -> feed Tier-0 findings
# to the remediator -> print a compact summary. This is what the /selfheal-watch
# Claude routine invokes each cycle; the Claude side reads the summary + ledger
# and only does deep analysis / opens a triage when a finding is new or unhealed.
set -uo pipefail
cd "$(dirname "$0")"; . ./lib.sh

findings=$(bash ./sweep.sh)                 # writes latest.json, echoes finding lines
printf '%s\n' "$findings" | grep -q . && printf '%s\n' "$findings" | bash ./ledger.sh
rem=$(printf '%s\n' "$findings" | bash ./remediate.sh)

n=$(printf '%s\n' "$findings" | grep -c . || true)
crit=$(printf '%s\n' "$findings" | grep -c '"severity":"crit"' || true)
echo "selfheal-watch: mode=$(sh_mode) findings=$n crit=$crit"
[ -n "$rem" ] && printf '%s\n' "$rem" | sed 's/^/  remediate: /'
echo "  ledger: $SELFHEAL_STATE_DIR/ledger.jsonl"
EOF
chmod +x scripts/selfheal/selfheal-watch.sh
```

Also create the Claude routine entry:

```bash
mkdir -p .claude/commands
cat > .claude/commands/selfheal-watch.md <<'EOF'
---
description: One self-heal cycle — sweep health/logs/edge/security, update the ledger, Tier-0 auto-remediate (by SELFHEAL_MODE), and report new/unhealed findings.
---
Run one OpenIDX self-heal cycle and report.

1. Run `bash scripts/selfheal/selfheal-watch.sh` and read its summary.
2. Read `oidx-runtime/selfheal/ledger.jsonl`. For any finding that is NEW
   (count==1) or NOT recovering (still `status:open` after remediation) with
   severity `high`/`crit`:
   - `ops` class: confirm the remediator's action (or, if it escalated, say why
     and what a human should do).
   - `bug`/`anomaly` class: note it as a candidate for `/selfheal-triage`
     (do NOT fix here — this cycle is observe/report + Tier-0 ops only).
   - `security` class: summarize the signal; never auto-act.
3. Output a short status: mode, counts by class/severity, what was remediated,
   and anything that needs a human. Do not take Tier-1/Tier-2 actions here.

Guardrails: honor `oidx-runtime/selfheal/DISABLE` (kill-switch) and
`SELFHEAL_MODE`. This command must not deploy, migrate, or edit code.
EOF
```

And the runbook:

```bash
cat > docs/selfheal/runbook.md <<'EOF'
# Self-Heal Loop — Runbook

## What it is
A Claude-driven ops loop. Deterministic collectors emit findings → a
fingerprint-deduped ledger → the remediator applies Tier-0 fixes inside a safety
envelope. See `docs/selfheal/2026-08-20-selfheal-loop-design.md`.

## Files
- `scripts/selfheal/` — collectors, sweep, ledger, remediate, selfheal-watch (+ tests)
- `oidx-runtime/selfheal/` — runtime state: `latest.json`, `ledger.jsonl`, `MODE`, `DISABLE`, `flap`
- `.claude/commands/selfheal-watch.md` — the Claude routine entry

## Controls
- **Mode:** `echo tier0 > oidx-runtime/selfheal/MODE` (off | observe | tier0 | tier1). Default observe.
- **Kill-switch:** `touch oidx-runtime/selfheal/DISABLE` halts ALL autonomy. Remove to resume.
- **Manual run:** `bash scripts/selfheal/selfheal-watch.sh`
- **Dry-run remediation:** `bash scripts/selfheal/sweep.sh | bash scripts/selfheal/remediate.sh --dry-run`

## Rollout
1. `observe` (default) — detect + record + report, no mutation. Watch a few days.
2. `tier0` — enable ops remediation (restart unit / nginx, etc.).
3. `tier1` — enable autonomous code-fix (phase 2; backup+canary+rollback armored).

## Tiers
- Tier-0 (auto): restart dead unit, restart nginx (SPA mount fix), etc.
- Tier-1 (auto, guardrailed, phase 2): code/config fix → test → canary deploy → rollback.
- Tier-2 (human): schema-destructive migrations, RBAC/secret/edge-route changes, blast-radius overflow.
EOF
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bash scripts/selfheal/selfheal-watch.test.sh`
Expected: PASS — `selfheal-watch PASS`

- [ ] **Step 5: Commit**

```bash
git add scripts/selfheal/selfheal-watch.sh scripts/selfheal/selfheal-watch.test.sh .claude/commands/selfheal-watch.md docs/selfheal/runbook.md
git commit -m "feat(selfheal): selfheal-watch orchestrator + /selfheal-watch routine + runbook"
```

---

### Task 11: CI wiring + live smoke on the box

**Files:**
- Modify: `.github/workflows/ci.yml` (add a step running the selfheal tests)

- [ ] **Step 1: Add the test step to CI**

Find the job that runs the other `*.test.sh` (it runs `bash scripts/check-*.test.sh`). Add, alongside those steps:

```yaml
      - name: selfheal unit tests
        run: |
          for t in scripts/selfheal/*.test.sh; do
            echo "== $t =="; bash "$t"
          done
```

- [ ] **Step 2: Run the whole suite locally**

Run:
```bash
for t in scripts/selfheal/*.test.sh; do echo "== $t =="; bash "$t" || exit 1; done
```
Expected: every file prints `... PASS`, exit 0.

- [ ] **Step 3: Live smoke on the box (observe mode, no mutation)**

Run:
```bash
SELFHEAL_MODE=observe bash scripts/selfheal/selfheal-watch.sh
cat /home/cmit/oidx-runtime/selfheal/latest.json | python3 -m json.tool | head -30
```
Expected: a real snapshot with `findings` (likely near-empty on a healthy box), a summary line `mode=observe findings=<n>`, and `ledger.jsonl` created. No services touched.

- [ ] **Step 4: Verify the kill-switch + dry-run end-to-end**

Run:
```bash
touch /home/cmit/oidx-runtime/selfheal/DISABLE
bash scripts/selfheal/sweep.sh | bash scripts/selfheal/remediate.sh   # prints "halted (kill-switch)" for any ops finding
rm -f /home/cmit/oidx-runtime/selfheal/DISABLE
bash scripts/selfheal/sweep.sh | bash scripts/selfheal/remediate.sh --dry-run
```
Expected: with `DISABLE` present, no action ("halted"); with `--dry-run`, only "dry-run: would ..." lines. No unit is restarted.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci(selfheal): run selfheal unit tests in CI"
```

---

## Self-Review

**Spec coverage:**
- Collectors (health, log-liveness, log-signal, edge, security) → Tasks 2-6 ✓
- Sweep/snapshot → Task 7 ✓ · Ledger + fingerprint dedup → Tasks 1,8 ✓
- Remediator Tier-0 + safety envelope (mode gate, kill-switch, anti-flap, health-gate, dry-run, blast-radius via anti-flap+escalate) → Task 9 ✓
- `/selfheal-watch` routine (observe mode) + runbook + phased rollout controls → Task 10 ✓
- Testing convention (per-collector tests, remediator envelope tests, ledger tests) + CI → all tasks + Task 11 ✓
- Phase-2 items (triage/security/review routines, Tier-1 harness) are explicitly out of MVP scope (spec §MVP) — no task, by design.

**Placeholder scan:** No TBD/TODO; every step has complete runnable code and exact commands. Injected-action seams (`SH_*_PROBE`/`SH_ACT_*`) are defined where used.

**Type/name consistency:** finding keys (`fingerprint,class,severity,service,message,data,suggested_action`) are identical across lib/collectors/ledger/remediator; `sh_finding`/`sh_fingerprint`/`sh_mode`/`sh_killed` names match between `lib.sh` and callers; state paths (`latest.json`, `ledger.jsonl`, `DISABLE`, `MODE`, `flap`) consistent; suggested actions (`restart_unit`, `restart_nginx`) match between `collect-*` emitters and the remediator `case`.
