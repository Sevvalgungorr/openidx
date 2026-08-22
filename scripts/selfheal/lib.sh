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
  # Default data to '{}' in a separate step: "${6:-{}}" mis-parses in bash
  # (the first '}' closes the expansion, leaving a stray trailing '}').
  local sf_data="${6:-}"; [ -z "$sf_data" ] && sf_data='{}'
  SF_CLASS="$1" SF_SEV="$2" SF_FP="$3" SF_SVC="$4" SF_MSG="$5" \
  SF_DATA="$sf_data" SF_ACT="${7:-}" python3 - <<'PY'
import json, os, datetime
data = os.environ["SF_DATA"]
try: data = json.loads(data)
except Exception: data = {"raw": data}
print(json.dumps({
  "ts": datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ"),
  "class": os.environ["SF_CLASS"], "severity": os.environ["SF_SEV"],
  "fingerprint": os.environ["SF_FP"], "service": os.environ["SF_SVC"],
  "message": os.environ["SF_MSG"], "data": data,
  "suggested_action": os.environ["SF_ACT"],
}, separators=(",", ":")))
PY
}
