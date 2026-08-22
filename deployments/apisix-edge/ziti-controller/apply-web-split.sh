#!/usr/bin/env bash
# Apply the management/client web-listener split to a running OpenZiti controller.
# =============================================================================
# Idempotent. Splits the single `client-management` web listener on 0.0.0.0:1280
# into:
#   client-public    0.0.0.0:1280   edge-client + edge-oidc
#   management-local 127.0.0.1:1281  edge-management + fabric + zac
#
# The identity + options blocks are copied VERBATIM from the existing listener,
# so no PKI paths are invented. Backs up config.yml first. Verifies the split
# with live HTTP probes after restart and rolls back automatically if the client
# plane does not come back up.
#
# See web-listeners.reference.yml for the rationale and the 2026-08-17 measurements.
set -euo pipefail

CTR=${ZITI_CTRL_CONTAINER:-oidx-ziti-controller}
CFG=${ZITI_CTRL_CONFIG:-/ziti-controller/config.yml}
MGMT_PORT=${MGMT_LOCAL_PORT:-1281}
BACKUP_DIR=${BACKUP_DIR:-/home/cmit/oidx-runtime/ctrl-config-backup}
TS=$(date +%Y%m%d-%H%M%S)

log() { printf '%s\n' "$*" >&2; }

command -v podman >/dev/null || { log "podman not found"; exit 1; }
podman inspect "$CTR" >/dev/null 2>&1 || { log "container $CTR not found"; exit 1; }

mkdir -p "$BACKUP_DIR"
log "== backing up current config to $BACKUP_DIR/config.yml.$TS =="
podman cp "$CTR:$CFG" "$BACKUP_DIR/config.yml.$TS"

# --- already split? (idempotent no-op) ---
if podman exec "$CTR" grep -q 'name: management-local' "$CFG" 2>/dev/null; then
  log "== already split (management-local listener present); nothing to do =="
  exit 0
fi

log "== rewriting web: section (identity/options copied verbatim) =="
NEW=$(mktemp)
podman cp "$CTR:$CFG" "$NEW.orig"
python3 - "$NEW.orig" "$NEW" "$MGMT_PORT" <<'PY'
import sys, yaml
src, dst, mgmt_port = sys.argv[1], sys.argv[2], int(sys.argv[3])
with open(src) as f:
    doc = yaml.safe_load(f)
listeners = doc.get('web') or []
# Find the listener that binds 0.0.0.0:1280 and serves edge-management.
base = None
for l in listeners:
    apis = {a.get('binding') for a in l.get('apis', [])}
    if 'edge-management' in apis and 'edge-client' in apis:
        base = l
        break
if base is None:
    print("no combined client+management listener found; aborting", file=sys.stderr)
    sys.exit(2)

identity = base.get('identity')
options  = base.get('options')
# Preserve the public address from the base bindPoint.
bp = base['bindPoints'][0]
pub_iface = bp['interface']              # 0.0.0.0:1280
pub_addr  = bp.get('address', pub_iface) # ctrl.tdv.org:1280
host = pub_addr.rsplit(':', 1)[0]

client_public = {
    'name': 'client-public',
    'bindPoints': [{'interface': pub_iface, 'address': pub_addr}],
    'identity': identity,
    'options': options,
    'apis': [
        {'binding': 'edge-client', 'options': {}},
        {'binding': 'edge-oidc',   'options': {}},
    ],
}
management_local = {
    'name': 'management-local',
    'bindPoints': [{'interface': f'127.0.0.1:{mgmt_port}',
                    'address': f'{host}:{mgmt_port}'}],
    'identity': identity,
    'options': options,
    'apis': [
        {'binding': 'edge-management', 'options': {}},
        {'binding': 'fabric',          'options': {}},
        {'binding': 'zac', 'options': {'location': '/ziti-console',
                                       'indexFile': 'index.html'}},
    ],
}
# Replace the base listener in place; keep any other listeners untouched.
doc['web'] = [client_public if l is base else l for l in listeners]
doc['web'].insert(doc['web'].index(client_public) + 1, management_local)

with open(dst, 'w') as f:
    yaml.safe_dump(doc, f, default_flow_style=False, sort_keys=False)
print("split written", file=sys.stderr)
PY

log "== validating new YAML =="
python3 -c "import yaml,sys; d=yaml.safe_load(open('$NEW')); \
  names=[l['name'] for l in d['web']]; \
  assert 'client-public' in names and 'management-local' in names, names; \
  print('listeners:', names)"

log "== installing new config + restart =="
podman cp "$NEW" "$CTR:$CFG"
podman restart "$CTR" >/dev/null
sleep 6

probe() { curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "$1"; }
c_client=$(probe "https://127.0.0.1:1280/edge/client/v1/version")
c_mgmt=$(probe   "https://127.0.0.1:1280/edge/management/v1/version")
m_mgmt=$(probe   "https://127.0.0.1:$MGMT_PORT/edge/management/v1/version")
log "== probes: :1280 client=$c_client  :1280 mgmt=$c_mgmt  :$MGMT_PORT mgmt=$m_mgmt =="

if [[ "$c_client" == "200" && "$c_mgmt" == "404" && "$m_mgmt" == "200" ]]; then
  log "== SPLIT OK: client public, management loopback-only =="
  exit 0
fi

log "!! split verification FAILED; rolling back to $BACKUP_DIR/config.yml.$TS"
podman cp "$BACKUP_DIR/config.yml.$TS" "$CTR:$CFG"
podman restart "$CTR" >/dev/null
exit 1
