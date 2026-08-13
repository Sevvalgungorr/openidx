#!/usr/bin/env bash
# Apply the BrowZer WSS config to the OpenZiti edge router so it survives
# recreation: stage the *.tdv.org cert + the WSS config.yml into the router's
# named volume, then run the router with the canonical command.
#
# Prereq: the router must already be enrolled (identity in the volume). For a
# first-time/post-wipe enroll, pass --enroll with a fresh JWT staged at
# $JWT_DIR/oidx-router.jwt (see README.md).
#
# Idempotent: safe to re-run (uses podman --replace).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

ROUTER_NAME="${ROUTER_NAME:-oidx-ziti-router}"
VOLUME="${VOLUME:-oidx_ziti_router_cfg}"
IMAGE="${IMAGE:-docker.io/openziti/ziti-router:latest}"
CTRL_ADDR="${CTRL_ADDR:-ziti-controller.localtest.me}"
# NAT-facing router advertise FQDN. Must be publicly resolvable + TCP/3022
# forwarded to this host so off-network SDK/tunneler/mobile clients can reach
# the data plane (the internal ziti-router.localtest.me → 127.0.0.1 does not
# work over NAT). Reuses the browzer.tdv.org name + *.tdv.org cert.
ROUTER_ADDR="${ROUTER_ADDR:-browzer.tdv.org}"
# the real *.tdv.org cert/key presented on the WSS listener (browser-trusted)
TDV_CERT="${TDV_CERT:-/home/cmit/oidx-runtime/oidx-tls/tdv-fullchain.pem}"
TDV_KEY="${TDV_KEY:-/home/cmit/oidx-runtime/oidx-tls/tdv-key.pem}"
JWT_DIR="${JWT_DIR:-/home/cmit/oidx-runtime/oidx-ziti}"   # holds oidx-router.jwt for --enroll
ENROLL=false
[[ "${1:-}" == "--enroll" ]] && ENROLL=true

echo "==> staging *.tdv.org cert + WSS config.yml into volume ${VOLUME}"
# helper container that mounts the volume + the host cert dir, copies things in
podman run --rm \
  -v "${VOLUME}":/persistent \
  -v "${TDV_CERT}":/in/tdv-fullchain.pem:ro \
  -v "${TDV_KEY}":/in/tdv-key.pem:ro \
  -v "${HERE}/config.reference.yml":/in/config.yml:ro \
  docker.io/library/alpine:latest sh -c '
    cp /in/tdv-fullchain.pem /persistent/tdv-fullchain.pem
    cp /in/tdv-key.pem       /persistent/tdv-key.pem
    cp /in/config.yml        /persistent/config.yml
    chmod 644 /persistent/tdv-fullchain.pem /persistent/config.yml
    chmod 640 /persistent/tdv-key.pem
  '

COMMON_ENV=(
  -e ZITI_HOME=/persistent
  -e ZITI_CTRL_ADVERTISED_ADDRESS="${CTRL_ADDR}" -e ZITI_CTRL_ADVERTISED_PORT=1280
  -e ZITI_ROUTER_ADVERTISED_ADDRESS="${ROUTER_ADDR}" -e ZITI_ROUTER_PORT=3022
  -e ZITI_BOOTSTRAP=true -e ZITI_BOOTSTRAP_CONFIG=false -e PFXLOG_NO_JSON=true
)

if $ENROLL; then
  echo "==> running router WITH enrollment (JWT from ${JWT_DIR}/oidx-router.jwt)"
  podman run --replace -d --name "${ROUTER_NAME}" --network host \
    "${COMMON_ENV[@]}" \
    -e ZITI_BOOTSTRAP_ENROLLMENT=true -e ZITI_ENROLL_TOKEN=/jwt/oidx-router.jwt \
    -v "${VOLUME}":/persistent \
    -v "${JWT_DIR}":/jwt:ro,z \
    "${IMAGE}"
else
  echo "==> running router (steady state — already enrolled)"
  podman run --replace -d --name "${ROUTER_NAME}" --network host \
    "${COMMON_ENV[@]}" \
    -e ZITI_BOOTSTRAP_ENROLLMENT=false \
    -v "${VOLUME}":/persistent \
    "${IMAGE}"
fi

echo "==> done. verify: ss -ltn | grep 3023  &&  ziti edge list edge-routers"
