#!/usr/bin/env bash
# Deploy / re-create the PAM OpenZiti session broker stack (Z3).
#
# The direct PAM broker (pam-guacd + pam-guacamole) already runs; this adds the
# Ziti reach broker so PAM entries with reach_mode=ziti dial their target over
# the OpenZiti overlay (no inbound target exposure). Idempotent-ish: it removes
# and recreates the three ziti containers, reusing the enrolled tunnel identity
# and the guac_ziti database.
#
# Prerequrisites already satisfied on this box:
#   - pam-broker-net podman network + pam-guac-db (postgres, user 'guacamole')
#   - controller advertises ctrl.tdv.org (Z1) so the tunnel identity's JWT points
#     at a resolvable FQDN
#   - enrolled #pam-broker-dialers identity at
#     /home/cmit/oidx-runtime/oidx-ziti/pam-broker-identity/pam-broker.json
#   - guac_ziti database seeded with the Guacamole schema and its 'guacadmin'
#     password set to $GUAC_ZITI_ADMIN_PASSWORD (below)
#   - access-service run-access.sh exports GUACAMOLE_ZITI_URL/USER/PASSWORD
#
# After running, GET /api/v1/access/pam/broker/status must report
#   {"ziti_broker":true,"reach_modes":["direct","ziti"]}
set -euo pipefail

NET=pam-broker-net
ZITI_ID_DIR=/home/cmit/oidx-runtime/oidx-ziti/pam-broker-identity
GUAC_ZITI_PORT=10091
DB_PASS="$(podman inspect pam-guac-db --format '{{range .Config.Env}}{{println .}}{{end}}' | grep POSTGRES_PASSWORD | cut -d= -f2)"
GUAC_ZITI_ADMIN_PASSWORD="${GUAC_ZITI_ADMIN_PASSWORD:?set GUAC_ZITI_ADMIN_PASSWORD in the environment (do not hardcode secrets)}"

echo "== removing any existing ziti broker containers =="
podman rm -f pam-guacamole-ziti pam-ziti-tunnel pam-guacd-ziti 2>/dev/null || true

echo "== 1/3 guacd-ziti (owns the shared netns; publishes the broker port) =="
podman run -d --name pam-guacd-ziti --network "$NET" \
  -p 127.0.0.1:${GUAC_ZITI_PORT}:8080 --restart unless-stopped \
  docker.io/guacamole/guacd:1.6.0

echo "== 2/3 ziti-tunnel (shares guacd-ziti netns; dials PAM services over overlay) =="
podman run -d --name pam-ziti-tunnel --restart unless-stopped \
  --network "container:pam-guacd-ziti" --cap-add NET_ADMIN --device /dev/net/tun \
  -v "${ZITI_ID_DIR}:/ziti-identity:Z" \
  --entrypoint ziti-edge-tunnel \
  docker.io/openziti/ziti-edge-tunnel:1.16.2 \
  run --identity /ziti-identity/pam-broker.json

echo "== 3/3 guacamole-ziti (guac_ziti DB; guacd on localhost via shared netns) =="
podman run -d --name pam-guacamole-ziti --restart unless-stopped \
  --network "container:pam-guacd-ziti" \
  -e GUACD_HOSTNAME=localhost -e GUACD_PORT=4822 \
  -e POSTGRESQL_HOSTNAME=pam-guac-db -e POSTGRESQL_DATABASE=guac_ziti \
  -e POSTGRESQL_USER=guacamole -e POSTGRESQL_PASSWORD="$DB_PASS" \
  -e POSTGRESQL_AUTO_CREATE_ACCOUNTS=true \
  docker.io/guacamole/guacamole:1.6.0

echo "== waiting for guacamole-ziti to come up =="
sleep 12
code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${GUAC_ZITI_PORT}/guacamole/" || true)
echo "guacamole-ziti http://127.0.0.1:${GUAC_ZITI_PORT}/guacamole -> ${code}"
login=$(curl -s -o /dev/null -w '%{http_code}' -X POST \
  "http://127.0.0.1:${GUAC_ZITI_PORT}/guacamole/api/tokens" \
  -d "username=guacadmin&password=${GUAC_ZITI_ADMIN_PASSWORD}" || true)
echo "guacadmin REST login -> ${login} (expect 200)"

echo
echo "Done. Restart access-service so it picks up GUACAMOLE_ZITI_URL, then verify:"
echo "  systemctl --user restart oidx-access.service"
echo "  curl -sk -H 'Authorization: Bearer <admin>' https://openidx.tdv.org/api/v1/access/pam/broker/status"
echo "Expect: {\"ziti_broker\":true,\"reach_modes\":[\"direct\",\"ziti\"]}"
echo
echo "NOTE: enabling reach_mode=ziti on a PAM entry (admin) provisions a per-entry"
echo "Ziti service (openidx-pam-<id>) and a broker loopback port; the tunnel must be"
echo "restarted to proxy the new service->port binding (see README.pam-broker.md)."
