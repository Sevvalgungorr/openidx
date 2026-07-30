#!/usr/bin/env bash
# ziti-quickstart.sh — One-command OpenZiti fabric for OpenIDX.
#
# Brings up the Ziti controller (with the bundled ZAC admin console) and a
# self-enrolling edge router from the dev docker-compose stack, waits until
# the controller is healthy, and prints the console URL + credentials.
#
# Usage: ./scripts/ziti-quickstart.sh [down]
#   down  — stop the Ziti services (volumes are kept; `docker volume rm` to reset)
#   HA=1  — also start a second edge router (docker-compose.ziti-ha.yml) so the
#           data plane survives a router failure/restart

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/deployments/docker/docker-compose.yml"
HA_COMPOSE_FILE="$REPO_ROOT/deployments/docker/docker-compose.ziti-ha.yml"
ENV_FILE="$REPO_ROOT/.env"

ZITI_SERVICES=(ziti-controller ziti-router-init ziti-router)
COMPOSE_FILES=(-f "$COMPOSE_FILE")
if [[ "${HA:-0}" == "1" ]]; then
  COMPOSE_FILES+=(-f "$HA_COMPOSE_FILE")
  ZITI_SERVICES+=(ziti-router-2-init ziti-router-2)
fi
CONSOLE_URL="https://ziti-controller.localtest.me:11280/zac/"

# --- pick compose binary (v2 plugin preferred) ---
if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose)
else
  echo "ERROR: docker compose (or docker-compose) is required" >&2
  exit 1
fi

if [[ "${1:-}" == "down" ]]; then
  "${COMPOSE[@]}" "${COMPOSE_FILES[@]}" --env-file "$ENV_FILE" stop "${ZITI_SERVICES[@]}"
  echo "Ziti services stopped. State is preserved in docker volumes."
  exit 0
fi

# --- secrets ---
if [[ ! -f "$ENV_FILE" ]]; then
  echo "==> No .env found — generating secrets..."
  "$SCRIPT_DIR/generate-secrets.sh"
fi
ZITI_PWD="$(grep -E '^ZITI_PWD=' "$ENV_FILE" | cut -d= -f2-)"
if [[ -z "$ZITI_PWD" ]]; then
  echo "ERROR: ZITI_PWD is not set in $ENV_FILE — run scripts/generate-secrets.sh" >&2
  exit 1
fi

# --- start controller + router(s) ---
if [[ "${HA:-0}" == "1" ]]; then
  echo "==> Starting Ziti controller and TWO edge routers (HA data plane)..."
else
  echo "==> Starting Ziti controller and edge router..."
fi
"${COMPOSE[@]}" "${COMPOSE_FILES[@]}" --env-file "$ENV_FILE" up -d "${ZITI_SERVICES[@]}"

# --- wait for controller health ---
echo -n "==> Waiting for controller to become healthy"
for _ in $(seq 1 60); do
  state="$(docker inspect -f '{{.State.Health.Status}}' openidx-ziti-controller 2>/dev/null || echo starting)"
  if [[ "$state" == "healthy" ]]; then
    echo " ✓"
    break
  fi
  echo -n "."
  sleep 2
done
if [[ "${state:-}" != "healthy" ]]; then
  echo ""
  echo "ERROR: controller did not become healthy in time. Check logs:" >&2
  echo "  ${COMPOSE[*]} -f $COMPOSE_FILE logs ziti-controller" >&2
  exit 1
fi

cat <<EOF

──────────────────────────────────────────────────────────────────
 OpenZiti fabric is up.

 ZAC admin console:  $CONSOLE_URL
   username:         admin
   password:         \$ZITI_PWD from .env ($(printf '%.8s' "$ZITI_PWD")...)

 (The controller uses a self-signed CA — accept the browser warning.)

 Next steps:
   1. Start OpenIDX (make dev-docker) — the access-service auto-connects
      to this controller using the same credentials.
   2. Admin Console → Network Setup shows a guided checklist.
   3. Proxy Routes → flip the OpenZiti / BrowZer toggle on any route
      to publish it over the zero-trust overlay.
──────────────────────────────────────────────────────────────────
EOF
