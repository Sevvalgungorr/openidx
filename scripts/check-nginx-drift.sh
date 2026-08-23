#!/usr/bin/env bash
# Fails when the committed front-door config and the deployed one disagree.
#
# The Guacamole CSP defect (field report, 2026-08-14) was invisible in review
# because the file that set the header lived only on the box. Committing a copy
# only helps if the copies stay equal, so this compares them.
#
# On CI the live file is absent; we skip loudly rather than pass quietly, since
# a check that reports success without checking anything is worse than none.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

REPO="deployments/docker/oidx-nginx/nginx.conf"
LIVE="${OIDX_NGINX_LIVE_CONF:-/home/cmit/oidx-runtime/oidx-tls/nginx.conf}"

if [ ! -f "$REPO" ]; then
  echo "NGINX_DRIFT: committed config missing at $REPO"; exit 1
fi
if [ ! -f "$LIVE" ]; then
  echo "NGINX_DRIFT=skipped (no deployed config at $LIVE; run this on the edge host)"
  exit 0
fi
if diff -u "$REPO" "$LIVE" > /tmp/nginx-drift.diff 2>&1; then
  echo "NGINX_DRIFT=0"
  exit 0
fi
echo "NGINX_DRIFT=1 (deployed config differs from the committed one)"
sed -n '1,40p' /tmp/nginx-drift.diff
exit 1
