#!/usr/bin/env bash
# Blocks site-specific internal topology from entering this PUBLIC repository.
#
# Why this exists: while fixing an allow-list, a real deployment's LAN gateway
# address and its subnet breakdown were committed here, and a live internal
# proxy IP was used as test data. Neither is a credential, so secret scanners
# do not flag them -- but a gateway plus its subnet layout is an internal
# network map, and a site-specific value baked into a shared script silently
# misconfigures every OTHER deployment that runs it.
#
# SCOPE, stated honestly:
#   - This gates NEW changes (--staged / PR diffs). It does NOT claim the
#     existing tree is exhaustively clean; the repo carries many legitimate
#     placeholder addresses in UI hints, docs and fixtures.
#   - It checks internal ADDRESSES, not domain names. Whether this project's
#     own domain belongs in a public repo is a separate decision.
#   - It is a heuristic. It is deliberately biased toward silence: a checker
#     that fires on every 192.168.1.1 placeholder gets disabled within a week,
#     and then it protects nothing.
#   - --all therefore still reports false positives on the existing tree
#     (invented test fixtures, and boundary cases like a "is this private?"
#     table listing the top of each RFC1918 range). Those are NOT
#     leaks. --all is an advisory sweep for a human to read; only --staged
#     and --range are gates.
#
# Usage:
#   scripts/check-no-internal-topology.sh --staged        # pre-commit hook
#   scripts/check-no-internal-topology.sh --range <base>  # CI, diff vs base
#   scripts/check-no-internal-topology.sh --all           # advisory sweep
set -uo pipefail
cd "$(dirname "$0")/.."

# grep -P (PCRE) is a GNU extension. BSD grep on macOS does not have it and
# would exit non-zero on every call, which in a filter pipeline looks exactly
# like "found nothing" -- i.e. a silent pass. Fail loudly instead.
if ! echo x | grep -Pq x 2>/dev/null; then
  echo "FAIL: this check needs GNU grep with -P (PCRE)."
  echo "      macOS: brew install grep, then run with ggrep on PATH as grep."
  exit 2
fi

# Any private IPv4 host address.
PATTERN='(^|[^0-9.])(192\.168\.[0-9]{1,3}\.[0-9]{1,3}|10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3})([^0-9.]|$)'

# Conventional/illustrative addresses that carry no information about a real
# network. What survives this filter looks like it came from a live site
# rather than from a manual.
#   192.168.0.x / 192.168.1.x   the two subnets every manual uses
#   10.0.0.x                    stock example range
#   10.0.2.2                    VirtualBox/podman host alias
#   172.1x.0.x                  container bridge defaults
#   anything.0.0/nn             generic CIDR, not a host
# RFC5737 ranges (198.51.100.0/24, 203.0.113.0/24, 192.0.2.0/24) are public
# documentation ranges, so PATTERN never matches them -- they are the correct
# choice for tests and examples.
ALLOW='192\.168\.[01]\.[0-9]{1,3}|10\.0\.0\.[0-9]{1,3}|10\.0\.2\.2|172\.(1[6-9]|2[0-9]|3[01])\.0\.[0-9]{1,3}|[0-9]{1,3}\.[0-9]{1,3}\.0\.0/[0-9]{1,2}'

mode="${1:---staged}"

EXCL=(':!vendor/**' ':!**/node_modules/**' ':!**/*.lock' ':!**/package-lock.json')

if [ "$mode" = "--staged" ]; then
  raw=$(git diff --cached -U0 --diff-filter=ACM -- . "${EXCL[@]}" 2>/dev/null \
        | grep '^+' | grep -vE '^\+\+\+' || true)
elif [ "$mode" = "--range" ]; then
  base="${2:-}"
  [ -n "$base" ] || { echo "usage: $0 --range <base-sha>"; exit 2; }
  # Fail loudly if the base is missing: a shallow checkout would otherwise
  # make this scan an empty diff and report success.
  git rev-parse --verify --quiet "$base^{commit}" >/dev/null \
    || { echo "FAIL: base commit '$base' not available (shallow checkout?)"; exit 2; }
  raw=$(git diff -U0 --diff-filter=ACM "$base"...HEAD -- . "${EXCL[@]}" 2>/dev/null \
        | grep '^+' | grep -vE '^\+\+\+' || true)
else
  raw=$(git grep -PnI "$PATTERN" -- . "${EXCL[@]}" 2>/dev/null || true)
fi

hits=""
while IFS= read -r line; do
  [ -z "$line" ] && continue
  case "$line" in *topology-ok*) continue ;; esac
  # Keep the line only if it contains a private address that is NOT one of the
  # conventional examples.
  found=$(printf '%s' "$line" | grep -Po "$PATTERN" 2>/dev/null | grep -Pv "($ALLOW)" || true)
  [ -n "$found" ] && hits="${hits}${line}"$'\n'
done <<< "$raw"

hits=$(printf '%s' "$hits" | sed '/^$/d')

if [ -n "$hits" ]; then
  echo "FAIL: site-specific internal address in a public repository:"
  printf '%s\n' "$hits" | sed 's/^/  /'
  cat <<'EOF'

  These are not secrets, which is exactly why scanners miss them.

  Fix by either:
    - moving the value to an environment variable with a generic default
      (see MGMT_ALLOW_CIDRS in deployments/apisix-edge/seed-edge-routes.sh), or
    - using an RFC5737 documentation range in tests/examples:
      198.51.100.0/24, 203.0.113.0/24, 192.0.2.0/24, or
    - appending "topology-ok" to the line if it is genuinely required.
EOF
  exit 1
fi

echo "OK no site-specific internal topology ($mode)"
