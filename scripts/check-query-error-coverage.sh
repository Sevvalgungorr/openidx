#!/usr/bin/env bash
# Guard: every admin-console page that reads data with useQuery MUST render
# QueryError (directly or via QueryGate). Otherwise a 401/403 silently becomes a
# "no data" empty state — the console-wide masking defect this sub-project fixes.
# Default: warn (list offenders, exit 0). --enforce: exit 1 if any offender.
set -uo pipefail
cd "$(dirname "$0")/.."
PAGES="${SH_PAGES_DIR:-web/admin-console/src/pages}"
ENFORCE=0; [ "${1:-}" = "--enforce" ] && ENFORCE=1
ALLOWLIST="api-docs.tsx"
offenders=0
while IFS= read -r f; do
  base=$(basename "$f")
  case " $ALLOWLIST " in *" $base "*) continue;; esac
  grep -q 'useQuery' "$f" || continue
  if ! grep -Eq 'QueryError|QueryGate' "$f"; then
    echo "offender: $f"
    offenders=$((offenders+1))
  fi
done < <(find "$PAGES" -name '*.tsx' ! -name '*.test.tsx')
echo "query-error-coverage offenders: $offenders"
if [ "$ENFORCE" = 1 ] && [ "$offenders" -gt 0 ]; then exit 1; fi
exit 0
