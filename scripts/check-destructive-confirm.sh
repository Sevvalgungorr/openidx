#!/usr/bin/env bash
# Guard: a page containing a destructive mutation (identifier matches a destructive
# verb) MUST also use ConfirmAction or AlertDialog. Heuristic + allowlist. Backstop
# against "one-click delete/revoke/terminate with no confirmation".
# Default: warn (exit 0). --enforce: exit 1 if any offender.
set -uo pipefail
cd "$(dirname "$0")/.."
PAGES="${SH_PAGES_DIR:-web/admin-console/src/pages}"
ENFORCE=0; [ "${1:-}" = "--enforce" ] && ENFORCE=1
VERBS='delete|revoke|rotate|terminate|deprovision|quarantine|legalHold|legal_hold|broadcast|revert|unblock|remove'
ALLOWLIST=""
offenders=0
while IFS= read -r f; do
  base=$(basename "$f")
  case " $ALLOWLIST " in *" $base "*) continue;; esac
  if grep -Eiq "($VERBS)[A-Za-z]*\.mutate\(|\.mutate\([^)]*($VERBS)|api\.delete\(" "$f"; then
    if ! grep -Eq 'ConfirmAction|AlertDialog' "$f"; then
      echo "offender: $f"
      offenders=$((offenders+1))
    fi
  fi
done < <(find "$PAGES" -name '*.tsx' ! -name '*.test.tsx')
echo "destructive-confirm offenders: $offenders"
if [ "$ENFORCE" = 1 ] && [ "$offenders" -gt 0 ]; then exit 1; fi
exit 0
