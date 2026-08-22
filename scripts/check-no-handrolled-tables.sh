#!/usr/bin/env bash
# Guard: admin-console pages must render tabular data through the design-system
# <Table> component (components/ui/table), not a hand-rolled <table>. WHY: the
# shared Table carries the tokenized borders, header styling, hover and
# dark-mode colours; a raw <table> ships none of that, so it drifts visually,
# breaks in dark mode, and skips the accessibility affordances the wrapper adds.
#
# Default: warn (print offenders + count, exit 0). --enforce: exit 1 if any.
# SH_PAGES_DIR overrides the pages dir (used by the paired .test.sh).
set -uo pipefail
cd "$(dirname "$0")/.."
PAGES="${SH_PAGES_DIR:-web/admin-console/src/pages}"
ENFORCE=0; [ "${1:-}" = "--enforce" ] && ENFORCE=1

offenders=0
while IFS= read -r f; do
  if grep -q '<table' "$f"; then
    echo "offender: $f"
    offenders=$((offenders+1))
  fi
done < <(find "$PAGES" -name '*.tsx' ! -name '*.test.tsx' | sort)

echo "handrolled-tables offenders: $offenders"
if [ "$ENFORCE" = 1 ] && [ "$offenders" -gt 0 ]; then exit 1; fi
exit 0
