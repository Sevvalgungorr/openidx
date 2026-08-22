#!/usr/bin/env bash
# Guard: admin-console pages must use design-system tokens, not raw Tailwind
# neutral/brand literals. WHY: hard-coded bg-white / text-gray-500 / text-black
# / bg-blue-600 etc. render the same in light and dark mode, so a page that
# looks fine on a light background turns into unreadable dark-on-dark (or a
# blinding white panel) the moment the user flips the theme. The HSL token
# classes (bg-background, text-muted-foreground, bg-card, text-primary, ...)
# already adapt per theme, so pages should reach for those instead.
#
# Default: warn (print offenders + count, exit 0). --enforce: exit 1 if any.
# SH_PAGES_DIR overrides the pages dir (used by the paired .test.sh).
set -uo pipefail
cd "$(dirname "$0")/.."
PAGES="${SH_PAGES_DIR:-web/admin-console/src/pages}"
ENFORCE=0; [ "${1:-}" = "--enforce" ] && ENFORCE=1

# Neutral/brand literals that break dark mode. These should be tokens. The set is
# kept EXACTLY aligned with the token-migration mapping (spec Sub-project B): only
# the light neutrals + brand blue that have a token equivalent. Darker semantic
# grays (bg-gray-400..900 used as chart fills/dots) are intentionally NOT flagged.
PATTERN='bg-white|text-gray-[3-9]00\b|bg-gray-(50|100|200|300)\b|border-gray-(100|200|300)\b|text-black|text-blue-600\b|bg-blue-600\b'

offenders=0
while IFS= read -r f; do
  if grep -Eq "$PATTERN" "$f"; then
    echo "offender: $f"
    offenders=$((offenders+1))
  fi
done < <(find "$PAGES" -name '*.tsx' ! -name '*.test.tsx' | sort)

echo "raw-neutral-literals offenders: $offenders"
if [ "$ENFORCE" = 1 ] && [ "$offenders" -gt 0 ]; then exit 1; fi
exit 0
