/**
 * Visual helpers that give each authenticator account a recognizable, colorful
 * identity — the little rounded tile with the issuer's initial you see in
 * Microsoft / Google Authenticator. Deterministic: the same issuer always maps
 * to the same color, so the list stays visually stable across launches.
 */

/** A small, readable palette (Microsoft-Authenticator-ish tile colors). */
const TILE_COLORS = [
  '#2563EB', // blue
  '#7C3AED', // violet
  '#DB2777', // pink
  '#DC2626', // red
  '#EA580C', // orange
  '#CA8A04', // amber
  '#16A34A', // green
  '#0891B2', // cyan
  '#4F46E5', // indigo
  '#0D9488', // teal
];

/** Stable hash of a string → palette index. */
function hashString(input: string): number {
  let h = 0;
  for (let i = 0; i < input.length; i++) {
    h = (h << 5) - h + input.charCodeAt(i);
    h |= 0; // 32-bit
  }
  return Math.abs(h);
}

/** The tile background color for an issuer (deterministic). */
export function tileColor(issuer: string): string {
  const key = (issuer || 'Account').trim().toLowerCase();
  return TILE_COLORS[hashString(key) % TILE_COLORS.length];
}

/**
 * The one or two letters shown on the tile. Uses the first letters of the first
 * two words ("Amazon Web Services" → "AW"), else the first two characters.
 */
export function tileInitials(issuer: string): string {
  const name = (issuer || 'Account').trim();
  if (!name) return '?';
  const words = name.split(/\s+/).filter(Boolean);
  if (words.length >= 2) {
    return (words[0][0] + words[1][0]).toUpperCase();
  }
  return name.slice(0, 2).toUpperCase();
}
