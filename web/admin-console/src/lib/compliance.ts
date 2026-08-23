/**
 * Rendering helpers for `enrolled_agents.compliance_score`.
 *
 * The field is a 0.0-1.0 fraction: the agent report handler computes it as
 * `scoreSum / weightSum` (internal/access/agent_api.go) and the API returns it
 * verbatim. Two facts about it caused three separate display defects, so the
 * conversion lives here once instead of at each call site.
 *
 * 1. It must be multiplied by 100 to be a percentage. Two pages rendered
 *    `Math.round(score)%` directly, so a fully compliant device (1.0) showed
 *    as "1%" -- the worst possible misreading, since it looks like a real
 *    measurement of near-total failure.
 *
 * 2. It defaults to 0 when nothing has ever been reported. The column default
 *    is 0.0 and `compliance_status` defaults to 'unknown', so an agent that
 *    has never checked in is indistinguishable on screen from one that
 *    reported and scored nothing. Measured on the live database (2026-08-14):
 *    10 of 16 agents are 'unknown' with score 0, and the field report from
 *    the same day called this out as a suspicious "0%".
 */

/** Statuses that mean "we have no measurement", not "the measurement is zero". */
const UNMEASURED = new Set(['unknown', '', 'pending'])

export function hasComplianceMeasurement(status: string | undefined | null): boolean {
  return !UNMEASURED.has((status ?? '').toLowerCase())
}

/**
 * Formats the score for display.
 *
 * Returns an em dash when the status says nothing has been measured, so the
 * absence of data reads as absence rather than as a score of zero.
 */
export function formatCompliancePercent(
  status: string | undefined | null,
  score: number | undefined | null,
): string {
  if (!hasComplianceMeasurement(status)) return '—'
  const n = typeof score === 'number' && Number.isFinite(score) ? score : 0
  // Clamp: v128 normalized stored values into [0,1], but an agent reporting an
  // old percentage would otherwise render as "10000%" again.
  const pct = Math.round(Math.min(Math.max(n, 0), 1) * 100)
  return `${pct}%`
}

/** Human explanation for the em dash, used as a tooltip. */
export function complianceTooltip(
  status: string | undefined | null,
  lastReportAt?: string | null,
): string | undefined {
  if (hasComplianceMeasurement(status)) return undefined
  return lastReportAt
    ? `No compliance report since ${lastReportAt}; the score is unknown, not zero.`
    : 'This agent has never reported posture, so the score is unknown, not zero.'
}
