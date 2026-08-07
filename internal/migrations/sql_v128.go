package migrations

// Migration v128 — clamp enrolled_agents.compliance_score into 0.0-1.0.
//
// The Agent Fleet compliance score is stored as a 0.0-1.0 fraction and the
// admin console multiplies by 100 to render a percentage. Some agents reported
// an already-percentage 0-100 value that was stored verbatim, so a stored 100
// rendered as "10000%". This normalizes existing rows: values in (1,100] are
// divided by 100, anything >100 is clamped to 1.0, and negatives are floored at
// 0.0. The write path clamps too (see the report handler), so this is a
// one-time backfill.
//
// This migration was first applied out-of-band to the live database; the file
// backfills the registry so the version sequence stays contiguous. It is
// idempotent — re-running only touches rows still outside [0,1].
var normalizeAgentComplianceScoreUp = `-- Migration 128: normalize enrolled_agents.compliance_score to [0,1].
UPDATE enrolled_agents SET compliance_score = 1.0
  WHERE compliance_score > 100;
UPDATE enrolled_agents SET compliance_score = compliance_score / 100.0
  WHERE compliance_score > 1 AND compliance_score <= 100;
UPDATE enrolled_agents SET compliance_score = 0.0
  WHERE compliance_score < 0;
`

// Down is a no-op: the original per-row pre-normalization values are not
// recoverable, and re-inflating fractions to percentages would reintroduce the
// exact rendering bug. Kept non-empty to satisfy the migration contract.
var normalizeAgentComplianceScoreDown = `-- Rollback 128: no-op (original values are not recoverable and re-inflating would reintroduce the 10000% bug).
SELECT 1;
`
