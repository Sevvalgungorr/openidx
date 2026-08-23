import { describe, it, expect } from 'vitest'
import {
  complianceTooltip,
  formatCompliancePercent,
  hasComplianceMeasurement,
} from './compliance'

describe('compliance score rendering', () => {
  // The defect this file exists for: three pages turned "no data" and a bad
  // unit conversion into confident-looking numbers.
  it('does not print a percentage when nothing was measured', () => {
    // Measured on the live database 2026-08-14: 10 of 16 agents are 'unknown'
    // with score 0, which the console rendered as a flat "0%".
    expect(formatCompliancePercent('unknown', 0)).toBe('—')
    expect(formatCompliancePercent('', 0)).toBe('—')
    expect(formatCompliancePercent('pending', 0)).toBe('—')
    expect(formatCompliancePercent(undefined, undefined)).toBe('—')
  })

  it('explains the dash instead of leaving the reader guessing', () => {
    expect(complianceTooltip('unknown')).toMatch(/never reported/)
    expect(complianceTooltip('unknown', '2026-07-20')).toMatch(/2026-07-20/)
    expect(complianceTooltip('unknown')).toMatch(/not zero/)
    // A real measurement needs no excuse.
    expect(complianceTooltip('compliant')).toBeUndefined()
  })

  it('converts the 0-1 fraction to a percentage', () => {
    // my-devices.tsx and user-access-360.tsx rendered Math.round(score)%, so a
    // fully compliant device showed "1%".
    expect(formatCompliancePercent('compliant', 1)).toBe('100%')
    expect(formatCompliancePercent('non_compliant', 0.55)).toBe('55%')
    expect(formatCompliancePercent('grace_period', 0.804)).toBe('80%')
  })

  it('still distinguishes a measured zero from no measurement', () => {
    // This is the whole point: both used to look identical.
    expect(formatCompliancePercent('non_compliant', 0)).toBe('0%')
    expect(formatCompliancePercent('unknown', 0)).toBe('—')
  })

  it('clamps out-of-range values instead of printing 10000%', () => {
    // v128 normalized the stored rows, but an agent shipping an old
    // percentage would otherwise reproduce the original field report.
    expect(formatCompliancePercent('compliant', 100)).toBe('100%')
    expect(formatCompliancePercent('compliant', -1)).toBe('0%')
    expect(formatCompliancePercent('compliant', NaN)).toBe('0%')
  })

  it('treats status case-insensitively', () => {
    expect(hasComplianceMeasurement('UNKNOWN')).toBe(false)
    expect(hasComplianceMeasurement('compliant')).toBe(true)
  })
})
