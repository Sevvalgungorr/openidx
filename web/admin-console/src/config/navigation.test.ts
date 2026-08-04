import { describe, it, expect } from 'vitest'
import appSource from '../App.tsx?raw'
import { navigation, filterNavigation, allNavHrefs } from './navigation'

// Routes declared in App.tsx, e.g. path="users" or path="audit/dashboard".
// Parsing the source keeps this test a pure consistency check — no rendering,
// no lazy-loading — so menu/route drift fails fast with a readable diff.
function appRoutePaths(): Set<string> {
  const paths = new Set<string>()
  for (const match of appSource.matchAll(/<Route\s+[^>]*path="([^"*:]+)"/g)) {
    paths.add('/' + match[1].replace(/^\//, ''))
  }
  return paths
}

describe('navigation config integrity', () => {
  it('every menu item points at a route defined in App.tsx', () => {
    const routes = appRoutePaths()
    const missing = allNavHrefs().filter((href) => !routes.has(href))
    expect(missing).toEqual([])
  })

  it('has no duplicate hrefs', () => {
    // A handful of destinations intentionally appear twice: once as a
    // self-service entry for regular users and once in an admin/operator
    // section, because the page itself is role-aware (e.g. Sessions renders
    // "My Sessions" for a user and full "Session Management" for an operator).
    // Those are allowed; every other duplicate is a config mistake.
    const intentionalDuplicates = new Set(['/sessions'])
    const hrefs = allNavHrefs()
    const dupes = hrefs.filter(
      (href, i) => hrefs.indexOf(href) !== i && !intentionalDuplicates.has(href),
    )
    expect(dupes).toEqual([])
  })

  it('keeps every page reachable that used to be in the menu, plus the audit gaps', () => {
    const hrefs = new Set(allNavHrefs())
    // Pages the audit found unreachable before this config existed:
    expect(hrefs.has('/branding')).toBe(true)
    expect(hrefs.has('/audit/dashboard')).toBe(true)
  })

  it('covers the three platform pillars as top-level domains', () => {
    const ids = navigation.map((g) => g.id)
    expect(ids).toContain('iam')
    expect(ids).toContain('ziti')
    expect(ids).toContain('pam')
    expect(ids).toContain('audit')
  })
})

describe('filterNavigation role visibility', () => {
  it('shows a plain user only the personal workspace', () => {
    const groups = filterNavigation({ roles: ['user'], viewMode: 'admin' })
    expect(groups.map((g) => g.id)).toEqual(['home'])
  })

  it('gives auditors (reporters) the audit & reporting domain', () => {
    const groups = filterNavigation({ roles: ['auditor'], viewMode: 'admin' })
    const ids = groups.map((g) => g.id)
    expect(ids).toContain('audit')
    expect(ids).not.toContain('iam')
    expect(ids).not.toContain('pam')
    const auditHrefs = groups
      .find((g) => g.id === 'audit')!
      .sections.flatMap((s) => s.items.map((i) => i.href))
    expect(auditHrefs).toContain('/audit-logs')
    expect(auditHrefs).toContain('/reports')
    // admin-gated audit config stays hidden from auditors
    expect(auditHrefs).not.toContain('/audit-archival')
  })

  it('limits compliance_reader strictly to the audit domain', () => {
    const groups = filterNavigation({ roles: ['compliance_reader'], viewMode: 'admin' })
    expect(groups.map((g) => g.id)).toEqual(['home', 'audit'])
  })

  it('gives operators (management) day-to-day items but no admin config', () => {
    const groups = filterNavigation({ roles: ['operator'], viewMode: 'admin' })
    const hrefs = groups.flatMap((g) => g.sections.flatMap((s) => s.items.map((i) => i.href)))
    expect(hrefs).toContain('/users')
    expect(hrefs).toContain('/devices')
    expect(hrefs).toContain('/guacamole-sessions')
    expect(hrefs).not.toContain('/settings')
    expect(hrefs).not.toContain('/vault-secrets')
    expect(hrefs).not.toContain('/tenant-management')
  })

  it('gives admins everything except super_admin-only entries', () => {
    const groups = filterNavigation({ roles: ['admin'], viewMode: 'admin' })
    const hrefs = groups.flatMap((g) => g.sections.flatMap((s) => s.items.map((i) => i.href)))
    expect(hrefs).toContain('/vault-secrets')
    expect(hrefs).toContain('/ziti-network')
    expect(hrefs).toContain('/branding')
    // Backend: admin does NOT have tenants:manage
    expect(hrefs).not.toContain('/tenant-management')
  })

  it('reserves tenant management for super_admin', () => {
    const groups = filterNavigation({ roles: ['super_admin'], viewMode: 'admin' })
    const hrefs = groups.flatMap((g) => g.sections.flatMap((s) => s.items.map((i) => i.href)))
    expect(hrefs).toContain('/tenant-management')
  })
})

describe('filterNavigation view modes', () => {
  it('management view caps an admin to the operator slice', () => {
    const groups = filterNavigation({ roles: ['admin'], viewMode: 'management' })
    const hrefs = groups.flatMap((g) => g.sections.flatMap((s) => s.items.map((i) => i.href)))
    expect(hrefs).toContain('/users')
    expect(hrefs).toContain('/audit-logs')
    expect(hrefs).not.toContain('/settings')
    expect(hrefs).not.toContain('/vault-secrets')
  })

  it('reporting view narrows the console to personal + audit content', () => {
    const groups = filterNavigation({ roles: ['admin'], viewMode: 'reporting' })
    expect(groups.map((g) => g.id).sort()).toEqual(['audit', 'home'])
  })
})

describe('filterNavigation search', () => {
  it('matches by name', () => {
    const groups = filterNavigation({ roles: ['admin'], viewMode: 'admin', query: 'vault' })
    const hrefs = groups.flatMap((g) => g.sections.flatMap((s) => s.items.map((i) => i.href)))
    expect(hrefs).toEqual(['/vault-secrets'])
  })

  it('matches by keyword aliases (pam, ziti, reporter)', () => {
    const pam = filterNavigation({ roles: ['admin'], viewMode: 'admin', query: 'pam' })
    expect(allNavHrefs(pam)).toContain('/vault-secrets')

    const ziti = filterNavigation({ roles: ['admin'], viewMode: 'admin', query: 'ziti' })
    expect(allNavHrefs(ziti)).toContain('/ziti-network')

    const reporter = filterNavigation({ roles: ['auditor'], viewMode: 'admin', query: 'reporter' })
    expect(allNavHrefs(reporter)).toContain('/audit-logs')
  })

  it('never surfaces items above the caller role', () => {
    const groups = filterNavigation({ roles: ['user'], viewMode: 'admin', query: 'vault' })
    expect(allNavHrefs(groups)).toEqual([])
  })

  it('returns nothing for gibberish', () => {
    const groups = filterNavigation({ roles: ['admin'], viewMode: 'admin', query: 'zzzz-no-match' })
    expect(groups).toEqual([])
  })
})
