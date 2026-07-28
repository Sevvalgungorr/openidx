import { describe, it, expect } from 'vitest'
import { navigation, filterNavigation, flattenNavItems, scoreNavItem } from './navigation'

describe('command palette helpers', () => {
  it('flattens every nav item and carries a domain label', () => {
    const flat = flattenNavItems()
    const totalItems = navigation.reduce(
      (n, g) => n + g.sections.reduce((m, s) => m + s.items.length, 0),
      0
    )
    expect(flat).toHaveLength(totalItems)
    for (const item of flat) {
      expect(item.domainLabel.length).toBeGreaterThan(0)
      expect(item.href).toMatch(/^\//)
    }
  })

  it('only offers pages the role can see (respects filterNavigation)', () => {
    const asUser = flattenNavItems(filterNavigation({ roles: ['user'], viewMode: 'admin' }))
    // A plain user sees only the personal "home" domain.
    expect(asUser.every((i) => i.domainLabel === 'Home')).toBe(true)
    expect(asUser.some((i) => i.href === '/users')).toBe(false)

    const asAdmin = flattenNavItems(filterNavigation({ roles: ['admin'], viewMode: 'admin' }))
    expect(asAdmin.some((i) => i.href === '/users')).toBe(true)
    expect(asAdmin.length).toBeGreaterThan(asUser.length)
  })

  it('ranks an exact/prefix name match above a keyword-only match', () => {
    const flat = flattenNavItems()
    const users = flat.find((i) => i.href === '/users')!
    // "Users" starts with "use"; a page that only lists "user" as a keyword must score lower.
    expect(scoreNavItem(users, 'use')).toBeGreaterThanOrEqual(60)
    expect(scoreNavItem(users, 'users')).toBeGreaterThan(scoreNavItem(users, 'use'))
  })

  it('matches on curated keywords, not just the visible name', () => {
    const flat = flattenNavItems()
    // "yubikey" is a keyword on Hardware Tokens, not in its name.
    const hit = flat.find((i) => scoreNavItem(i, 'yubikey') > 0)
    expect(hit?.href).toBe('/hardware-tokens')
  })

  it('returns 0 for a non-match and a positive score for empty query', () => {
    const item = flattenNavItems()[0]
    expect(scoreNavItem(item, 'zzzzz-nope')).toBe(0)
    expect(scoreNavItem(item, '')).toBeGreaterThan(0)
  })
})
