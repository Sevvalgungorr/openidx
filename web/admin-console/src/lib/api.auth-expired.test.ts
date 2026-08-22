import { describe, it, expect, vi } from 'vitest'
import { setAuthExpiredHandler, notifyAuthExpired } from './api'

describe('auth-expired handler', () => {
  it('invokes a registered handler once, and is a no-op after clearing', () => {
    const fn = vi.fn()
    setAuthExpiredHandler(fn)
    notifyAuthExpired('/api/v1/users')
    expect(fn).toHaveBeenCalledTimes(1)
    setAuthExpiredHandler(null)
    notifyAuthExpired('/api/v1/users')
    expect(fn).toHaveBeenCalledTimes(1)
  })
  it('does not fire for OAuth/refresh/login URLs (avoids redirect loops)', () => {
    const fn = vi.fn()
    setAuthExpiredHandler(fn)
    notifyAuthExpired('/oauth/token')
    notifyAuthExpired('https://host/login')
    expect(fn).not.toHaveBeenCalled()
    setAuthExpiredHandler(null)
  })
})
