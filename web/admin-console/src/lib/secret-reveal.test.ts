import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { useRevealedSecret, copyWithWarning } from './secret-reveal'

describe('useRevealedSecret', () => {
  beforeEach(() => vi.useFakeTimers())
  afterEach(() => vi.useRealTimers())
  it('reveals then auto-clears after the TTL', () => {
    const { result } = renderHook(() => useRevealedSecret(1000))
    act(() => result.current.reveal('topsecret'))
    expect(result.current.value).toBe('topsecret')
    act(() => vi.advanceTimersByTime(1000))
    expect(result.current.value).toBeNull()
  })
  it('clear() wipes the value immediately', () => {
    const { result } = renderHook(() => useRevealedSecret(10000))
    act(() => result.current.reveal('x'))
    act(() => result.current.clear())
    expect(result.current.value).toBeNull()
  })
})

describe('copyWithWarning', () => {
  it('returns false when clipboard write rejects', async () => {
    vi.stubGlobal('navigator', { clipboard: { writeText: () => Promise.reject(new Error('denied')) } })
    expect(await copyWithWarning('s')).toBe(false)
    vi.unstubAllGlobals()
  })
})
