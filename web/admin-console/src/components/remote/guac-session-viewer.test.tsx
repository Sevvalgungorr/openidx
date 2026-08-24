import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, act } from '@testing-library/react'
import { classifyGuacHash, GuacSessionViewer } from './guac-session-viewer'

describe('classifyGuacHash', () => {
  it('treats client routes as active sessions', () => {
    expect(classifyGuacHash('#/client/abc123')).toBe('client')
    expect(classifyGuacHash('#/client/abc123?token=t')).toBe('client')
    expect(classifyGuacHash('/guacamole/#/client/xyz')).toBe('client')
  })

  it('treats every non-client route as "other" (guac home / manager / empty)', () => {
    expect(classifyGuacHash('')).toBe('other')
    expect(classifyGuacHash('#/')).toBe('other')
    expect(classifyGuacHash('#/home')).toBe('other')
    expect(classifyGuacHash('#/settings')).toBe('other')
    expect(classifyGuacHash('#/manage/connections')).toBe('other')
  })
})

describe('GuacSessionViewer', () => {
  // Drive what the polled iframe reports as its current hash. The component
  // reads iframeRef.current.contentWindow.location.hash; we stub the getter so
  // the test controls the "navigation" without a real guac frame.
  let currentHash = '#/client/abc'

  beforeEach(() => {
    vi.useFakeTimers()
    currentHash = '#/client/abc'
    // jsdom iframes have a real contentWindow but its location is same-origin
    // about:blank; override the hash getter to our controllable value.
    Object.defineProperty(HTMLIFrameElement.prototype, 'contentWindow', {
      configurable: true,
      get() {
        return { location: { get hash() { return currentHash } } }
      },
    })
  })

  afterEach(() => {
    vi.useRealTimers()
    delete (HTMLIFrameElement.prototype as unknown as Record<string, unknown>).contentWindow
  })

  function open() {
    return render(
      <GuacSessionViewer open url="https://guac/x" title="DC01" onClose={() => {}} />,
    )
  }

  it('frames the guac url while the session is on a client route', () => {
    open()
    // Advance one poll so the phase resolves to active.
    act(() => { vi.advanceTimersByTime(1100) })
    const iframe = document.querySelector('iframe') as HTMLIFrameElement
    expect(iframe).toBeInTheDocument()
    expect(iframe.getAttribute('src')).toBe('https://guac/x')
    expect(screen.queryByText('Session ended')).not.toBeInTheDocument()
  })

  it('shows the OpenIDX "Session ended" overlay (not guac home) when an active session leaves the client route', () => {
    open()
    // Reach an active client session first.
    act(() => { vi.advanceTimersByTime(1100) })
    expect(document.querySelector('iframe')).toBeInTheDocument()

    // Guac navigates back to its home/manager → our monitor must take over.
    currentHash = '#/'
    act(() => { vi.advanceTimersByTime(1100) })

    expect(screen.getByText('Session ended')).toBeInTheDocument()
    // The guac frame is gone — the user can never see its chrome.
    expect(document.querySelector('iframe')).not.toBeInTheDocument()
  })

  it('shows a "Couldn\'t connect" overlay if a client route is never reached within the grace window', () => {
    currentHash = '#/' // never a client route
    open()
    act(() => { vi.advanceTimersByTime(21_000) })

    expect(screen.getByText(/Couldn't connect to DC01/)).toBeInTheDocument()
    expect(document.querySelector('iframe')).not.toBeInTheDocument()
  })
})
