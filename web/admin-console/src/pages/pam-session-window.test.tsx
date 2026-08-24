import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, act } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { PamSessionWindow } from './pam-session-window'

describe('PamSessionWindow', () => {
  // Drive what the polled iframe reports as its hash (same technique as the
  // GuacSessionViewer test) so we control the "navigation" without a real frame.
  let currentHash = '#/client/abc'

  beforeEach(() => {
    vi.useFakeTimers()
    currentHash = '#/client/abc'
    localStorage.clear()
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
    localStorage.clear()
  })

  function renderAt(search: string) {
    return render(
      <MemoryRouter initialEntries={[`/pam-session${search}`]}>
        <PamSessionWindow />
      </MemoryRouter>,
    )
  }

  it('frames the guac url from a valid single-use handoff, then consumes it', () => {
    localStorage.setItem('pam-session:k1', JSON.stringify({ url: 'https://guac/x', title: 'DC01' }))
    renderAt('?k=k1')

    // Handoff is consumed (removed) immediately on mount — single use.
    expect(localStorage.getItem('pam-session:k1')).toBeNull()

    act(() => { vi.advanceTimersByTime(1100) })
    const iframe = document.querySelector('iframe') as HTMLIFrameElement
    expect(iframe).toBeInTheDocument()
    expect(iframe.getAttribute('src')).toBe('https://guac/x')
    expect(screen.queryByText('Session ended')).not.toBeInTheDocument()
  })

  it('shows the OpenIDX "Session ended" overlay (not guac chrome) when the session leaves the client route', () => {
    localStorage.setItem('pam-session:k2', JSON.stringify({ url: 'https://guac/x', title: 'DC01' }))
    renderAt('?k=k2')

    // Reach an active client session first.
    act(() => { vi.advanceTimersByTime(1100) })
    expect(document.querySelector('iframe')).toBeInTheDocument()

    // Guac navigates back to its home/manager → the monitor takes over.
    currentHash = '#/'
    act(() => { vi.advanceTimersByTime(1100) })

    expect(screen.getByText('Session ended')).toBeInTheDocument()
    // The guac frame is unmounted — the user can never see guac's chrome.
    expect(document.querySelector('iframe')).not.toBeInTheDocument()
  })

  it('shows the expired card when the handoff is missing / already consumed', () => {
    renderAt('?k=missing')
    expect(screen.getByText(/this session link has expired/i)).toBeInTheDocument()
    // No frame is ever mounted without a handoff.
    expect(document.querySelector('iframe')).not.toBeInTheDocument()
  })
})
