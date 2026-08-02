import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'

vi.mock('../lib/auth', () => ({ OAUTH_URL: 'https://oauth.example.com' }))

import { DeviceAuthorizationPage } from './device-authorization'

/** Records every request the page makes so tests can assert on URL and body. */
function mockFetch(handler: (url: string, init?: RequestInit) => Response | Promise<Response>) {
  const spy = vi.fn(async (url: string, init?: RequestInit) => handler(url, init))
  globalThis.fetch = spy as unknown as typeof fetch
  return spy
}

function jsonResponse(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => body } as Response
}

const codeInfo = {
  user_code: 'ACDE-FGHJ',
  client_id: 'tv-app',
  client_name: 'Living Room TV',
  scope: 'openid profile',
  state: 'pending',
  expires_in: 540,
}

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <DeviceAuthorizationPage />
    </MemoryRouter>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
})

describe('DeviceAuthorizationPage', () => {
  it('looks up a typed code and shows what is being authorized', async () => {
    mockFetch(() => jsonResponse(codeInfo))
    const user = userEvent.setup()
    renderAt('/device')

    await user.type(screen.getByLabelText(/device code/i), 'acde-fghj')
    await user.click(screen.getByRole('button', { name: /continue/i }))

    await waitFor(() => expect(screen.getByText('Living Room TV')).toBeInTheDocument())
    // The user has to be told which application they are about to trust; a
    // consent screen that does not name the client is not consent.
    expect(screen.getByText(/about to give/i)).toBeInTheDocument()
    expect(screen.getByText('openid')).toBeInTheDocument()
    expect(screen.getByText('profile')).toBeInTheDocument()
  })

  it('normalizes what the user types before sending it', async () => {
    const spy = mockFetch(() => jsonResponse(codeInfo))
    const user = userEvent.setup()
    renderAt('/device')

    await user.type(screen.getByLabelText(/device code/i), 'acde-fghj')
    await user.click(screen.getByRole('button', { name: /continue/i }))

    await waitFor(() => expect(spy).toHaveBeenCalled())
    // Sent normalized, and to the OAuth service rather than the admin API —
    // routing these through the shared api client would hit the wrong origin.
    expect(spy.mock.calls[0][0]).toBe(
      'https://oauth.example.com/oauth/device/lookup?user_code=ACDEFGHJ',
    )
  })

  it('keeps Continue disabled until the code is complete', async () => {
    const user = userEvent.setup()
    renderAt('/device')

    const button = screen.getByRole('button', { name: /continue/i })
    expect(button).toBeDisabled()

    await user.type(screen.getByLabelText(/device code/i), 'ACDE')
    expect(button).toBeDisabled()

    await user.type(screen.getByLabelText(/device code/i), '-FGHJ')
    expect(button).toBeEnabled()
  })

  it('auto-submits a code arriving via verification_uri_complete', async () => {
    const spy = mockFetch(() => jsonResponse(codeInfo))
    renderAt('/device?user_code=ACDE-FGHJ')

    // The QR path should land on the confirmation, not on a filled-in form the
    // user still has to submit.
    await waitFor(() => expect(screen.getByText('Living Room TV')).toBeInTheDocument())
    expect(spy.mock.calls[0][0]).toContain('user_code=ACDEFGHJ')
  })

  it('approves by sending the code the server issued', async () => {
    const spy = mockFetch(() => jsonResponse(codeInfo))
    const user = userEvent.setup()
    renderAt('/device?user_code=ACDE-FGHJ')

    await waitFor(() => expect(screen.getByText('Living Room TV')).toBeInTheDocument())
    await user.click(screen.getByRole('button', { name: /allow/i }))

    await waitFor(() => expect(spy.mock.calls.length).toBeGreaterThan(1))
    const [url, init] = spy.mock.calls[1]
    expect(url).toBe('https://oauth.example.com/oauth/device/decision')
    expect(init?.method).toBe('POST')
    expect(JSON.parse(String(init?.body))).toEqual({ user_code: 'ACDE-FGHJ', approve: true })
    expect(await screen.findByText(/device connected/i)).toBeInTheDocument()
  })

  it('sends approve=false when denying', async () => {
    const spy = mockFetch(() => jsonResponse(codeInfo))
    const user = userEvent.setup()
    renderAt('/device?user_code=ACDE-FGHJ')

    await waitFor(() => screen.getByText('Living Room TV'))
    await user.click(screen.getByRole('button', { name: /deny/i }))

    await waitFor(() => expect(spy.mock.calls.length).toBeGreaterThan(1))
    expect(JSON.parse(String(spy.mock.calls[1][1]?.body))).toEqual({
      user_code: 'ACDE-FGHJ',
      approve: false,
    })
    expect(await screen.findByText(/request denied/i)).toBeInTheDocument()
  })

  it('shows one message for unknown and expired codes', async () => {
    mockFetch(() => jsonResponse({ error: 'invalid_user_code' }, 404))
    const user = userEvent.setup()
    renderAt('/device')

    await user.type(screen.getByLabelText(/device code/i), 'ACDEFGHJ')
    await user.click(screen.getByRole('button', { name: /continue/i }))

    // The API deliberately refuses to distinguish these, so the page must not
    // invent a distinction and turn itself into a code-probing oracle.
    expect(await screen.findByText(/not valid or has expired/i)).toBeInTheDocument()
    expect(screen.queryByText('Living Room TV')).not.toBeInTheDocument()
  })

  it('reports a decision that lost a race instead of claiming success', async () => {
    let call = 0
    mockFetch(() => (call++ === 0 ? jsonResponse(codeInfo) : jsonResponse({}, 404)))
    const user = userEvent.setup()
    renderAt('/device?user_code=ACDE-FGHJ')

    await waitFor(() => screen.getByText('Living Room TV'))
    await user.click(screen.getByRole('button', { name: /allow/i }))

    expect(await screen.findByText(/expired or was already used/i)).toBeInTheDocument()
    expect(screen.queryByText(/device connected/i)).not.toBeInTheDocument()
  })

  it('warns against approving a code the user did not start', async () => {
    mockFetch(() => jsonResponse(codeInfo))
    renderAt('/device?user_code=ACDE-FGHJ')

    // The device grant's realistic attack is social: someone reads a code to a
    // victim and asks them to enter it. The page has to say so.
    expect(await screen.findByText(/only continue if you started this/i)).toBeInTheDocument()
  })
})
