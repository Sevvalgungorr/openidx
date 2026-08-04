import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { LoginPage } from './login'

// Mutable auth state so we can exercise the already-authenticated path.
const authState = { isAuthenticated: false, isLoading: false, login: vi.fn() }
const navigateSpy = vi.fn()

vi.mock('../lib/auth', () => ({
  useAuth: () => authState,
}))

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom')
  return { ...actual, useNavigate: () => navigateSpy }
})

vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(() => Promise.resolve([])),
    getIdentityProviders: vi.fn(() => Promise.resolve([])),
  },
  baseURL: 'http://localhost:8001',
  getOAuthURL: vi.fn(() => 'http://localhost:8001'),
}))
vi.mock('../lib/webauthn', () => ({
  decodeCredentialRequestOptions: vi.fn((x) => x),
  serializeAssertionResponse: vi.fn(() => '{}'),
}))
vi.mock('qrcode.react', () => ({ QRCodeSVG: () => <div>QR</div> }))
vi.mock('../components/icons/social-providers', () => ({ getProviderIcon: () => null }))

function setLocation(search: string) {
  Object.defineProperty(window, 'location', {
    value: { hostname: 'localhost', search, href: 'http://localhost:5173/login' + search, origin: 'http://localhost:5173' },
    writable: true,
  })
}

const renderPage = () => render(<MemoryRouter><LoginPage /></MemoryRouter>)

describe('LoginPage login_session (pending OIDC) handling', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    sessionStorage.clear()
    authState.isAuthenticated = false
    authState.isLoading = false
    setLocation('')
    window.history.replaceState({}, '', '/login')
  })

  it('persists login_session from the URL into sessionStorage (survives URL cleanup)', () => {
    setLocation('?login_session=abc123')
    renderPage()
    expect(sessionStorage.getItem('oidc_login_session')).toBe('abc123')
  })

  it('does NOT redirect an already-authenticated user to /dashboard when a login_session is pending', () => {
    authState.isAuthenticated = true
    sessionStorage.setItem('oidc_login_session', 'pending-xyz')
    setLocation('?login_session=pending-xyz')
    renderPage()
    expect(navigateSpy).not.toHaveBeenCalledWith('/dashboard', expect.anything())
  })

  it('DOES redirect an already-authenticated user to /dashboard when there is no pending login_session', () => {
    authState.isAuthenticated = true
    renderPage()
    expect(navigateSpy).toHaveBeenCalledWith('/dashboard', { replace: true })
  })
})
