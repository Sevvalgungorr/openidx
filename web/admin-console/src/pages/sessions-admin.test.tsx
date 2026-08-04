import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(() => Promise.resolve({})),
    put: vi.fn(() => Promise.resolve({})),
    delete: vi.fn(() => Promise.resolve({})),
  },
}))

vi.mock('../hooks/use-toast', () => ({
  useToast: () => ({ toast: vi.fn() }),
}))

// The page reads the caller's roles via useAuth to decide between the admin
// (org-wide) view and the self-service ("My Sessions") view. Mock hasRole so
// each test can pick the role set it needs.
const hasRoleMock = vi.fn((_role: string) => true)
vi.mock('../lib/auth', () => ({
  useAuth: () => ({ hasRole: hasRoleMock }),
}))

import { SessionsAdminPage } from './sessions-admin'
import { api } from '../lib/api'

const activeSession = {
  id: 'sess-1',
  user_id: 'u-1',
  username: 'alice',
  email: 'alice@example.com',
  device_name: 'MacBook Pro',
  device_type: 'desktop',
  device_trusted: true,
  location: 'New York, US',
  ip_address: '203.0.113.10',
  risk_score: 25,
  auth_methods: ['password', 'totp'],
  is_active: true,
  started_at: '2026-06-09T08:00:00Z',
  last_active_at: '2026-06-09T10:00:00Z',
}

const riskySession = {
  ...activeSession,
  id: 'sess-2',
  user_id: 'u-2',
  username: 'mallory',
  email: 'mallory@example.com',
  device_name: 'Unknown Linux',
  device_trusted: false,
  risk_score: 85,
  ip_address: '198.51.100.5',
  location: 'Unknown',
}

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('SessionsAdminPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    // Default to an admin caller so the org-wide view is exercised.
    hasRoleMock.mockImplementation((role: string) =>
      role === 'admin' || role === 'super_admin' || role === 'operator',
    )
    vi.mocked(api.get).mockResolvedValue({
      sessions: [activeSession, riskySession],
      total: 2,
    })
  })

  it('renders the heading + subtitle', async () => {
    render(<SessionsAdminPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('Session Management')).toBeInTheDocument()
    expect(
      screen.getByText(/view and manage active user sessions/i),
    ).toBeInTheDocument()
  })

  it('shows the four stat cards (Active / Unique / High Risk / Trusted Devices)', async () => {
    render(<SessionsAdminPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('Active Sessions')).toBeInTheDocument()
    expect(screen.getByText('Unique Users')).toBeInTheDocument()
    expect(screen.getByText('High Risk')).toBeInTheDocument()
    expect(screen.getByText('Trusted Devices')).toBeInTheDocument()
  })

  it('lists session rows with username + ip + device name', async () => {
    render(<SessionsAdminPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('alice')).toBeInTheDocument()
    expect(screen.getByText('mallory')).toBeInTheDocument()
    expect(screen.getByText('alice@example.com')).toBeInTheDocument()
    expect(screen.getByText('mallory@example.com')).toBeInTheDocument()
    expect(screen.getByText('MacBook Pro')).toBeInTheDocument()
    expect(screen.getByText('Unknown Linux')).toBeInTheDocument()
    expect(screen.getByText('203.0.113.10')).toBeInTheDocument()
    expect(screen.getByText('198.51.100.5')).toBeInTheDocument()
  })

  it('exposes the user-ID filter input + "Active only" checkbox', async () => {
    render(<SessionsAdminPage />, { wrapper: createWrapper() })
    await screen.findByText('Session Management')

    expect(
      screen.getByPlaceholderText(/filter by user id/i),
    ).toBeInTheDocument()
    expect(screen.getByLabelText(/active only/i)).toBeInTheDocument()
  })

  it('shows the empty state when no sessions exist', async () => {
    vi.mocked(api.get).mockResolvedValue({ sessions: [], total: 0 })

    render(<SessionsAdminPage />, { wrapper: createWrapper() })

    expect(await screen.findByText(/no active sessions/i)).toBeInTheDocument()
    expect(
      screen.getByText(/user sessions will appear here when users log in/i),
    ).toBeInTheDocument()
  })
})

describe('SessionsAdminPage (self-service, non-admin)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    // A regular user: no admin/operator roles.
    hasRoleMock.mockImplementation(() => false)
    vi.mocked(api.get).mockResolvedValue({
      sessions: [activeSession],
      total: 1,
    })
  })

  it('reads the caller\'s own sessions from /me/sessions', async () => {
    render(<SessionsAdminPage />, { wrapper: createWrapper() })
    await screen.findByText('My Sessions')

    expect(api.get).toHaveBeenCalledWith('/api/v1/identity/users/me/sessions')
  })

  it('renders the "My Sessions" heading + self-service subtitle', async () => {
    render(<SessionsAdminPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('My Sessions')).toBeInTheDocument()
    expect(
      screen.getByText(/devices and apps currently signed in to your account/i),
    ).toBeInTheDocument()
  })

  it('hides admin-only affordances (user filter, admin stat cards)', async () => {
    render(<SessionsAdminPage />, { wrapper: createWrapper() })
    await screen.findByText('My Sessions')

    expect(screen.queryByPlaceholderText(/filter by user id/i)).not.toBeInTheDocument()
    expect(screen.queryByText('Unique Users')).not.toBeInTheDocument()
    expect(screen.queryByText('High Risk')).not.toBeInTheDocument()
    expect(screen.queryByText('Trusted Devices')).not.toBeInTheDocument()
    // The self view keeps the "Active Sessions" summary card.
    expect(screen.getByText('Active Sessions')).toBeInTheDocument()
  })
})
