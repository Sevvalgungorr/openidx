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

import { PAMDashboardPage } from './pam-dashboard'
import { api } from '../lib/api'

const overview = {
  secrets: { total: 12, by_type: { password: 8, ssh_key: 3, api_key: 1 } },
  rotation: {
    policies: 5,
    policies_enabled: 4,
    policies_failing: 1,
    policies_overdue: 2,
    runs_30d: 40,
    failures_30d: 3,
  },
  checkouts: {
    active_leases: 2,
    checkouts_30d: 17,
    pending_credential_requests: 4,
  },
  sessions: {
    active_sessions: 1,
    sessions_30d: 9,
    pending_requests: 3,
    recordings_on_hold: 1,
  },
  generated_at: '2026-07-09T10:00:00Z',
}

function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('PAMDashboardPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
  })

  it('renders headline tiles from the overview endpoint', async () => {
    vi.mocked(api.get).mockResolvedValue(overview)

    render(<PAMDashboardPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('Vault Secrets')).toBeInTheDocument()
    expect(api.get).toHaveBeenCalledWith('/api/v1/pam/overview')

    expect(screen.getByText('12')).toBeInTheDocument() // secrets total
    expect(screen.getByText('password: 8')).toBeInTheDocument()
    expect(screen.getByText('ssh_key: 3')).toBeInTheDocument()
    // Pending approvals tile = 4 credential + 3 session
    expect(screen.getByText('7')).toBeInTheDocument()
    expect(screen.getByText('4 credential · 3 session')).toBeInTheDocument()
    expect(screen.getByText('17 checkouts in the last 30 days')).toBeInTheDocument()
    expect(screen.getByText('9 sessions in the last 30 days')).toBeInTheDocument()
  })

  it('flags rotation problems with an explicit label, not color alone', async () => {
    vi.mocked(api.get).mockResolvedValue(overview)

    render(<PAMDashboardPage />, { wrapper: createWrapper() })
    await screen.findByText('Rotation Health')

    expect(screen.getByText('Needs attention')).toBeInTheDocument()
    expect(screen.getByText('Failing (last run)')).toBeInTheDocument()
    expect(screen.getByText('Overdue')).toBeInTheDocument()
  })

  it('shows Healthy when no policy is failing or overdue', async () => {
    vi.mocked(api.get).mockResolvedValue({
      ...overview,
      rotation: { ...overview.rotation, policies_failing: 0, policies_overdue: 0 },
    })

    render(<PAMDashboardPage />, { wrapper: createWrapper() })
    await screen.findByText('Rotation Health')

    expect(screen.getByText('Healthy')).toBeInTheDocument()
  })

  it('renders manage links to the three admin PAM pages', async () => {
    vi.mocked(api.get).mockResolvedValue(overview)

    render(<PAMDashboardPage />, { wrapper: createWrapper() })
    await screen.findByText('Vault Secrets')

    expect(screen.getByRole('link', { name: /manage vault secrets/i })).toHaveAttribute(
      'href',
      '/vault-secrets',
    )
    expect(screen.getByRole('link', { name: /manage rotation policies/i })).toHaveAttribute(
      'href',
      '/rotation-policies',
    )
    expect(screen.getByRole('link', { name: /manage privileged sessions/i })).toHaveAttribute(
      'href',
      '/guacamole-sessions',
    )
  })

  it('shows a permission error on 403', async () => {
    vi.mocked(api.get).mockRejectedValue({ response: { status: 403 } })

    render(<PAMDashboardPage />, { wrapper: createWrapper() })

    expect(await screen.findByText(/don't have permission to view PAM overview/)).toBeInTheDocument()
  })
})
