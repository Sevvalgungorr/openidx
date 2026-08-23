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

import { AuthAnalyticsPage } from './auth-analytics'
import { api } from '../lib/api'

const dashboard = {
  period: '7d',
  total_logins: 12_500,
  successful_logins: 11_800,
  failed_logins: 700,
  mfa_usage_count: 9_400,
  active_users: 215,
  login_methods: [
    { method: 'password', count: 8_000, percentage: 64.0 },
    { method: 'webauthn', count: 3_500, percentage: 28.0 },
    { method: 'social', count: 1_000, percentage: 8.0 },
  ],
  geo_top_countries: [
    { country: 'US', count: 7_500, failed: 200 },
    { country: 'GB', count: 2_000, failed: 80 },
  ],
  hourly_activity: [
    { hour: 9, count: 1_200 },
    { hour: 13, count: 900 },
  ],
  recent_failed_logins: [
    {
      user_id: 'u-1',
      email: 'alice@example.com',
      source_ip: '203.0.113.42',
      reason: 'bad_credentials',
      timestamp: '2026-06-09T12:00:00Z',
    },
  ],
}

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('AuthAnalyticsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockResolvedValue({ dashboard })
  })

  it('renders the page heading + subtitle', async () => {
    render(<AuthAnalyticsPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Authentication Analytics')).toBeInTheDocument()
    expect(
      screen.getByText(/authentication patterns, mfa usage, and security insights/i),
    ).toBeInTheDocument()
  })

  it('shows the four stat cards (total logins / success rate / mfa rate / active users)', async () => {
    render(<AuthAnalyticsPage />, { wrapper: createWrapper() })
    await screen.findByText('Authentication Analytics')

    // Card titles
    expect(screen.getByText('Total Logins')).toBeInTheDocument()
    expect(screen.getByText('Success Rate')).toBeInTheDocument()
    expect(screen.getByText('MFA Usage Rate')).toBeInTheDocument()
    expect(screen.getByText('Active Users')).toBeInTheDocument()

    // total_logins is rendered via toLocaleString — 12,500
    expect(screen.getByText('12,500')).toBeInTheDocument()
    // Success rate: 11,800 / 12,500 = 94.4%
    expect(screen.getByText('94.4%')).toBeInTheDocument()
    // MFA rate: 9,400 / 12,500 = 75.2%
    expect(screen.getByText('75.2%')).toBeInTheDocument()
    // Active users
    expect(screen.getByText('215')).toBeInTheDocument()
  })

  it('renders the success/failure subtitle on the Total Logins card', async () => {
    render(<AuthAnalyticsPage />, { wrapper: createWrapper() })
    await screen.findByText('Authentication Analytics')
    expect(
      screen.getByText((_, node) => node?.textContent === '11,800 successful, 700 failed'),
    ).toBeInTheDocument()
  })

  it('shows the per-period selector with the default "Last 7 Days" label', async () => {
    render(<AuthAnalyticsPage />, { wrapper: createWrapper() })
    await screen.findByText('Authentication Analytics')

    // The Radix Select displays the active period in its trigger
    expect(screen.getByText('Last 7 Days')).toBeInTheDocument()
  })

  it('renders the section headers for the supporting charts', async () => {
    render(<AuthAnalyticsPage />, { wrapper: createWrapper() })
    await screen.findByText('Authentication Analytics')

    expect(screen.getByText(/login method breakdown/i)).toBeInTheDocument()
    // The remaining card titles depend on which charts the page renders for
    // a non-empty geo + hourly + failed list — we only check one extra to
    // keep the test resilient to future chart reorderings.
    expect(screen.getByText(/recent failed logins/i)).toBeInTheDocument()
  })

  it('renders without hitting the error boundary when numeric fields are omitted (null/absent from backend)', async () => {
    // Simulate a Go zero-value / nil-slice response: scalars absent, array items
    // missing their numeric fields. Should NOT throw on .toLocaleString()/.toFixed().
    vi.mocked(api.get).mockResolvedValue({
      dashboard: {
        period: '7d',
        // total_logins / successful_logins / failed_logins / mfa_usage_count /
        // active_users all OMITTED
        login_methods: [{ method: 'password' }], // count / percentage OMITTED
        geo_top_countries: [{ country: 'US' }], // count / failed OMITTED
        hourly_activity: [{ hour: 9 }], // count OMITTED
        recent_failed_logins: [
          { email: 'alice@example.com', source_ip: '203.0.113.42', reason: 'bad' },
        ], // timestamp / user_id OMITTED
      },
    } as unknown as { dashboard: typeof dashboard })

    render(<AuthAnalyticsPage />, { wrapper: createWrapper() })

    // Heading + a section render => page did not blank out via the error boundary.
    expect(await screen.findByText('Authentication Analytics')).toBeInTheDocument()
    expect(screen.getByText(/login method breakdown/i)).toBeInTheDocument()
    expect(screen.getByText('Total Logins')).toBeInTheDocument()
  })

  it('shows the no-data state when the API returns no dashboard', async () => {
    vi.mocked(api.get).mockResolvedValue({} as unknown as { dashboard: typeof dashboard })
    render(<AuthAnalyticsPage />, { wrapper: createWrapper() })

    expect(
      await screen.findByText(/no authentication analytics data available/i),
    ).toBeInTheDocument()
  })
})
