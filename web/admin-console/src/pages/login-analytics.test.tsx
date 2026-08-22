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

import { LoginAnalyticsPage } from './login-analytics'
import { api } from '../lib/api'

const analytics = {
  analytics: {
    summary: {
      total_logins: 12345,
      successful_logins: 12200,
      failed_logins: 145,
      unique_users: 1024,
      high_risk_logins: 8,
      average_risk_score: 24.6,
      mfa_challenges: 950,
      new_devices: 42,
    },
    daily_trends: [
      { date: '2026-06-01', successful: 400, failed: 5 },
      { date: '2026-06-02', successful: 410, failed: 7 },
    ],
    hourly_pattern: [
      { hour: 9, successful: 50, failed: 1 },
      { hour: 10, successful: 60, failed: 1 },
    ],
  },
}

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('LoginAnalyticsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockResolvedValue(analytics)
  })

  it('renders the heading + subtitle', async () => {
    render(<LoginAnalyticsPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('Login Analytics')).toBeInTheDocument()
    expect(
      screen.getByText(/authentication patterns and security insights/i),
    ).toBeInTheDocument()
  })

  it('shows the four summary cards (Total / Success Rate / High Risk / MFA)', async () => {
    render(<LoginAnalyticsPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('Total Logins')).toBeInTheDocument()
    expect(screen.getByText('Success Rate')).toBeInTheDocument()
    expect(screen.getByText('High Risk Logins')).toBeInTheDocument()
    expect(screen.getByText('MFA Challenges')).toBeInTheDocument()
  })

  it('renders the computed summary values', async () => {
    render(<LoginAnalyticsPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('12,345')).toBeInTheDocument() // total
    // successful + failed in badges
    expect(screen.getByText('12200')).toBeInTheDocument()
    expect(screen.getByText('145')).toBeInTheDocument()
    // Success rate (12200 / 12345 * 100).toFixed(1) = "98.8%"
    expect(screen.getByText('98.8%')).toBeInTheDocument()
    expect(screen.getByText('8')).toBeInTheDocument() // high_risk_logins
    expect(screen.getByText('950')).toBeInTheDocument() // mfa_challenges
  })

  it('renders the chart section titles', async () => {
    render(<LoginAnalyticsPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('Daily Login Trend')).toBeInTheDocument()
    expect(
      screen.getByText(/successful vs failed logins over time/i),
    ).toBeInTheDocument()
  })

  it('shows the "No analytics data available" empty branch when the payload has no analytics', async () => {
    // A defined-but-empty response (no `analytics` key) exercises the empty
    // branch. Note: a rejected/undefined read now surfaces via QueryError
    // instead of silently falling through to this empty state.
    vi.mocked(api.get).mockResolvedValue({})

    render(<LoginAnalyticsPage />, { wrapper: createWrapper() })

    expect(
      await screen.findByText(/no analytics data available/i),
    ).toBeInTheDocument()
  })
})
