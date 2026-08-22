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

import { PredictiveAnalyticsPage } from './predictive-analytics'
import { api } from '../lib/api'

const predictions = {
  login_forecast: {
    avg_daily: 1250.5,
    trend: 'increasing',
    historical: [{ date: '2026-06-01', value: 1200 }],
    predicted: [{ date: '2026-06-10', value: 1300 }],
  },
  risk_forecast: {
    current_avg: 38.4,
    trend: 'stable',
    historical: [{ date: '2026-06-01', value: 38 }],
    predicted: [{ date: '2026-06-10', value: 39 }],
  },
  capacity_forecast: {
    peak_concurrent_sessions: 850,
    recommended_capacity: 1000,
  },
  account_growth: {
    current_users: 5200,
    projected_30d: 5600,
    projected_90d: 6500,
    growth_rate_monthly_pct: 7.7,
    historical: [{ date: '2026-06-01', value: 5100 }],
  },
  churn_risk_users: [
    {
      user_id: 'u-1',
      username: 'alice',
      email: 'alice@example.com',
      risk_score: 0.8,
      login_freq_change_pct: -45,
      last_login: '2026-04-01T00:00:00Z',
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

describe('PredictiveAnalyticsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockResolvedValue(predictions)
  })

  it('renders the heading + subtitle', async () => {
    render(<PredictiveAnalyticsPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('Predictive Analytics')).toBeInTheDocument()
    expect(
      screen.getByText(/forward-looking insights for capacity planning and proactive security/i),
    ).toBeInTheDocument()
  })

  it('shows the four key-metric cards', async () => {
    render(<PredictiveAnalyticsPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('Avg Daily Logins')).toBeInTheDocument()
    expect(screen.getByText('Avg Risk Score')).toBeInTheDocument()
    expect(screen.getByText('Active Users')).toBeInTheDocument()
    expect(screen.getByText('Peak Sessions')).toBeInTheDocument()
  })

  it('renders the forecast section titles', async () => {
    render(<PredictiveAnalyticsPage />, { wrapper: createWrapper() })

    expect(await screen.findByText(/login volume forecast/i)).toBeInTheDocument()
    expect(screen.getByText(/risk score forecast/i)).toBeInTheDocument()
    // "Capacity Planning" appears in the section header AND in the
    // recommended-capacity sentence under the same card → getAllByText.
    expect(screen.getAllByText(/capacity planning/i).length).toBeGreaterThan(0)
    expect(screen.getByText(/account growth projection/i)).toBeInTheDocument()
  })

  it('lists churn-risk users and their churn count label', async () => {
    render(<PredictiveAnalyticsPage />, { wrapper: createWrapper() })

    expect(
      await screen.findByText(/churn risk users \(1\)/i),
    ).toBeInTheDocument()
    // The churn row renders `username`, not email.
    expect(screen.getByText('alice')).toBeInTheDocument()
  })

  it('links each at-risk user to their Access 360 drill-down', async () => {
    render(<PredictiveAnalyticsPage />, { wrapper: createWrapper() })

    const username = await screen.findByText('alice')
    const link = username.closest('a')
    expect(link).not.toBeNull()
    expect(link).toHaveAttribute('href', '/users/u-1/access-360')
  })

  it('surfaces a read error when the fetch fails', async () => {
    vi.mocked(api.get).mockRejectedValue({ response: { status: 403 } })

    render(<PredictiveAnalyticsPage />, { wrapper: createWrapper() })

    expect(
      await screen.findByText(/don't have permission to view predictive analytics/i),
    ).toBeInTheDocument()
  })
})
