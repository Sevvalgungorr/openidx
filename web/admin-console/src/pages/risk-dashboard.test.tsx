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

import { RiskDashboardPage } from './risk-dashboard'
import { api } from '../lib/api'

const riskOverview = {
  avg_risk_score: 42.5,
  high_risk_logins_24h: 5,
  active_alerts: 8,
  impossible_travel_events: 2,
  risk_distribution: [
    { bucket: '0-20', min: 0, max: 20, count: 100 },
    { bucket: '21-40', min: 21, max: 40, count: 50 },
    { bucket: '41-60', min: 41, max: 60, count: 25 },
    { bucket: '61-80', min: 61, max: 80, count: 10 },
    { bucket: '81-100', min: 81, max: 100, count: 3 },
  ],
  top_risky_users: [
    {
      user_id: 'u-1',
      email: 'alice@example.com',
      username: 'alice',
      avg_risk_score: 75.2,
      last_login: '2026-06-09T10:00:00Z',
      anomaly_count: 4,
    },
    {
      user_id: 'u-2',
      email: 'bob@example.com',
      username: 'bob',
      avg_risk_score: 62.0,
      last_login: '2026-06-09T11:00:00Z',
      anomaly_count: 2,
    },
  ],
}

const timeline = {
  days: [
    { date: '2026-06-01', avg_score: 38.1, max_score: 71.0, login_count: 200 },
    { date: '2026-06-02', avg_score: 41.0, max_score: 80.0, login_count: 210 },
  ],
}

const alerts = [
  {
    id: 'a-1',
    alert_type: 'brute_force',
    severity: 'critical',
    status: 'open',
    title: 'Multiple failed logins from suspicious IP',
    description: 'Detected 15 attempts in 60 seconds',
    source_ip: '203.0.113.10',
    created_at: '2026-06-09T10:00:00Z',
  },
]

function routeGet(url: string) {
  if (url.includes('/analytics/risk-timeline')) return Promise.resolve({ timeline })
  if (url.includes('/analytics/risk')) return Promise.resolve({ risk: riskOverview })
  if (url.includes('/security-alerts')) return Promise.resolve({ alerts })
  return Promise.resolve({})
}

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('RiskDashboardPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockImplementation((url: string) => routeGet(url) as ReturnType<typeof api.get>)
  })

  it('renders the heading + subtitle', async () => {
    render(<RiskDashboardPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Risk Dashboard')).toBeInTheDocument()
    expect(
      screen.getByText(/security risk overview, threat indicators, and anomaly detection/i),
    ).toBeInTheDocument()
  })

  it('shows the four summary cards with their labels', async () => {
    render(<RiskDashboardPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('Avg Risk Score')).toBeInTheDocument()
    expect(screen.getByText('High Risk Logins (24h)')).toBeInTheDocument()
    expect(screen.getByText('Active Alerts')).toBeInTheDocument()
  })

  it('renders the computed summary numbers from the fixture', async () => {
    render(<RiskDashboardPage />, { wrapper: createWrapper() })
    // avg_risk_score 42.5 → 42.5 (toFixed(1))
    expect(await screen.findByText('42.5')).toBeInTheDocument()
    // high_risk_logins_24h = 5
    expect(screen.getByText('5')).toBeInTheDocument()
    // active_alerts = 8
    expect(screen.getByText('8')).toBeInTheDocument()
  })

  it('lists the top risky users', async () => {
    render(<RiskDashboardPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('alice@example.com')).toBeInTheDocument()
    expect(screen.getByText('bob@example.com')).toBeInTheDocument()
  })

  it('renders each active alert as a link to the actionable /security-alerts view', async () => {
    render(<RiskDashboardPage />, { wrapper: createWrapper() })

    const alertTitle = await screen.findByText('Multiple failed logins from suspicious IP')
    const link = alertTitle.closest('a')
    expect(link).not.toBeNull()
    expect(link).toHaveAttribute('href', '/security-alerts')
  })

  it('renders the loading branch when the queries are pending', async () => {
    vi.mocked(api.get).mockReturnValue(new Promise(() => undefined) as ReturnType<typeof api.get>)
    const { container } = render(<RiskDashboardPage />, { wrapper: createWrapper() })

    // The LoadingSpinner has an animate-spin element; check for it via class.
    expect(
      container.querySelector('.animate-spin'),
    ).toBeInTheDocument()
  })

  it('renders without hitting the error boundary when numeric fields are omitted from the API response', async () => {
    // Simulate a Go backend nil/zero-value response: nested rows arrive with
    // their numeric fields absent (would throw on .toFixed()/.toLocaleString()).
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url.includes('/analytics/risk-timeline')) {
        return Promise.resolve({
          timeline: { days: [{ date: '2026-06-01' }] },
        }) as ReturnType<typeof api.get>
      }
      if (url.includes('/analytics/risk')) {
        return Promise.resolve({
          risk: {
            risk_distribution: [{ bucket: '0-20' }],
            top_risky_users: [{ user_id: 'u-x', email: 'x@example.com', username: 'x' }],
          },
        }) as ReturnType<typeof api.get>
      }
      if (url.includes('/security-alerts')) {
        return Promise.resolve({ alerts: [{ id: 'a-x', title: 'partial alert' }] }) as ReturnType<typeof api.get>
      }
      return Promise.resolve({}) as ReturnType<typeof api.get>
    })

    render(<RiskDashboardPage />, { wrapper: createWrapper() })

    // Page renders its heading + a nested section instead of blanking out.
    expect(await screen.findByText('Risk Dashboard')).toBeInTheDocument()
    expect(screen.getByText('Risk Score Distribution')).toBeInTheDocument()
    expect(screen.getByText('x@example.com')).toBeInTheDocument()
  })

  it('renders the "No risk data available" empty state when the risk query returns empty', async () => {
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url.includes('/analytics/risk-timeline')) return Promise.resolve({ timeline }) as ReturnType<typeof api.get>
      if (url.includes('/analytics/risk')) return Promise.resolve({}) as ReturnType<typeof api.get>
      if (url.includes('/security-alerts')) return Promise.resolve({ alerts: [] }) as ReturnType<typeof api.get>
      return Promise.resolve({}) as ReturnType<typeof api.get>
    })

    render(<RiskDashboardPage />, { wrapper: createWrapper() })

    expect(await screen.findByText(/no risk data available/i)).toBeInTheDocument()
  })
})
