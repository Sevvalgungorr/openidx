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

// login-anomalies exports default — use the default import.
import LoginAnomalies from './login-anomalies'
import { api } from '../lib/api'

const overview = {
  avg_risk_score: 28.5,
  high_risk_count: 12,
  total_logins_7d: 5400,
  risk_distribution: { low: 3000, medium: 1800, high: 500, critical: 100 },
}

const anomalies = {
  anomalies: [
    {
      id: 'an-1',
      user_id: 'u-1',
      username: 'alice',
      email: 'alice@example.com',
      ip_address: '203.0.113.10',
      location: 'New York, US',
      risk_score: 75,
      auth_methods: ['password'],
      anomaly_status: 'flagged',
      created_at: '2026-06-09T10:00:00Z',
    },
  ],
  total: 1,
  page: 1,
  page_size: 25,
}

function routeGet(url: string) {
  if (url.includes('/risk/overview')) return Promise.resolve(overview)
  if (url.includes('/risk/anomalies')) return Promise.resolve(anomalies)
  if (url.includes('/risk/user-profile')) return Promise.resolve({})
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

describe('LoginAnomaliesPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockImplementation((url: string) => routeGet(url) as ReturnType<typeof api.get>)
  })

  it('renders the heading + subtitle', async () => {
    render(<LoginAnomalies />, { wrapper: createWrapper() })

    expect(await screen.findByText('Login Anomalies')).toBeInTheDocument()
    expect(
      screen.getByText(/monitor login risk scores and detect anomalous authentication patterns/i),
    ).toBeInTheDocument()
  })

  it('shows the four overview cards (Avg / High-Risk / Total / Distribution)', async () => {
    render(<LoginAnomalies />, { wrapper: createWrapper() })

    expect(await screen.findByText('Average Risk Score')).toBeInTheDocument()
    expect(screen.getByText('High-Risk Logins (7d)')).toBeInTheDocument()
    expect(screen.getByText('Total Logins (7d)')).toBeInTheDocument()
    expect(screen.getByText('Risk Distribution')).toBeInTheDocument()

    expect(screen.getByText('28.5')).toBeInTheDocument()
    expect(screen.getByText('12')).toBeInTheDocument()
    expect(screen.getByText('5400')).toBeInTheDocument()
  })

  it('renders the distribution badges with bucket counts', async () => {
    render(<LoginAnomalies />, { wrapper: createWrapper() })

    expect(await screen.findByText('Low: 3000')).toBeInTheDocument()
    expect(screen.getByText('Med: 1800')).toBeInTheDocument()
    expect(screen.getByText('High: 500')).toBeInTheDocument()
    expect(screen.getByText('Crit: 100')).toBeInTheDocument()
  })

  it('lists the anomaly row with username, IP, and location', async () => {
    render(<LoginAnomalies />, { wrapper: createWrapper() })

    expect(await screen.findByText('alice')).toBeInTheDocument()
    expect(screen.getByText('203.0.113.10')).toBeInTheDocument()
    expect(screen.getByText('New York, US')).toBeInTheDocument()
  })

  it('renders an anomaly row whose numeric/array fields are omitted without crashing', async () => {
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url.includes('/risk/overview')) return Promise.resolve({}) as ReturnType<typeof api.get>
      if (url.includes('/risk/anomalies')) {
        return Promise.resolve({
          anomalies: [
            {
              id: 'an-omit',
              user_id: 'u-omit',
              username: 'bob',
              ip_address: '198.51.100.5',
              location: 'Berlin, DE',
              // risk_score, auth_methods, success, created_at omitted
            },
          ],
          // total/page/page_size omitted
        }) as ReturnType<typeof api.get>
      }
      return Promise.resolve({}) as ReturnType<typeof api.get>
    })

    render(<LoginAnomalies />, { wrapper: createWrapper() })

    // Heading + row render, no error boundary blank-out.
    expect(await screen.findByText('Login Anomalies')).toBeInTheDocument()
    expect(await screen.findByText('bob')).toBeInTheDocument()
    expect(screen.getByText('198.51.100.5')).toBeInTheDocument()
  })

  it('shows the empty state when no anomalies match the filters', async () => {
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url.includes('/risk/overview')) return Promise.resolve(overview) as ReturnType<typeof api.get>
      if (url.includes('/risk/anomalies')) {
        return Promise.resolve({ anomalies: [], total: 0, page: 1, page_size: 25 }) as ReturnType<typeof api.get>
      }
      return Promise.resolve({}) as ReturnType<typeof api.get>
    })

    render(<LoginAnomalies />, { wrapper: createWrapper() })

    expect(await screen.findByText(/no anomalies found/i)).toBeInTheDocument()
  })
})
