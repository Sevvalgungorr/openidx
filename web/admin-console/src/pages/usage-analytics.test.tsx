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

import { UsageAnalyticsPage } from './usage-analytics'
import { api } from '../lib/api'

const usage = {
  usage: {
    dau: 1234,
    wau: 4567,
    mau: 12345,
    total_users: 50000,
    total_groups: 250,
    total_apps: 80,
    new_registrations: [
      { date: '2026-06-01', count: 50 },
      { date: '2026-06-02', count: 70 },
    ],
  },
}

const adoption = {
  adoption: {
    features: [
      {
        name: 'mfa', category: 'security',
        adopted_users: 32500, total_users: 50000, adoption_percentage: 65,
      },
      {
        name: 'sso', category: 'access',
        adopted_users: 40000, total_users: 50000, adoption_percentage: 80,
      },
    ],
  },
}

const apiUsage = {
  api_usage: {
    endpoints: [
      {
        method: 'GET', path: '/api/v1/identity/users',
        request_count: 1000000, avg_latency_ms: 25.5, error_rate: 0.5,
      },
    ],
  },
}

function routeGet(url: string) {
  if (url.includes('/feature-adoption')) return Promise.resolve(adoption)
  if (url.includes('/api-usage')) return Promise.resolve(apiUsage)
  if (url.includes('/usage')) return Promise.resolve(usage)
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

describe('UsageAnalyticsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockImplementation((url: string) => routeGet(url) as ReturnType<typeof api.get>)
  })

  it('renders the heading + subtitle', async () => {
    render(<UsageAnalyticsPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('Usage Analytics')).toBeInTheDocument()
    expect(
      screen.getByText(/user engagement, feature adoption, and platform utilization/i),
    ).toBeInTheDocument()
  })

  it('shows the six top-line stat cards (DAU / WAU / MAU / Total Users / Groups / Apps)', async () => {
    render(<UsageAnalyticsPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('DAU')).toBeInTheDocument()
    expect(screen.getByText('WAU')).toBeInTheDocument()
    expect(screen.getByText('MAU')).toBeInTheDocument()
    expect(screen.getByText('Total Users')).toBeInTheDocument()
    expect(screen.getByText('Total Groups')).toBeInTheDocument()
    expect(screen.getByText('Total Apps')).toBeInTheDocument()
  })

  it('renders the numeric stat values via toLocaleString', async () => {
    render(<UsageAnalyticsPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('1,234')).toBeInTheDocument() // DAU
    expect(screen.getByText('4,567')).toBeInTheDocument() // WAU
    expect(screen.getByText('12,345')).toBeInTheDocument() // MAU
    expect(screen.getByText('50,000')).toBeInTheDocument() // total_users
  })

  it('renders the Feature Adoption section', async () => {
    render(<UsageAnalyticsPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('Feature Adoption')).toBeInTheDocument()
    expect(
      screen.getByText(/security and authentication feature usage across your user base/i),
    ).toBeInTheDocument()
  })

  it('renders without crashing when analytics rows omit numeric fields', async () => {
    // Regression: rows can arrive with numeric fields absent/null (a Go zero
    // value dropped in JSON). The cards call .toLocaleString()/.toFixed() on
    // them, which crashed the page with "Cannot read properties of undefined
    // (reading 'toLocaleString')". The queryFns now default every field.
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url.includes('/feature-adoption')) {
        // name/category only — the three numeric fields omitted.
        return Promise.resolve({ adoption: { features: [{ name: 'mfa', category: 'security' }] } }) as ReturnType<typeof api.get>
      }
      if (url.includes('/api-usage')) {
        // method/path only — request_count/avg_latency_ms/error_rate omitted.
        return Promise.resolve({ api_usage: { endpoints: [{ method: 'GET', path: '/x' }] } }) as ReturnType<typeof api.get>
      }
      if (url.includes('/usage')) {
        // registration row without count; top-line metrics omitted.
        return Promise.resolve({ usage: { new_registrations: [{ date: '2026-06-01' }] } }) as ReturnType<typeof api.get>
      }
      return Promise.resolve({}) as ReturnType<typeof api.get>
    })

    render(<UsageAnalyticsPage />, { wrapper: createWrapper() })

    // Page renders its sections rather than the error boundary.
    expect(await screen.findByText('Usage Analytics')).toBeInTheDocument()
    expect(screen.getByText('Feature Adoption')).toBeInTheDocument()
    // The undefined numerics render as a defaulted 0 via toLocaleString.
    expect(screen.getAllByText(/\b0\b/).length).toBeGreaterThan(0)
  })
})
