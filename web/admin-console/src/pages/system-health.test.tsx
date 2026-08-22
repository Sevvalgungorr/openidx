import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
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

import { SystemHealthPage } from './system-health'
import { api } from '../lib/api'

// Raw shape as returned by GET /api/v1/system/health (admin-api): dependency
// status is healthy/degraded/unhealthy, which the page normalizes to up/
// degraded/down. Using the real vocabulary here guards the normalizer.
const rawSystemHealth = {
  status: 'healthy',
  uptime: '2h 2m 5s',
  version: '1.1.0',
  timestamp: new Date().toISOString(),
  dependencies: [
    { name: 'postgres', status: 'healthy', latency_ms: 3, details: 'Connected to primary' },
    { name: 'redis', status: 'healthy', latency_ms: 1 },
    { name: 'elasticsearch', status: 'degraded', latency_ms: 250, details: 'High response time observed' },
  ],
}

const emptyRelations = { findings: [] }

// Route api.get by URL: the page issues two queries (system health + relations).
function routeGet(url: string) {
  if (url.includes('/system/health')) return Promise.resolve(rawSystemHealth)
  if (url.includes('/access/health/relations')) return Promise.resolve(emptyRelations)
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

describe('SystemHealthPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockImplementation((url: string) => routeGet(url) as ReturnType<typeof api.get>)
  })

  afterEach(() => {
    vi.clearAllMocks()
  })

  it('renders the heading + subtitle once health resolves', async () => {
    render(<SystemHealthPage />, { wrapper: createWrapper() })
    expect(
      await screen.findByText(/monitor openidx platform dependencies and uptime/i),
    ).toBeInTheDocument()
    // Heading appears in both the loading branch and post-load branch — pick
    // by role to disambiguate.
    expect(
      screen.getByRole('heading', { name: /system health/i, level: 1 }),
    ).toBeInTheDocument()
  })

  it('shows the overall status banner with version badge + Check Now button', async () => {
    render(<SystemHealthPage />, { wrapper: createWrapper() })

    expect(await screen.findByText(/system healthy/i)).toBeInTheDocument()
    expect(screen.getByText('1.1.0')).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /check now/i }),
    ).toBeInTheDocument()
  })

  it('renders each dependency card with its name + latency', async () => {
    render(<SystemHealthPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('postgres')).toBeInTheDocument()
    expect(screen.getByText('redis')).toBeInTheDocument()
    expect(screen.getByText('elasticsearch')).toBeInTheDocument()

    expect(screen.getByText('3ms')).toBeInTheDocument()
    expect(screen.getByText('1ms')).toBeInTheDocument()
    expect(screen.getByText('250ms')).toBeInTheDocument()

    // Detail lines survive normalization.
    expect(screen.getByText(/connected to primary/i)).toBeInTheDocument()
    expect(
      screen.getByText(/high response time observed/i),
    ).toBeInTheDocument()
  })

  it('renders the loading branch before fetch resolves', async () => {
    vi.mocked(api.get).mockImplementation((url: string) =>
      (url.includes('/system/health')
        ? new Promise(() => undefined)
        : routeGet(url)) as ReturnType<typeof api.get>,
    )
    render(<SystemHealthPage />, { wrapper: createWrapper() })

    expect(
      await screen.findByText(/loading health status/i),
    ).toBeInTheDocument()
  })

  it('surfaces a read error instead of a misleading "Unhealthy" banner', async () => {
    vi.mocked(api.get).mockImplementation((url: string) =>
      (url.includes('/system/health')
        ? Promise.reject(new Error('boom'))
        : routeGet(url)) as ReturnType<typeof api.get>,
    )

    render(<SystemHealthPage />, { wrapper: createWrapper() })

    expect(
      await screen.findByText(/failed to load system health/i),
    ).toBeInTheDocument()
  })
})
