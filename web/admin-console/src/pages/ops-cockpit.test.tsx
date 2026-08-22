import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(() => Promise.resolve([])),
    post: vi.fn(() => Promise.resolve({})),
    put: vi.fn(() => Promise.resolve({})),
    delete: vi.fn(() => Promise.resolve({})),
  },
}))

// Stub the react-flow-backed graph so the page test stays deterministic and does
// not depend on the (headless-flaky) @xyflow/react canvas.
vi.mock('../components/topology-graph', () => ({
  TopologyGraph: ({ topology }: { topology: { nodes: unknown[] } }) => (
    <div data-testid="topology-graph-stub">nodes:{topology.nodes.length}</div>
  ),
}))

import { OpsCockpitPage } from './ops-cockpit'
import { api } from '../lib/api'

const overview = {
  health: {
    controller_reachable: true,
    sdk_ready: true,
    routers_online: 2,
    routers_total: 3,
    services_count: 4,
    identities_count: 5,
    policies_count: 1,
  },
}
const status = { enabled: true, sdk_ready: true, controller_reachable: true, services_count: 4, identities_count: 5 }
const routers = [
  { id: 'r-1', name: 'edge-1', isOnline: true },
  { id: 'r-2', name: 'edge-2', isOnline: true },
  { id: 'r-3', name: 'edge-3', isOnline: false },
]
const services = [{ id: 'svc-1', name: 'internal-app', roleAttributes: ['dev-clients'] }]
const identities = [
  { id: 'id-1', name: 'alice', attributes: ['dev'], enrolled: true },
  { id: 'id-2', name: 'bob', attributes: ['ops'], enrolled: false },
]
const policies = [
  { id: 'p-1', name: 'dev-policy', type: 'Dial', identityRoles: ['#dev'], serviceRoles: ['#dev-clients'] },
]
const sessions = [{ id: 's-1' }, { id: 's-2' }]
const alerts = {
  alerts: [
    { id: 'a-1', alert_type: 'brute_force', severity: 'high', status: 'open', title: 'Brute force detected', description: '', source_ip: '1.2.3.4', created_at: '2026-08-01T00:00:00Z' },
  ],
  total: 1,
}
const risk = { risk: { avg_risk_score: 10, high_risk_logins_24h: 1, active_alerts: 2, impossible_travel_events: 0 } }

function wireDefaultApi() {
  vi.mocked(api.get).mockImplementation((url: string) => {
    if (url.includes('/fabric/overview')) return Promise.resolve(overview)
    if (url.includes('/ziti/status')) return Promise.resolve(status)
    if (url.includes('/fabric/routers')) return Promise.resolve(routers)
    if (url.includes('/ziti/services')) return Promise.resolve({ services })
    if (url.includes('/ziti/identities')) return Promise.resolve({ identities })
    if (url.includes('/fabric/service-policies')) return Promise.resolve(policies)
    if (url.includes('/ziti/sessions')) return Promise.resolve(sessions)
    if (url.includes('/security-alerts')) return Promise.resolve(alerts)
    if (url.includes('/analytics/risk')) return Promise.resolve(risk)
    return Promise.resolve([])
  })
}

function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('OpsCockpitPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    wireDefaultApi()
  })

  it('renders the header and health/topology tiles with mocked data', async () => {
    render(<OpsCockpitPage />, { wrapper: createWrapper() })

    await waitFor(() => {
      expect(screen.getByText('Operations Cockpit')).toBeInTheDocument()
    })

    // Health tiles + topology preview populate from the fixtures.
    await waitFor(() => {
      expect(screen.getByText('Edge Routers')).toBeInTheDocument()
      // routers_online/total from the overview fixture.
      expect(screen.getByText('2/3')).toBeInTheDocument()
      expect(screen.getByTestId('topology-graph-stub')).toBeInTheDocument()
    })

    // Security tile top item.
    await waitFor(() => {
      expect(screen.getByText('Brute force detected')).toBeInTheDocument()
    })
  })

  it('shows QueryError when the primary fabric-overview query is forbidden (403)', async () => {
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url.includes('/fabric/overview')) {
        return Promise.reject({ response: { status: 403 } })
      }
      return Promise.resolve([])
    })

    render(<OpsCockpitPage />, { wrapper: createWrapper() })

    await waitFor(() => {
      expect(screen.getByText(/don't have permission to view operations cockpit/i)).toBeInTheDocument()
    })
  })
})
