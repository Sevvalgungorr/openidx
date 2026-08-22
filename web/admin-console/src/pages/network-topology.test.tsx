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

import { NetworkTopologyPage } from './network-topology'
import { api } from '../lib/api'

const identities = [
  { id: 'id-1', name: 'alice', attributes: ['dev'], enrolled: true },
  { id: 'id-2', name: 'bob', attributes: ['ops'], enrolled: true },
]
const services = [{ id: 'svc-1', name: 'internal-app', roleAttributes: ['dev-clients'] }]
const routers = [{ id: 'r-1', name: 'edge-1', isOnline: true }]
const policies = [
  { id: 'p-1', name: 'dev-policy', type: 'Dial', identityRoles: ['#dev'], serviceRoles: ['#dev-clients'] },
]

function wireDefaultApi() {
  vi.mocked(api.get).mockImplementation((url: string) => {
    if (url.includes('/ziti/identities')) return Promise.resolve({ identities })
    if (url.includes('/ziti/services')) return Promise.resolve({ services })
    if (url.includes('/fabric/routers')) return Promise.resolve(routers)
    if (url.includes('/fabric/service-policies')) return Promise.resolve(policies)
    if (url.includes('/ziti/sessions')) return Promise.resolve([])
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

describe('NetworkTopologyPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    wireDefaultApi()
  })

  it('renders the header and overlay summary', async () => {
    render(<NetworkTopologyPage />, { wrapper: createWrapper() })

    await waitFor(() => {
      expect(screen.getByText('Network Topology')).toBeInTheDocument()
    })
    // Summary panel (no selection) shows counts built from the fixtures.
    await waitFor(() => {
      expect(screen.getByText('Overlay summary')).toBeInTheDocument()
      expect(screen.getByTestId('topology-graph-stub')).toBeInTheDocument()
    })
  })

  it('renders the search and live-sessions controls', async () => {
    render(<NetworkTopologyPage />, { wrapper: createWrapper() })

    await waitFor(() => {
      expect(screen.getByPlaceholderText('Filter nodes by name...')).toBeInTheDocument()
      expect(screen.getByText('Show live sessions')).toBeInTheDocument()
    })
  })

  it('shows QueryError when the primary identities query is forbidden (403)', async () => {
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url.includes('/ziti/identities')) {
        return Promise.reject({ response: { status: 403 } })
      }
      if (url.includes('/ziti/services')) return Promise.resolve({ services })
      if (url.includes('/fabric/routers')) return Promise.resolve(routers)
      if (url.includes('/fabric/service-policies')) return Promise.resolve(policies)
      return Promise.resolve([])
    })

    render(<NetworkTopologyPage />, { wrapper: createWrapper() })

    await waitFor(() => {
      expect(screen.getByText(/don't have permission to view network topology/i)).toBeInTheDocument()
    })
  })
})
