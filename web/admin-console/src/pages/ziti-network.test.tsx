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

import { ZitiNetworkPage } from './ziti-network'
import { api } from '../lib/api'

const status = {
  enabled: true,
  sdk_ready: true,
  controller_reachable: true,
  controller_version: { version: '0.30.0' },
  services_count: 12,
  identities_count: 47,
}

// The overview endpoint nests health under `health` (verified against the live
// API). routers_online/total drive the Routers card.
const overview = {
  health: {
    controller_reachable: true,
    controller_version: '0.30.0',
    sdk_ready: true,
    routers_online: 3,
    routers_total: 3,
    services_count: 12,
    identities_count: 47,
    policies_count: 8,
  },
}

const routers = [
  {
    id: 'r-1',
    name: 'edge-router-east',
    // The controller returns camelCase and no fingerprint/created_at.
    isOnline: true,
    isVerified: true,
    hostname: 'east.routers.example.com',
    versionInfo: { os: 'linux', arch: 'amd64', version: 'v1.6.12' },
  },
]

function routeGet(url: string) {
  if (url.includes('/ziti/status')) return Promise.resolve(status)
  if (url.includes('/ziti/fabric/overview')) return Promise.resolve(overview)
  if (url.includes('/ziti/fabric/routers')) return Promise.resolve(routers)
  if (url.includes('/ziti/fabric/health')) return Promise.resolve({ healthy: true })
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

describe('ZitiNetworkPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockImplementation((url: string) => routeGet(url) as ReturnType<typeof api.get>)
  })

  it('renders the heading + subtitle', async () => {
    render(<ZitiNetworkPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Ziti Network')).toBeInTheDocument()
    expect(
      screen.getByText(/manage your openziti zero-trust network overlay/i),
    ).toBeInTheDocument()
  })

  it('shows the Connected status pill + counters in the header', async () => {
    render(<ZitiNetworkPage />, { wrapper: createWrapper() })

    expect(await screen.findByText(/^connected$/i)).toBeInTheDocument()
    expect(screen.getByText(/12 services/i)).toBeInTheDocument()
    expect(screen.getByText(/47 identities/i)).toBeInTheDocument()
  })

  it('renders all five tabs (Overview / Services / Identities / Security / Remote Access)', async () => {
    render(<ZitiNetworkPage />, { wrapper: createWrapper() })
    await screen.findByText('Ziti Network')

    expect(screen.getByRole('tab', { name: /overview/i })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /services/i })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /identities/i })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /security/i })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /remote access/i })).toBeInTheDocument()
  })

  it('shows the OverviewTab stat cards (Controller / Routers / Services / Identities) with values', async () => {
    render(<ZitiNetworkPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('Controller')).toBeInTheDocument()
    expect(screen.getByText('Routers')).toBeInTheDocument()

    // The Services and Identities labels render in BOTH the header badges
    // ("12 services") AND the stat-card titles ("Services"/"Identities"),
    // so check for the bare titles via getAllByText.
    expect(screen.getAllByText('Services').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Identities').length).toBeGreaterThan(0)

    // Controller is online → stat card shows "Online" (may also show in
    // a status indicator, so allow multiple).
    expect(screen.getAllByText('Online').length).toBeGreaterThan(0)
    // Router count + online/offline hint
    expect(screen.getAllByText('3').length).toBeGreaterThan(0)
    expect(
      screen.getByText(/3 online, 0 offline/i),
    ).toBeInTheDocument()
  })

  it('shows the Disconnected pill when the controller is unreachable', async () => {
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url.includes('/ziti/status')) {
        return Promise.resolve({ ...status, controller_reachable: false }) as ReturnType<typeof api.get>
      }
      if (url.includes('/ziti/fabric/overview')) {
        return Promise.resolve({
          health: { ...overview.health, controller_reachable: false, routers_online: 0 },
        }) as ReturnType<typeof api.get>
      }
      return Promise.resolve({}) as ReturnType<typeof api.get>
    })

    render(<ZitiNetworkPage />, { wrapper: createWrapper() })

    expect(await screen.findByText(/^disconnected$/i)).toBeInTheDocument()
    // Controller stat card flips to Offline
    expect(screen.getByText('Offline')).toBeInTheDocument()
  })
})
