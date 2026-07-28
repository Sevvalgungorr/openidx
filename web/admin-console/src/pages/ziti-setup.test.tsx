import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import React from 'react'

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

import { ZitiSetupPage } from './ziti-setup'
import { api } from '../lib/api'

const status = {
  ready: false,
  summary: 'Two steps remain before the overlay is production-ready.',
  console_url: 'https://ctrl.tdv.org/console',
  steps: [
    {
      id: 'controller',
      title: 'Controller reachable',
      description: 'The OpenZiti controller responds to management calls.',
      status: 'complete',
    },
    {
      id: 'router',
      title: 'Edge router online',
      description: 'At least one edge router is registered and connected.',
      status: 'action_needed',
    },
  ],
  components: [
    { id: 'ctrl', name: 'Controller', role: 'control-plane', required: 'required', status: 'complete' },
    { id: 'router', name: 'Edge Router', role: 'data-plane', required: 'required', status: 'action_needed' },
  ],
  routes: [
    {
      route_name: 'Internal Wiki',
      service_name: 'openidx-wiki',
      to_url: '127.0.0.1:8080',
      stored_mode: 'ziti',
      effective_mode: 'ziti',
      browzer_enabled: false,
      route_enabled: true,
      next_hop: 'router-1',
      client_side: 'tunnel',
      reconcile_state: 'ok',
    },
  ],
  routers: [
    {
      id: 'router-1',
      name: 'oidx-router',
      hostname: 'ziti-router.localtest.me',
    },
  ],
  sync_status: {
    unsynced_users: 0,
    total_users: 10,
    total_identities: 10,
  },
}

function routeGet(url: string) {
  if (url.includes('/ziti/setup/status')) return Promise.resolve(status)
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

describe('ZitiSetupPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockImplementation((url: string) => routeGet(url) as ReturnType<typeof api.get>)
  })

  it('renders the heading and the status summary', async () => {
    render(<ZitiSetupPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Network Setup')).toBeInTheDocument()
    expect(
      await screen.findByText(/two steps remain before the overlay/i),
    ).toBeInTheDocument()
  })

  it('renders the setup checklist with its steps', async () => {
    render(<ZitiSetupPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Setup checklist')).toBeInTheDocument()
    expect(screen.getByText('Controller reachable')).toBeInTheDocument()
    expect(screen.getByText('Edge router online')).toBeInTheDocument()
    expect(
      screen.getByText(/at least one edge router is registered/i),
    ).toBeInTheDocument()
  })

  it('renders the applications-on-the-network card with the ziti route', async () => {
    render(<ZitiSetupPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Your applications on the network')).toBeInTheDocument()
    expect((await screen.findAllByText('Internal Wiki')).length).toBeGreaterThan(0)
  })
})
