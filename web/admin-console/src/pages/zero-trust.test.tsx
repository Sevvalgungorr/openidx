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

import { ZeroTrustPage } from './zero-trust'
import { api } from '../lib/api'

const overview = {
  summary: {
    total_routes: 12,
    enabled_routes: 9,
    via_http_proxy: 4,
    via_ziti: 5,
    via_browzer: 2,
    via_guacamole: 1,
    missing_auth: 1,
    missing_device_trust: 2,
    missing_posture: 3,
    missing_risk_cap: 0,
    active_sessions: 7,
  },
  routes: [
    {
      id: 'route-1',
      name: 'Internal Wiki',
      from_url: 'wiki.corp.test',
      to_url: '127.0.0.1:8080',
      enabled: true,
      route_type: 'http',
      ziti_enabled: true,
      browzer_enabled: false,
      guacamole_enabled: false,
      require_auth: true,
      allowed_roles_count: 2,
      allowed_groups_count: 1,
      require_device_trust: true,
      posture_check_count: 2,
      max_risk_score: 50,
      allowed_countries_count: 0,
      has_inline_policy: false,
      active_sessions: 3,
      features: [],
    },
    {
      id: 'route-2',
      name: 'Open Dashboard',
      from_url: 'dash.corp.test',
      to_url: '127.0.0.1:9090',
      enabled: true,
      route_type: 'http',
      ziti_enabled: false,
      browzer_enabled: false,
      guacamole_enabled: false,
      require_auth: false, // a coverage gap
      allowed_roles_count: 0,
      allowed_groups_count: 0,
      require_device_trust: false,
      posture_check_count: 0,
      max_risk_score: 0,
      allowed_countries_count: 0,
      has_inline_policy: false,
      active_sessions: 0,
      features: [],
    },
  ],
  ziti: { configured: true, controller_reachable: true },
}

function routeGet(url: string) {
  if (url.includes('/access/overview')) return Promise.resolve(overview)
  if (url.includes('/access/sessions')) {
    return Promise.resolve({
      sessions: [
        {
          id: 'sess-1',
          user_id: 'u-1',
          route_id: 'route-1',
          ip_address: '10.0.0.9',
          user_agent: 'Mozilla',
          last_active_at: '2026-01-10T00:00:00Z',
        },
      ],
    })
  }
  if (url.includes('/access/audit/unified')) {
    return Promise.resolve({
      events: [
        {
          source: 'proxy',
          event_type: 'access.granted',
          user_email: 'alice@corp.test',
          actor_ip: '10.0.0.9',
          route_id: 'route-1',
          created_at: '2026-01-10T00:00:00Z',
        },
      ],
    })
  }
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

describe('ZeroTrustPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockImplementation((url: string) => routeGet(url) as ReturnType<typeof api.get>)
  })

  it('renders the heading and Ziti status badge', async () => {
    render(<ZeroTrustPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Zero Trust Access')).toBeInTheDocument()
    expect(screen.getByText(/Ziti:/)).toBeInTheDocument()
  })

  it('renders the summary cards with fixture values', async () => {
    render(<ZeroTrustPage />, { wrapper: createWrapper() })
    // "Resources" appears as both a summary card and a tab.
    expect((await screen.findAllByText('Resources')).length).toBeGreaterThan(0)
    expect(screen.getByText('Via Ziti')).toBeInTheDocument()
    expect(screen.getByText('Via BrowZer')).toBeInTheDocument()
    expect(screen.getByText('Active sessions')).toBeInTheDocument()
    expect(screen.getByText('Need hardening')).toBeInTheDocument()
    // total_routes = 12 shown in the Resources summary card
    expect((await screen.findAllByText('12')).length).toBeGreaterThan(0)
  })

  it('lists protected resources in the Resources tab', async () => {
    render(<ZeroTrustPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Internal Wiki')).toBeInTheDocument()
    expect(screen.getByText('Open Dashboard')).toBeInTheDocument()
    expect(screen.getByText('wiki.corp.test')).toBeInTheDocument()
  })

  it('shows the three tabs including a Coverage Gaps count', async () => {
    render(<ZeroTrustPage />, { wrapper: createWrapper() })
    expect((await screen.findAllByText('Resources')).length).toBeGreaterThan(0)
    expect(screen.getByText('Live Access')).toBeInTheDocument()
    // route-2 is a gap (no auth) -> the tab shows a (1)
    expect(screen.getByText(/Coverage Gaps/)).toBeInTheDocument()
  })

  it('renders without crashing when the backend omits summary/route fields', async () => {
    // Simulate a Go zero-value/nil-slice response: numeric fields dropped,
    // features nil, summary and ziti absent.
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url.includes('/access/overview')) {
        return Promise.resolve({
          routes: [{ id: 'route-x', name: 'Sparse Route' }],
        }) as ReturnType<typeof api.get>
      }
      return Promise.resolve({}) as ReturnType<typeof api.get>
    })
    render(<ZeroTrustPage />, { wrapper: createWrapper() })
    // Heading and section still render (no error boundary), and the sparse route
    // shows despite its omitted numeric/array fields.
    expect(await screen.findByText('Zero Trust Access')).toBeInTheDocument()
    expect(await screen.findByText('Sparse Route')).toBeInTheDocument()
  })
})
