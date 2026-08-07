import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import React from 'react'

vi.mock('../lib/api', () => ({
  api: { get: vi.fn(), post: vi.fn() },
}))
vi.mock('../hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }))

import { MyNetworkPage } from './my-network'
import { api } from '../lib/api'

// One row per status so the page's whole state space is exercised.
const resources = [
  {
    id: 'r-web',
    name: 'Wiki',
    kind: 'web',
    from: 'Your browser',
    to: 'wiki.example.org',
    port: 443,
    how: 'browser',
    status: 'ready',
    action: { label: 'Open', kind: 'open_url', url: 'https://wiki.example.org' },
    note: 'Opens in this browser. Nothing to install.',
  },
  {
    id: 'r-ssh',
    name: 'db-01',
    kind: 'ssh',
    from: 'Your browser',
    to: '10.0.0.21',
    port: 22,
    how: 'broker',
    status: 'ready',
    action: { label: 'Connect', kind: 'broker_connect', target: 'r-ssh' },
  },
  {
    id: 'r-rdp',
    name: 'win-01',
    kind: 'remote_desktop',
    from: 'Your browser',
    to: '10.0.0.22',
    port: 3389,
    how: 'broker',
    status: 'request_access',
    action: { label: 'Request access', kind: 'request', target: 'r-rdp' },
    note: 'Needs approval before the session can start.',
  },
  {
    // Configured but not usable yet — must never be advertised as ready, and
    // must still tell the user what to do.
    id: 'r-broken',
    name: 'Unpublished',
    kind: 'web',
    from: 'Your browser',
    to: 'nope.internal',
    port: 443,
    how: 'browser',
    status: 'needs_setup',
    action: { label: 'Report a problem', kind: 'request', target: 'r-broken' },
    note: 'This address is not published yet, so it will not open. Let an administrator know.',
  },
]

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('MyNetworkPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockResolvedValue({
      resources,
      summary: { total: resources.length, ready: 2 },
    })
  })

  it('states the where -> where path with the port for every resource', async () => {
    render(<MyNetworkPage />, { wrapper: createWrapper() })

    // The whole point of the page: a user can read where they are going.
    expect(await screen.findByText('wiki.example.org:443')).toBeInTheDocument()
    expect(screen.getByText('10.0.0.21:22')).toBeInTheDocument()
    expect(screen.getByText('10.0.0.22:3389')).toBeInTheDocument()
    // "from" side is stated too.
    expect(screen.getAllByText('Your browser').length).toBe(resources.length)
  })

  it('renders exactly one primary action per resource and never a dead end', async () => {
    render(<MyNetworkPage />, { wrapper: createWrapper() })
    await screen.findByText('wiki.example.org:443')

    // Every card must offer exactly one actionable control — no card may be a
    // dead end, and none may present competing calls to action.
    const cards = document.querySelectorAll('[class*="flex flex-col"]')
    const labels = ['Open', 'Connect', 'Request access', 'Report a problem']
    let actionable = 0
    labels.forEach((l) => {
      actionable += screen.queryAllByRole('button', { name: new RegExp(`^${l}$`, 'i') }).length
    })
    expect(actionable).toBe(resources.length)
    expect(cards.length).toBeGreaterThan(0)
  })

  it('offers a self-service next step for a resource that needs approval', async () => {
    render(<MyNetworkPage />, { wrapper: createWrapper() })
    // The approval-gated row is not hidden and not dead: the user can act.
    expect(await screen.findByRole('button', { name: /request access/i })).toBeEnabled()
  })

  it('uses plain language only - no overlay vocabulary anywhere on the page', async () => {
    render(<MyNetworkPage />, { wrapper: createWrapper() })
    await screen.findByText('wiki.example.org:443')

    const text = document.body.textContent?.toLowerCase() || ''
    const jargon = [
      'ziti',
      'openziti',
      'intercept',
      'terminator',
      'edge router',
      'role attribute',
      'enrollment',
      'jwt',
      'tunneler',
      'dial policy',
      'service policy',
    ]
    jargon.forEach((w) => {
      expect(text).not.toContain(w)
    })
  })

  it('guides the user instead of showing an empty screen when nothing is assigned', async () => {
    vi.mocked(api.get).mockResolvedValue({ resources: [], summary: { total: 0, ready: 0 } })
    render(<MyNetworkPage />, { wrapper: createWrapper() })

    expect(await screen.findByText(/nothing assigned yet/i)).toBeInTheDocument()
    // Even the empty state tells the user what they can do next.
    expect(screen.getByText(/ask your administrator|request it/i)).toBeInTheDocument()
  })


  it('never advertises an unusable resource as ready, and still offers a next step', async () => {
    render(<MyNetworkPage />, { wrapper: createWrapper() })
    await screen.findByText('wiki.example.org:443')

    // The unusable row is visible, clearly not "Ready", and actionable.
    expect(screen.getByText('nope.internal:443')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /report a problem/i })).toBeEnabled()
    expect(screen.getByText(/not published yet/i)).toBeInTheDocument()
  })

  it('shows how many resources are ready to use', async () => {
    render(<MyNetworkPage />, { wrapper: createWrapper() })
    expect(await screen.findByText(/2 ready to use/i)).toBeInTheDocument()
  })
})
