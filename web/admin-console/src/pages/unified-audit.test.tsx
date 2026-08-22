import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
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

import { UnifiedAuditPage } from './unified-audit'
import { api } from '../lib/api'

const openidxEvent = {
  id: 'evt-1',
  source: 'openidx',
  event_type: 'login.success',
  user_email: 'alice@example.com',
  actor_ip: '203.0.113.10',
  created_at: '2026-06-09T10:00:00Z',
  details: { mfa_method: 'totp', session_id: 'sess-abc123' },
}

const zitiEvent = {
  id: 'evt-2',
  source: 'ziti',
  event_type: 'session.created',
  route_name: 'prod-database',
  user_email: 'bob@example.com',
  actor_ip: '198.51.100.5',
  created_at: '2026-06-09T11:00:00Z',
}

const summary = {
  total_last_24h: 1532,
  by_source: { openidx: 1200, ziti: 300, guacamole: 32 },
}

function routeGet(url: string) {
  if (url.includes('/audit/unified/summary')) return Promise.resolve(summary)
  if (url.includes('/audit/unified')) {
    return Promise.resolve({
      events: [openidxEvent, zitiEvent],
      total: 2,
      sources: ['openidx', 'ziti', 'guacamole'],
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

describe('UnifiedAuditPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockImplementation((url: string) => routeGet(url) as ReturnType<typeof api.get>)
  })

  it('renders the heading + subtitle + Refresh button', async () => {
    render(<UnifiedAuditPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Unified Audit Log')).toBeInTheDocument()
    expect(
      screen.getByText(/combined events from openidx, ziti, and guacamole/i),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /refresh/i }),
    ).toBeInTheDocument()
  })

  it('shows the four summary cards (Total 24h + per-source from by_source)', async () => {
    render(<UnifiedAuditPage />, { wrapper: createWrapper() })
    // Total label is hardcoded — wait on a value that depends on the
    // summary query resolving instead.
    expect(await screen.findByText('1532')).toBeInTheDocument()
    expect(screen.getByText('Total (24h)')).toBeInTheDocument()

    // Per-source values from by_source map
    expect(screen.getByText('1200')).toBeInTheDocument()
    expect(screen.getByText('300')).toBeInTheDocument()
    expect(screen.getByText('32')).toBeInTheDocument()

    // Source labels rendered via <span className="capitalize">{src}</span>
    // — the DOM text is the bare key. These also appear inside each
    // event row's SourceBadge, so use getAllByText for the sources that
    // match a fixture event.
    expect(screen.getAllByText('openidx').length).toBeGreaterThan(0)
    expect(screen.getAllByText('ziti').length).toBeGreaterThan(0)
    expect(screen.getByText('guacamole')).toBeInTheDocument()
  })

  it('lists events with their event_type, user_email, and actor_ip', async () => {
    render(<UnifiedAuditPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('login.success')).toBeInTheDocument()
    expect(screen.getByText('session.created')).toBeInTheDocument()

    expect(screen.getByText('alice@example.com')).toBeInTheDocument()
    expect(screen.getByText('bob@example.com')).toBeInTheDocument()
    expect(screen.getByText('203.0.113.10')).toBeInTheDocument()
    expect(screen.getByText('198.51.100.5')).toBeInTheDocument()
  })

  it('exposes the event-type filter input + the source Select', async () => {
    render(<UnifiedAuditPage />, { wrapper: createWrapper() })
    await screen.findByText('Unified Audit Log')

    expect(
      screen.getByPlaceholderText(/filter by event type/i),
    ).toBeInTheDocument()
    // The Select trigger renders its placeholder copy.
    expect(screen.getByText('All Sources')).toBeInTheDocument()
  })

  it('opens a details dialog showing the event details when a row is clicked', async () => {
    render(<UnifiedAuditPage />, { wrapper: createWrapper() })
    const eventCell = await screen.findByText('login.success')

    // Click the row (or its View button) to open the drill-down.
    fireEvent.click(eventCell)

    // The dialog surfaces the details object contents.
    expect(await screen.findByText('Event Details')).toBeInTheDocument()
    expect(screen.getByText(/mfa_method/)).toBeInTheDocument()
    expect(screen.getByText(/sess-abc123/)).toBeInTheDocument()
  })

  it('shows the empty-events message when no events match', async () => {
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url.includes('/audit/unified/summary')) {
        return Promise.resolve(summary) as ReturnType<typeof api.get>
      }
      return Promise.resolve({ events: [], total: 0, sources: [] }) as ReturnType<typeof api.get>
    })
    render(<UnifiedAuditPage />, { wrapper: createWrapper() })

    expect(
      await screen.findByText(/no audit events found/i),
    ).toBeInTheDocument()
  })
})
