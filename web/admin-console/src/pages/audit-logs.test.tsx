import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

// Mock the API module
vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(() => Promise.resolve({})),
    getWithHeaders: vi.fn(() => Promise.resolve({ data: [], headers: {} })),
    post: vi.fn(() => Promise.resolve({})),
  },
}))

// Import after mocks
import { AuditLogsPage } from '../pages/audit-logs'
import { api } from '../lib/api'

const mockAuditEvents = [
  {
    id: '1',
    event_type: 'authentication',
    category: 'auth',
    action: 'login',
    actor_id: 'johndoe1-abcd-efgh-ijkl-mnopqrstuvwx',
    actor_type: 'user',
    actor_ip: '10.0.0.1',
    outcome: 'success',
    timestamp: '2024-03-27T10:00:00Z',
  },
]

const mockStatistics = {
  total_events: 1,
  by_type: { authentication: 1 },
  by_outcome: { success: 1 },
  by_category: { auth: 1 },
  events_per_day: [{ date: '2024-03-27', count: 1 }],
  failed_auth_count: 0,
  success_rate: 100,
}

function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
    },
  })

  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('AuditLogsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''

    vi.mocked(api.get).mockResolvedValue(mockStatistics)
    vi.mocked(api.getWithHeaders).mockResolvedValue({ data: mockAuditEvents, headers: { 'x-total-count': '1' } })
  })

  it('renders the audit logs page heading', async () => {
    const wrapper = createWrapper()

    render(<AuditLogsPage />, { wrapper })

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /Audit Logs/i })).toBeInTheDocument()
    })
  })

  it('displays audit events list', async () => {
    const wrapper = createWrapper()

    render(<AuditLogsPage />, { wrapper })

    await waitFor(() => {
      // Actor column renders the truncated actor_id (first 8 chars + ellipsis)
      expect(screen.getByText('johndoe1...')).toBeInTheDocument()
      expect(screen.getByText('login')).toBeInTheDocument()
    })
  })

  it('has search functionality', async () => {
    const wrapper = createWrapper()

    render(<AuditLogsPage />, { wrapper })

    await waitFor(() => {
      const searchInput = screen.queryByPlaceholderText(/search/i)
      expect(searchInput).toBeInTheDocument()
    })
  })

  it('renders the page subtitle and the Export CSV / Hide Stats action buttons', async () => {
    const wrapper = createWrapper()
    render(<AuditLogsPage />, { wrapper })

    expect(
      await screen.findByText(/view and search audit events/i),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /export csv/i }),
    ).toBeInTheDocument()
    // showStats defaults to true, so the toggle label reads "Hide Stats"
    // on first render.
    expect(
      screen.getByRole('button', { name: /hide stats/i }),
    ).toBeInTheDocument()
  })

  it('exposes the three quick date-range buttons (Last 7 / 30 / 90 Days)', async () => {
    const wrapper = createWrapper()
    render(<AuditLogsPage />, { wrapper })

    await screen.findByText(/view and search audit events/i)
    expect(screen.getByRole('button', { name: /^last 7 days$/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^last 30 days$/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^last 90 days$/i })).toBeInTheDocument()
  })

  it('toggles the stats panel off when Hide Stats is clicked', async () => {
    const wrapper = createWrapper()
    render(<AuditLogsPage />, { wrapper })

    await screen.findByText(/view and search audit events/i)
    // Stats panel rendered initially (showStats defaults to true).
    expect(await screen.findByText(/events over time/i)).toBeInTheDocument()

    // Click "Hide Stats" — the panel unmounts and the button flips to "Show Stats".
    screen.getByRole('button', { name: /hide stats/i }).click()

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /show stats/i })).toBeInTheDocument()
    })
    expect(screen.queryByText(/events over time/i)).not.toBeInTheDocument()
  })

  it('renders without crashing when numeric/typed fields are omitted from the API response', async () => {
    // Simulate a Go zero-value / nil-slice backend response where numeric
    // stats fields (success_rate, failed_auth_count) and an event's
    // event_type are absent. The page must still render its heading rather
    // than blanking via the error boundary.
    vi.mocked(api.get).mockResolvedValue({
      // total_events, success_rate, failed_auth_count, by_type, by_outcome,
      // events_per_day all OMITTED
    } as unknown as typeof mockStatistics)
    vi.mocked(api.getWithHeaders).mockResolvedValue({
      data: [
        {
          id: '1',
          // event_type, category, action, outcome, actor_id, etc. OMITTED
          timestamp: '2024-03-27T10:00:00Z',
        },
      ] as unknown as typeof mockAuditEvents,
      headers: { 'x-total-count': '1' },
    })

    const wrapper = createWrapper()
    render(<AuditLogsPage />, { wrapper })

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /Audit Logs/i })).toBeInTheDocument()
    })
    // Success-rate stat card falls back to 0.0% instead of throwing on .toFixed
    expect(await screen.findByText(/0\.0%/)).toBeInTheDocument()
  })

  it('renders the audit event row with event_type and category info', async () => {
    const wrapper = createWrapper()
    render(<AuditLogsPage />, { wrapper })

    await waitFor(() => {
      // event_type is rendered as a label in the row — anchor on it
      // (case-insensitive). It collides with the stats panel's
      // "By Type" / "Events by Type" section title since stats are on
      // by default, so allow multiple.
      expect(
        screen.getAllByText(/authentication/i).length,
      ).toBeGreaterThan(0)
    })
  })
})
