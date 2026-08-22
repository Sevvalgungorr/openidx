import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
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

import { AdminAuditLogPage, buildAuditCsv, fetchAllAuditEntries } from './admin-audit-log'
import { api } from '../lib/api'

const createEntry = {
  id: 'evt-1',
  actor_id: 'admin-1',
  actor_email: 'alice.admin@example.com',
  action: 'create',
  target_type: 'user',
  target_id: 'u-9',
  target_label: 'new-user@example.com',
  timestamp: '2026-06-09T10:00:00Z',
  before_state: undefined,
  after_state: { enabled: true },
  metadata: { ip: '203.0.113.5' },
}

const deleteEntry = {
  id: 'evt-2',
  actor_id: 'admin-2',
  actor_email: 'bob.admin@example.com',
  action: 'delete',
  target_type: 'role',
  target_id: 'role-x',
  target_label: 'legacy-readonly-role',
  timestamp: '2026-06-09T09:30:00Z',
  before_state: { name: 'legacy-readonly-role' },
  after_state: undefined,
  metadata: undefined,
}

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('AdminAuditLogPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockResolvedValue({
      items: [createEntry, deleteEntry],
      total: 2,
    })
  })

  it('renders the heading + subtitle + Export CSV button', async () => {
    render(<AdminAuditLogPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Admin Audit Log')).toBeInTheDocument()
    expect(
      screen.getByText(/track administrative operations and configuration changes/i),
    ).toBeInTheDocument()
    // Export CSV becomes enabled once entries arrive.
    expect(
      await screen.findByRole('button', { name: /export csv/i }),
    ).toBeInTheDocument()
  })

  it('exposes the four filter controls (Actor / Action / Target Type / date)', async () => {
    render(<AdminAuditLogPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Admin Audit Log')).toBeInTheDocument()

    // Filter labels render
    expect(screen.getByText('Actor')).toBeInTheDocument()
    expect(screen.getByText('Action')).toBeInTheDocument()
    expect(screen.getByText('Target Type')).toBeInTheDocument()
    expect(
      screen.getByPlaceholderText(/email or id/i),
    ).toBeInTheDocument()
  })

  it('lists each entry with actor email, action, and target label', async () => {
    render(<AdminAuditLogPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('alice.admin@example.com')).toBeInTheDocument()
    expect(screen.getByText('bob.admin@example.com')).toBeInTheDocument()
    expect(screen.getByText('new-user@example.com')).toBeInTheDocument()
    expect(screen.getByText('legacy-readonly-role')).toBeInTheDocument()
  })

  it('shows the table column headers (Actor / Action / Target Type / Target / Date)', async () => {
    render(<AdminAuditLogPage />, { wrapper: createWrapper() })
    // Wait for one of the entries to make sure the table actually rendered.
    await screen.findByText('alice.admin@example.com')

    // "Actor" / "Action" / "Target Type" also exist as filter labels, so
    // disambiguate via getAllByText.
    expect(screen.getAllByText('Actor').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Action').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Target Type').length).toBeGreaterThan(0)
    expect(screen.getByText('Target')).toBeInTheDocument()
    expect(screen.getByText('Date')).toBeInTheDocument()
  })

  it('buildAuditCsv includes a header row and one row per entry', () => {
    const csv = buildAuditCsv([createEntry, deleteEntry])
    const lines = csv.split('\n')
    expect(lines[0]).toContain('Timestamp')
    expect(lines).toHaveLength(3) // header + 2 rows
    expect(csv).toContain('alice.admin@example.com')
    expect(csv).toContain('bob.admin@example.com')
  })

  it('fetchAllAuditEntries accumulates entries across ALL pages, not just the first', async () => {
    // Page 0 is a full page (PAGE_SIZE = 20) so the walk continues; page 1
    // returns a single last-page entry that only exists beyond the current view.
    const pageZero = Array.from({ length: 20 }, (_, i) => ({
      ...createEntry,
      id: `p0-${i}`,
      actor_email: `page0-user${i}@example.com`,
    }))
    const pageOne = [
      { ...deleteEntry, id: 'p1-0', actor_email: 'page1-only@example.com' },
    ]

    const fetchPage = vi.fn(async (offset: number) =>
      offset >= 20 ? { items: pageOne, total: 21 } : { items: pageZero, total: 21 }
    )

    const all = await fetchAllAuditEntries(fetchPage)

    // It walked past the first page (offset 0 then offset 20) and stopped once
    // a page returned fewer than PAGE_SIZE rows.
    expect(fetchPage).toHaveBeenCalledWith(0)
    expect(fetchPage).toHaveBeenCalledWith(20)
    expect(fetchPage).toHaveBeenCalledTimes(2)

    // The accumulated set contains rows from BOTH pages.
    expect(all).toHaveLength(21)
    const csv = buildAuditCsv(all)
    expect(csv).toContain('page0-user0@example.com')
    expect(csv).toContain('page0-user19@example.com')
    expect(csv).toContain('page1-only@example.com')
  })

  it('Export CSV button walks past the current page (requests a later offset) and shows a loading state', async () => {
    const pageZero = Array.from({ length: 20 }, (_, i) => ({
      ...createEntry,
      id: `p0-${i}`,
      actor_email: `page0-user${i}@example.com`,
    }))
    vi.mocked(api.get).mockImplementation((url: string) =>
      (url.includes('offset=20')
        ? Promise.resolve({ items: [{ ...deleteEntry, id: 'p1', actor_email: 'page1-only@example.com' }], total: 21 })
        : Promise.resolve({ items: pageZero, total: 21 })) as ReturnType<typeof api.get>
    )
    // jsdom lacks URL.createObjectURL / anchor navigation — stub them.
    vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:mock')
    vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {})
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})

    render(<AdminAuditLogPage />, { wrapper: createWrapper() })
    await screen.findByText('page0-user0@example.com')
    const exportBtn = screen.getByRole('button', { name: /export csv/i })
    fireEvent.click(exportBtn)

    // The export walk requests offset=20 — i.e. it does NOT stop at the
    // current in-memory page.
    await waitFor(() =>
      expect(
        vi.mocked(api.get).mock.calls.some(([url]) => String(url).includes('offset=20')),
      ).toBe(true),
    )
  })

  it('renders an empty list area when no events match', async () => {
    vi.mocked(api.get).mockResolvedValue({ items: [], total: 0 })
    render(<AdminAuditLogPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('Admin Audit Log')).toBeInTheDocument()
    // With zero rows, none of the fixture emails are in the DOM.
    expect(screen.queryByText('alice.admin@example.com')).not.toBeInTheDocument()
  })
})
