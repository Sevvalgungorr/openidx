import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
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

import { AuditArchivalPage } from './audit-archival'
import { api } from '../lib/api'

const retentionPolicy = {
  id: 'rp-1',
  name: 'Auth events — 90 days',
  event_category: 'authentication',
  retention_days: 90,
  archive_enabled: true,
  archive_format: 'gzip',
  enabled: true,
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
}

const disabledPolicy = {
  ...retentionPolicy,
  id: 'rp-2',
  name: 'Authorization events — 30 days (paused)',
  event_category: 'authorization',
  retention_days: 30,
  enabled: false,
}

const archive = {
  id: 'arc-1',
  name: '2025 audit archive',
  date_range_start: '2025-01-01T00:00:00Z',
  date_range_end: '2025-12-31T23:59:59Z',
  event_count: 12345,
  file_size: 5242880, // 5 MB
  file_path: '/var/openidx/archives/2025.tar.gz',
  format: 'gzip',
  status: 'completed',
  created_by: 'admin-1',
  created_at: '2026-01-15T00:00:00Z',
}

function routeGet(url: string) {
  if (url.includes('/audit-retention')) return Promise.resolve({ data: [retentionPolicy, disabledPolicy] })
  if (url.includes('/audit-archives')) return Promise.resolve({ data: [archive] })
  return Promise.resolve({ data: [] })
}

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('AuditArchivalPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockImplementation((url: string) => routeGet(url) as ReturnType<typeof api.get>)
  })

  it('renders the heading + subtitle + three summary cards', async () => {
    render(<AuditArchivalPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Audit Archival & Retention')).toBeInTheDocument()
    expect(
      screen.getByText(/manage audit event lifecycle, retention policies, and archives/i),
    ).toBeInTheDocument()
    // "Retention Policies" text appears in *both* the summary card and
    // the tab button. We only check the card-side identifiers that are
    // unique to summary cards.
    expect(screen.getByText('Archived Events')).toBeInTheDocument()
    expect(screen.getByText('Archive Storage')).toBeInTheDocument()
    // Tab buttons exist
    expect(screen.getByRole('button', { name: /^retention policies$/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^archives$/i })).toBeInTheDocument()
  })

  it('lists retention policies on the default tab with status badges and retention description', async () => {
    render(<AuditArchivalPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Auth events — 90 days')).toBeInTheDocument()
    expect(screen.getByText('Authorization events — 30 days (paused)')).toBeInTheDocument()

    // Status badges
    expect(screen.getByText('Enabled')).toBeInTheDocument()
    expect(screen.getByText('Disabled')).toBeInTheDocument()
    // The retention summary line for the first policy
    expect(
      screen.getByText(/retain for 90 days \(archive before delete\)/i),
    ).toBeInTheDocument()
  })

  it('toggles the New Policy form when the button is clicked', async () => {
    const user = userEvent.setup()
    render(<AuditArchivalPage />, { wrapper: createWrapper() })
    await screen.findByText('Auth events — 90 days')

    expect(screen.queryByText('New Retention Policy')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: /new policy/i }))
    expect(await screen.findByText('New Retention Policy')).toBeInTheDocument()
  })

  it('switches to the Archives tab and surfaces archive rows', async () => {
    const user = userEvent.setup()
    render(<AuditArchivalPage />, { wrapper: createWrapper() })
    await screen.findByText('Audit Archival & Retention')

    // Plain <button> tab, not Radix — fireEvent would work, but userEvent
    // is the recommended path either way.
    await user.click(screen.getByRole('button', { name: /^archives$/i }))
    expect(await screen.findByText('2025 audit archive')).toBeInTheDocument()
    // Event count is rendered via toLocaleString
    expect(screen.getByText(/12,345 events/i)).toBeInTheDocument()
    // Status badge
    expect(screen.getByText('completed')).toBeInTheDocument()
    // Completed archives offer a Restore button
    expect(screen.getByRole('button', { name: /restore/i })).toBeInTheDocument()
  })

  it('renders without crashing when numeric fields are omitted from the API response', async () => {
    const user = userEvent.setup()
    // Backend may drop/nullify numeric fields (Go zero-values / nil serialize
    // to null or are absent). The page must not blank out via the error boundary.
    const bareArchive = {
      id: 'arc-bare',
      name: 'archive with missing numbers',
      date_range_start: null,
      date_range_end: null,
      // event_count and file_size intentionally OMITTED
      file_path: '/var/openidx/archives/bare.tar.gz',
      format: 'gzip',
      status: 'completed',
      created_by: null,
      created_at: '2026-01-15T00:00:00Z',
    }
    const barePolicy = {
      id: 'rp-bare',
      name: 'policy with missing retention_days',
      event_category: 'all',
      // retention_days intentionally OMITTED
      archive_enabled: true,
      archive_format: 'gzip',
      enabled: true,
      created_at: '2026-01-01T00:00:00Z',
      updated_at: '2026-01-01T00:00:00Z',
    }
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url.includes('/audit-archives')) return Promise.resolve({ data: [bareArchive] }) as ReturnType<typeof api.get>
      if (url.includes('/audit-retention')) return Promise.resolve({ data: [barePolicy] }) as ReturnType<typeof api.get>
      return Promise.resolve({ data: [] }) as ReturnType<typeof api.get>
    })
    render(<AuditArchivalPage />, { wrapper: createWrapper() })
    // Heading + summary sections still render (no error boundary).
    expect(await screen.findByText('Audit Archival & Retention')).toBeInTheDocument()
    expect(screen.getByText('Archived Events')).toBeInTheDocument()
    expect(screen.getByText('Archive Storage')).toBeInTheDocument()

    // The archives tab renders the bare row without throwing on toLocaleString.
    await user.click(screen.getByRole('button', { name: /^archives$/i }))
    expect(await screen.findByText('archive with missing numbers')).toBeInTheDocument()
    expect(screen.getByText(/0 events/i)).toBeInTheDocument()
  })

  it('shows the empty-archives state when no archives exist', async () => {
    const user = userEvent.setup()
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url.includes('/audit-archives')) return Promise.resolve({ data: [] })
      if (url.includes('/audit-retention')) return Promise.resolve({ data: [] })
      return Promise.resolve({ data: [] })
    })
    render(<AuditArchivalPage />, { wrapper: createWrapper() })
    await screen.findByText('Audit Archival & Retention')

    await user.click(screen.getByRole('button', { name: /^archives$/i }))
    expect(await screen.findByText('No archives created yet')).toBeInTheDocument()
  })
})
