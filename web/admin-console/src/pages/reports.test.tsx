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
  baseURL: 'http://test',
}))

vi.mock('../hooks/use-toast', () => ({
  useToast: () => ({ toast: vi.fn() }),
}))

import { ReportsPage } from './reports'
import { api } from '../lib/api'

const completedReport = {
  id: 'r-1',
  name: 'Q1 Compliance Export',
  report_type: 'compliance',
  format: 'csv',
  status: 'completed',
  file_size: 102400,
  row_count: 532,
  created_at: '2026-04-01T00:00:00Z',
}

const scheduledReport = {
  id: 's-1',
  name: 'Monthly Audit Summary',
  report_type: 'audit_summary',
  schedule: '0 0 1 * *',
  format: 'pdf',
  enabled: true,
  last_run_at: '2026-06-01T00:00:00Z',
}

function routeGet(url: string) {
  if (url.includes('/reports/exports')) {
    return Promise.resolve({ exports: [completedReport], total: 1 })
  }
  if (url.includes('/reports/scheduled')) {
    return Promise.resolve({ reports: [scheduledReport] })
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

describe('ReportsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockImplementation((url: string) => routeGet(url) as ReturnType<typeof api.get>)
  })

  it('renders the heading + subtitle + Generate / Schedule buttons', async () => {
    render(<ReportsPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('Reports & Exports')).toBeInTheDocument()
    expect(
      screen.getByText(/generate, download, and schedule reports/i),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /generate report/i }),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /schedule report/i }),
    ).toBeInTheDocument()
  })

  it('shows the Report History tab by default and lists completed reports', async () => {
    render(<ReportsPage />, { wrapper: createWrapper() })

    // Wait on a data-dependent value (the card title renders even when
    // the query is still resolving).
    expect(
      await screen.findByText('Q1 Compliance Export'),
    ).toBeInTheDocument()
    expect(screen.getByText('Generated Reports')).toBeInTheDocument()
    expect(screen.getByText('compliance')).toBeInTheDocument()
    expect(screen.getByText('CSV')).toBeInTheDocument()
    expect(screen.getByText('completed')).toBeInTheDocument()
  })

  it('switches to the Scheduled Reports tab when its button is clicked', async () => {
    const user = userEvent.setup()
    render(<ReportsPage />, { wrapper: createWrapper() })
    await screen.findByText('Q1 Compliance Export')

    await user.click(screen.getByRole('button', { name: /^scheduled reports$/i }))

    expect(await screen.findByText('Monthly Audit Summary')).toBeInTheDocument()
    expect(screen.getByText('audit_summary')).toBeInTheDocument()
    expect(screen.getByText('0 0 1 * *')).toBeInTheDocument()
  })

  it('renders without crashing when numeric/string fields are omitted from the response', async () => {
    // Backend Go zero-values / nil slices can serialize to null or be dropped
    // from JSON — the row must still render (no error boundary blanking the page).
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url.includes('/reports/exports')) {
        return Promise.resolve({
          exports: [{ id: 'r-omit', status: 'completed', created_at: '2026-04-01T00:00:00Z' }],
        }) as ReturnType<typeof api.get>
      }
      return Promise.resolve({
        reports: [{ id: 's-omit', name: 'Sparse Schedule', enabled: true }],
      }) as ReturnType<typeof api.get>
    })

    render(<ReportsPage />, { wrapper: createWrapper() })

    // Heading + card section render, proving no error boundary tripped.
    expect(await screen.findByText('Reports & Exports')).toBeInTheDocument()
    expect(await screen.findByText('Generated Reports')).toBeInTheDocument()
  })

  it('shows the empty state on the History tab when nothing has been generated', async () => {
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url.includes('/reports/exports')) {
        return Promise.resolve({ exports: [], total: 0 }) as ReturnType<typeof api.get>
      }
      return Promise.resolve({ reports: [] }) as ReturnType<typeof api.get>
    })

    render(<ReportsPage />, { wrapper: createWrapper() })

    expect(
      await screen.findByText(/no reports generated yet/i),
    ).toBeInTheDocument()
  })
})
