import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
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

import { ReviewDetailPage } from './review-detail'
import { api } from '../lib/api'

const pendingReview = {
  id: 'rv-1',
  name: 'Q2 Access Review',
  description: 'Quarterly access review of admin roles',
  status: 'pending',
  start_date: '2026-04-01T00:00:00Z',
  end_date: '2026-06-30T00:00:00Z',
  created_at: '2026-04-01T00:00:00Z',
}

const items = [
  {
    id: 'it-1',
    user_email: 'alice@example.com',
    resource_name: 'admin role',
    resource_type: 'role',
    decision: 'pending',
    last_used_at: '2026-05-01T00:00:00Z',
  },
  {
    id: 'it-2',
    user_email: 'bob@example.com',
    resource_name: 'database access',
    resource_type: 'group',
    decision: 'approve',
    last_used_at: '2026-05-15T00:00:00Z',
  },
]

function routeGet(url: string) {
  if (url.match(/\/reviews\/rv-1\/items/)) return Promise.resolve(items)
  if (url.match(/\/reviews\/rv-1$/)) return Promise.resolve(pendingReview)
  return Promise.resolve({})
}

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={['/access-reviews/rv-1']}>
        <Routes>
          <Route path="/access-reviews/:id" element={children} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>
  )
}

describe('ReviewDetailPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockImplementation((url: string) => routeGet(url) as ReturnType<typeof api.get>)
  })

  it('renders the review heading + description', async () => {
    render(<ReviewDetailPage />, { wrapper: createWrapper() })

    expect(
      await screen.findByRole('heading', { name: 'Q2 Access Review', level: 1 }),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/quarterly access review of admin roles/i),
    ).toBeInTheDocument()
  })

  it('shows the Start Review button when the review is pending', async () => {
    render(<ReviewDetailPage />, { wrapper: createWrapper() })
    await screen.findByText('Q2 Access Review')

    // "Start Review" matches both the visible button and the
    // "Starting..." label variant during pending state.
    expect(
      screen.getAllByRole('button', { name: /start.*review|starting/i })
        .length,
    ).toBeGreaterThan(0)
  })

  it('renders the four summary cards (Status / Period / Progress / Pending)', async () => {
    render(<ReviewDetailPage />, { wrapper: createWrapper() })
    await screen.findByText('Q2 Access Review')

    expect(screen.getByText('Status')).toBeInTheDocument()
    expect(screen.getByText('Review Period')).toBeInTheDocument()
    expect(screen.getByText('Progress')).toBeInTheDocument()
    expect(screen.getByText('Pending Items')).toBeInTheDocument()

    // Progress = 1/2 reviewed.
    expect(screen.getByText('1/2')).toBeInTheDocument()
  })

  it('renders the "Review not found" fallback when the review query is empty', async () => {
    // Resolve a defined-but-null payload (a successful "no such review"),
    // not undefined — react-query treats an undefined resolve as an error,
    // which would hit the QueryError branch instead of the not-found fallback.
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url.match(/\/reviews\/rv-1\/items/)) return Promise.resolve(items) as ReturnType<typeof api.get>
      return Promise.resolve(null) as ReturnType<typeof api.get>
    })

    render(<ReviewDetailPage />, { wrapper: createWrapper() })

    expect(
      await screen.findByText(/review not found/i),
    ).toBeInTheDocument()
  })
})
