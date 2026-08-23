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

import { AIRecommendationsPage } from './ai-recommendations'
import { api } from '../lib/api'

const recommendation = {
  id: 'rec-1',
  recommendation_type: 'mfa_enforcement',
  category: 'security',
  title: 'Enforce MFA on Admin role',
  description: 'Admin accounts without MFA are a high-impact compromise vector',
  impact: 'high',
  effort: 'low',
  affected_entities: [{ type: 'role', id: 'admin', name: 'admin', count: 3 }],
  suggested_action: { type: 'add_mfa_policy', target: 'admin' },
  status: 'pending',
  dismissed_reason: '',
  applied_at: null,
}

const stats = {
  by_status: { pending: 4, applied: 6, dismissed: 2 },
  pending_by_category: { security: 2, performance: 1, compliance: 1 },
  acceptance_rate: 75.0,
  total_resolved: 8,
  total_accepted: 6,
}

function routeGet(url: string) {
  if (url.includes('/recommendations/stats')) return Promise.resolve(stats)
  if (url.includes('/recommendations')) return Promise.resolve({ data: [recommendation] })
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

describe('AIRecommendationsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockImplementation((url: string) => routeGet(url) as ReturnType<typeof api.get>)
  })

  it('renders the heading + subtitle + Generate Recommendations button', async () => {
    render(<AIRecommendationsPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('AI Recommendations')).toBeInTheDocument()
    expect(
      screen.getByText(/intelligent suggestions to improve your security posture/i),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /generate recommendations/i }),
    ).toBeInTheDocument()
  })

  it('shows the five stat cards (Pending / Accepted / Applied / Dismissed / Acceptance Rate)', async () => {
    render(<AIRecommendationsPage />, { wrapper: createWrapper() })
    // Wait for the stats query to resolve so the cards are present.
    expect(await screen.findByText('Acceptance Rate')).toBeInTheDocument()

    // "Pending"/"Accepted"/"Applied"/"Dismissed" all collide with the
    // status-filter Select options, so assert presence rather than
    // uniqueness.
    expect(screen.getAllByText('Pending').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Accepted').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Applied').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Dismissed').length).toBeGreaterThan(0)

    // Derived values from the fixture — "2" (dismissed) collides with
    // the same value on Recommendation row counts, so assert presence.
    expect(screen.getByText('4')).toBeInTheDocument() // pending
    expect(screen.getAllByText('2').length).toBeGreaterThan(0) // dismissed
    expect(screen.getByText('75%')).toBeInTheDocument() // acceptance rate
  })

  it('shows the pending-by-category breakdown', async () => {
    render(<AIRecommendationsPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Pending by Category')).toBeInTheDocument()
    // "security" collides with the recommendation's `category` field
    // shown elsewhere — disambiguate.
    expect(screen.getAllByText('security').length).toBeGreaterThan(0)
    expect(screen.getByText('performance')).toBeInTheDocument()
    expect(screen.getByText('compliance')).toBeInTheDocument()
  })

  it('renders the recommendation list with the loaded title and description', async () => {
    render(<AIRecommendationsPage />, { wrapper: createWrapper() })
    expect(
      await screen.findByText('Enforce MFA on Admin role'),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/admin accounts without mfa are a high-impact compromise vector/i),
    ).toBeInTheDocument()
  })

  it('renders without crashing when recommendation + stats fields are omitted', async () => {
    // Backend can return rows/objects with numeric/string/array fields absent.
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url.includes('/recommendations/stats')) {
        return Promise.resolve({}) as ReturnType<typeof api.get>
      }
      if (url.includes('/recommendations')) {
        return Promise.resolve({ data: [{ id: 'rec-bare' }] }) as ReturnType<typeof api.get>
      }
      return Promise.resolve({ data: [] }) as ReturnType<typeof api.get>
    })

    render(<AIRecommendationsPage />, { wrapper: createWrapper() })

    // Heading renders (no error boundary blanking the page) even though the
    // recommendation lacks recommendation_type/affected_entities and the stats
    // object is entirely empty.
    expect(await screen.findByText('AI Recommendations')).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /generate recommendations/i }),
    ).toBeInTheDocument()
  })
})
