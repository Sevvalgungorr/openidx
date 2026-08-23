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

import { AttestationCampaignsPage } from './attestation-campaigns'
import { api } from '../lib/api'

const campaignA = {
  id: 'cmp-1',
  name: 'Q1 Privileged Role Attestation',
  description: 'Quarterly review of admin-tier role assignments',
  campaign_type: 'role',
  scope: { resource_types: ['role'] },
  reviewer_strategy: 'manager',
  status: 'active',
  due_date: '2026-04-01T00:00:00Z',
  escalation_after_days: 7,
  auto_revoke_on_expiry: true,
  total_items: 20,
  certified_count: 12,
  revoked_count: 3,
  pending_count: 5,
  created_at: '2026-01-01T00:00:00Z',
  completed_at: null,
}

const campaignB = {
  id: 'cmp-2',
  name: 'Application access review — Sandbox',
  description: 'Sandbox-tier app assignments',
  campaign_type: 'application',
  scope: {},
  reviewer_strategy: 'owner',
  status: 'draft',
  due_date: null,
  escalation_after_days: 7,
  auto_revoke_on_expiry: false,
  total_items: 0,
  certified_count: 0,
  revoked_count: 0,
  pending_count: 0,
  created_at: '2026-01-02T00:00:00Z',
  completed_at: null,
}

function routeGet(url: string) {
  if (url.includes('/attestation-campaigns') && !url.includes('/items') && !url.includes('/progress')) {
    return Promise.resolve({ data: [campaignA, campaignB] })
  }
  if (url.includes('/items')) return Promise.resolve({ data: [] })
  if (url.includes('/progress')) {
    return Promise.resolve({ total: 0, certified: 0, revoked: 0, pending: 0, delegated: 0, completion_pct: 0 })
  }
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

describe('AttestationCampaignsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockImplementation((url: string) => routeGet(url) as ReturnType<typeof api.get>)
  })

  it('renders the heading + subtitle + New Campaign button', async () => {
    render(<AttestationCampaignsPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Attestation Campaigns')).toBeInTheDocument()
    expect(
      screen.getByText(/certify user access through periodic review campaigns/i),
    ).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /new campaign/i })).toBeInTheDocument()
  })

  it('lists the campaigns with their type + status badges and progress percentage', async () => {
    render(<AttestationCampaignsPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Q1 Privileged Role Attestation')).toBeInTheDocument()
    expect(screen.getByText('Application access review — Sandbox')).toBeInTheDocument()

    // Status badges
    expect(screen.getByText('active')).toBeInTheDocument()
    expect(screen.getByText('draft')).toBeInTheDocument()

    // Progress: (12 certified + 3 revoked) / 20 = 75% for campaignA
    expect(screen.getByText('75% complete')).toBeInTheDocument()
    // CampaignB has total_items=0 — its progress bar is suppressed
  })

  it('renders without crashing when campaign numeric/string fields are omitted', async () => {
    // Backend may return rows with numeric/string fields absent — must not blow up
    // (e.g. c.total_items feeding pct.toFixed, or c.name/status rendering).
    const sparse = { id: 'cmp-sparse' } as Record<string, unknown>
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url.includes('/attestation-campaigns') && !url.includes('/items') && !url.includes('/progress')) {
        return Promise.resolve({ data: [sparse] }) as ReturnType<typeof api.get>
      }
      return routeGet(url) as ReturnType<typeof api.get>
    })
    render(<AttestationCampaignsPage />, { wrapper: createWrapper() })
    // Heading + section render, no error boundary
    expect(await screen.findByText('Attestation Campaigns')).toBeInTheDocument()
    expect(await screen.findByText('Campaigns (1)')).toBeInTheDocument()
  })

  it('shows the campaign count in the section header', async () => {
    render(<AttestationCampaignsPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Campaigns (2)')).toBeInTheDocument()
  })

  it('toggles the create form when New Campaign is clicked', async () => {
    const user = userEvent.setup()
    render(<AttestationCampaignsPage />, { wrapper: createWrapper() })
    await screen.findByText('Attestation Campaigns')

    // Form not visible initially
    expect(screen.queryByText('New Attestation Campaign')).not.toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: /new campaign/i }))
    expect(await screen.findByText('New Attestation Campaign')).toBeInTheDocument()
    // The toggle button now reads "Cancel"
    expect(screen.getByRole('button', { name: /^cancel$/i })).toBeInTheDocument()

    // Click again — form closes
    await user.click(screen.getByRole('button', { name: /^cancel$/i }))
    expect(screen.queryByText('New Attestation Campaign')).not.toBeInTheDocument()
  })
})
