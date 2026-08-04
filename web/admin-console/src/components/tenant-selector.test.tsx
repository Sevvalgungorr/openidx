import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { TenantSelector } from './tenant-selector'

const mockSetOrg = vi.fn()
let mockSelectedOrgSlug: string | null = null

vi.mock('@/lib/store', () => ({
  useOrgStore: () => ({
    selectedOrgSlug: mockSelectedOrgSlug,
    setOrg: mockSetOrg,
  }),
}))

vi.mock('@/lib/api', () => ({
  api: {
    // GET /api/v1/organizations returns a plain array (verified against the
    // live API); the component reads it directly as Organization[].
    get: vi.fn().mockResolvedValue([
      { id: '1', name: 'Acme Corp', slug: 'acme' },
      { id: '2', name: 'Globex', slug: 'globex' },
    ]),
  },
}))

function renderSelector() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <TenantSelector />
    </QueryClientProvider>
  )
}

describe('TenantSelector', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockSelectedOrgSlug = null
  })

  it('renders the org select with own-org default', () => {
    renderSelector()
    const trigger = screen.getByLabelText('Select organization')
    expect(trigger).toBeInTheDocument()
    expect(trigger).toHaveTextContent('Your organization')
  })

  it('shows the selected org slug when one is chosen', async () => {
    mockSelectedOrgSlug = 'acme'
    renderSelector()
    const trigger = screen.getByLabelText('Select organization')
    // Until options load, Radix shows the raw value's item text once available;
    // the trigger itself must render without crashing with a stored slug.
    expect(trigger).toBeInTheDocument()
    expect(await screen.findByText('Acme Corp')).toBeInTheDocument()
  })
})
