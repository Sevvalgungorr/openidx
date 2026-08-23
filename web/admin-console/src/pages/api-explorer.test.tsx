import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(),
    getWithHeaders: vi.fn(),
    post: vi.fn(() => Promise.resolve({})),
    put: vi.fn(() => Promise.resolve({})),
    delete: vi.fn(() => Promise.resolve({})),
  },
}))

vi.mock('../hooks/use-toast', () => ({
  useToast: () => ({ toast: vi.fn() }),
}))

import { ApiExplorerPage } from './api-explorer'
import { api } from '../lib/api'

const endpoints = [
  {
    id: 'ep-users-list',
    service: 'identity',
    method: 'GET' as const,
    path: '/api/v1/identity/users',
    description: 'List users with optional filters',
    scopes: ['identity:read'],
    path_params: [],
    query_params: [],
    has_body: false,
  },
  {
    id: 'ep-oauth-token',
    service: 'oauth',
    method: 'POST' as const,
    path: '/oauth/token',
    description: 'Exchange a grant for an access token',
    scopes: [],
    path_params: [],
    query_params: [],
    has_body: true,
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

describe('ApiExplorerPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockResolvedValue({
      endpoints: {
        identity: endpoints.filter((e) => e.service === 'identity'),
        oauth: endpoints.filter((e) => e.service === 'oauth'),
      },
    })
  })

  it('renders the heading once endpoints have loaded', async () => {
    render(<ApiExplorerPage />, { wrapper: createWrapper() })
    // Wait for the post-loading subtitle copy (anchored on a long
    // substring resilient to formatting changes).
    expect(
      await screen.findByText(/browse, test, and generate code/i),
    ).toBeInTheDocument()
    // Heading also renders (both in the loading branch and after).
    expect(screen.getAllByText('API Explorer').length).toBeGreaterThan(0)
  })

  it('shows a search input for filtering endpoints once loaded', async () => {
    render(<ApiExplorerPage />, { wrapper: createWrapper() })
    expect(
      await screen.findByPlaceholderText(/search endpoints/i),
    ).toBeInTheDocument()
  })

  it('renders the initial loading state before endpoints arrive', async () => {
    // Make the query stay pending so we land on the isLoading branch.
    vi.mocked(api.get).mockReturnValue(new Promise(() => undefined) as ReturnType<typeof api.get>)
    render(<ApiExplorerPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('API Explorer')).toBeInTheDocument()
    expect(screen.getByText(/loading api endpoints/i)).toBeInTheDocument()
  })

  it('opens an endpoint whose array fields are missing without crashing', async () => {
    // Regression: the catalog can return an endpoint with null/absent
    // scopes/path_params/query_params (a Go nil slice serializes to null). The
    // detail pane reads their .length unconditionally, which crashed the page
    // with "Cannot read properties of undefined (reading 'length')". The
    // queryFn now defaults these to [], so selecting such an endpoint renders.
    const malformed = {
      id: 'ep-broken',
      service: 'identity',
      method: 'GET' as const,
      path: '/api/v1/identity/broken',
      description: 'Endpoint with no array fields set',
      has_body: false,
      // scopes / path_params / query_params intentionally omitted
    }
    vi.mocked(api.get).mockResolvedValue({
      endpoints: { identity: [malformed] },
    })
    const user = userEvent.setup()
    render(<ApiExplorerPage />, { wrapper: createWrapper() })
    await screen.findByText(/browse, test, and generate code/i)
    // Service groups start expanded, so the endpoint is already listed — select it.
    await user.click(await screen.findByText('/api/v1/identity/broken'))
    // Detail pane renders (its unique "Try It" section) rather than the error
    // boundary — proves the undefined .length no longer throws.
    expect(await screen.findByText('Try It')).toBeInTheDocument()
  })

  it('groups endpoints under the SERVICE_GROUPS sidebar', async () => {
    render(<ApiExplorerPage />, { wrapper: createWrapper() })
    await screen.findByText(/browse, test, and generate code/i)
    // SERVICE_GROUPS labels render in the sidebar — exactly "Identity"
    // and "OAuth" are two of the labels (see the const list at the top
    // of api-explorer.tsx).
    expect(screen.getByText('Identity')).toBeInTheDocument()
    expect(screen.getByText('OAuth')).toBeInTheDocument()
  })
})
