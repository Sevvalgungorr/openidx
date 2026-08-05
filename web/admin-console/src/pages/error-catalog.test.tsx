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

import { ErrorCatalogPage } from './error-catalog'
import { api } from '../lib/api'

const entries = [
  {
    code: 'AUTH_001',
    description: 'Invalid credentials',
    category: 'auth',
    http_status: 401,
    resolution: 'Check that the supplied username and password are correct.',
  },
  {
    code: 'POL_042',
    description: 'Policy rule conflict',
    category: 'policy',
    http_status: 409,
    resolution: 'Resolve overlapping conditions in the policy rule.',
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

describe('ErrorCatalogPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockResolvedValue({ errors: entries, total: entries.length })
  })

  it('renders the heading + subtitle + search input', async () => {
    render(<ErrorCatalogPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('Error Catalog')).toBeInTheDocument()
    expect(
      screen.getByText(/reference of all error codes, descriptions, and resolution hints/i),
    ).toBeInTheDocument()
    expect(
      screen.getByPlaceholderText(/search by error code or description/i),
    ).toBeInTheDocument()
  })

  it('lists each error entry with its code + status + description', async () => {
    render(<ErrorCatalogPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('AUTH_001')).toBeInTheDocument()
    expect(screen.getByText('POL_042')).toBeInTheDocument()

    expect(screen.getByText('401')).toBeInTheDocument()
    expect(screen.getByText('409')).toBeInTheDocument()

    expect(screen.getByText(/invalid credentials/i)).toBeInTheDocument()
    expect(screen.getByText(/policy rule conflict/i)).toBeInTheDocument()
  })

  it('shows the count line "N of N error codes shown"', async () => {
    render(<ErrorCatalogPage />, { wrapper: createWrapper() })

    expect(
      await screen.findByText(/2 of 2 error codes shown/i),
    ).toBeInTheDocument()
  })

  it('shows the empty state when no codes match', async () => {
    vi.mocked(api.get).mockResolvedValue({ errors: [], total: 0 })

    render(<ErrorCatalogPage />, { wrapper: createWrapper() })

    expect(
      await screen.findByText(/no error codes match your search/i),
    ).toBeInTheDocument()
  })
})
