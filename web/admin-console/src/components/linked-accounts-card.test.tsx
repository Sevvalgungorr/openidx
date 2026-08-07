import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(() => Promise.resolve({})),
    delete: vi.fn(() => Promise.resolve({})),
  },
}))

import { LinkedAccountsCard } from './linked-accounts-card'
import { api } from '../lib/api'

function renderCard() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <LinkedAccountsCard />
    </QueryClientProvider>,
  )
}

// Route the two reads this card performs. Returning by URL keeps the tests
// honest about which endpoint supplies which piece of the screen.
function mockReads(links: unknown[], providers: unknown[]) {
  ;(api.get as ReturnType<typeof vi.fn>).mockImplementation((url: string) => {
    if (url.includes('identity-links')) return Promise.resolve({ data: links })
    if (url.includes('/providers')) return Promise.resolve(providers)
    return Promise.resolve({})
  })
}

describe('LinkedAccountsCard', () => {
  beforeEach(() => vi.clearAllMocks())

  it('tells a user with no connected accounts what they can do', async () => {
    mockReads([], [])
    renderCard()
    expect(await screen.findByText(/you sign in with your work account only/i)).toBeInTheDocument()
  })

  it('lists a connected account with a way to remove it', async () => {
    mockReads(
      [
        {
          id: 'link-1',
          provider_id: 'p-1',
          provider_name: 'Google',
          external_email: 'ayse@example.com',
          display_name: 'Ayse',
          linked_at: '2026-01-01T00:00:00Z',
          last_used_at: '2026-02-01T00:00:00Z',
        },
      ],
      [],
    )
    renderCard()

    expect(await screen.findByText('Google')).toBeInTheDocument()
    expect(screen.getByText(/ayse@example.com/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /remove/i })).toBeInTheDocument()
  })

  it('offers only providers that are not already connected', async () => {
    mockReads(
      [
        {
          id: 'link-1',
          provider_id: 'p-1',
          provider_name: 'Google',
          external_email: 'ayse@example.com',
          display_name: null,
          linked_at: '2026-01-01T00:00:00Z',
          last_used_at: null,
        },
      ],
      [
        { id: 'p-1', name: 'Google' },
        { id: 'p-2', name: 'Microsoft' },
      ],
    )
    renderCard()

    expect(await screen.findByRole('button', { name: /connect microsoft/i })).toBeInTheDocument()
    // Offering to connect an account that is already connected would be a dead end.
    expect(screen.queryByRole('button', { name: /connect google/i })).not.toBeInTheDocument()
  })

  it('starts linking through the authenticated start endpoint', async () => {
    mockReads([], [{ id: 'p-2', name: 'Microsoft' }])
    ;(api.post as ReturnType<typeof vi.fn>).mockResolvedValue({
      authorization_url: 'https://idp.example.com/authorize?state=abc',
    })

    // window.location is not assignable under jsdom; capture the navigation.
    const original = window.location
    // @ts-expect-error jsdom location replacement
    delete window.location
    // @ts-expect-error minimal stub
    window.location = { href: '' }

    renderCard()
    await userEvent.click(await screen.findByRole('button', { name: /connect microsoft/i }))

    await waitFor(() => {
      expect(api.post).toHaveBeenCalledWith('/oauth/social/link/p-2/start', {})
    })
    expect(window.location.href).toBe('https://idp.example.com/authorize?state=abc')

    // @ts-expect-error restore
    window.location = original
  })

  it('keeps connected accounts visible when the provider list cannot be read', async () => {
    ;(api.get as ReturnType<typeof vi.fn>).mockImplementation((url: string) => {
      if (url.includes('identity-links')) {
        return Promise.resolve({
          data: [
            {
              id: 'link-1',
              provider_id: 'p-1',
              provider_name: 'Google',
              external_email: 'ayse@example.com',
              display_name: null,
              linked_at: '2026-01-01T00:00:00Z',
              last_used_at: null,
            },
          ],
        })
      }
      return Promise.reject(new Error('providers unavailable'))
    })

    renderCard()
    expect(await screen.findByText('Google')).toBeInTheDocument()
  })
})
