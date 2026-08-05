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

import { DeveloperSettingsPage } from './developer-settings'
import { api } from '../lib/api'

const settings = {
  api_key_max_per_user: 5,
  api_key_default_expiry: '365d',
  api_key_allowed_scopes: ['read:users', 'read:audit'],
  webhook_ip_allowlist: ['203.0.113.0/24'],
  webhook_max_retries: 3,
  cors_allowed_origins: ['https://admin.example.com'],
  rate_limit_default: 100,
  sandbox_enabled: false,
}

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('DeveloperSettingsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockResolvedValue(settings)
  })

  it('renders the heading + subtitle + Save Changes button once settings load', async () => {
    render(<DeveloperSettingsPage />, { wrapper: createWrapper() })
    // The post-load layout has the subtitle; the loading branch doesn't.
    expect(
      await screen.findByText(/configure api keys, webhooks, cors, and rate limits/i),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /save changes/i }),
    ).toBeInTheDocument()
  })

  it('shows the four sidebar tabs (API Keys / Webhooks / CORS / Rate Limits)', async () => {
    render(<DeveloperSettingsPage />, { wrapper: createWrapper() })
    await screen.findByText(/configure api keys, webhooks, cors, and rate limits/i)
    expect(screen.getByRole('button', { name: /^api keys$/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^webhooks$/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^cors$/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^rate limits$/i })).toBeInTheDocument()
  })

  it('opens the API Keys tab by default and shows the API Key Defaults card', async () => {
    render(<DeveloperSettingsPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('API Key Defaults')).toBeInTheDocument()
    expect(
      screen.getByText(/configure defaults for developer api key creation/i),
    ).toBeInTheDocument()
    // max_keys_per_user value is bound to an Input — assert via display value.
    expect(screen.getByDisplayValue('5')).toBeInTheDocument()
  })

  it('switches to the Webhooks tab when its sidebar button is clicked', async () => {
    const user = userEvent.setup()
    render(<DeveloperSettingsPage />, { wrapper: createWrapper() })
    await screen.findByText('API Key Defaults')

    await user.click(screen.getByRole('button', { name: /^webhooks$/i }))
    // Distinct copy unique to the Webhooks tab — the IP allowlist value
    // is bound to an Input.
    expect(await screen.findByDisplayValue('203.0.113.0/24')).toBeInTheDocument()
  })

  it('renders the loading branch before the settings query resolves', async () => {
    vi.mocked(api.get).mockReturnValue(new Promise(() => undefined) as ReturnType<typeof api.get>)
    render(<DeveloperSettingsPage />, { wrapper: createWrapper() })
    expect(
      await screen.findByText(/loading developer settings/i),
    ).toBeInTheDocument()
  })
})
