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

import { SAMLServiceProvidersPage } from './saml-service-providers'
import { api } from '../lib/api'

const slackSP = {
  id: 'sp-1',
  name: 'Slack',
  entity_id: 'https://example.slack.com',
  acs_url: 'https://example.slack.com/sso/saml',
  name_id_format: 'emailAddress',
  enabled: true,
  created_at: '2026-01-01T00:00:00Z',
}

const salesforceSP = {
  id: 'sp-2',
  name: 'Salesforce',
  entity_id: 'https://saml.salesforce.com',
  acs_url: 'https://login.salesforce.com',
  name_id_format: 'persistent',
  enabled: false,
  created_at: '2026-02-01T00:00:00Z',
}

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('SAMLServiceProvidersPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockResolvedValue({
      service_providers: [slackSP, salesforceSP],
    })
  })

  it('renders the heading + subtitle + Add SP / Download metadata buttons', async () => {
    render(<SAMLServiceProvidersPage />, { wrapper: createWrapper() })

    expect(
      await screen.findByText('SAML Service Providers'),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/manage saml 2.0 service provider registrations for sso/i),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /add service provider/i }),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /download idp metadata/i }),
    ).toBeInTheDocument()
  })

  it('lists service-provider rows with their name + entity ID + ACS URL', async () => {
    render(<SAMLServiceProvidersPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('Slack')).toBeInTheDocument()
    expect(screen.getByText('Salesforce')).toBeInTheDocument()
    expect(screen.getByText('https://example.slack.com')).toBeInTheDocument()
    expect(screen.getByText('https://example.slack.com/sso/saml')).toBeInTheDocument()
  })

  it('shows the search input', async () => {
    render(<SAMLServiceProvidersPage />, { wrapper: createWrapper() })
    await screen.findByText('Slack')

    expect(
      screen.getByPlaceholderText(/search by name, entity id, or acs url/i),
    ).toBeInTheDocument()
  })

  it('renders the registered count "Registered Service Providers (2)"', async () => {
    render(<SAMLServiceProvidersPage />, { wrapper: createWrapper() })

    expect(
      await screen.findByText(/registered service providers \(2\)/i),
    ).toBeInTheDocument()
  })

  // Regression: the page rendered the empty state while the API was returning
  // rows, because the handler emitted them under "providers" and this page
  // reads "service_providers". Every test above mocks the shape this page
  // expects, so none of them could catch a backend that sent another shape --
  // a test that asserts its own assumption. This one uses the response the Go
  // handler actually marshals (see saml_sp_contract_test.go, which pins the
  // same two keys from the other side).
  it('renders rows from the real backend response body', async () => {
    vi.mocked(api.get).mockResolvedValue({
      service_providers: [slackSP, salesforceSP],
      providers: [slackSP, salesforceSP],
      total: 2,
      page: 1,
      page_size: 20,
    })

    render(<SAMLServiceProvidersPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('Slack')).toBeInTheDocument()
    expect(await screen.findByText('Salesforce')).toBeInTheDocument()
    expect(
      screen.queryByText(/no saml service providers found/i),
    ).not.toBeInTheDocument()
  })

  // The pre-fix backend body, verbatim: rows present, but only under the
  // legacy key. The page must not silently show "no providers" for it.
  it('does not fall back to the empty state when only the legacy key is sent', async () => {
    vi.mocked(api.get).mockResolvedValue({
      providers: [slackSP, salesforceSP],
      total: 2,
    })

    render(<SAMLServiceProvidersPage />, { wrapper: createWrapper() })

    // Documents the failure mode that was shipped: with only "providers",
    // this page shows the empty state. The backend therefore has to send
    // "service_providers", which the Go contract test enforces.
    expect(
      await screen.findByText(/no saml service providers found/i),
    ).toBeInTheDocument()
  })

  it('shows the empty state when no providers are registered', async () => {
    vi.mocked(api.get).mockResolvedValue({ service_providers: [] })

    render(<SAMLServiceProvidersPage />, { wrapper: createWrapper() })

    expect(
      await screen.findByText(/no saml service providers found/i),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/register a service provider to enable saml sso/i),
    ).toBeInTheDocument()
  })
})
