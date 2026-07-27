import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import React from 'react'

vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(() => Promise.resolve({ observations: 12, new_anomalies: 1, baseline_identities: 3 })),
    put: vi.fn(() => Promise.resolve({})),
    delete: vi.fn(() => Promise.resolve({})),
  },
}))

vi.mock('../hooks/use-toast', () => ({
  useToast: () => ({ toast: vi.fn() }),
}))

import { ZitiAIInsightsPage } from './ziti-ai-insights'
import { api } from '../lib/api'

const insights = {
  identities_total: 8,
  identities_at_risk: 3,
  risk_levels: { high: 1, medium: 2 },
  open_anomalies: 2,
  recommendation_count: 4,
  controller_features: {
    version: '1.1.15',
    semver_major: 1,
    ha_controllers: true,
    oidc_auth: true,
    jwt_session_auth: true,
    granular_permissions: false,
    advisories: ['Upgrade to OpenZiti v2.0 to unlock granular permissions'],
  },
  top_risks: [
    {
      identity_id: 'zid-alice',
      identity_name: 'Alice',
      score: 82,
      level: 'high',
      signals: ['2 open anomalies', 'posture failing'],
      open_anomalies: 2,
      posture_failures: 1,
      quarantined: false,
    },
    {
      identity_id: 'zid-bob',
      identity_name: 'Bob',
      score: 40,
      level: 'medium',
      signals: ['dormant 45 days'],
      open_anomalies: 0,
      posture_failures: 0,
      quarantined: true,
    },
  ],
}

const anomalies = [
  {
    id: 'anom-1',
    identity_id: 'zid-alice',
    identity_name: 'Alice',
    anomaly_type: 'new_service_access',
    severity: 'high',
    score: 0.9,
    details: { service: 'svc-db' },
    status: 'open',
    detected_at: '2026-01-02T09:00:00Z',
  },
]

const recommendations = [
  {
    type: 'over_permissive_policy',
    severity: 'medium',
    title: 'Tighten over-permissive Dial policy',
    description: 'Policy openidx-dial-all grants every identity access to every service',
    target_name: 'openidx-dial-all',
    action: 'Scope the policy to the roles that actually need it',
  },
]

function routeGet(url: string) {
  if (url.includes('/ziti/ai/insights')) return Promise.resolve(insights)
  if (url.includes('/ziti/ai/anomalies')) return Promise.resolve(anomalies)
  if (url.includes('/ziti/ai/recommendations')) return Promise.resolve(recommendations)
  return Promise.resolve([])
}

function routeGetEmpty(url: string) {
  if (url.includes('/ziti/ai/insights')) {
    return Promise.resolve({
      identities_total: 0,
      identities_at_risk: 0,
      risk_levels: {},
      open_anomalies: 0,
      recommendation_count: 0,
      controller_features: null,
      top_risks: [],
    })
  }
  if (url.includes('/ziti/ai/anomalies')) return Promise.resolve([])
  if (url.includes('/ziti/ai/recommendations')) return Promise.resolve([])
  return Promise.resolve([])
}

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('ZitiAIInsightsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockImplementation((url: string) => routeGet(url) as ReturnType<typeof api.get>)
  })

  it('renders the heading, subtitle and Run Analysis button', async () => {
    render(<ZitiAIInsightsPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Ziti AI Insights')).toBeInTheDocument()
    expect(
      screen.getByText(/behavioral anomaly detection, identity risk scoring/i),
    ).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /run analysis/i })).toBeInTheDocument()
  })

  it('shows the four summary cards with fixture values and controller capability badges', async () => {
    render(<ZitiAIInsightsPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Identities at Risk')).toBeInTheDocument()
    // "Open Anomalies" appears twice (summary card + table title) — assert presence.
    expect(screen.getAllByText('Open Anomalies').length).toBeGreaterThan(0)
    expect(screen.getByText('Recommendations')).toBeInTheDocument()

    // identities at risk = 3, total = 8
    expect(screen.getByText('3')).toBeInTheDocument()
    expect(screen.getByText(/\/ 8/)).toBeInTheDocument()
    // controller version + capability badges
    expect(screen.getByText('1.1.15')).toBeInTheDocument()
    expect(screen.getByText('HA')).toBeInTheDocument()
    expect(screen.getByText('OIDC')).toBeInTheDocument()
    expect(screen.getByText('JWT Auth')).toBeInTheDocument()
    // granular_permissions=false -> badge should not render
    expect(screen.queryByText('Granular Perms')).not.toBeInTheDocument()
  })

  it('renders the upgrade advisory when the controller reports one', async () => {
    render(<ZitiAIInsightsPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('OpenZiti Upgrade Advisories')).toBeInTheDocument()
    expect(
      screen.getByText(/upgrade to openziti v2\.0 to unlock granular permissions/i),
    ).toBeInTheDocument()
  })

  it('renders the open anomalies table with the loaded anomaly', async () => {
    render(<ZitiAIInsightsPage />, { wrapper: createWrapper() })
    // "Open Anomalies" is both a summary card and the table title.
    expect((await screen.findAllByText('Open Anomalies')).length).toBeGreaterThan(0)
    // human-readable label for the anomaly_type
    expect(await screen.findByText('New Service Access')).toBeInTheDocument()
    // identity name appears in both the anomaly and risk tables
    expect(screen.getAllByText('Alice').length).toBeGreaterThan(0)
    expect(screen.getByRole('button', { name: /acknowledge/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /resolve/i })).toBeInTheDocument()
  })

  it('renders the identity risk table with quarantine and restore controls', async () => {
    render(<ZitiAIInsightsPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Identity Risk')).toBeInTheDocument()
    // Alice not quarantined -> Quarantine button; Bob quarantined -> Restore Access
    expect(await screen.findByRole('button', { name: /^quarantine$/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /restore access/i })).toBeInTheDocument()
    // scores render
    expect(screen.getByText('82')).toBeInTheDocument()
    expect(screen.getByText('40')).toBeInTheDocument()
    // Bob appears in the risk table
    expect(screen.getByText('Bob')).toBeInTheDocument()
  })

  it('renders the policy-hygiene recommendations', async () => {
    render(<ZitiAIInsightsPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Policy Hygiene Recommendations')).toBeInTheDocument()
    expect(screen.getByText('Tighten over-permissive Dial policy')).toBeInTheDocument()
    expect(screen.getByText('openidx-dial-all')).toBeInTheDocument()
    expect(
      screen.getByText(/scope the policy to the roles that actually need it/i),
    ).toBeInTheDocument()
  })

  it('calls the analyze endpoint when Run Analysis is clicked', async () => {
    render(<ZitiAIInsightsPage />, { wrapper: createWrapper() })
    const btn = await screen.findByRole('button', { name: /run analysis/i })
    fireEvent.click(btn)
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/api/v1/access/ziti/ai/analyze', {}),
    )
  })

  it('quarantines an identity when the Quarantine button is clicked', async () => {
    render(<ZitiAIInsightsPage />, { wrapper: createWrapper() })
    const btn = await screen.findByRole('button', { name: /^quarantine$/i })
    fireEvent.click(btn)
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith(
        '/api/v1/access/ziti/ai/identities/zid-alice/quarantine',
        expect.objectContaining({ reason: expect.any(String) }),
      ),
    )
  })

  it('shows empty-state fallbacks when there is no data', async () => {
    vi.mocked(api.get).mockImplementation((url: string) => routeGetEmpty(url) as ReturnType<typeof api.get>)
    render(<ZitiAIInsightsPage />, { wrapper: createWrapper() })
    expect(
      await screen.findByText(/no open anomalies/i),
    ).toBeInTheDocument()
    expect(screen.getByText(/no identities found/i)).toBeInTheDocument()
    expect(screen.getByText(/the fabric looks healthy/i)).toBeInTheDocument()
  })
})
