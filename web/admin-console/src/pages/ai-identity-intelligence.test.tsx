import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import React from 'react'

vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(() => Promise.resolve({ answer: 'Focus on alice: no MFA and 2 overlay anomalies.' })),
    put: vi.fn(() => Promise.resolve({})),
    delete: vi.fn(() => Promise.resolve({})),
  },
}))

vi.mock('../hooks/use-toast', () => ({
  useToast: () => ({ toast: vi.fn() }),
}))

import { AIIdentityIntelligencePage } from './ai-identity-intelligence'
import { api } from '../lib/api'

const overviewAIOff = {
  total_users: 20,
  risk_levels: { high: 2, medium: 3 },
  identities_at_risk: 5,
  mfa_enrolled: 12,
  mfa_coverage_pct: 60,
  open_alerts: 4,
  logins_24h: 130,
  failed_logins_24h: 7,
  ziti_open_anomalies: 2,
  top_risks: [
    {
      user_id: 'u-alice',
      username: 'alice',
      email: 'alice@corp.test',
      score: 88,
      level: 'critical',
      reasons: ['no MFA', '2 overlay anomalies'],
      mfa_enrolled: false,
      open_alerts: 2,
      ziti_anomalies: 2,
      friction: 'strict',
    },
  ],
  ai: { enabled: false, reachable: false },
}

const overviewAIOn = {
  ...overviewAIOff,
  ai: { enabled: true, reachable: true, base_url: 'http://localhost:11434/v1', model: 'llama3.2' },
}

const briefing = {
  briefing: 'Overall risk is elevated: 5 of 20 identities need attention.',
  generated_by: 'llama3.2',
  generated_at: '2026-01-02T09:00:00Z',
}

function makeRouteGet(overview: unknown) {
  return (url: string) => {
    if (url.includes('/ai/intelligence/overview')) return Promise.resolve(overview)
    if (url.includes('/ai/intelligence/briefing')) return Promise.resolve(briefing)
    return Promise.resolve({})
  }
}

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('AIIdentityIntelligencePage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockImplementation((url: string) => makeRouteGet(overviewAIOff)(url) as ReturnType<typeof api.get>)
  })

  it('renders the heading, subtitle and Refresh button', async () => {
    render(<AIIdentityIntelligencePage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Identity Intelligence')).toBeInTheDocument()
    expect(screen.getByText(/cross-pillar identity risk fusion/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /refresh/i })).toBeInTheDocument()
  })

  it('shows the four summary cards with fused fixture values', async () => {
    render(<AIIdentityIntelligencePage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Identities at Risk')).toBeInTheDocument()
    expect(screen.getByText('Open Security Alerts')).toBeInTheDocument()
    expect(screen.getByText('MFA Coverage')).toBeInTheDocument()
    expect(screen.getByText('Local AI')).toBeInTheDocument()
    // identities_at_risk=5 / total=20, open_alerts=4, mfa_coverage=60%
    expect(screen.getByText('5')).toBeInTheDocument()
    expect(screen.getByText(/\/ 20/)).toBeInTheDocument()
    expect(screen.getByText('4')).toBeInTheDocument()
    expect(screen.getByText('60%')).toBeInTheDocument()
  })

  it('shows Local AI as Off and disables the copilot input when AI is disabled', async () => {
    render(<AIIdentityIntelligencePage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Off')).toBeInTheDocument()
    expect(screen.getByText(/set ai_enabled=true/i)).toBeInTheDocument()
    const input = screen.getByPlaceholderText(/which identities need attention first/i)
    expect(input).toBeDisabled()
  })

  it('renders the highest-risk identities table', async () => {
    render(<AIIdentityIntelligencePage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Highest-Risk Identities')).toBeInTheDocument()
    expect(screen.getByText('alice')).toBeInTheDocument()
    expect(screen.getByText('alice@corp.test')).toBeInTheDocument()
    expect(screen.getByText('88')).toBeInTheDocument()
    expect(screen.getByText('critical')).toBeInTheDocument()
    expect(screen.getByText(/no mfa; 2 overlay anomalies/i)).toBeInTheDocument()
  })

  it('generates a briefing when the button is clicked', async () => {
    render(<AIIdentityIntelligencePage />, { wrapper: createWrapper() })
    const btn = await screen.findByRole('button', { name: /generate briefing/i })
    fireEvent.click(btn)
    expect(
      await screen.findByText(/overall risk is elevated: 5 of 20 identities need attention/i),
    ).toBeInTheDocument()
    expect(api.get).toHaveBeenCalledWith('/api/v1/ai/intelligence/briefing')
  })

  it('enables the copilot and asks a question when AI is online', async () => {
    vi.mocked(api.get).mockImplementation((url: string) => makeRouteGet(overviewAIOn)(url) as ReturnType<typeof api.get>)
    render(<AIIdentityIntelligencePage />, { wrapper: createWrapper() })
    // AI online -> model badge + Online status
    expect(await screen.findByText('Online')).toBeInTheDocument()
    expect(screen.getAllByText('llama3.2').length).toBeGreaterThan(0)

    const input = screen.getByPlaceholderText(/which identities need attention first/i)
    expect(input).not.toBeDisabled()
    fireEvent.change(input, { target: { value: 'Who needs attention?' } })
    fireEvent.click(screen.getByRole('button', { name: /^ask$/i }))
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/api/v1/ai/intelligence/ask', {
        question: 'Who needs attention?',
      }),
    )
    expect(await screen.findByText(/focus on alice/i)).toBeInTheDocument()
  })

  it('shows the empty state when there are no risky identities', async () => {
    vi.mocked(api.get).mockImplementation((url: string) =>
      makeRouteGet({ ...overviewAIOff, top_risks: [] })(url) as ReturnType<typeof api.get>,
    )
    render(<AIIdentityIntelligencePage />, { wrapper: createWrapper() })
    expect(await screen.findByText(/no identities found/i)).toBeInTheDocument()
  })
})
