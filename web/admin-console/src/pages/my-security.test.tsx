import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import React from 'react'

vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(() => Promise.resolve({})),
    put: vi.fn(() => Promise.resolve({})),
    delete: vi.fn(() => Promise.resolve({})),
  },
}))

import { MySecurityPage } from './my-security'
import { api } from '../lib/api'

const insights = {
  score: 34,
  level: 'medium',
  friction: 'normal',
  summary: 'Your account is in reasonable shape, but enabling MFA would help.',
  generated_by: 'template',
  mfa_enrolled: false,
  tips: ['Enable multi-factor authentication', 'Review your trusted devices'],
  devices: [
    { name: 'Work Laptop', trusted: true, last_seen: '2026-01-02T09:00:00Z' },
    { name: 'Unknown Phone', trusted: false },
  ],
  recent_logins: [
    { at: '2026-01-02T09:00:00Z', ip_address: '10.0.0.5', location: 'Istanbul', success: true, risk_score: 10 },
    { at: '2026-01-01T22:00:00Z', ip_address: '203.0.113.9', success: false, risk_score: 80 },
  ],
  open_alerts: 1,
  failed_logins_7d: 3,
}

const emptyInsights = {
  score: 0,
  level: 'low',
  friction: 'low',
  summary: 'All clear.',
  generated_by: 'template',
  mfa_enrolled: true,
  tips: [],
  devices: [],
  recent_logins: [],
  open_alerts: 0,
  failed_logins_7d: 0,
}

function makeRouteGet(data: unknown) {
  return (url: string) => {
    if (url.includes('/portal/security-insights')) return Promise.resolve(data)
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

describe('MySecurityPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockImplementation((url: string) => makeRouteGet(insights)(url) as ReturnType<typeof api.get>)
  })

  it('renders the heading, subtitle and Refresh button', async () => {
    render(<MySecurityPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('My Security')).toBeInTheDocument()
    expect(screen.getByText(/how safe is my account/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /refresh/i })).toBeInTheDocument()
  })

  it('shows the risk score, level and summary', async () => {
    render(<MySecurityPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('34')).toBeInTheDocument()
    expect(screen.getByText(/risk score \/ 100/i)).toBeInTheDocument()
    expect(screen.getByText('medium')).toBeInTheDocument()
    expect(screen.getByText(/enabling mfa would help/i)).toBeInTheDocument()
  })

  it('shows a "No MFA yet" badge when the user is not enrolled', async () => {
    render(<MySecurityPage />, { wrapper: createWrapper() })
    expect(await screen.findByText(/no mfa yet/i)).toBeInTheDocument()
  })

  it('renders the recommendation tips', async () => {
    render(<MySecurityPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Enable multi-factor authentication')).toBeInTheDocument()
    expect(screen.getByText('Review your trusted devices')).toBeInTheDocument()
  })

  it('renders my devices with trusted / not-trusted badges', async () => {
    render(<MySecurityPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Work Laptop')).toBeInTheDocument()
    expect(screen.getByText('Unknown Phone')).toBeInTheDocument()
    expect(screen.getByText('trusted')).toBeInTheDocument()
    expect(screen.getByText('not trusted')).toBeInTheDocument()
  })

  it('renders recent sign-ins with ok / failed badges', async () => {
    render(<MySecurityPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Recent Sign-ins')).toBeInTheDocument()
    expect(screen.getByText(/10\.0\.0\.5/)).toBeInTheDocument()
    expect(screen.getByText('ok')).toBeInTheDocument()
    expect(screen.getByText('failed')).toBeInTheDocument()
  })

  it('shows empty-state fallbacks for devices and sign-ins', async () => {
    vi.mocked(api.get).mockImplementation((url: string) => makeRouteGet(emptyInsights)(url) as ReturnType<typeof api.get>)
    render(<MySecurityPage />, { wrapper: createWrapper() })
    expect(await screen.findByText(/no devices registered yet/i)).toBeInTheDocument()
    expect(screen.getByText(/no recent sign-ins/i)).toBeInTheDocument()
    // enrolled -> MFA enrolled badge
    expect(screen.getByText(/mfa enrolled/i)).toBeInTheDocument()
  })
})
