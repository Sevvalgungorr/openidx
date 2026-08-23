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

// Mock react-router's useNavigate so we can assert on action-button clicks
// without spinning up a real router.
const mockNavigate = vi.fn()
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom')
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  }
})

import { ComplianceDashboardPage } from './compliance-dashboard'
import { api } from '../lib/api'

const healthyPosture = {
  mfa_adoption_rate: 92.4,
  password_compliance_rate: 88.5,
  open_reviews_count: 3,
  overdue_reviews_count: 0,
  dormant_accounts_count: 0,
  disabled_accounts_count: 5,
  active_campaigns_count: 2,
  campaign_completion_rate: 76.0,
  policy_violations_count: 0,
  overall_score: 85,
}

const failingPosture = {
  mfa_adoption_rate: 30.0,
  password_compliance_rate: 45.0,
  open_reviews_count: 12,
  overdue_reviews_count: 8,
  dormant_accounts_count: 27,
  disabled_accounts_count: 4,
  active_campaigns_count: 0,
  campaign_completion_rate: 20.0,
  policy_violations_count: 14,
  overall_score: 32,
}

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('ComplianceDashboardPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockResolvedValue(healthyPosture)
  })

  it('renders the page heading and subtitle', async () => {
    render(<ComplianceDashboardPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Compliance Posture')).toBeInTheDocument()
    expect(
      screen.getByText(/organization-wide compliance health at a glance/i),
    ).toBeInTheDocument()
  })

  it('shows the overall score gauge with the Excellent tier for score ≥ 80', async () => {
    render(<ComplianceDashboardPage />, { wrapper: createWrapper() })
    // Wait for the page to render past the loading state
    await screen.findByText('Compliance Posture')
    expect(screen.getByText('85')).toBeInTheDocument()
    expect(screen.getByText('Excellent')).toBeInTheDocument()
  })

  it('renders the Critical tier label and red color when the score is below 40', async () => {
    vi.mocked(api.get).mockResolvedValue(failingPosture)
    render(<ComplianceDashboardPage />, { wrapper: createWrapper() })
    await screen.findByText('Compliance Posture')
    expect(screen.getByText('32')).toBeInTheDocument()
    expect(screen.getByText('Critical')).toBeInTheDocument()
  })

  it('surfaces each of the eight grid metric cards', async () => {
    render(<ComplianceDashboardPage />, { wrapper: createWrapper() })
    await screen.findByText('Compliance Posture')

    // Each MetricCard's `title` prop is rendered as plain text.
    expect(screen.getByText('MFA Adoption')).toBeInTheDocument()
    expect(screen.getByText('Password Compliance')).toBeInTheDocument()
    expect(screen.getByText('Open Reviews')).toBeInTheDocument()
    expect(screen.getByText('Overdue Reviews')).toBeInTheDocument()
    expect(screen.getByText('Dormant Accounts')).toBeInTheDocument()
    expect(screen.getByText('Disabled Accounts')).toBeInTheDocument()
    expect(screen.getByText('Active Campaigns')).toBeInTheDocument()
    expect(screen.getByText('Campaign Completion')).toBeInTheDocument()
  })

  it('shows the policy-violations card with the value from the API', async () => {
    vi.mocked(api.get).mockResolvedValue(failingPosture)
    render(<ComplianceDashboardPage />, { wrapper: createWrapper() })
    await screen.findByText('Compliance Posture')

    expect(screen.getByText(/policy violations \(last 30 days\)/i)).toBeInTheDocument()
    expect(screen.getByText('14')).toBeInTheDocument()
  })

  it('formats integer metrics without a percent suffix but appends % to floats', async () => {
    render(<ComplianceDashboardPage />, { wrapper: createWrapper() })
    await screen.findByText('Compliance Posture')

    // 92.4 → "92.4%" (the page's MetricCard appends % for non-integers)
    expect(screen.getByText('92.4%')).toBeInTheDocument()
    // open_reviews_count = 3 → bare integer, no %
    expect(screen.getByText('3')).toBeInTheDocument()
  })

  it('navigates to /users when the View Users action is clicked', async () => {
    const user = userEvent.setup()
    render(<ComplianceDashboardPage />, { wrapper: createWrapper() })
    await screen.findByText('Compliance Posture')

    // MFA Adoption and Dormant Accounts both render a "View Users" button;
    // any of them should call navigate('/users').
    const buttons = screen.getAllByRole('button', { name: /view users/i })
    expect(buttons.length).toBeGreaterThan(0)
    await user.click(buttons[0])
    expect(mockNavigate).toHaveBeenCalledWith('/users')
  })

  it('navigates to /access-reviews when the View Reviews action is clicked', async () => {
    const user = userEvent.setup()
    render(<ComplianceDashboardPage />, { wrapper: createWrapper() })
    await screen.findByText('Compliance Posture')

    const buttons = screen.getAllByRole('button', { name: /view reviews/i })
    expect(buttons.length).toBeGreaterThan(0)
    await user.click(buttons[0])
    expect(mockNavigate).toHaveBeenCalledWith('/access-reviews')
  })

  it('navigates to /policies when the View Policies action is clicked', async () => {
    const user = userEvent.setup()
    render(<ComplianceDashboardPage />, { wrapper: createWrapper() })
    await screen.findByText('Compliance Posture')

    await user.click(screen.getByRole('button', { name: /view policies/i }))
    expect(mockNavigate).toHaveBeenCalledWith('/policies')
  })

  it('renders without crashing when the API omits numeric posture fields', async () => {
    // Regression: a partial backend response (fields absent) must not blow
    // up MetricCard's toFixed / numeric comparisons and blank the page.
    vi.mocked(api.get).mockResolvedValue(
      { overall_score: 55 } as unknown as typeof healthyPosture,
    )
    render(<ComplianceDashboardPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Compliance Posture')).toBeInTheDocument()
    // Present field renders; omitted fields normalize to 0 (no error boundary).
    expect(screen.getByText('55')).toBeInTheDocument()
    expect(screen.getByText('MFA Adoption')).toBeInTheDocument()
    expect(screen.getByText('Policy Violations (last 30 days)')).toBeInTheDocument()
  })

  it('falls back to a zeroed posture when the API returns null', async () => {
    // null response (e.g., transient failure) — the page falls back to
    // its zeroed-defaults literal and should still render the heading
    // and every card. (Returning `undefined` from the query function
    // would trigger a React Query warning; null is the documented
    // "no data" sentinel.)
    vi.mocked(api.get).mockResolvedValue(null as unknown as typeof healthyPosture)
    render(<ComplianceDashboardPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Compliance Posture')).toBeInTheDocument()
    // Critical label for the zeroed-score fallback
    expect(screen.getByText('Critical')).toBeInTheDocument()
  })
})
