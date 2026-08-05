import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(() => Promise.resolve([])),
    post: vi.fn(() => Promise.resolve({})),
    put: vi.fn(() => Promise.resolve({})),
    delete: vi.fn(() => Promise.resolve({})),
  },
}))

vi.mock('../hooks/use-toast', () => ({
  useToast: () => ({ toast: vi.fn() }),
}))

import { AgentFleetPage } from './agent-fleet'
import { api } from '../lib/api'

const activeAgent = {
  agent_id: 'agt-001',
  device_id: 'dev-aaa-111',
  hostname: 'CMIT0601L-025',
  status: 'active',
  compliance_status: 'compliant',
  compliance_score: 95,
  last_seen_at: '2026-01-10T00:00:00Z',
  enrolled_at: '2026-01-01T00:00:00Z',
  platform: 'android',
  form_factor: 'phone',
}

const pendingAgent = {
  agent_id: 'agt-002',
  device_id: 'dev-bbb-222',
  status: 'pending',
  compliance_status: 'unknown',
  compliance_score: 0,
  last_seen_at: null,
  enrolled_at: '2026-01-11T00:00:00Z',
  platform: 'android',
  form_factor: 'phone',
}

const nonCompliantAgent = {
  agent_id: 'agt-003',
  device_id: 'dev-ccc-333',
  status: 'active',
  compliance_status: 'non_compliant',
  compliance_score: 35,
  last_seen_at: '2026-01-08T00:00:00Z',
  enrolled_at: '2026-01-02T00:00:00Z',
  platform: 'macos',
  form_factor: 'laptop',
}

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('AgentFleetPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockResolvedValue([activeAgent, pendingAgent, nonCompliantAgent])
  })

  it('renders the page heading and Generate QR button', async () => {
    render(<AgentFleetPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Agent Fleet')).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /generate android enrollment qr/i }),
    ).toBeInTheDocument()
  })

  it('shows the four summary cards (total / active / pending / non-compliant)', async () => {
    render(<AgentFleetPage />, { wrapper: createWrapper() })
    await screen.findByText('Agent Fleet')
    expect(screen.getByText('Total agents')).toBeInTheDocument()
    expect(screen.getByText('Active')).toBeInTheDocument()
    expect(screen.getByText('Pending approval')).toBeInTheDocument()
    expect(screen.getByText('Non-compliant')).toBeInTheDocument()
  })

  it('lists the enrolled agents in the table', async () => {
    render(<AgentFleetPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('agt-001')).toBeInTheDocument()
    expect(screen.getByText('agt-002')).toBeInTheDocument()
    expect(screen.getByText('agt-003')).toBeInTheDocument()
  })

  it('shows the human-readable hostname as the primary label and finds it by search', async () => {
    const user = userEvent.setup()
    render(<AgentFleetPage />, { wrapper: createWrapper() })
    // The device reports its hostname in metadata; the row must surface it
    // (previously only agent_id/device_id showed, so an operator searching for
    // the machine name "CMIT0601L-025" found nothing even though it was enrolled).
    expect(await screen.findByText('CMIT0601L-025')).toBeInTheDocument()

    await user.type(screen.getByPlaceholderText(/search hostname/i), 'CMIT0601')
    expect(screen.getByText('CMIT0601L-025')).toBeInTheDocument()
    // The two agents without that hostname are filtered out.
    expect(screen.queryByText('agt-002')).not.toBeInTheDocument()
    expect(screen.queryByText('agt-003')).not.toBeInTheDocument()
  })

  it('filters by platform via the platform selector', async () => {
    const user = userEvent.setup()
    render(<AgentFleetPage />, { wrapper: createWrapper() })
    await screen.findByText('agt-001')

    // The platform filter is a native <select>, so userEvent.selectOptions
    // is the supported path.
    await user.selectOptions(screen.getByDisplayValue(/all platforms/i), 'macos')
    // After filtering to macOS, the macOS row should remain and the two
    // Android rows should be gone.
    expect(screen.getByText('agt-003')).toBeInTheDocument()
    expect(screen.queryByText('agt-001')).not.toBeInTheDocument()
    expect(screen.queryByText('agt-002')).not.toBeInTheDocument()
  })

  it('renders an empty state when no agents are enrolled', async () => {
    vi.mocked(api.get).mockResolvedValue([])
    render(<AgentFleetPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('Agent Fleet')).toBeInTheDocument()
    expect(screen.queryByText('agt-001')).not.toBeInTheDocument()
  })

  it('opens the posture & tier dialog and shows tier + checks', async () => {
    const user = userEvent.setup()
    // Route the posture endpoint; the agents list uses the default array mock.
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url.includes('/posture')) {
        return Promise.resolve({
          agent_id: 'agt-001',
          compliant: true,
          device_trusted: true,
          tier: 'tier2',
          results: [
            {
              check_type: 'screen_lock',
              status: 'pass',
              score: 100,
              severity: 'high',
              message: 'Device lock enrolled',
              enforced: false,
              enforcement_action: 'none',
              reported_at: '2026-01-10T00:00:00Z',
              expires_at: '2026-01-11T00:00:00Z',
            },
          ],
        }) as ReturnType<typeof api.get>
      }
      return Promise.resolve([activeAgent]) as ReturnType<typeof api.get>
    })
    render(<AgentFleetPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('agt-001')).toBeInTheDocument()
    // Open the row action menu, then the posture item.
    await user.click(screen.getByRole('button', { name: '' }) ?? screen.getAllByRole('button')[0])
    const menuItem = await screen.findByText(/view posture & tier/i)
    await user.click(menuItem)

    expect(await screen.findByText('Device posture & Ziti tier')).toBeInTheDocument()
    expect(await screen.findByText(/Tier 2 · device-trusted/i)).toBeInTheDocument()
    expect(screen.getByText('screen_lock')).toBeInTheDocument()
    expect(screen.getByText('Device lock enrolled')).toBeInTheDocument()
  })
})
