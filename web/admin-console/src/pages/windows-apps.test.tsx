import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AxiosError, AxiosHeaders } from 'axios'

vi.mock('../lib/api', () => ({
  api: {
    windowsApps: {
      list: vi.fn(),
      create: vi.fn(),
      update: vi.fn(),
      remove: vi.fn(),
      launch: vi.fn(),
      importDiscovery: vi.fn(),
      iconURL: (id: string) => `/icon/${id}`,
    },
    pam: { listEntries: vi.fn() },
  },
}))
vi.mock('../hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }))

import { WindowsAppsPage } from './windows-apps'
import { api } from '../lib/api'

const wa = api.windowsApps as unknown as Record<string, ReturnType<typeof vi.fn>>
const pam = api.pam as unknown as Record<string, ReturnType<typeof vi.fn>>

const app = {
  id: 'a1', host_entry_id: 'h1', host_name: 'RDS01', alias: 'SSMS',
  display_name: 'SQL Server Management Studio', has_icon: false,
  source: 'discovered' as const, verified: true, status: 'active' as const,
  require_approval: false, record_session: true,
  created_at: '2026-08-01T00:00:00Z', updated_at: '2026-08-01T00:00:00Z',
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter><WindowsAppsPage /></MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('WindowsAppsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    wa.list.mockResolvedValue({ apps: [app], pools: [], host_state: [] })
    pam.listEntries.mockResolvedValue({ entries: [] })
    wa.launch.mockResolvedValue({ launch_type: 'guacamole', connect_url: 'https://guac/x', app_id: 'a1', host_entry_id: 'h1', host_name: 'RDS01', recorded: true })
    window.open = vi.fn()
  })

  it('renders published apps with a verified badge', async () => {
    renderPage()
    expect(await screen.findByText('SQL Server Management Studio')).toBeInTheDocument()
    expect(screen.getByText('published')).toBeInTheDocument()
  })

  it('shows the empty state when there are no apps', async () => {
    wa.list.mockResolvedValue({ apps: [], pools: [], host_state: [] })
    renderPage()
    expect(await screen.findByText(/no published apps yet/i)).toBeInTheDocument()
  })

  it('prominently warns about hosts allowing unlisted programs', async () => {
    wa.list.mockResolvedValue({
      apps: [app],
      pools: [],
      host_state: [{ host_entry_id: 'h1', allow_unlisted_remote_programs: true }],
    })
    renderPage()
    expect(await screen.findByText(/allow unlisted programs/i)).toBeInTheDocument()
  })

  it('launches an app and opens the connect URL', async () => {
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: /launch/i }))
    await waitFor(() => expect(wa.launch).toHaveBeenCalledWith('a1', undefined))
    await waitFor(() => expect(window.open).toHaveBeenCalledWith('https://guac/x', '_blank', 'noopener'))
  })

  it('opens the conflict dialog on a 409 instead of erroring', async () => {
    const err = new AxiosError('conflict', 'ERR_BAD_REQUEST', undefined, undefined, {
      status: 409, statusText: 'Conflict', headers: {}, config: { headers: new AxiosHeaders() },
      data: {
        reason: 'user_session_conflict',
        message: 'You already have a session on RDS01.',
        conflicts: [{ host_entry_id: 'h1', host_name: 'RDS01', session_id: 's1', app_name: 'Notepad', started_at: '2026-08-01T00:00:00Z' }],
      },
    })
    wa.launch.mockRejectedValueOnce(err)
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: /launch/i }))
    // The conflict resolution dialog appears with an explicit disconnect action.
    expect(await screen.findByText(/you have an active session/i)).toBeInTheDocument()
    expect(screen.getByText(/you already have a session on rds01/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /disconnect & launch here/i })).toBeInTheDocument()
    // Choosing the session retries the launch with the replace id.
    fireEvent.click(screen.getByRole('button', { name: /disconnect & launch here/i }))
    await waitFor(() => expect(wa.launch).toHaveBeenCalledWith('a1', 's1'))
  })
})
