import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AxiosError, AxiosHeaders } from 'axios'

vi.mock('../lib/api', () => ({
  api: {
    windowsApps: {
      listMine: vi.fn(),
      launch: vi.fn(),
      iconURL: (id: string) => `/icon/${id}`,
    },
  },
}))
vi.mock('../hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }))

import { MyWindowsAppsPage } from './my-windows-apps'
import { api } from '../lib/api'

const wa = api.windowsApps as unknown as Record<string, ReturnType<typeof vi.fn>>

const app = {
  id: 'a1', display_name: 'SQL Server Management Studio', alias: 'SSMS',
  host_name: 'RDS01', has_icon: false, require_approval: false,
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter><MyWindowsAppsPage /></MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('MyWindowsAppsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    wa.listMine.mockResolvedValue({ apps: [app] })
    wa.launch.mockResolvedValue({ launch_type: 'guacamole', connect_url: 'https://guac/x', app_id: 'a1', host_entry_id: 'h1', host_name: 'RDS01', recorded: true })
    window.open = vi.fn()
  })

  it('renders launchable app tiles', async () => {
    renderPage()
    expect(await screen.findByText('SQL Server Management Studio')).toBeInTheDocument()
    expect(screen.getByText('RDS01')).toBeInTheDocument()
  })

  it('shows the empty state when no apps are published to the user', async () => {
    wa.listMine.mockResolvedValue({ apps: [] })
    renderPage()
    expect(await screen.findByText(/no apps available/i)).toBeInTheDocument()
  })

  it('launches an app and opens the connect URL', async () => {
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: /launch/i }))
    await waitFor(() => expect(wa.launch).toHaveBeenCalledWith('a1', undefined))
    await waitFor(() => expect(window.open).toHaveBeenCalledWith('https://guac/x', '_blank', 'noopener'))
  })

  it('opens the conflict dialog on a 409 and retries with the chosen session', async () => {
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
    expect(await screen.findByText(/you have an active session/i)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /disconnect & launch here/i }))
    await waitFor(() => expect(wa.launch).toHaveBeenCalledWith('a1', 's1'))
  })
})
