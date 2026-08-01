import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

vi.mock('../lib/api', () => ({
  api: {
    pam: {
      listEntryTypes: vi.fn(),
      listFolders: vi.fn(),
      listEntries: vi.fn(),
      connect: vi.fn(),
      favorite: vi.fn(),
      unfavorite: vi.fn(),
      reveal: vi.fn(),
      requestAccess: vi.fn(),
      importRDM: vi.fn(),
      createEntry: vi.fn(),
      updateEntry: vi.fn(),
      deleteEntry: vi.fn(),
      createFolder: vi.fn(),
      brokerStatus: vi.fn(),
      enableZiti: vi.fn(),
      disableZiti: vi.fn(),
    },
  },
}))
vi.mock('../hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }))

import { PamConnectionsPage } from './pam-connections'
import { connectionPathSteps } from '../lib/connection-path'
import { api, PamEntry } from '../lib/api'

const pam = api.pam as unknown as Record<string, ReturnType<typeof vi.fn>>

const entryTypes = [
  { type: 'rdp', kind: 'session', label: 'RDP Session', protocol: 'rdp', secret_label: 'Password' },
  { type: 'ssh', kind: 'session', label: 'SSH Shell', protocol: 'ssh' },
  { type: 'credential', kind: 'credential', label: 'Credential' },
]

const rdpEntry = {
  id: 'e1', name: 'DC01', entry_type: 'rdp', kind: 'session',
  tags: [], hostname: 'dc01.corp', port: 3389, username: 'administrator',
  settings: {}, has_secret: true, allow_reveal: true,
  require_approval: false, record_session: true, favorite: false,
  reach_mode: 'direct', ziti_enabled: false,
  connect_count: 3, created_at: '2026-07-10T00:00:00Z', updated_at: '2026-07-10T00:00:00Z',
}

const gatedEntry = {
  ...rdpEntry, id: 'e2', name: 'prod-bastion', hostname: 'bastion.corp', username: 'root',
  require_approval: true, allow_reveal: false, favorite: true,
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter><PamConnectionsPage /></MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('PamConnectionsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    pam.listEntryTypes.mockResolvedValue({ types: entryTypes })
    pam.listFolders.mockResolvedValue({ folders: [{ id: 'f1', name: 'Production', entry_count: 2, created_at: '', updated_at: '' }] })
    pam.listEntries.mockResolvedValue({ entries: [rdpEntry, gatedEntry] })
    pam.connect.mockResolvedValue({ launch_type: 'guacamole', connect_url: 'https://guac/x', entry_id: 'e1', credential_injected: true })
    pam.favorite.mockResolvedValue({ favorite: true })
    pam.unfavorite.mockResolvedValue({ favorite: false })
    pam.reveal.mockResolvedValue({ value: 'hunter2' })
    pam.requestAccess.mockResolvedValue({ request_id: 'r1' })
    pam.brokerStatus.mockResolvedValue({ available: true, reach_modes: ['direct', 'ziti'] })
    pam.enableZiti.mockResolvedValue({ reach_mode: 'ziti', ziti_service_name: 'openidx-pam-e1', ziti_intercept_port: 14000 })
    pam.disableZiti.mockResolvedValue({ reach_mode: 'direct' })
    window.open = vi.fn()
  })

  it('renders entries with type and host', async () => {
    renderPage()
    expect(await screen.findByText('DC01')).toBeInTheDocument()
    expect(screen.getByText('prod-bastion')).toBeInTheDocument()
    expect(screen.getByText(/administrator@dc01.corp:3389/)).toBeInTheDocument()
  })

  it('launches a session (passwordless) and opens the connect URL', async () => {
    renderPage()
    const card = (await screen.findByText('DC01')).closest('[class*="rounded"]') as HTMLElement
    fireEvent.click(within(card).getByRole('button', { name: /connect/i }))
    await waitFor(() => expect(pam.connect).toHaveBeenCalledWith('e1'))
    await waitFor(() => expect(window.open).toHaveBeenCalledWith('https://guac/x', '_blank', 'noopener'))
  })

  it('shows a request-access button only for approval-gated entries', async () => {
    renderPage()
    await screen.findByText('prod-bastion')
    // Two entries; only the gated one exposes a request (Send) action alongside Connect.
    const sendButtons = screen.getAllByTitle('Request access')
    expect(sendButtons).toHaveLength(1)
  })

  it('renders the RDM import action', async () => {
    renderPage()
    expect(await screen.findByRole('button', { name: /import from rdm/i })).toBeInTheDocument()
  })

  it('shows a reveal button only when allowed', async () => {
    renderPage()
    await screen.findByText('DC01')
    // rdpEntry allows reveal; gatedEntry does not.
    expect(screen.getAllByTitle('Reveal secret')).toHaveLength(1)
  })

  it('enables Ziti reach on a session entry when the overlay is available', async () => {
    renderPage()
    const card = (await screen.findByText('DC01')).closest('[class*="rounded"]') as HTMLElement
    fireEvent.click(within(card).getByTitle(/enable ziti reach/i))
    await waitFor(() => expect(pam.enableZiti).toHaveBeenCalledWith('e1'))
  })

  it('shows a via-Ziti badge and offers disable for ziti-enabled entries', async () => {
    pam.listEntries.mockResolvedValue({
      entries: [{ ...rdpEntry, reach_mode: 'ziti', ziti_enabled: true }],
    })
    renderPage()
    expect(await screen.findByText(/via ziti/i)).toBeInTheDocument()
    const card = (await screen.findByText('DC01')).closest('[class*="rounded"]') as HTMLElement
    fireEvent.click(within(card).getByTitle(/disable ziti reach/i))
    await waitFor(() => expect(pam.disableZiti).toHaveBeenCalledWith('e1'))
  })

  it('shows a RemoteApp badge for entries publishing a single app', async () => {
    pam.listEntries.mockResolvedValue({
      entries: [{ ...rdpEntry, name: 'SQL01 SSMS', settings: { 'remote-app': '||SSMS' } }],
    })
    renderPage()
    await screen.findByText('SQL01 SSMS')
    // Badge shows the alias without Guacamole's "||" prefix.
    expect(screen.getByText('app: SSMS')).toBeInTheDocument()
  })

  it('saves RemoteApp fields into entry settings with the || alias prefix', async () => {
    pam.createEntry.mockResolvedValue({ id: 'e9' })
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: /new entry/i }))
    fireEvent.change(screen.getByPlaceholderText('DC01 – Domain Controller'), { target: { value: 'SSMS' } })
    fireEvent.change(screen.getByPlaceholderText('SSMS'), { target: { value: 'SSMS' } })
    fireEvent.change(screen.getByPlaceholderText('-S sql01.corp.local -E'), { target: { value: '-E' } })
    fireEvent.click(screen.getByRole('button', { name: /create/i }))
    await waitFor(() => expect(pam.createEntry).toHaveBeenCalled())
    const body = pam.createEntry.mock.calls[0][0]
    expect(body.settings).toMatchObject({ 'remote-app': '||SSMS', 'remote-app-args': '-E' })
  })

  it('shows a used-by badge on credential entries that session entries link to', async () => {
    const cred = {
      ...rdpEntry, id: 'c1', name: 'svc-admin', entry_type: 'credential', kind: 'credential',
      hostname: '', username: 'svc-admin',
    }
    pam.listEntries.mockResolvedValue({
      entries: [cred, { ...rdpEntry, credential_entry_id: 'c1', credential_entry_name: 'svc-admin' }],
    })
    renderPage()
    await screen.findByText('svc-admin')
    expect(screen.getByText('used by 1')).toBeInTheDocument()
    expect(screen.getByTitle('Injected into: DC01')).toBeInTheDocument()
  })

  it('opens the connection path explainer from a session entry', async () => {
    renderPage()
    const card = (await screen.findByText('DC01')).closest('[class*="rounded"]') as HTMLElement
    fireEvent.click(within(card).getByTitle('Launch path'))
    expect(await screen.findByText(/how “DC01” connects/i)).toBeInTheDocument()
    // rdpEntry: no approval, own secret, plain RDP, recording on, direct reach.
    expect(screen.getByText('Vaulted secret')).toBeInTheDocument()
    expect(screen.getByText('Guacamole RDP session')).toBeInTheDocument()
    expect(screen.getByText('Session recording')).toBeInTheDocument()
    expect(screen.getByText('Direct reach')).toBeInTheDocument()
  })
})

describe('connectionPathSteps', () => {
  const base = rdpEntry as unknown as PamEntry

  it('tells the approval + linked-credential + RemoteApp + Ziti story', () => {
    const steps = connectionPathSteps({
      ...base,
      require_approval: true,
      credential_entry_id: 'c1', credential_entry_name: 'svc-admin',
      settings: { 'remote-app': '||SSMS' },
      ziti_enabled: true,
    })
    const titles = steps.map((s) => s.title)
    expect(titles).toEqual([
      'Approval gate',
      'Linked credential: svc-admin',
      'RemoteApp: SSMS',
      'Session recording',
      'Ziti overlay (zero-trust)',
      'dc01.corp:3389',
    ])
  })

  it('describes the wasm-ssh renderer as a browser terminal', () => {
    const steps = connectionPathSteps({ ...base, entry_type: 'ssh', renderer: 'wasm-ssh', record_session: false })
    expect(steps.map((s) => s.title)).toContain('Browser terminal')
    expect(steps.map((s) => s.title)).not.toContain('Session recording')
  })
})
