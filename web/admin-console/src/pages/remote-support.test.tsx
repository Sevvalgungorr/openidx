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

import { RemoteSupportPage } from './remote-support'
import { api } from '../lib/api'

const activeSession = {
  id: 'sess-active-abcdef12',
  agent_id: 'agent-xxxxxxxx',
  mode: 'view',
  status: 'active',
  started_at: '2026-06-09T10:00:00Z',
  recording_enabled: true,
}

function routeGet(url: string) {
  if (url.includes('/remote-support/sessions')) {
    return Promise.resolve([activeSession])
  }
  if (url.includes('/recording-retention-policy')) {
    return Promise.resolve({ retention_days: 30 })
  }
  return Promise.resolve({})
}

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('RemoteSupportPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockImplementation((url: string) => routeGet(url) as ReturnType<typeof api.get>)
  })

  it('renders the heading + subtitle + Start session button', async () => {
    render(<RemoteSupportPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('Remote support')).toBeInTheDocument()
    expect(
      screen.getByText(/live screen view and \(with consent\) control of enrolled android agents/i),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /start session/i }),
    ).toBeInTheDocument()
  })

  it('renders the Sessions card', async () => {
    render(<RemoteSupportPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('Sessions')).toBeInTheDocument()
  })

  it('lists session rows with their agent_id', async () => {
    render(<RemoteSupportPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('agent-xxxxxxxx')).toBeInTheDocument()
  })

  it('renders without crashing when a session omits numeric/optional fields', async () => {
    // Backend can serialize Go zero-values as null or drop keys entirely.
    // A row with a recording (triggers formatBytes + legal-hold buttons) but
    // no recording_size_bytes / recording_chunk_count / is_on_legal_hold must
    // still render rather than tripping the error boundary.
    const sparseSession = {
      id: 'sess-sparse-99887766',
      agent_id: 'agent-sparse',
      mode: 'view',
      status: 'ended',
      started_at: '2026-06-09T10:00:00Z',
      recording_url: '/rec/sess-sparse',
      // recording_size_bytes, recording_chunk_count, recording_enabled,
      // is_on_legal_hold intentionally omitted
    }
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url.includes('/remote-support/sessions')) {
        return Promise.resolve([sparseSession]) as ReturnType<typeof api.get>
      }
      if (url.includes('/recording-retention-policy')) {
        return Promise.resolve({ retention_days: 30 }) as ReturnType<typeof api.get>
      }
      return Promise.resolve({}) as ReturnType<typeof api.get>
    })

    render(<RemoteSupportPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('Remote support')).toBeInTheDocument()
    expect(await screen.findByText('Sessions')).toBeInTheDocument()
    expect(await screen.findByText('agent-sparse')).toBeInTheDocument()
  })

  it('shows the empty "No sessions yet." state when the list is empty', async () => {
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url.includes('/remote-support/sessions')) {
        return Promise.resolve([]) as ReturnType<typeof api.get>
      }
      if (url.includes('/recording-retention-policy')) {
        return Promise.resolve({ retention_days: 30 }) as ReturnType<typeof api.get>
      }
      return Promise.resolve({}) as ReturnType<typeof api.get>
    })

    render(<RemoteSupportPage />, { wrapper: createWrapper() })

    expect(
      await screen.findByText(/no sessions yet/i),
    ).toBeInTheDocument()
  })
})
