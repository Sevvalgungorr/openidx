import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

// Mock navigator.clipboard
// Must be configurable so @testing-library/user-event's setup() can attach its
// own clipboard stub on top of it; otherwise userEvent.setup() throws
// "Cannot redefine property: clipboard".
const mockClipboard = {
  writeText: vi.fn(() => Promise.resolve()),
}
Object.defineProperty(navigator, 'clipboard', {
  value: mockClipboard,
  writable: true,
  configurable: true,
})

// Mock the API module
vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(() => Promise.resolve({})),
    post: vi.fn(() => Promise.resolve({})),
  },
}))

// Import after mocks
import { NotificationBell } from '../components/notification-bell'
import { api } from '../lib/api'

const mockNotifications = {
  notifications: [
    {
      id: '1',
      type: 'security',
      title: 'New login detected',
      body: 'A new login was detected',
      read: false,
      created_at: new Date().toISOString(),
    },
  ],
}

function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  })

  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('NotificationBell', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''

    vi.mocked(api.get).mockImplementation((url: string) => {
      // The component reads `unread_count` from the unread-count endpoint
      // (matched to the live API shape); the list endpoint returns { notifications }.
      if (url.includes('unread-count')) return Promise.resolve({ unread_count: 1 })
      return Promise.resolve(mockNotifications)
    })
  })

  it('renders the bell icon button', () => {
    const wrapper = createWrapper()

    render(<NotificationBell />, { wrapper })

    const bellButton = screen.getByRole('button')
    expect(bellButton).toBeInTheDocument()
  })

  it('shows unread count badge when there are unread notifications', async () => {
    const wrapper = createWrapper()

    render(<NotificationBell />, { wrapper })

    await waitFor(() => {
      const badge = screen.queryByText('1')
      expect(badge).toBeInTheDocument()
    })
  })

  it('opens dropdown menu when bell is clicked', async () => {
    const wrapper = createWrapper()
    const user = userEvent.setup()

    render(<NotificationBell />, { wrapper })

    const bellButton = screen.getAllByRole('button')[0]
    await user.click(bellButton)

    await waitFor(() => {
      expect(screen.getByText('Notifications')).toBeInTheDocument()
    })
  })

  it('displays notification items in dropdown', async () => {
    const wrapper = createWrapper()
    const user = userEvent.setup()

    render(<NotificationBell />, { wrapper })

    const bellButton = screen.getAllByRole('button')[0]
    await user.click(bellButton)

    await waitFor(() => {
      expect(screen.getByText('New login detected')).toBeInTheDocument()
    })
  })

  it('has "View All Notifications" link', async () => {
    const wrapper = createWrapper()
    const user = userEvent.setup()

    render(<NotificationBell />, { wrapper })

    const bellButton = screen.getAllByRole('button')[0]
    await user.click(bellButton)

    await waitFor(() => {
      expect(screen.getByText('View All Notifications')).toBeInTheDocument()
    })
  })

  it('has "Manage Preferences" link', async () => {
    const wrapper = createWrapper()
    const user = userEvent.setup()

    render(<NotificationBell />, { wrapper })

    const bellButton = screen.getAllByRole('button')[0]
    await user.click(bellButton)

    await waitFor(() => {
      expect(screen.getByText('Manage Preferences')).toBeInTheDocument()
    })
  })
})
