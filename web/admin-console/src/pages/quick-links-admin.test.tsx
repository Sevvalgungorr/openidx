import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import React from 'react'

vi.mock('../lib/api', () => ({
  api: {
    quickLinks: {
      list: vi.fn(),
      listMine: vi.fn(),
      create: vi.fn(() => Promise.resolve({ id: 'ql-new' })),
      update: vi.fn(() => Promise.resolve({ status: 'ok' })),
      remove: vi.fn(() => Promise.resolve()),
    },
    pam: {
      listEntries: vi.fn(),
    },
  },
}))

vi.mock('../hooks/use-toast', () => ({
  useToast: () => ({ toast: vi.fn() }),
}))

import { QuickLinksAdminPage } from './quick-links-admin'
import { api } from '../lib/api'

const links = {
  quick_links: [
    {
      id: 'ql-1',
      title: 'Company Wiki',
      description: 'Internal knowledge base',
      category: 'Docs',
      icon: 'book',
      type: 'external',
      url: 'https://wiki.corp.test',
      pam_entry_id: '',
      pam_renderer: '',
      min_role: 'user',
      sort_order: 1,
      enabled: true,
      open_in_new: true,
    },
    {
      id: 'ql-2',
      title: 'Prod SSH',
      description: 'Jump host',
      category: 'Infra',
      icon: 'terminal',
      type: 'pam',
      pam_entry_id: 'pam-9',
      pam_renderer: 'ssh',
      min_role: 'admin',
      sort_order: 2,
      enabled: false,
      open_in_new: false,
    },
  ],
}

const pamEntries = {
  entries: [{ id: 'pam-9', name: 'Prod SSH', entry_type: 'ssh' }],
}

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('QuickLinksAdminPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.quickLinks.list).mockResolvedValue(links as never)
    vi.mocked(api.pam.listEntries).mockResolvedValue(pamEntries as never)
  })

  it('renders the heading and the All quick links card', async () => {
    render(<QuickLinksAdminPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Quick Links')).toBeInTheDocument()
    expect(await screen.findByText('All quick links')).toBeInTheDocument()
  })

  it('lists the configured quick links', async () => {
    render(<QuickLinksAdminPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Company Wiki')).toBeInTheDocument()
    expect(screen.getByText('Prod SSH')).toBeInTheDocument()
    // external link shows its url; pam link shows a disabled badge
    expect(screen.getByText('https://wiki.corp.test')).toBeInTheDocument()
    expect(screen.getByText('disabled')).toBeInTheDocument()
  })

  it('shows role + type badges for each link', async () => {
    render(<QuickLinksAdminPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Company Wiki')).toBeInTheDocument()
    // type badges 'external' and 'pam'
    expect(screen.getByText('external')).toBeInTheDocument()
    expect(screen.getByText('pam')).toBeInTheDocument()
    // min_role badges rendered as "≥ user" / "≥ admin"
    expect(screen.getByText(/≥ user/)).toBeInTheDocument()
    expect(screen.getByText(/≥ admin/)).toBeInTheDocument()
  })
})
