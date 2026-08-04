import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
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

vi.mock('../hooks/use-toast', () => ({
  useToast: () => ({ toast: vi.fn() }),
}))

import { BrandingPage } from './branding'
import { api } from '../lib/api'

// GET /api/v1/organizations returns a plain array (verified against the live
// API); the page reads orgs[0].id to pick which tenant to brand.
const orgs = [{ id: 'org-1', name: 'Acme Corp' }]

const branding = {
  logo_url: 'https://cdn.example/logo.svg',
  favicon_url: '',
  background_image_url: '',
  primary_color: '#208AEF',
  secondary_color: '#111111',
  background_color: '#ffffff',
  login_page_title: 'Welcome to Acme',
  portal_title: 'Acme Portal',
  login_page_message: 'Sign in with your corporate account',
  custom_footer: '',
  custom_css: '',
  powered_by_visible: true,
}

function routeGet(url: string) {
  if (url.includes('/organizations')) return Promise.resolve(orgs)
  if (url.includes('/branding')) return Promise.resolve(branding)
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

describe('BrandingPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockImplementation((url: string) => routeGet(url) as ReturnType<typeof api.get>)
  })

  it('renders the heading and the three branding cards', async () => {
    render(<BrandingPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Branding')).toBeInTheDocument()
    expect(await screen.findByText('Logo & colors')).toBeInTheDocument()
    expect(screen.getByText('Login & portal copy')).toBeInTheDocument()
    expect(screen.getByText('Custom CSS')).toBeInTheDocument()
  })

  it('loads the org branding into the form fields', async () => {
    render(<BrandingPage />, { wrapper: createWrapper() })
    expect(await screen.findByDisplayValue('https://cdn.example/logo.svg')).toBeInTheDocument()
    expect(screen.getByDisplayValue('Welcome to Acme')).toBeInTheDocument()
    expect(screen.getByDisplayValue('Acme Portal')).toBeInTheDocument()
  })

  it('saves branding via PUT when the form is submitted', async () => {
    render(<BrandingPage />, { wrapper: createWrapper() })
    // Wait for the branding to load into the form before saving.
    await screen.findByDisplayValue('Welcome to Acme')
    const saveBtn = await screen.findByRole('button', { name: /save branding/i })
    fireEvent.click(saveBtn)
    await waitFor(() =>
      expect(api.put).toHaveBeenCalledWith(
        '/api/v1/tenants/org-1/branding',
        expect.objectContaining({ login_page_title: 'Welcome to Acme' }),
      ),
    )
  })

  it('edits a field and includes the new value in the save payload', async () => {
    render(<BrandingPage />, { wrapper: createWrapper() })
    const portal = await screen.findByDisplayValue('Acme Portal')
    fireEvent.change(portal, { target: { value: 'New Portal Name' } })
    fireEvent.click(screen.getByRole('button', { name: /save branding/i }))
    await waitFor(() =>
      expect(api.put).toHaveBeenCalledWith(
        '/api/v1/tenants/org-1/branding',
        expect.objectContaining({ portal_title: 'New Portal Name' }),
      ),
    )
  })
})
