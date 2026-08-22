import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(() => Promise.resolve({})),
    put: vi.fn(() => Promise.resolve({})),
    delete: vi.fn(() => Promise.resolve({})),
    vault: {
      listSecrets: vi.fn(),
      createSecret: vi.fn(),
      getSecret: vi.fn(),
      newVersion: vi.fn(),
      deleteSecret: vi.fn(),
      reveal: vi.fn(),
      addGrant: vi.fn(),
      removeGrant: vi.fn(),
      listGrants: vi.fn(),
      listCheckouts: vi.fn(),
      listPolicies: vi.fn(),
      createPolicy: vi.fn(),
      getPolicy: vi.fn(),
      updatePolicy: vi.fn(),
      deletePolicy: vi.fn(),
      rotateNow: vi.fn(),
      listRotations: vi.fn(),
    },
  },
}))

vi.mock('../hooks/use-toast', () => ({
  useToast: () => ({ toast: vi.fn() }),
}))

import { VaultSecretsPage } from './vault-secrets'
import { api } from '../lib/api'

const secretA = {
  id: 'sec-1',
  name: 'prod-db-password',
  type: 'password',
  description: 'Production database password',
  current_version: 3,
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-06-01T00:00:00Z',
}

const secretB = {
  id: 'sec-2',
  name: 'stripe-api-key',
  type: 'api_key',
  description: 'Stripe payment API key',
  current_version: 1,
  created_at: '2026-02-01T00:00:00Z',
  updated_at: '2026-02-01T00:00:00Z',
}

const detailA = {
  ...secretA,
  versions: [
    { version: 3, key_id: 1, created_by: 'user-abc', created_at: '2026-06-01T00:00:00Z' },
    { version: 2, key_id: 1, created_by: 'user-abc', created_at: '2026-04-01T00:00:00Z' },
    { version: 1, key_id: 1, created_by: 'user-abc', created_at: '2026-01-01T00:00:00Z' },
  ],
}

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('VaultSecretsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''

    vi.mocked(api.vault.listSecrets).mockResolvedValue({ secrets: [secretA, secretB] })
    vi.mocked(api.vault.getSecret).mockResolvedValue(detailA)
    vi.mocked(api.vault.listGrants).mockResolvedValue({ grants: [] })
    vi.mocked(api.vault.listCheckouts).mockResolvedValue({ checkouts: [] })
    vi.mocked(api.vault.createSecret).mockResolvedValue(secretA)
    vi.mocked(api.vault.reveal).mockResolvedValue({ value: 'supersecret123' })
    vi.mocked(api.vault.rotateNow).mockResolvedValue({ status: 'completed' })
    vi.mocked(api.vault.listRotations).mockResolvedValue({ rotations: [
      {
        id: 'run-1',
        status: 'success',
        trigger: 'manual',
        connector_type: 'generate_only',
        version_from: 2,
        version_to: 3,
        started_at: '2026-06-01T00:00:00Z',
      },
    ]})
  })

  it('renders the heading + subtitle + New Secret button', async () => {
    render(<VaultSecretsPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Vault Secrets')).toBeInTheDocument()
    expect(
      screen.getByText(/manage encrypted credentials/i),
    ).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /new secret/i })).toBeInTheDocument()
  })

  it('lists secrets with name, type badge, version', async () => {
    render(<VaultSecretsPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('prod-db-password')).toBeInTheDocument()
    expect(screen.getByText('stripe-api-key')).toBeInTheDocument()
    // Type badges
    expect(screen.getByText('Password')).toBeInTheDocument()
    expect(screen.getByText('API Key')).toBeInTheDocument()
    // Versions
    expect(screen.getByText('v3')).toBeInTheDocument()
    expect(screen.getByText('v1')).toBeInTheDocument()
  })

  it('shows the secret count in the section header', async () => {
    render(<VaultSecretsPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Secrets (2)')).toBeInTheDocument()
  })

  it('no value column in the list', async () => {
    render(<VaultSecretsPage />, { wrapper: createWrapper() })
    await screen.findByText('prod-db-password')
    // Column headers should not include "Value"
    expect(screen.queryByRole('columnheader', { name: /^value$/i })).not.toBeInTheDocument()
    // No revealed value anywhere in the list
    expect(screen.queryByTestId('revealed-value')).not.toBeInTheDocument()
  })

  it('toggles the create form when New Secret is clicked', async () => {
    const user = userEvent.setup()
    render(<VaultSecretsPage />, { wrapper: createWrapper() })
    await screen.findByText('Vault Secrets')

    // Form title not visible initially
    expect(screen.queryByText('Create New Secret')).not.toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: /new secret/i }))
    expect(await screen.findByText('Create New Secret')).toBeInTheDocument()
    // The toggle button now reads "Cancel"
    expect(screen.getByRole('button', { name: /^cancel$/i })).toBeInTheDocument()

    // Click Cancel — form closes
    await user.click(screen.getByRole('button', { name: /^cancel$/i }))
    expect(screen.queryByText('Create New Secret')).not.toBeInTheDocument()
  })

  it('calls createSecret when form is submitted', async () => {
    const user = userEvent.setup()
    render(<VaultSecretsPage />, { wrapper: createWrapper() })
    await screen.findByText('Vault Secrets')

    await user.click(screen.getByRole('button', { name: /new secret/i }))
    await screen.findByText('Create New Secret')

    // Fill the name field (first input after the form opens)
    const nameInput = screen.getByPlaceholderText('my-api-key')
    await user.type(nameInput, 'test-secret')

    // Fill the value field (password input)
    const valueInput = screen.getByPlaceholderText(/enter secret value/i)
    await user.type(valueInput, 'hunter2')

    // Submit
    const createBtn = screen.getByRole('button', { name: /create secret/i })
    await user.click(createBtn)

    await waitFor(() => {
      expect(vi.mocked(api.vault.createSecret)).toHaveBeenCalledWith(
        expect.objectContaining({ name: 'test-secret', value: 'hunter2' }),
      )
    })
  })

  it('reveal requires a non-empty reason before allowing submit', async () => {
    const user = userEvent.setup()
    render(<VaultSecretsPage />, { wrapper: createWrapper() })

    // Select a secret to show the detail panel
    const row = await screen.findByText('prod-db-password')
    await user.click(row)

    // Click Reveal button
    const revealBtn = await screen.findByRole('button', { name: /^reveal$/i })
    await user.click(revealBtn)

    // Reveal Value button should be disabled when reason is empty
    const submitRevealBtn = screen.getByRole('button', { name: /reveal value/i })
    expect(submitRevealBtn).toBeDisabled()

    // reveal API should NOT have been called yet
    expect(vi.mocked(api.vault.reveal)).not.toHaveBeenCalled()
  })

  it('reveal shows the returned value with a copy button and "shown once" note', async () => {
    const user = userEvent.setup()
    render(<VaultSecretsPage />, { wrapper: createWrapper() })

    const row = await screen.findByText('prod-db-password')
    await user.click(row)

    const revealBtn = await screen.findByRole('button', { name: /^reveal$/i })
    await user.click(revealBtn)

    // Type a reason
    const reasonInput = screen.getByPlaceholderText(/emergency credential rotation/i)
    await user.type(reasonInput, 'incident-response-2026')

    const submitBtn = screen.getByRole('button', { name: /reveal value/i })
    await user.click(submitBtn)

    // Wait for the value to appear
    const revealedInput = await screen.findByTestId('revealed-value')
    expect(revealedInput).toHaveValue('supersecret123')

    // "shown once" note
    expect(screen.getByText(/value shown once/i)).toBeInTheDocument()

    // Copy button present
    expect(screen.getByRole('button', { name: '' })).toBeInTheDocument() // icon-only button

    // The API was called with the reason
    expect(vi.mocked(api.vault.reveal)).toHaveBeenCalledWith('sec-1', 'incident-response-2026')
  })

  it('does not show secret value anywhere in the list or detail', async () => {
    const user = userEvent.setup()
    render(<VaultSecretsPage />, { wrapper: createWrapper() })

    // List render — no value field
    await screen.findByText('prod-db-password')
    expect(screen.queryByTestId('revealed-value')).not.toBeInTheDocument()

    // Open detail
    await user.click(screen.getByText('prod-db-password'))
    await screen.findByText('Versions (3)')

    // Still no revealed value
    expect(screen.queryByTestId('revealed-value')).not.toBeInTheDocument()
  })

  it('Rotate now button calls rotateNow', async () => {
    const user = userEvent.setup()
    render(<VaultSecretsPage />, { wrapper: createWrapper() })

    const row = await screen.findByText('prod-db-password')
    await user.click(row)

    const rotateBtn = await screen.findByTestId('rotate-now-btn')
    await user.click(rotateBtn)

    // Rotation is now guarded by a confirmation dialog — confirm it.
    const confirmBtn = await screen.findByRole('button', { name: /^rotate$/i })
    await user.click(confirmBtn)

    await waitFor(() => {
      expect(vi.mocked(api.vault.rotateNow)).toHaveBeenCalledWith('sec-1')
    })
  })

  it('Rotations tab renders listRotations results', async () => {
    const user = userEvent.setup()
    render(<VaultSecretsPage />, { wrapper: createWrapper() })

    const row = await screen.findByText('prod-db-password')
    await user.click(row)

    // Wait for detail panel to load
    await screen.findByText('Versions (3)')

    // Click the Rotations tab
    await user.click(screen.getByRole('tab', { name: /rotations/i }))

    // The rotation run should be visible
    expect(await screen.findByText('success')).toBeInTheDocument()
    expect(screen.getByText('manual')).toBeInTheDocument()
    expect(screen.getByText('generate_only')).toBeInTheDocument()
  })
})
