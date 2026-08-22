import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { ConfirmAction } from './confirm-action'

describe('ConfirmAction', () => {
  it('opens the dialog from the trigger and confirms', async () => {
    const onConfirm = vi.fn()
    render(
      <ConfirmAction title="Delete item?" description="This cannot be undone." onConfirm={onConfirm}>
        {(open) => <button onClick={open}>Delete</button>}
      </ConfirmAction>,
    )
    fireEvent.click(screen.getByText('Delete'))
    expect(await screen.findByText('Delete item?')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /confirm/i }))
    await waitFor(() => expect(onConfirm).toHaveBeenCalledTimes(1))
  })

  it('blocks confirm until a required reason is entered, then passes it', async () => {
    const onConfirm = vi.fn()
    render(
      <ConfirmAction title="Revoke access?" description="Removes the grant." requireReason onConfirm={onConfirm}>
        {(open) => <button onClick={open}>Revoke</button>}
      </ConfirmAction>,
    )
    fireEvent.click(screen.getByText('Revoke'))
    const confirm = screen.getByRole('button', { name: /confirm/i })
    expect(confirm).toBeDisabled()
    fireEvent.change(await screen.findByLabelText(/reason/i), { target: { value: 'offboarding' } })
    expect(confirm).not.toBeDisabled()
    fireEvent.click(confirm)
    await waitFor(() => expect(onConfirm).toHaveBeenCalledWith('offboarding'))
  })
})
