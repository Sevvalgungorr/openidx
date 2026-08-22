import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { SessionExpiredDialog } from './session-expired-dialog'

describe('SessionExpiredDialog', () => {
  it('shows when open and calls onSignIn', () => {
    const onSignIn = vi.fn()
    render(<SessionExpiredDialog open onSignIn={onSignIn} />)
    expect(screen.getByText(/session ended/i)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }))
    expect(onSignIn).toHaveBeenCalled()
  })
  it('renders nothing when closed', () => {
    const { container } = render(<SessionExpiredDialog open={false} onSignIn={() => {}} />)
    expect(container.textContent).toBe('')
  })
  it('has no dismiss (close) button — non-dismissable', () => {
    render(<SessionExpiredDialog open onSignIn={() => {}} />)
    // Radix's DialogContent renders a built-in close (X) button as its last
    // DIRECT child. We hide it with the Tailwind rule `[&>button]:hidden` on the
    // DialogContent, so the X gets `display:none` and can't be used to dismiss
    // the modal without re-authenticating. jsdom doesn't compute CSS, so we can't
    // rely on visibility APIs — instead assert the two facts that make the X
    // hidden: (1) the DialogContent carries the [&>button]:hidden class, and
    // (2) the close (X) button is a DIRECT child of it (so the rule applies).
    const dialog = screen.getByRole('dialog')
    expect(dialog.className).toContain('[&>button]:hidden')

    const buttons = Array.from(dialog.querySelectorAll('button'))
    const closeBtn = buttons.find((b) => /close/i.test(b.textContent || ''))
    expect(closeBtn).toBeTruthy()
    // Direct child => matched by [&>button]:hidden => rendered display:none.
    expect(closeBtn?.parentElement).toBe(dialog)

    // The only NON-hidden actionable control is "Sign in": it lives in the
    // footer (a nested <div>), NOT a direct child of the dialog, so the
    // [&>button]:hidden rule does not touch it and it stays visible/clickable.
    const signInBtn = buttons.find((b) => /sign in/i.test(b.textContent || ''))
    expect(signInBtn).toBeTruthy()
    expect(signInBtn?.parentElement).not.toBe(dialog)
  })
})
