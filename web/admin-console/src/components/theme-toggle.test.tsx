import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const setTheme = vi.fn()

// Mock the store so the toggle reads a known theme and we can assert on setTheme.
vi.mock('../lib/store', () => ({
  useAppStore: () => ({ theme: 'system', setTheme }),
}))

import { ThemeToggle } from './theme-toggle'

describe('ThemeToggle', () => {
  beforeEach(() => {
    setTheme.mockClear()
    document.body.innerHTML = ''
  })

  it('renders the trigger button', () => {
    render(<ThemeToggle />)
    expect(screen.getByRole('button')).toBeInTheDocument()
  })

  it('opens the menu and offers Light / Dark / System', async () => {
    const user = userEvent.setup()
    render(<ThemeToggle />)
    await user.click(screen.getByRole('button'))
    expect(screen.getByText('Light')).toBeInTheDocument()
    expect(screen.getByText('Dark')).toBeInTheDocument()
    expect(screen.getByText('System')).toBeInTheDocument()
  })

  it('calls setTheme("dark") when Dark is clicked', async () => {
    const user = userEvent.setup()
    render(<ThemeToggle />)
    await user.click(screen.getByRole('button'))
    await user.click(screen.getByText('Dark'))
    expect(setTheme).toHaveBeenCalledWith('dark')
  })
})
