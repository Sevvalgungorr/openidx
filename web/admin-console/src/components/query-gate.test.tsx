import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { QueryGate } from './query-gate'

const q = (over: Record<string, unknown>) =>
  ({ isLoading: false, isError: false, error: null, data: undefined, ...over }) as never

describe('QueryGate', () => {
  it('renders a spinner while loading', () => {
    const { container } = render(<QueryGate query={q({ isLoading: true })} resource="users">{() => <div>rows</div>}</QueryGate>)
    expect(container.querySelector('.animate-spin')).toBeTruthy()
    expect(screen.queryByText('rows')).toBeNull()
  })

  it('renders QueryError (permission copy) on a 403', () => {
    render(<QueryGate query={q({ isError: true, error: { response: { status: 403 } } })} resource="users">{() => <div>rows</div>}</QueryGate>)
    expect(screen.getByText(/don't have permission to view users/i)).toBeInTheDocument()
    expect(screen.queryByText('rows')).toBeNull()
  })

  it('renders the empty fallback when data is an empty array', () => {
    render(<QueryGate query={q({ data: [] })} resource="users" empty={<div>none</div>}>{() => <div>rows</div>}</QueryGate>)
    expect(screen.getByText('none')).toBeInTheDocument()
  })

  it('renders children with data', () => {
    render(<QueryGate query={q({ data: [1, 2] })} resource="users">{(d: number[]) => <div>{d.length} rows</div>}</QueryGate>)
    expect(screen.getByText('2 rows')).toBeInTheDocument()
  })
})
