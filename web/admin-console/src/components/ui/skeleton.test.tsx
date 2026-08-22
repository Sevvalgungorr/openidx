import { describe, it, expect } from 'vitest'
import { render } from '@testing-library/react'
import { Skeleton, TableSkeleton } from './skeleton'

describe('Skeleton', () => {
  it('renders a pulsing placeholder', () => {
    const { container } = render(<Skeleton />)
    expect(container.querySelectorAll('.animate-pulse')).toHaveLength(1)
  })

  it('merges a custom className', () => {
    const { container } = render(<Skeleton className="h-8 w-32" />)
    const el = container.querySelector('.animate-pulse')
    expect(el).toHaveClass('h-8', 'w-32')
  })
})

describe('TableSkeleton', () => {
  it('renders rows * cols skeleton cells', () => {
    const { container } = render(<TableSkeleton rows={3} cols={2} />)
    expect(container.querySelectorAll('.animate-pulse')).toHaveLength(6)
  })

  it('defaults to 5 rows and 4 cols', () => {
    const { container } = render(<TableSkeleton />)
    expect(container.querySelectorAll('.animate-pulse')).toHaveLength(20)
  })
})
