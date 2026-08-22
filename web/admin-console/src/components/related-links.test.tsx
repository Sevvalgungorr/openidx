import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { RelatedLinks } from './related-links'

describe('RelatedLinks', () => {
  it('renders each link as an anchor with the correct href', () => {
    render(
      <MemoryRouter>
        <RelatedLinks
          links={[
            { to: '/users', label: 'Users' },
            { to: '/groups', label: 'Groups' },
          ]}
        />
      </MemoryRouter>
    )

    const users = screen.getByRole('link', { name: 'Users' })
    const groups = screen.getByRole('link', { name: 'Groups' })
    expect(users).toHaveAttribute('href', '/users')
    expect(groups).toHaveAttribute('href', '/groups')
  })

  it('renders nothing when links is empty', () => {
    const { container } = render(
      <MemoryRouter>
        <RelatedLinks links={[]} />
      </MemoryRouter>
    )
    expect(container).toBeEmptyDOMElement()
  })
})
