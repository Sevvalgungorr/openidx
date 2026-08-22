import { describe, it, expect, beforeAll, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { TopologyGraph } from './topology-graph'
import type { Topology } from '../lib/topology-model'

// react-flow needs ResizeObserver; src/test/setup.ts polyfills it, but add a
// local guard so this test stays resilient if run in isolation.
beforeAll(() => {
  if (!('ResizeObserver' in globalThis)) {
    // eslint-disable-next-line @typescript-eslint/no-extraneous-class
    class RO {
      observe = vi.fn()
      unobserve = vi.fn()
      disconnect = vi.fn()
    }
    globalThis.ResizeObserver = RO as unknown as typeof ResizeObserver
  }
})

const topology: Topology = {
  nodes: [
    { id: 'id1', kind: 'identity', label: 'alice', status: 'up', column: 0, row: 0 },
    { id: 'r1', kind: 'router', label: 'edge-1', status: 'up', column: 1, row: 0 },
    { id: 'svc1', kind: 'service', label: 'app', status: 'up', column: 2, row: 0 },
  ],
  edges: [
    { id: 'router:id1:r1', source: 'id1', target: 'r1', kind: 'router' },
    { id: 'router:svc1:r1', source: 'r1', target: 'svc1', kind: 'router' },
  ],
}

describe('TopologyGraph', () => {
  it('mounts without throwing and renders the summary line', () => {
    expect(() => render(<TopologyGraph topology={topology} interactive={false} />)).not.toThrow()
    // Summary counts render regardless of react-flow layout in jsdom.
    expect(screen.getByText(/1 identities/)).toBeInTheDocument()
    expect(screen.getByText(/1 routers/)).toBeInTheDocument()
    expect(screen.getByText(/1 services/)).toBeInTheDocument()
  })

  it('renders the legend chips', () => {
    render(<TopologyGraph topology={topology} interactive={false} />)
    // Kind labels appear in the legend (and possibly in rendered node cards);
    // assert at least one of each is present without depending on RF layout.
    expect(screen.getAllByText('Identity').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Router').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Service').length).toBeGreaterThan(0)
  })
})
