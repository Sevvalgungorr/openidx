import { describe, it, expect } from 'vitest'
import { buildTopology, type BuildInput } from './topology-model'

describe('buildTopology', () => {
  it('builds nodes + policy edges from a #all Dial policy (both identities → svc1)', () => {
    const input: BuildInput = {
      identities: [
        { id: 'id1', name: 'alice' },
        { id: 'id2', name: 'bob' },
      ],
      services: [{ id: 'svc1', name: 'app' }],
      routers: [{ id: 'r1', name: 'edge-1', online: true }],
      servicePolicies: [
        { id: 'p1', type: 'Dial', identityRoles: ['#all'], serviceRoles: ['@svc1'] },
      ],
    }
    const topo = buildTopology(input)

    // 2 identities + 1 router + 1 service = 4 nodes
    expect(topo.nodes).toHaveLength(4)

    const policyEdges = topo.edges.filter((e) => e.kind === 'policy')
    expect(policyEdges).toHaveLength(2)
    expect(policyEdges.map((e) => e.id).sort()).toEqual(['p1:id1:svc1', 'p1:id2:svc1'])

    // Router edges present (2 identities→r1 + 1 r1→svc1)
    const routerEdges = topo.edges.filter((e) => e.kind === 'router')
    expect(routerEdges).toHaveLength(3)
  })

  it('returns empty topology for empty input', () => {
    expect(
      buildTopology({ identities: [], services: [], routers: [], servicePolicies: [] }),
    ).toEqual({ nodes: [], edges: [] })
  })

  it('resolves a @id ref to exactly that node', () => {
    const input: BuildInput = {
      identities: [
        { id: 'id1', name: 'alice' },
        { id: 'id2', name: 'bob' },
      ],
      services: [{ id: 'svc1', name: 'app' }],
      routers: [],
      servicePolicies: [
        { id: 'p1', type: 'Dial', identityRoles: ['@id2'], serviceRoles: ['@svc1'] },
      ],
    }
    const policyEdges = buildTopology(input).edges.filter((e) => e.kind === 'policy')
    expect(policyEdges).toHaveLength(1)
    expect(policyEdges[0].id).toBe('p1:id2:svc1')
  })

  it('resolves a #attr ref to members with that roleAttribute', () => {
    const input: BuildInput = {
      identities: [
        { id: 'id1', name: 'alice', roleAttributes: ['admins'] },
        { id: 'id2', name: 'bob', roleAttributes: ['users'] },
      ],
      services: [{ id: 'svc1', name: 'app', roleAttributes: ['web'] }],
      routers: [],
      servicePolicies: [
        { id: 'p1', type: 'Dial', identityRoles: ['#admins'], serviceRoles: ['#web'] },
      ],
    }
    const policyEdges = buildTopology(input).edges.filter((e) => e.kind === 'policy')
    expect(policyEdges).toHaveLength(1)
    expect(policyEdges[0].id).toBe('p1:id1:svc1')
  })

  it('skips an unknown ref without throwing', () => {
    const input: BuildInput = {
      identities: [{ id: 'id1', name: 'alice', roleAttributes: ['admins'] }],
      services: [{ id: 'svc1', name: 'app' }],
      routers: [],
      servicePolicies: [
        { id: 'p1', type: 'Dial', identityRoles: ['#nonexistent'], serviceRoles: ['@svc1'] },
      ],
    }
    let topo: ReturnType<typeof buildTopology>
    expect(() => {
      topo = buildTopology(input)
    }).not.toThrow()
    expect(topo!.edges.filter((e) => e.kind === 'policy')).toHaveLength(0)
  })

  it('adds one session edge per identity+service session', () => {
    const input: BuildInput = {
      identities: [{ id: 'id1', name: 'alice' }],
      services: [{ id: 'svc1', name: 'app' }],
      routers: [],
      servicePolicies: [],
      sessions: [{ identityId: 'id1', serviceId: 'svc1' }],
    }
    const sessionEdges = buildTopology(input).edges.filter((e) => e.kind === 'session')
    expect(sessionEdges).toHaveLength(1)
    expect(sessionEdges[0].id).toBe('session:id1:svc1')
  })
})
