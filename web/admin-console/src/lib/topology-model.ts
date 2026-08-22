// Topology model — pure builder that turns the raw OpenZiti data (identities,
// services, fabric routers, service-policies, sessions) into a layered graph
// (identity → router → service) for the ops-cockpit topology view.
//
// The input shapes here are minimal, normalized projections of the real
// ziti-network.tsx response types (ZitiIdentity/ZitiService/FabricRouter/
// ServicePolicy/ZitiSessionEntry). Those page-level interfaces are not exported,
// so the caller maps the API responses onto these BuildInput shapes.

export type TopoKind = 'identity' | 'router' | 'service' | 'role'
export type TopoStatus = 'up' | 'down' | 'degraded' | 'unknown'

export interface TopoNode {
  id: string
  kind: TopoKind
  label: string
  status: TopoStatus
  column: number
  row: number
}

export type TopoEdgeKind = 'policy' | 'router' | 'session'

export interface TopoEdge {
  id: string
  source: string
  target: string
  kind: TopoEdgeKind
}

export interface Topology {
  nodes: TopoNode[]
  edges: TopoEdge[]
}

export interface BuildInput {
  identities: { id: string; name: string; roleAttributes?: string[]; hasApiSession?: boolean; disabled?: boolean }[]
  services: { id: string; name: string; roleAttributes?: string[] }[]
  routers: { id: string; name: string; online?: boolean }[]
  servicePolicies: { id: string; name?: string; type?: string; identityRoles: string[]; serviceRoles: string[] }[]
  sessions?: { identityId?: string; serviceId?: string }[]
}

// resolveRefs turns a list of ziti role refs into the set of matching member
// ids. Supported ref forms:
//   @<id>   → the specific member with that id
//   #<attr> → every member whose roleAttributes include <attr>
//   all / #all → every member
// Unknown attributes (or @<id> that matches nothing) resolve to nothing and are
// silently skipped.
function resolveRefs(
  refs: string[],
  members: { id: string; roleAttributes?: string[] }[],
): Set<string> {
  const out = new Set<string>()
  for (const ref of refs) {
    if (!ref) continue
    if (ref === 'all' || ref === '#all') {
      for (const m of members) out.add(m.id)
      continue
    }
    if (ref.startsWith('@')) {
      const id = ref.slice(1)
      if (members.some((m) => m.id === id)) out.add(id)
      continue
    }
    if (ref.startsWith('#')) {
      const attr = ref.slice(1)
      for (const m of members) {
        if (m.roleAttributes?.includes(attr)) out.add(m.id)
      }
      continue
    }
    // Bare, non-prefixed ref: treat as an id match (best-effort).
    if (members.some((m) => m.id === ref)) out.add(ref)
  }
  return out
}

export function buildTopology(input: BuildInput): Topology {
  const nodes: TopoNode[] = []
  const edges: TopoEdge[] = []
  const seenEdges = new Set<string>()

  const addEdge = (edge: TopoEdge) => {
    if (seenEdges.has(edge.id)) return
    seenEdges.add(edge.id)
    edges.push(edge)
  }

  // Column 0: identities
  input.identities.forEach((identity, i) => {
    nodes.push({
      id: identity.id,
      kind: 'identity',
      label: identity.name,
      status: identity.disabled ? 'down' : 'up',
      column: 0,
      row: i,
    })
  })

  // Column 1: routers
  input.routers.forEach((router, i) => {
    nodes.push({
      id: router.id,
      kind: 'router',
      label: router.name,
      status: router.online === false ? 'down' : 'up',
      column: 1,
      row: i,
    })
  })

  // Column 2: services
  input.services.forEach((service, i) => {
    nodes.push({
      id: service.id,
      kind: 'service',
      label: service.name,
      status: 'up',
      column: 2,
      row: i,
    })
  })

  const identityIds = new Set(input.identities.map((i) => i.id))
  const serviceIds = new Set(input.services.map((s) => s.id))

  // Policy edges: identity → service for each resolved pair.
  for (const policy of input.servicePolicies) {
    const identityMatches = resolveRefs(policy.identityRoles ?? [], input.identities)
    const serviceMatches = resolveRefs(policy.serviceRoles ?? [], input.services)
    for (const identityId of identityMatches) {
      if (!identityIds.has(identityId)) continue
      for (const serviceId of serviceMatches) {
        if (!serviceIds.has(serviceId)) continue
        addEdge({
          id: `${policy.id}:${identityId}:${serviceId}`,
          source: identityId,
          target: serviceId,
          kind: 'policy',
        })
      }
    }
  }

  // Router edges: the fabric routes all traffic through edge routers, so wire
  // every identity → router and every router → service. Bounded: skip entirely
  // when there are no routers.
  if (input.routers.length > 0) {
    for (const router of input.routers) {
      for (const identity of input.identities) {
        addEdge({
          id: `router:${identity.id}:${router.id}`,
          source: identity.id,
          target: router.id,
          kind: 'router',
        })
      }
      for (const service of input.services) {
        addEdge({
          id: `router:${service.id}:${router.id}`,
          source: router.id,
          target: service.id,
          kind: 'router',
        })
      }
    }
  }

  // Session edges: live identity → service connections.
  for (const session of input.sessions ?? []) {
    if (!session.identityId || !session.serviceId) continue
    addEdge({
      id: `session:${session.identityId}:${session.serviceId}`,
      source: session.identityId,
      target: session.serviceId,
      kind: 'session',
    })
  }

  return { nodes, edges }
}
