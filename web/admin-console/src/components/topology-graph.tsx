import { useMemo, useCallback } from 'react'
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  type Node as RFNode,
  type Edge as RFEdge,
  type NodeProps,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import type { Topology, TopoNode, TopoKind } from '../lib/topology-model'
import { cn } from '../lib/utils'

interface TopologyGraphProps {
  topology: Topology
  onSelect?: (node: TopoNode) => void
  interactive?: boolean
  showSessions?: boolean
}

// Per-kind border/accent tokens.
const KIND_BORDER: Record<TopoKind, string> = {
  identity: 'border-primary',
  service: 'border-emerald-500',
  router: 'border-amber-500',
  role: 'border-border',
}

const KIND_CHIP: Record<TopoKind, string> = {
  identity: 'bg-primary',
  service: 'bg-emerald-500',
  router: 'bg-amber-500',
  role: 'bg-muted-foreground',
}

const KIND_LABEL: Record<TopoKind, string> = {
  identity: 'Identity',
  service: 'Service',
  router: 'Router',
  role: 'Role',
}

// A node carrying the original TopoNode so click handlers can hand it back out.
type TopoRFData = { topo: TopoNode }

function TopoNodeCard({ data }: NodeProps<RFNode<TopoRFData>>) {
  const { topo } = data
  const down = topo.status === 'down'
  const degraded = topo.status === 'degraded'
  return (
    <div
      className={cn(
        'rounded-md border-2 bg-card px-3 py-2 shadow-sm min-w-[140px]',
        KIND_BORDER[topo.kind],
        down && 'opacity-60 ring-2 ring-red-500',
        degraded && 'ring-2 ring-amber-400',
      )}
    >
      <div className="text-[10px] uppercase tracking-wide text-muted-foreground">
        {KIND_LABEL[topo.kind]}
      </div>
      <div className="text-sm font-medium text-foreground truncate max-w-[180px]">{topo.label}</div>
      {(down || degraded) && (
        <div className={cn('text-[10px] mt-0.5', down ? 'text-red-500' : 'text-amber-500')}>
          {topo.status}
        </div>
      )}
    </div>
  )
}

const nodeTypes = { topo: TopoNodeCard }

export function TopologyGraph({
  topology,
  onSelect,
  interactive = true,
  showSessions = true,
}: TopologyGraphProps) {
  const rfNodes: RFNode<TopoRFData>[] = useMemo(
    () =>
      topology.nodes.map((n) => ({
        id: n.id,
        type: 'topo',
        position: { x: n.column * 260, y: n.row * 90 },
        data: { topo: n },
      })),
    [topology.nodes],
  )

  const rfEdges: RFEdge[] = useMemo(() => {
    const edges = showSessions
      ? topology.edges
      : topology.edges.filter((e) => e.kind !== 'session')
    return edges.map((e) => {
      const isSession = e.kind === 'session'
      const isRouter = e.kind === 'router'
      return {
        id: e.id,
        source: e.source,
        target: e.target,
        animated: isSession,
        style: {
          stroke: isSession ? '#22d3ee' : isRouter ? '#f59e0b' : '#94a3b8',
          strokeWidth: isSession ? 2 : 1,
          strokeDasharray: isRouter ? '4 3' : undefined,
        },
      } satisfies RFEdge
    })
  }, [topology.edges, showSessions])

  const handleNodeClick = useCallback(
    (_e: React.MouseEvent, node: RFNode<TopoRFData>) => {
      if (onSelect && node.data?.topo) onSelect(node.data.topo)
    },
    [onSelect],
  )

  const counts = useMemo(() => {
    let identities = 0
    let routers = 0
    let services = 0
    for (const n of topology.nodes) {
      if (n.kind === 'identity') identities++
      else if (n.kind === 'router') routers++
      else if (n.kind === 'service') services++
    }
    return { identities, routers, services }
  }, [topology.nodes])

  return (
    <div className="space-y-2">
      {/* Legend + summary */}
      <div className="flex flex-wrap items-center gap-4 text-xs text-muted-foreground">
        <div className="flex items-center gap-3">
          {(['identity', 'router', 'service'] as const).map((kind) => (
            <span key={kind} className="flex items-center gap-1.5">
              <span className={cn('h-2.5 w-2.5 rounded-full', KIND_CHIP[kind])} />
              {KIND_LABEL[kind]}
            </span>
          ))}
        </div>
        <span className="text-foreground">
          {counts.identities} identities · {counts.routers} routers · {counts.services} services
        </span>
      </div>

      <div
        className={cn(
          'rounded-md border border-border bg-background',
          interactive ? 'h-[600px]' : 'h-64',
        )}
        data-testid="topology-canvas"
      >
        <ReactFlow
          nodes={rfNodes}
          edges={rfEdges}
          nodeTypes={nodeTypes}
          fitView
          onNodeClick={handleNodeClick}
          nodesDraggable={interactive}
          nodesConnectable={false}
          elementsSelectable={interactive}
          zoomOnScroll={interactive}
          panOnDrag={interactive}
          proOptions={{ hideAttribution: true }}
        >
          {interactive && (
            <>
              <Background />
              <Controls />
              <MiniMap />
            </>
          )}
        </ReactFlow>
      </div>
    </div>
  )
}

export default TopologyGraph
