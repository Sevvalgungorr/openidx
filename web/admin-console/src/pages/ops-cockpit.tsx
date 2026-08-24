import { useMemo } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import type { UseQueryResult } from '@tanstack/react-query'
import {
  Gauge, Server, Router, Activity, Network, ShieldCheck, ShieldAlert,
  Share2, ExternalLink, ArrowRight, KeyRound, ArrowRightLeft,
} from 'lucide-react'
import { api } from '../lib/api'
import { QueryGate } from '../components/query-gate'
import { Skeleton } from '../components/ui/skeleton'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Button } from '../components/ui/button'
import { Badge } from '../components/ui/badge'
import { TopologyGraph } from '../components/topology-graph'
import { buildTopology, type BuildInput } from '../lib/topology-model'

// ─── API response shapes (copied from ziti-network.tsx / risk-dashboard.tsx /
//     security-alerts.tsx — do not guess) ──────────────────────────────────────

interface ZitiStatus {
  enabled: boolean
  sdk_ready: boolean
  controller_reachable?: boolean
  services_count: number
  identities_count: number
  routers_online?: number
  routers_total?: number
}

interface FabricHealth {
  controller_reachable: boolean
  sdk_ready?: boolean
  routers_online: number
  routers_total: number
  services_count: number
  identities_count: number
  policies_count: number
}
interface FabricOverview {
  health?: FabricHealth
}

interface FabricRouterResp {
  id: string
  name: string
  isOnline?: boolean
  roleAttributes?: string[]
}

interface ZitiServiceResp {
  id: string
  name: string
  roleAttributes?: string[]
}

interface ZitiIdentityResp {
  id: string
  name: string
  attributes?: string[]
  enrolled?: boolean
  disabled?: boolean
}

interface ServicePolicyResp {
  id?: string
  name?: string
  type?: string
  identityRoles: string[]
  serviceRoles: string[]
}

interface ZitiSessionEntry {
  id: string
}

interface SecurityAlert {
  id: string
  alert_type: string
  severity: string
  status: string
  title: string
  description: string
  source_ip: string
  created_at: string
}

interface RiskOverview {
  avg_risk_score: number
  high_risk_logins_24h: number
  active_alerts: number
  impossible_travel_events: number
}

// PAM broker health. Two reads back this tile because no single endpoint carries
// both signals:
//  1. /pam/broker/status  — which brokers are CONFIGURED/wired (direct/ziti) and
//     which reach modes are available.
//  2. /health/guacamole   — LIVE reachability + auth for the direct guacd broker
//     (server_reachable / authenticated). This is the signal that would have
//     surfaced the 6-week-wedged guacd instead of silently failing.
// Both interfaces are defensive: every rendered field is defaulted at the queryFn
// so a sparse/unknown backend response renders as down/unknown, never a crash.
interface PamBrokerStatusResp {
  available: boolean
  reach_modes: string[]
  direct_broker: boolean
  ziti_broker: boolean
}

interface GuacamoleHealthResp {
  status: string // "healthy" | "degraded" | "unhealthy" | "unavailable" | ...
  server_reachable: boolean
  authenticated: boolean
  connections_count: number
  active_sessions: number
  error_message: string
}

/** A broker's rolled-up health state, used to pick the badge colour/label. */
type BrokerHealth = 'healthy' | 'degraded' | 'down'

// ─── Small tile helpers ────────────────────────────────────────────────────────

/** Renders a small skeleton while loading, "—" on error, else the value. Keeps
 *  every secondary tile degrading gracefully without masking the primary query. */
function TileValue<T>({
  query,
  render,
}: {
  query: Pick<UseQueryResult<T>, 'isLoading' | 'isError' | 'data'>
  render: (data: T) => React.ReactNode
}) {
  if (query.isLoading) return <Skeleton className="h-8 w-20" />
  if (query.isError || query.data === undefined) {
    return <span className="text-2xl font-bold text-muted-foreground">—</span>
  }
  return <>{render(query.data)}</>
}

function StatTile({
  to,
  title,
  icon: Icon,
  accent,
  children,
  description,
}: {
  to: string
  title: string
  icon: typeof Server
  accent?: string
  children: React.ReactNode
  description?: React.ReactNode
}) {
  return (
    <Link to={to} className="block focus:outline-none">
      <Card className="h-full transition-all hover:border-primary hover:shadow-md">
        <CardHeader className="flex flex-row items-center justify-between pb-2">
          <CardTitle className="text-sm font-medium text-muted-foreground">{title}</CardTitle>
          <Icon className={`h-4 w-4 ${accent ?? 'text-primary'}`} />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold text-foreground">{children}</div>
          {description && <p className="mt-1 text-xs text-muted-foreground">{description}</p>}
        </CardContent>
      </Card>
    </Link>
  )
}

// ─── Page ──────────────────────────────────────────────────────────────────────

export function OpsCockpitPage() {
  // Primary query: the fabric overview drives the whole cockpit's health story,
  // so a 401/403 here surfaces through QueryGate (never masked as "—").
  const overviewQuery = useQuery({
    queryKey: ['ops-fabric-overview'],
    queryFn: () => api.get<FabricOverview>('/api/v1/access/ziti/fabric/overview'),
    refetchInterval: 15000,
  })

  const statusQuery = useQuery({
    queryKey: ['ops-ziti-status'],
    queryFn: () => api.get<ZitiStatus>('/api/v1/access/ziti/status'),
    refetchInterval: 15000,
  })
  const routersQuery = useQuery({
    queryKey: ['ops-fabric-routers'],
    queryFn: () => api.get<FabricRouterResp[]>('/api/v1/access/ziti/fabric/routers'),
  })
  const servicesQuery = useQuery({
    queryKey: ['ops-ziti-services'],
    queryFn: () => api.get<{ services: ZitiServiceResp[] }>('/api/v1/access/ziti/services'),
  })
  const identitiesQuery = useQuery({
    queryKey: ['ops-ziti-identities'],
    queryFn: () => api.get<{ identities: ZitiIdentityResp[] }>('/api/v1/access/ziti/identities'),
  })
  const policiesQuery = useQuery({
    queryKey: ['ops-service-policies'],
    queryFn: () => api.get<ServicePolicyResp[]>('/api/v1/access/ziti/fabric/service-policies'),
  })
  const sessionsQuery = useQuery({
    queryKey: ['ops-ziti-sessions'],
    queryFn: () => api.get<ZitiSessionEntry[]>('/api/v1/access/ziti/sessions'),
  })
  const alertsQuery = useQuery({
    queryKey: ['ops-security-alerts'],
    queryFn: () => api.get<{ alerts: SecurityAlert[]; total: number }>('/api/v1/security-alerts?status=open'),
  })
  const riskQuery = useQuery({
    queryKey: ['ops-risk-overview'],
    queryFn: () => api.get<{ risk: RiskOverview }>('/api/v1/analytics/risk'),
  })

  // PAM broker health (two reads, each defaulting every rendered field so a
  // sparse response can't crash the tile). Non-gating — the fabric overview
  // remains the primary gate; these degrade to "unknown"/down on failure.
  const brokerStatusQuery = useQuery({
    queryKey: ['ops-pam-broker-status'],
    queryFn: async (): Promise<PamBrokerStatusResp> => {
      const r = await api.get<Partial<PamBrokerStatusResp>>('/api/v1/access/pam/broker/status')
      return {
        available: r?.available ?? false,
        reach_modes: Array.isArray(r?.reach_modes) ? r.reach_modes : [],
        direct_broker: r?.direct_broker ?? false,
        ziti_broker: r?.ziti_broker ?? false,
      }
    },
    refetchInterval: 15000,
  })
  const guacHealthQuery = useQuery({
    queryKey: ['ops-guacamole-health'],
    queryFn: async (): Promise<GuacamoleHealthResp> => {
      const r = await api.get<Partial<GuacamoleHealthResp>>('/api/v1/access/health/guacamole')
      return {
        status: typeof r?.status === 'string' ? r.status : 'unknown',
        server_reachable: r?.server_reachable ?? false,
        authenticated: r?.authenticated ?? false,
        connections_count: r?.connections_count ?? 0,
        active_sessions: r?.active_sessions ?? 0,
        error_message: typeof r?.error_message === 'string' ? r.error_message : '',
      }
    },
    refetchInterval: 15000,
  })

  // Topology preview built from the same reads as network-topology.
  const buildInput: BuildInput = useMemo(() => {
    const identities = identitiesQuery.data?.identities ?? []
    const services = servicesQuery.data?.services ?? []
    const routers = Array.isArray(routersQuery.data) ? routersQuery.data : []
    const policies = Array.isArray(policiesQuery.data) ? policiesQuery.data : []
    return {
      identities: identities.map((i) => ({
        id: i.id,
        name: i.name,
        roleAttributes: i.attributes,
        disabled: i.disabled ?? i.enrolled === false,
      })),
      services: services.map((s) => ({ id: s.id, name: s.name, roleAttributes: s.roleAttributes })),
      routers: routers.map((r) => ({ id: r.id, name: r.name, online: r.isOnline })),
      servicePolicies: policies.map((p, idx) => ({
        id: p.id ?? `policy-${idx}`,
        name: p.name,
        type: p.type,
        identityRoles: p.identityRoles ?? [],
        serviceRoles: p.serviceRoles ?? [],
      })),
      sessions: [],
    }
  }, [identitiesQuery.data, servicesQuery.data, routersQuery.data, policiesQuery.data])

  const topology = useMemo(() => buildTopology(buildInput), [buildInput])

  const topLoading =
    identitiesQuery.isLoading || servicesQuery.isLoading ||
    routersQuery.isLoading || policiesQuery.isLoading

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <Gauge className="h-7 w-7 text-primary" />
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-foreground">Operations Cockpit</h1>
          <p className="text-muted-foreground">
            One situational-awareness surface for overlay health, device posture, and active threats —
            each tile drills into the source page.
          </p>
        </div>
      </div>

      {/* The fabric overview is the primary read — QueryGate owns its 401/403. */}
      <QueryGate query={overviewQuery} resource="operations cockpit">
        {(overview) => {
          const h = overview?.health
          const controllerUp = (h?.controller_reachable ?? statusQuery.data?.controller_reachable) ?? false

          return (
            <div className="space-y-6">
              {/* Health stat tiles */}
              <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
                <StatTile to="/ziti-network" title="Services" icon={Server} accent="text-purple-500"
                  description="Registered overlay services">
                  <TileValue
                    query={servicesQuery}
                    render={(d) => {
                      const total = d.services?.length ?? h?.services_count ?? 0
                      return <span>{total}</span>
                    }}
                  />
                </StatTile>

                <StatTile to="/ziti-network" title="Edge Routers" icon={Router}
                  description={
                    <RouterDesc overview={h} routers={routersQuery} />
                  }>
                  <TileValue
                    query={routersQuery}
                    render={(routers) => {
                      const list = Array.isArray(routers) ? routers : []
                      const online = h?.routers_online ?? list.filter((r) => r.isOnline).length
                      const total = h?.routers_total ?? list.length
                      return <span>{online}/{total}</span>
                    }}
                  />
                </StatTile>

                <StatTile to="/ziti-network" title="Active Sessions" icon={Activity} accent="text-orange-500"
                  description="Live overlay dial/bind sessions">
                  <TileValue
                    query={sessionsQuery}
                    render={(s) => <span>{Array.isArray(s) ? s.length : 0}</span>}
                  />
                </StatTile>

                <StatTile to="/zero-trust" title="Overlay Status" icon={Network}
                  accent={controllerUp ? 'text-green-500' : 'text-red-500'}
                  description={(h?.sdk_ready ?? statusQuery.data?.sdk_ready) ? 'SDK ready' : 'SDK not ready'}>
                  <span className={controllerUp ? 'text-green-500' : 'text-red-500'}>
                    {controllerUp ? 'Online' : 'Offline'}
                  </span>
                </StatTile>
              </div>

              {/* Posture + Security wider cards */}
              <div className="grid gap-4 lg:grid-cols-2">
                <PostureCard identities={identitiesQuery} />
                <SecurityCard alerts={alertsQuery} risk={riskQuery} />
              </div>

              {/* PAM broker health — the direct + ziti guacd brokers had zero
                  visibility (a wedged guacd went unseen for 6 weeks). */}
              <PamBrokersCard status={brokerStatusQuery} guac={guacHealthQuery} />

              {/* Topology preview */}
              <Card>
                <CardHeader className="flex flex-row items-center justify-between">
                  <CardTitle className="flex items-center gap-2 text-base text-foreground">
                    <Share2 className="h-4 w-4 text-primary" /> Overlay Topology
                  </CardTitle>
                  <Button variant="outline" size="sm" asChild>
                    <Link to="/network-topology">
                      <ExternalLink className="mr-2 h-4 w-4" /> Open full map
                    </Link>
                  </Button>
                </CardHeader>
                <CardContent>
                  {topLoading ? (
                    <Skeleton className="h-[320px] w-full" />
                  ) : (
                    <div className="h-[320px]">
                      <TopologyGraph topology={topology} interactive={false} />
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          )
        }}
      </QueryGate>
    </div>
  )
}

// ─── Router description (online/offline split) ─────────────────────────────────

function RouterDesc({
  overview,
  routers,
}: {
  overview?: FabricHealth
  routers: Pick<UseQueryResult<FabricRouterResp[]>, 'isLoading' | 'isError' | 'data'>
}) {
  if (routers.isLoading) return <span>Loading…</span>
  const list = Array.isArray(routers.data) ? routers.data : []
  const online = overview?.routers_online ?? list.filter((r) => r.isOnline).length
  const total = overview?.routers_total ?? list.length
  return <span>{online} online, {Math.max(0, total - online)} offline</span>
}

// ─── Posture tile ──────────────────────────────────────────────────────────────

function PostureCard({
  identities,
}: {
  identities: Pick<UseQueryResult<{ identities: ZitiIdentityResp[] }>, 'isLoading' | 'isError' | 'data'>
}) {
  const list = identities.data?.identities ?? []
  const compliant = list.filter((i) => i.enrolled && !i.disabled).length
  const atRisk = list.filter((i) => !i.enrolled || i.disabled).length

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between pb-2">
        <CardTitle className="flex items-center gap-2 text-base text-foreground">
          <ShieldCheck className="h-4 w-4 text-primary" /> Device Posture
        </CardTitle>
        <Link to="/devices" className="text-xs text-primary hover:underline inline-flex items-center gap-1">
          Devices <ArrowRight className="h-3 w-3" />
        </Link>
      </CardHeader>
      <CardContent>
        {identities.isLoading ? (
          <Skeleton className="h-14 w-full" />
        ) : identities.isError ? (
          <p className="text-2xl font-bold text-muted-foreground">—</p>
        ) : (
          <div className="flex items-center gap-8">
            <div>
              <div className="text-2xl font-bold text-green-500">{compliant}</div>
              <p className="text-xs text-muted-foreground">Enrolled &amp; compliant</p>
            </div>
            <div>
              <div className="text-2xl font-bold text-red-500">{atRisk}</div>
              <p className="text-xs text-muted-foreground">Unenrolled / disabled</p>
            </div>
          </div>
        )}
        <div className="mt-3 border-t border-border pt-3">
          <Link to="/zero-trust" className="text-xs text-primary hover:underline inline-flex items-center gap-1">
            Zero-trust posture policies <ArrowRight className="h-3 w-3" />
          </Link>
        </div>
      </CardContent>
    </Card>
  )
}

// ─── Security tile ─────────────────────────────────────────────────────────────

const severityVariant: Record<string, 'default' | 'destructive' | 'secondary'> = {
  critical: 'destructive',
  high: 'destructive',
  medium: 'secondary',
  low: 'secondary',
}

function SecurityCard({
  alerts,
  risk,
}: {
  alerts: Pick<UseQueryResult<{ alerts: SecurityAlert[]; total: number }>, 'isLoading' | 'isError' | 'data'>
  risk: Pick<UseQueryResult<{ risk: RiskOverview }>, 'isLoading' | 'isError' | 'data'>
}) {
  const openAlerts = alerts.data?.alerts ?? []
  const openCount = alerts.data?.total ?? openAlerts.length
  const top3 = openAlerts.slice(0, 3)

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between pb-2">
        <CardTitle className="flex items-center gap-2 text-base text-foreground">
          <ShieldAlert className="h-4 w-4 text-red-500" /> Open Threats
        </CardTitle>
        <Link to="/security-alerts" className="text-xs text-primary hover:underline inline-flex items-center gap-1">
          Alerts <ArrowRight className="h-3 w-3" />
        </Link>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex items-end gap-6">
          <div>
            {alerts.isLoading ? (
              <Skeleton className="h-8 w-16" />
            ) : (
              <div className="text-2xl font-bold text-foreground">
                {alerts.isError ? '—' : openCount}
              </div>
            )}
            <p className="text-xs text-muted-foreground">Open alerts</p>
          </div>
          <div>
            {risk.isLoading ? (
              <Skeleton className="h-8 w-16" />
            ) : (
              <div className="text-2xl font-bold text-foreground">
                {risk.isError || !risk.data ? '—' : risk.data.risk.active_alerts}
              </div>
            )}
            <p className="text-xs text-muted-foreground">Risk engine alerts</p>
          </div>
        </div>

        {top3.length > 0 && (
          <ul className="space-y-1.5 border-t border-border pt-3">
            {top3.map((a) => (
              <li key={a.id} className="flex items-center justify-between gap-2 text-sm">
                <span className="truncate text-foreground">{a.title}</span>
                <Badge variant={severityVariant[a.severity] ?? 'secondary'} className="shrink-0 capitalize">
                  {a.severity}
                </Badge>
              </li>
            ))}
          </ul>
        )}

        <div className="border-t border-border pt-3">
          <Link to="/risk-dashboard" className="text-xs text-primary hover:underline inline-flex items-center gap-1">
            Open risk dashboard <ArrowRight className="h-3 w-3" />
          </Link>
        </div>
      </CardContent>
    </Card>
  )
}

// ─── PAM broker health tile ────────────────────────────────────────────────────

const brokerBadgeVariant: Record<BrokerHealth, 'success' | 'warning' | 'destructive'> = {
  healthy: 'success',
  degraded: 'warning',
  down: 'destructive',
}
const brokerBadgeLabel: Record<BrokerHealth, string> = {
  healthy: 'Healthy',
  degraded: 'Degraded',
  down: 'Down',
}

/** Roll up the direct broker: configured? then reachable + authenticated. */
function directBrokerHealth(configured: boolean, guac: GuacamoleHealthResp | undefined): BrokerHealth {
  if (!configured) return 'down'
  if (!guac) return 'degraded' // configured but health unknown — don't claim healthy
  if (!guac.server_reachable) return 'down'
  if (!guac.authenticated) return 'degraded'
  return 'healthy'
}

/** One broker row: label, colored health badge, and detail lines. */
function BrokerRow({
  icon: Icon,
  name,
  health,
  loading,
  details,
}: {
  icon: typeof Server
  name: string
  health: BrokerHealth
  loading: boolean
  details: React.ReactNode
}) {
  return (
    <div className="flex items-start justify-between gap-3 rounded-lg border border-border p-3">
      <div className="flex items-start gap-2">
        <Icon className="mt-0.5 h-4 w-4 text-primary" />
        <div>
          <div className="text-sm font-medium text-foreground">{name}</div>
          <div className="mt-0.5 text-xs text-muted-foreground">{details}</div>
        </div>
      </div>
      {loading ? (
        <Skeleton className="h-5 w-16" />
      ) : (
        <Badge variant={brokerBadgeVariant[health]} className="shrink-0">
          {brokerBadgeLabel[health]}
        </Badge>
      )}
    </div>
  )
}

function PamBrokersCard({
  status,
  guac,
}: {
  status: Pick<UseQueryResult<PamBrokerStatusResp>, 'isLoading' | 'isError' | 'data'>
  guac: Pick<UseQueryResult<GuacamoleHealthResp>, 'isLoading' | 'isError' | 'data'>
}) {
  // Fall back to safe defaults so a failed/absent status read renders both
  // brokers as "down (unconfigured)" rather than crashing or masking.
  const s = status.data
  const directConfigured = s?.direct_broker ?? false
  const zitiConfigured = s?.ziti_broker ?? false
  const g = status.isError ? undefined : guac.data

  const directHealth = directBrokerHealth(directConfigured, guac.isError ? undefined : g)
  // The ziti broker only has a wiring signal exposed (broker + live overlay);
  // configured ⇒ healthy, otherwise down (unconfigured).
  const zitiHealth: BrokerHealth = zitiConfigured ? 'healthy' : 'down'

  const directDetails = !directConfigured ? (
    <span>Not configured</span>
  ) : status.isError ? (
    <span>Broker status unavailable</span>
  ) : (
    <>
      <div>guacd reachable: {g ? (g.server_reachable ? 'yes' : 'no') : 'unknown'}</div>
      <div>authenticated: {g ? (g.authenticated ? 'yes' : 'no') : 'unknown'}</div>
      {g && g.server_reachable && (
        <div>active sessions: {g.active_sessions}</div>
      )}
      {g?.error_message ? (
        <div className="text-red-500">{g.error_message}</div>
      ) : null}
    </>
  )

  const zitiDetails = zitiConfigured ? (
    <span>Broker configured, overlay linked</span>
  ) : (
    <span>Not configured (needs ziti broker + live overlay)</span>
  )

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between pb-2">
        <CardTitle className="flex items-center gap-2 text-base text-foreground">
          <KeyRound className="h-4 w-4 text-primary" /> PAM Brokers
        </CardTitle>
        <Link to="/pam-connections" className="text-xs text-primary hover:underline inline-flex items-center gap-1">
          Connections <ArrowRight className="h-3 w-3" />
        </Link>
      </CardHeader>
      <CardContent>
        {status.isError ? (
          <p className="text-sm text-muted-foreground">
            Broker status unavailable — treating brokers as unreachable.
          </p>
        ) : null}
        <div className="grid gap-3 sm:grid-cols-2">
          <BrokerRow
            icon={KeyRound}
            name="Direct broker"
            health={directHealth}
            loading={status.isLoading || (directConfigured && guac.isLoading)}
            details={directDetails}
          />
          <BrokerRow
            icon={ArrowRightLeft}
            name="Ziti broker"
            health={zitiHealth}
            loading={status.isLoading}
            details={zitiDetails}
          />
        </div>
      </CardContent>
    </Card>
  )
}

export default OpsCockpitPage
