// Network Setup — guided, visual OpenZiti onboarding.
//
// One backend call (GET /api/v1/access/ziti/setup/status) powers the whole
// page: a live topology strip, an ordered setup checklist with remediation,
// an install advisor (what must be installed for THIS deployment), and
// per-route next-hop advice that mirrors exactly what the reconciler does.
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  CheckCircle2,
  XCircle,
  AlertTriangle,
  ArrowRightCircle,
  MinusCircle,
  Lock,
  ChevronDown,
  ChevronRight,
  ExternalLink,
  RefreshCw,
  Network,
  Globe,
  Laptop,
  Router as RouterIcon,
  ServerCog,
  AppWindow,
  Shield,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '../components/ui/table'
import { QueryError } from '../components/query-error'
import { api } from '../lib/api'

// ─── API types (mirror internal/access/ziti_setup_handlers.go) ──────────────

interface SetupStep {
  id: string
  title: string
  description: string
  status: string
  detail?: string
  remediation?: string
  action_label?: string
  action_href?: string
}

interface SetupComponent {
  id: string
  name: string
  role: string
  required: 'required' | 'conditional' | 'optional'
  status: string
  detail?: string
  install?: string[]
}

interface RouteAdvice {
  route_name: string
  service_name: string
  to_url: string
  stored_mode: string
  effective_mode: string
  browzer_enabled: boolean
  route_enabled: boolean
  hop_port?: number
  next_hop: string
  client_side: string
  reconcile_state: string
  requirements?: string[]
  warnings?: string[]
}

interface RouterInfo {
  id: string
  name: string
  hostname: string
  isOnline: boolean
}

interface SetupSyncStatus {
  unsynced_users: number
  total_users: number
  total_identities: number
}

interface SetupStatus {
  ready: boolean
  summary: string
  console_url?: string
  steps: SetupStep[]
  components: SetupComponent[]
  routes: RouteAdvice[] | null
  routers: RouterInfo[] | null
  sync_status?: SetupSyncStatus
}

// ─── Status visuals ──────────────────────────────────────────────────────────

const STATUS_META: Record<string, { icon: typeof CheckCircle2; className: string; label: string }> = {
  complete: { icon: CheckCircle2, className: 'text-green-600', label: 'Complete' },
  warning: { icon: AlertTriangle, className: 'text-amber-500', label: 'Warning' },
  action_needed: { icon: ArrowRightCircle, className: 'text-blue-500', label: 'Action needed' },
  error: { icon: XCircle, className: 'text-red-500', label: 'Error' },
  blocked: { icon: Lock, className: 'text-muted-foreground', label: 'Blocked' },
  optional: { icon: MinusCircle, className: 'text-muted-foreground', label: 'Optional' },
}

function StatusIcon({ status, className = 'h-5 w-5' }: { status: string; className?: string }) {
  const meta = STATUS_META[status] ?? STATUS_META.optional
  const Icon = meta.icon
  return <Icon className={`${className} ${meta.className}`} aria-label={meta.label} />
}

function statusBadgeClass(status: string): string {
  switch (status) {
    case 'complete':
      return 'bg-green-100 text-green-700'
    case 'warning':
      return 'bg-amber-100 text-amber-700'
    case 'action_needed':
      return 'bg-blue-100 text-blue-700'
    case 'error':
      return 'bg-red-100 text-red-700'
    default:
      return 'bg-muted text-muted-foreground'
  }
}

function modeBadgeClass(mode: string): string {
  switch (mode) {
    case 'identity':
      return 'bg-purple-100 text-purple-700'
    case 'direct':
      return 'bg-blue-100 text-blue-700'
    case 'hop':
      return 'bg-orange-100 text-orange-700'
    default:
      return 'bg-muted text-muted-foreground'
  }
}

// ─── Topology strip ──────────────────────────────────────────────────────────

interface TopoNode {
  label: string
  sub?: string
  ok: boolean | null // null = unknown/neutral
}

function TopoColumn({ title, icon: Icon, nodes }: { title: string; icon: typeof Globe; nodes: TopoNode[] }) {
  return (
    <div className="flex min-w-[9.5rem] flex-1 flex-col gap-2">
      <div className="flex items-center gap-1.5 text-xs font-medium uppercase tracking-wide text-muted-foreground">
        <Icon className="h-3.5 w-3.5" />
        {title}
      </div>
      {nodes.map((n, i) => (
        <div key={i} className="rounded-lg border bg-card px-3 py-2 text-sm shadow-sm">
          <div className="flex items-center gap-2">
            <span
              className={`h-2 w-2 shrink-0 rounded-full ${
                n.ok === null ? 'bg-muted-foreground/40' : n.ok ? 'bg-green-500' : 'bg-red-500'
              }`}
            />
            <span className="truncate font-medium">{n.label}</span>
          </div>
          {n.sub && <div className="mt-0.5 truncate pl-4 text-xs text-muted-foreground">{n.sub}</div>}
        </div>
      ))}
      {nodes.length === 0 && (
        <div className="rounded-lg border border-dashed px-3 py-2 text-xs text-muted-foreground">none yet</div>
      )}
    </div>
  )
}

function TopoArrow() {
  return (
    <div className="flex items-center self-stretch px-1 pt-6 text-muted-foreground/50">
      <ChevronRight className="h-5 w-5" />
    </div>
  )
}

// TopologyStrip draws the data path left→right: who connects, through what,
// governed by which control plane, to reach which applications.
function TopologyStrip({ data }: { data: SetupStatus }) {
  const routes = data.routes ?? []
  const routers = data.routers ?? []
  const step = (id: string) => data.steps.find((s) => s.id === id)
  const comp = (id: string) => data.components.find((c) => c.id === id)

  const browzerRoutes = routes.filter((r) => r.browzer_enabled).length
  const identityRoutes = routes.filter((r) => r.effective_mode === 'identity').length

  const clients: TopoNode[] = []
  if (browzerRoutes > 0 || comp('browzer')?.status === 'complete') {
    clients.push({
      label: 'Browser (BrowZer)',
      sub: `${browzerRoutes} web app(s), nothing installed`,
      ok: comp('browzer')?.status === 'complete',
    })
  }
  clients.push({
    label: 'Tunneler / Agent',
    sub:
      identityRoutes > 0
        ? `needed for ${identityRoutes} identity-mode app(s)`
        : 'Ziti Desktop/Mobile Edge, OpenIDX Agent',
    ok: null,
  })

  const routerNodes: TopoNode[] = routers.slice(0, 3).map((r) => ({
    label: r.name,
    sub: r.hostname || undefined,
    ok: r.isOnline,
  }))
  if (routers.length > 3) {
    routerNodes.push({ label: `+${routers.length - 3} more`, ok: null })
  }

  const controllerOK = step('controller')?.status === 'complete'
  const proxyOK = step('access_proxy')?.status === 'complete'
  const controlNodes: TopoNode[] = [
    { label: 'Ziti Controller', sub: 'policies · identities', ok: controllerOK },
    { label: 'OpenIDX access-proxy', sub: 'identity headers', ok: proxyOK },
  ]

  const appNodes: TopoNode[] = routes.slice(0, 3).map((r) => ({
    label: r.route_name,
    sub: `${r.effective_mode} → ${r.to_url}`,
    ok: r.reconcile_state === 'synced' ? true : r.reconcile_state.startsWith('error') ? false : null,
  }))
  if (routes.length > 3) {
    appNodes.push({ label: `+${routes.length - 3} more`, ok: null })
  }

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <Network className="h-4 w-4" />
          Network at a glance
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="overflow-x-auto">
          <div className="flex min-w-[44rem] items-start gap-1">
            <TopoColumn title="Clients" icon={Laptop} nodes={clients} />
            <TopoArrow />
            <TopoColumn title="Edge Routers" icon={RouterIcon} nodes={routerNodes} />
            <TopoArrow />
            <TopoColumn title="Control Plane" icon={ServerCog} nodes={controlNodes} />
            <TopoArrow />
            <TopoColumn title="Applications" icon={AppWindow} nodes={appNodes} />
          </div>
        </div>
      </CardContent>
    </Card>
  )
}

// ─── Setup checklist ─────────────────────────────────────────────────────────

function SetupStepRow({ step, index }: { step: SetupStep; index: number }) {
  return (
    <li className="relative flex gap-4 pb-8 last:pb-0">
      {/* vertical connector */}
      <div className="absolute left-[15px] top-8 h-full w-px bg-border last:hidden" aria-hidden />
      <div className="z-10 flex h-8 w-8 shrink-0 items-center justify-center rounded-full border bg-background">
        {step.status === 'complete' ? (
          <CheckCircle2 className="h-5 w-5 text-green-600" />
        ) : (
          <span className="text-sm font-semibold text-muted-foreground">{index + 1}</span>
        )}
      </div>
      <div className="min-w-0 flex-1 space-y-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-medium">{step.title}</span>
          <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${statusBadgeClass(step.status)}`}>
            {(STATUS_META[step.status] ?? STATUS_META.optional).label}
          </span>
        </div>
        <p className="text-sm text-muted-foreground">{step.description}</p>
        {step.detail && <p className="text-sm">{step.detail}</p>}
        {step.remediation && step.status !== 'complete' && (
          <div className="mt-1 flex items-start gap-2 rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-800">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
            <span>{step.remediation}</span>
          </div>
        )}
        {step.action_href && step.action_label && (
          <Button asChild variant="outline" size="sm" className="mt-1">
            <Link to={step.action_href}>{step.action_label}</Link>
          </Button>
        )}
      </div>
    </li>
  )
}

// ─── Install advisor ─────────────────────────────────────────────────────────

function requiredBadge(required: SetupComponent['required']) {
  switch (required) {
    case 'required':
      return <Badge className="bg-red-100 text-red-700 hover:bg-red-100">Required</Badge>
    case 'conditional':
      return <Badge className="bg-amber-100 text-amber-700 hover:bg-amber-100">Needed for your setup</Badge>
    default:
      return <Badge variant="outline">Optional</Badge>
  }
}

function ComponentCard({ comp }: { comp: SetupComponent }) {
  const [open, setOpen] = useState(false)
  return (
    <Card>
      <CardContent className="pt-5">
        <div className="flex items-start justify-between gap-2">
          <div className="flex items-center gap-2">
            <StatusIcon status={comp.status} className="h-4 w-4" />
            <span className="font-medium">{comp.name}</span>
          </div>
          {requiredBadge(comp.required)}
        </div>
        <p className="mt-2 text-sm text-muted-foreground">{comp.role}</p>
        {comp.detail && <p className="mt-1 text-xs text-muted-foreground">{comp.detail}</p>}
        {comp.install && comp.install.length > 0 && (
          <button
            type="button"
            className="mt-2 flex items-center gap-1 text-sm font-medium text-primary"
            onClick={() => setOpen(!open)}
          >
            {open ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
            How to install
          </button>
        )}
        {open && comp.install && (
          <ul className="mt-2 space-y-1.5">
            {comp.install.map((line, i) => (
              <li key={i} className="rounded bg-muted px-2.5 py-1.5 font-mono text-xs leading-relaxed">
                {line}
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  )
}

// ─── Route advice table ──────────────────────────────────────────────────────

function reconcileBadge(state: string) {
  if (state === 'synced') return <Badge className="bg-green-100 text-green-700 hover:bg-green-100">synced</Badge>
  if (state.startsWith('error'))
    return (
      <Badge className="bg-red-100 text-red-700 hover:bg-red-100" title={state}>
        error
      </Badge>
    )
  return <Badge variant="outline">{state.split('_').join(' ')}</Badge>
}

function RouteRow({ route }: { route: RouteAdvice }) {
  const [open, setOpen] = useState(false)
  const autoCorrected = route.stored_mode !== route.effective_mode
  return (
    <>
      <TableRow className="cursor-pointer hover:bg-muted/50" onClick={() => setOpen(!open)}>
        <TableCell>
          <div className="flex items-center gap-1.5">
            {open ? (
              <ChevronDown className="h-4 w-4 text-muted-foreground" />
            ) : (
              <ChevronRight className="h-4 w-4 text-muted-foreground" />
            )}
            <span className="font-medium">{route.route_name}</span>
            {route.browzer_enabled && (
              <Badge variant="outline" className="text-xs">
                BrowZer
              </Badge>
            )}
          </div>
        </TableCell>
        <TableCell>
          <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${modeBadgeClass(route.effective_mode)}`}>
            {route.effective_mode}
          </span>
          {autoCorrected && (
            <span
              className="ml-1.5 inline-flex items-center text-amber-500"
              title={`Stored as '${route.stored_mode}', applied as '${route.effective_mode}'`}
            >
              <AlertTriangle className="h-3.5 w-3.5" />
            </span>
          )}
        </TableCell>
        <TableCell className="max-w-[16rem] truncate text-sm text-muted-foreground" title={route.to_url}>
          {route.to_url}
        </TableCell>
        <TableCell>{reconcileBadge(route.route_enabled ? route.reconcile_state : 'route_disabled')}</TableCell>
      </TableRow>
      {open && (
        <TableRow className="bg-muted/30 hover:bg-muted/30">
          <TableCell colSpan={4} className="space-y-3 py-4">
            <div>
              <div className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Data path</div>
              <p className="mt-1 font-mono text-xs">{route.next_hop}</p>
            </div>
            <div>
              <div className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Client side</div>
              <p className="mt-1 text-sm">{route.client_side}</p>
            </div>
            {route.requirements && route.requirements.length > 0 && (
              <div>
                <div className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Requires</div>
                <ul className="mt-1 list-inside list-disc space-y-0.5 text-sm">
                  {route.requirements.map((r, i) => (
                    <li key={i}>{r}</li>
                  ))}
                </ul>
              </div>
            )}
            {route.warnings && route.warnings.length > 0 && (
              <div className="flex items-start gap-2 rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-800">
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                <div className="space-y-0.5">
                  {route.warnings.map((w, i) => (
                    <p key={i}>{w}</p>
                  ))}
                </div>
              </div>
            )}
            {route.reconcile_state.startsWith('error') && (
              <div className="flex items-start gap-2 rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800">
                <XCircle className="mt-0.5 h-4 w-4 shrink-0" />
                <span>{route.reconcile_state}</span>
              </div>
            )}
          </TableCell>
        </TableRow>
      )}
    </>
  )
}

// ─── Page ────────────────────────────────────────────────────────────────────

export function ZitiSetupPage() {
  const {
    data,
    isLoading,
    isError,
    error,
    refetch,
    isFetching,
  } = useQuery({
    queryKey: ['ziti-setup-status'],
    queryFn: () => api.get<SetupStatus>('/api/v1/access/ziti/setup/status'),
    refetchInterval: 15000,
  })

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Network Setup</h1>
          <p className="text-muted-foreground">
            Everything needed to run your zero-trust network — what's done, what's missing, and what to install.
          </p>
        </div>
        <div className="flex items-center gap-3">
          {data && (
            <span
              className={`flex items-center gap-1.5 rounded-full px-3 py-1 text-sm font-medium ${
                data.ready ? 'bg-green-100 text-green-700' : 'bg-amber-100 text-amber-700'
              }`}
            >
              <Shield className="h-4 w-4" />
              {data.ready ? 'Network ready' : data.summary}
            </span>
          )}
          {data?.console_url && (
            <Button variant="outline" size="sm" asChild>
              <a href={data.console_url} target="_blank" rel="noreferrer">
                <ExternalLink className="mr-1.5 h-4 w-4" />
                Ziti Console
              </a>
            </Button>
          )}
          <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isFetching}>
            <RefreshCw className={`mr-1.5 h-4 w-4 ${isFetching ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
        </div>
      </div>

      {isLoading && <p className="text-sm text-muted-foreground">Loading network state…</p>}

      {isError && <QueryError error={error} resource="the network setup status" />}

      {data && (
        <>
          <TopologyStrip data={data} />

          <div className="grid gap-6 lg:grid-cols-5">
            <Card className="lg:col-span-3">
              <CardHeader>
                <CardTitle className="text-base">Setup checklist</CardTitle>
              </CardHeader>
              <CardContent>
                <ol>
                  {data.steps.map((step, i) => (
                    <SetupStepRow key={step.id} step={step} index={i} />
                  ))}
                </ol>
              </CardContent>
            </Card>

            <div className="space-y-4 lg:col-span-2">
              <h2 className="text-sm font-medium uppercase tracking-wide text-muted-foreground">
                What you need to install
              </h2>
              {data.components.map((comp) => (
                <ComponentCard key={comp.id} comp={comp} />
              ))}
            </div>
          </div>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">Your applications on the network</CardTitle>
              <p className="text-sm text-muted-foreground">
                Per route: the hosting mode actually applied, the full data path, and what each side needs. Click a
                row for details.
              </p>
            </CardHeader>
            <CardContent>
              {(data.routes ?? []).length === 0 ? (
                <div className="rounded-lg border border-dashed py-8 text-center text-sm text-muted-foreground">
                  No Ziti-enabled routes yet.{' '}
                  <Link to="/proxy-routes" className="font-medium text-primary underline-offset-2 hover:underline">
                    Expose your first app →
                  </Link>
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Route</TableHead>
                      <TableHead>Mode</TableHead>
                      <TableHead>Upstream</TableHead>
                      <TableHead>State</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {(data.routes ?? []).map((route) => (
                      <RouteRow key={route.service_name || route.route_name} route={route} />
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </>
      )}
    </div>
  )
}
