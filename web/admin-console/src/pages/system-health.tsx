import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Activity,
  Database,
  Server,
  RefreshCw,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Clock,
  Wand2,
  ShieldCheck,
  Wrench,
} from 'lucide-react'
import { Button } from '../components/ui/button'
import { Badge } from '../components/ui/badge'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '../components/ui/card'
import { useToast } from '../hooks/use-toast'
import { QueryError } from '../components/query-error'
import { api } from '../lib/api'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface DependencyHealth {
  name: string
  status: 'up' | 'degraded' | 'down'
  latency_ms: number
  last_checked: string
  details?: string
}

interface HealthResponse {
  status: 'healthy' | 'degraded' | 'unhealthy'
  uptime_seconds: number
  version?: string
  dependencies: DependencyHealth[]
}

// Raw shape returned by GET /api/v1/system/health (admin-api). Dependency status
// is healthy/degraded/unhealthy there; the UI vocabulary is up/degraded/down.
interface RawDependency {
  name: string
  status: string
  latency_ms?: number
  details?: string
}
interface RawSystemHealth {
  status?: string
  uptime?: string
  timestamp?: string
  version?: string
  dependencies?: RawDependency[]
}

// Map a backend dependency status to the UI's up/degraded/down vocabulary.
function depStatus(s: string): 'up' | 'degraded' | 'down' {
  switch (s) {
    case 'healthy':
    case 'up':
      return 'up'
    case 'degraded':
      return 'degraded'
    default:
      return 'down' // unhealthy, unknown, empty
  }
}

// Coerce the aggregated backend payload into the shape this page renders. This
// keeps the component's markup stable regardless of the backend's exact status
// vocabulary.
function normalizeHealth(raw: RawSystemHealth): HealthResponse {
  const deps = raw.dependencies || []
  const overall: 'healthy' | 'degraded' | 'unhealthy' =
    raw.status === 'healthy' || raw.status === 'up'
      ? 'healthy'
      : raw.status === 'degraded'
        ? 'degraded'
        : raw.status === 'unhealthy' || raw.status === 'down'
          ? 'unhealthy'
          : 'unhealthy'
  return {
    status: overall,
    uptime_seconds: 0,
    version: raw.version,
    dependencies: deps.map(d => ({
      name: d.name,
      status: depStatus(d.status),
      latency_ms: d.latency_ms ?? 0,
      last_checked: raw.timestamp || '',
      details: d.details,
    })),
  }
}

// Relations & Integrity Doctor types — mirrors the backend Finding/Report
// shape returned by GET /api/v1/access/health/relations.
interface Finding {
  check_id: string
  domain: string
  severity: string
  status: string
  subject: string
  detail: string
  safe: boolean
  action: string
}

interface RelationsReport {
  findings: Finding[]
  healed?: Finding[]
  remaining?: Finding[]
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatUptime(seconds: number): string {
  const days = Math.floor(seconds / 86400)
  const hours = Math.floor((seconds % 86400) / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  const parts: string[] = []
  if (days > 0) parts.push(`${days}d`)
  if (hours > 0) parts.push(`${hours}h`)
  parts.push(`${minutes}m`)
  return parts.join(' ')
}

function formatTimestamp(iso: string): string {
  try {
    return new Date(iso).toLocaleString()
  } catch {
    return iso
  }
}

const STATUS_CONFIG = {
  healthy: {
    label: 'Healthy',
    bgColor: 'bg-green-50 border-green-200',
    textColor: 'text-green-800',
    icon: CheckCircle2,
    iconColor: 'text-green-600',
  },
  degraded: {
    label: 'Degraded',
    bgColor: 'bg-yellow-50 border-yellow-200',
    textColor: 'text-yellow-800',
    icon: AlertTriangle,
    iconColor: 'text-yellow-600',
  },
  unhealthy: {
    label: 'Unhealthy',
    bgColor: 'bg-red-50 border-red-200',
    textColor: 'text-red-800',
    icon: XCircle,
    iconColor: 'text-red-600',
  },
} as const

const DEP_STATUS_CONFIG = {
  up: {
    dotColor: 'bg-green-500',
    label: 'Up',
    badgeClass: 'bg-green-100 text-green-800 border-green-200',
  },
  degraded: {
    dotColor: 'bg-yellow-500',
    label: 'Degraded',
    badgeClass: 'bg-yellow-100 text-yellow-800 border-yellow-200',
  },
  down: {
    dotColor: 'bg-red-500',
    label: 'Down',
    badgeClass: 'bg-red-100 text-red-800 border-red-200',
  },
} as const

const DEP_ICONS: Record<string, React.ElementType> = {
  PostgreSQL: Database,
  Redis: Server,
  Elasticsearch: Activity,
  OPA: Server,
}

const SEVERITY_BADGE: Record<string, string> = {
  critical: 'bg-red-100 text-red-800 border-red-200',
  high: 'bg-red-100 text-red-800 border-red-200',
  warning: 'bg-yellow-100 text-yellow-800 border-yellow-200',
  medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
  info: 'bg-blue-100 text-blue-800 border-blue-200',
  low: 'bg-blue-100 text-blue-800 border-blue-200',
}

function severityClass(severity: string): string {
  return SEVERITY_BADGE[severity?.toLowerCase()] || 'bg-muted text-foreground border-border'
}

// ---------------------------------------------------------------------------
// Relations & Integrity Doctor
// ---------------------------------------------------------------------------

function RelationsDoctor() {
  const queryClient = useQueryClient()
  const { toast } = useToast()

  const { data, isLoading, isFetching } = useQuery({
    queryKey: ['health-relations'],
    queryFn: () => api.get<RelationsReport>('/api/v1/access/health/relations'),
  })

  const heal = useMutation({
    mutationFn: () => api.get<RelationsReport>('/api/v1/access/health/relations?heal=safe'),
    onSuccess: (report) => {
      toast({
        title: 'Scan complete',
        description: `${report.healed?.length ?? 0} safe fix(es) applied, ${report.remaining?.length ?? 0} remaining.`,
        variant: 'success',
      })
      queryClient.invalidateQueries({ queryKey: ['health-relations'] })
    },
    onError: (e: Error) => {
      toast({ title: 'Heal failed', description: e.message, variant: 'destructive' })
    },
  })

  const fix = useMutation({
    mutationFn: (f: Finding) => api.post(`/api/v1/access/health/fix/${f.check_id}`, { subject: f.subject }),
    onSuccess: () => {
      toast({ title: 'Fix applied', variant: 'success' })
      queryClient.invalidateQueries({ queryKey: ['health-relations'] })
    },
    onError: (e: Error) => {
      toast({ title: 'Fix failed', description: e.message, variant: 'destructive' })
    },
  })

  // Only surface findings that represent drift (anything not "ok").
  const findings = (data?.findings ?? []).filter((f) => f.status !== 'ok')

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-lg font-semibold">Relations &amp; Integrity</h3>
          <p className="text-sm text-muted-foreground">
            Cross-domain relations &amp; referential integrity across the access fabric
          </p>
        </div>
        <Button onClick={() => heal.mutate()} disabled={heal.isPending || isFetching}>
          <Wand2 className={`mr-2 h-4 w-4 ${heal.isPending ? 'animate-pulse' : ''}`} />
          {heal.isPending ? 'Healing...' : 'Scan & Heal (safe)'}
        </Button>
      </div>

      {isLoading ? (
        <Card>
          <CardContent className="py-8 text-center text-sm text-muted-foreground">
            Scanning relations...
          </CardContent>
        </Card>
      ) : findings.length === 0 ? (
        <Card>
          <CardContent className="py-8 text-center">
            <ShieldCheck className="h-10 w-10 mx-auto text-green-500 mb-3" />
            <p className="font-medium">No drift detected</p>
            <p className="text-sm text-muted-foreground">
              All cross-domain relations are consistent.
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {findings.map((f, i) => (
            <Card key={`${f.check_id}-${f.subject}-${i}`}>
              <CardContent className="py-4 flex items-start justify-between gap-4">
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <Badge variant="outline">{f.domain}</Badge>
                    <span
                      className={`text-xs font-medium px-2 py-0.5 rounded-full border ${severityClass(f.severity)}`}
                    >
                      {f.severity || f.status}
                    </span>
                    <code className="text-xs bg-muted px-1.5 py-0.5 rounded">{f.check_id}</code>
                  </div>
                  <p className="text-sm mt-1.5 break-words">{f.detail || f.subject}</p>
                  {f.detail && f.subject && (
                    <p className="text-xs text-muted-foreground mt-0.5 break-words">
                      Subject: {f.subject}
                    </p>
                  )}
                </div>
                <div className="shrink-0">
                  {f.safe ? (
                    <span className="text-xs text-green-600 whitespace-nowrap">
                      auto-heals on scan
                    </span>
                  ) : (
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={fix.isPending}
                      onClick={() => fix.mutate(f)}
                    >
                      <Wrench className="mr-1.5 h-3.5 w-3.5" />
                      {f.action || 'Fix'}
                    </Button>
                  )}
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function SystemHealthPage() {
  const { toast } = useToast()
  const queryClient = useQueryClient()

  const {
    data: health,
    isLoading,
    isError,
    error,
    isFetching,
    dataUpdatedAt,
  } = useQuery({
    queryKey: ['system-health'],
    queryFn: () => api_get_health(),
    refetchInterval: 30_000,
  })

  // We use the api helper (auth + baseURL handled centrally) and hit the
  // aggregated system-health endpoint served by admin-api and routed at the edge
  // under /api/*. (The previous `${baseURL}/health` had no backend route at the
  // edge — it hit the SPA fallback and returned index.html, so the JSON parse
  // failed and the page always rendered "Unhealthy".)
  async function api_get_health(): Promise<HealthResponse> {
    const raw = await api.get<RawSystemHealth>('/api/v1/system/health')
    return normalizeHealth(raw)
  }

  const handleRefresh = () => {
    queryClient.invalidateQueries({ queryKey: ['system-health'] })
    toast({ title: 'Refreshing', description: 'Checking system health...' })
  }

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------

  if (isLoading) {
    return (
      <div className="space-y-6">
        <h1 className="text-3xl font-bold tracking-tight">System Health</h1>
        <p className="text-center py-8">Loading health status...</p>
      </div>
    )
  }

  // A failed/403 health load is distinct from a real outage: surface it as an
  // error rather than a misleading "Unhealthy" banner.
  if (isError) {
    return (
      <div className="space-y-6">
        <h1 className="text-3xl font-bold tracking-tight">System Health</h1>
        <QueryError error={error} resource="system health" />
      </div>
    )
  }

  const overallStatus = health?.status || 'unhealthy'
  const config = STATUS_CONFIG[overallStatus]
  const StatusIcon = config.icon

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">System Health</h1>
          <p className="text-muted-foreground">
            Monitor OpenIDX platform dependencies and uptime
          </p>
        </div>
        <div className="flex items-center gap-3">
          {dataUpdatedAt > 0 && (
            <span className="text-xs text-muted-foreground">
              Last checked: {new Date(dataUpdatedAt).toLocaleTimeString()}
            </span>
          )}
          <Button
            variant="outline"
            onClick={handleRefresh}
            disabled={isFetching}
          >
            <RefreshCw
              className={`mr-2 h-4 w-4 ${isFetching ? 'animate-spin' : ''}`}
            />
            {isFetching ? 'Checking...' : 'Check Now'}
          </Button>
        </div>
      </div>

      {/* Overall status banner */}
      <div className={`rounded-lg border p-6 ${config.bgColor}`}>
        <div className="flex items-center gap-4">
          <StatusIcon className={`h-10 w-10 ${config.iconColor}`} />
          <div>
            <h2 className={`text-2xl font-bold ${config.textColor}`}>
              System {config.label}
            </h2>
            <div className="flex items-center gap-4 mt-1">
              {health && (
                <>
                  <div className="flex items-center gap-1 text-sm text-muted-foreground">
                    <Clock className="h-4 w-4" />
                    Uptime: {formatUptime(health.uptime_seconds)}
                  </div>
                  {health.version && (
                    <Badge variant="outline">{health.version}</Badge>
                  )}
                </>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Dependency cards */}
      <div>
        <h3 className="text-lg font-semibold mb-4">Dependencies</h3>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          {(health?.dependencies || []).map((dep) => {
            const depConfig = DEP_STATUS_CONFIG[dep.status]
            const DepIcon = DEP_ICONS[dep.name] || Server

            return (
              <Card key={dep.name}>
                <CardHeader className="pb-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <DepIcon className="h-5 w-5 text-muted-foreground" />
                      <CardTitle className="text-base">{dep.name}</CardTitle>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <span
                        className={`inline-block h-2.5 w-2.5 rounded-full ${depConfig.dotColor}`}
                      />
                      <span
                        className={`text-xs font-medium px-2 py-0.5 rounded-full border ${depConfig.badgeClass}`}
                      >
                        {depConfig.label}
                      </span>
                    </div>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-muted-foreground">Latency</span>
                      <span className="font-mono font-medium">
                        {dep.latency_ms}ms
                      </span>
                    </div>
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-muted-foreground">Last Checked</span>
                      <span className="text-xs">
                        {formatTimestamp(dep.last_checked)}
                      </span>
                    </div>
                    {dep.details && (
                      <p className="text-xs text-muted-foreground border-t pt-2 mt-2">
                        {dep.details}
                      </p>
                    )}
                  </div>
                </CardContent>
              </Card>
            )
          })}
        </div>
      </div>

      {/* Relations & Integrity Doctor */}
      <RelationsDoctor />

      {/* Empty state if no health data */}
      {!health && (
        <Card>
          <CardContent className="py-12 text-center">
            <XCircle className="h-12 w-12 mx-auto text-red-400 mb-4" />
            <CardTitle className="mb-2">Unable to Retrieve Health Status</CardTitle>
            <CardDescription>
              The health endpoint did not respond. Verify that the platform services are running.
            </CardDescription>
            <Button variant="outline" className="mt-4" onClick={handleRefresh}>
              <RefreshCw className="mr-2 h-4 w-4" />
              Retry
            </Button>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
