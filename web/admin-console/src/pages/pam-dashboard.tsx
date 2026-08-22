import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  AlertTriangle,
  CheckCircle2,
  Clock,
  Gavel,
  KeyRound,
  MonitorPlay,
  RefreshCw,
  Vault,
} from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'
import { api } from '../lib/api'

interface PAMOverview {
  secrets: { total: number; by_type: Record<string, number> }
  rotation: {
    policies: number
    policies_enabled: number
    policies_failing: number
    policies_overdue: number
    runs_30d: number
    failures_30d: number
  }
  checkouts: {
    active_leases: number
    checkouts_30d: number
    pending_credential_requests: number
  }
  sessions: {
    active_sessions: number
    sessions_30d: number
    pending_requests: number
    recordings_on_hold: number
  }
  generated_at: string
}

// One stat line inside a section card: label + value in text tokens; color only
// ever accompanies an icon + label (status is never conveyed by color alone).
function StatRow({ label, value, alert }: { label: string; value: number; alert?: boolean }) {
  return (
    <div className="flex items-center justify-between py-1">
      <span className="text-sm text-muted-foreground flex items-center gap-1.5">
        {alert && value > 0 && <AlertTriangle className="h-3.5 w-3.5 text-red-600" />}
        {label}
      </span>
      <span className={`text-sm font-semibold tabular-nums ${alert && value > 0 ? 'text-red-600' : ''}`}>
        {value}
      </span>
    </div>
  )
}

export function PAMDashboardPage() {
  const { data, isLoading, error } = useQuery({
    queryKey: ['pam-overview'],
    queryFn: () => api.get<PAMOverview>('/api/v1/pam/overview'),
    refetchInterval: 30000,
  })

  if (isLoading) {
    return (
      <div className="flex justify-center py-12">
        <LoadingSpinner size="lg" />
      </div>
    )
  }

  if (error) {
    return <QueryError error={error} resource="PAM overview" />
  }

  if (!data) return null

  const rotationHealthy = data.rotation.policies_failing === 0 && data.rotation.policies_overdue === 0
  const needsAttention =
    data.checkouts.pending_credential_requests + data.sessions.pending_requests

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Privileged Access</h1>
          <p className="text-muted-foreground">
            Vault inventory, rotation health, checkout activity, and privileged sessions
          </p>
        </div>
        <span className="text-xs text-muted-foreground">
          Updated {new Date(data.generated_at).toLocaleTimeString()}
        </span>
      </div>

      {/* Headline tiles */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Vault Secrets</CardTitle>
            <Vault className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold tabular-nums">{data.secrets.total}</div>
            <div className="mt-1 flex flex-wrap gap-1">
              {Object.entries(data.secrets.by_type).map(([type, count]) => (
                <Badge key={type} variant="outline" className="text-xs">
                  {type}: {count}
                </Badge>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Leases</CardTitle>
            <KeyRound className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold tabular-nums">{data.checkouts.active_leases}</div>
            <p className="text-xs text-muted-foreground mt-1">
              {data.checkouts.checkouts_30d} checkouts in the last 30 days
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Sessions</CardTitle>
            <MonitorPlay className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold tabular-nums">{data.sessions.active_sessions}</div>
            <p className="text-xs text-muted-foreground mt-1">
              {data.sessions.sessions_30d} sessions in the last 30 days
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Pending Approvals</CardTitle>
            <Clock className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold tabular-nums">{needsAttention}</div>
            <p className="text-xs text-muted-foreground mt-1">
              {data.checkouts.pending_credential_requests} credential ·{' '}
              {data.sessions.pending_requests} session
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Detail sections */}
      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-sm font-medium">
              <RefreshCw className="h-4 w-4" />
              Rotation Health
              {rotationHealthy ? (
                <span className="inline-flex items-center gap-1 text-xs font-medium text-green-700">
                  <CheckCircle2 className="h-3.5 w-3.5" />
                  Healthy
                </span>
              ) : (
                <span className="inline-flex items-center gap-1 text-xs font-medium text-red-600">
                  <AlertTriangle className="h-3.5 w-3.5" />
                  Needs attention
                </span>
              )}
            </CardTitle>
            <CardDescription>Credential rotation policies and recent runs</CardDescription>
          </CardHeader>
          <CardContent className="divide-y">
            <StatRow label="Policies" value={data.rotation.policies} />
            <StatRow label="Enabled" value={data.rotation.policies_enabled} />
            <StatRow label="Failing (last run)" value={data.rotation.policies_failing} alert />
            <StatRow label="Overdue" value={data.rotation.policies_overdue} alert />
            <StatRow label="Runs (30 days)" value={data.rotation.runs_30d} />
            <StatRow label="Failed runs (30 days)" value={data.rotation.failures_30d} alert />
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-sm font-medium">
              <Gavel className="h-4 w-4" />
              Session Assurance
            </CardTitle>
            <CardDescription>Brokered privileged sessions and recording holds</CardDescription>
          </CardHeader>
          <CardContent className="divide-y">
            <StatRow label="Active sessions" value={data.sessions.active_sessions} />
            <StatRow label="Sessions (30 days)" value={data.sessions.sessions_30d} />
            <StatRow label="Pending session requests" value={data.sessions.pending_requests} />
            <StatRow label="Recordings on legal hold" value={data.sessions.recordings_on_hold} />
          </CardContent>
        </Card>
      </div>

      {/* Manage links */}
      <div className="grid gap-3 sm:grid-cols-3">
        <Link
          to="/vault-secrets"
          className="flex items-center gap-2 rounded-md border bg-background p-3 text-sm font-medium transition-shadow hover:shadow-md"
        >
          <KeyRound className="h-4 w-4 text-purple-600" />
          Manage Vault Secrets
        </Link>
        <Link
          to="/rotation-policies"
          className="flex items-center gap-2 rounded-md border bg-background p-3 text-sm font-medium transition-shadow hover:shadow-md"
        >
          <RefreshCw className="h-4 w-4 text-purple-600" />
          Manage Rotation Policies
        </Link>
        <Link
          to="/guacamole-sessions"
          className="flex items-center gap-2 rounded-md border bg-background p-3 text-sm font-medium transition-shadow hover:shadow-md"
        >
          <MonitorPlay className="h-4 w-4 text-purple-600" />
          Manage Privileged Sessions
        </Link>
      </div>
    </div>
  )
}
