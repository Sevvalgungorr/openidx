import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  ShieldAlert, AlertTriangle, Activity, Plane, TrendingUp, Users, Clock,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '../components/ui/table'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'
import { api } from '../lib/api'

interface RiskOverview {
  avg_risk_score: number
  high_risk_logins_24h: number
  active_alerts: number
  impossible_travel_events: number
  risk_distribution: Array<{
    bucket: string
    min: number
    max: number
    count: number
  }>
  top_risky_users: Array<{
    user_id: string
    email: string
    username: string
    avg_risk_score: number
    last_login: string
    anomaly_count: number
  }>
}

interface RiskTimeline {
  days: Array<{
    date: string
    avg_score: number
    max_score: number
    login_count: number
  }>
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

const severityStyles: Record<string, string> = {
  critical: 'bg-red-100 text-red-800',
  high: 'bg-orange-100 text-orange-800',
  medium: 'bg-yellow-100 text-yellow-800',
  low: 'bg-blue-100 text-blue-800',
}

const statusStyles: Record<string, string> = {
  open: 'bg-red-100 text-red-800',
  investigating: 'bg-yellow-100 text-yellow-800',
  resolved: 'bg-green-100 text-green-800',
  false_positive: 'bg-muted text-foreground',
}

function bucketColor(min: number): string {
  if (min >= 81) return 'bg-red-600'
  if (min >= 61) return 'bg-orange-500'
  if (min >= 41) return 'bg-yellow-500'
  if (min >= 21) return 'bg-blue-400'
  return 'bg-green-500'
}

function bucketLabel(min: number): string {
  if (min >= 81) return 'Critical'
  if (min >= 61) return 'High'
  if (min >= 41) return 'Medium'
  if (min >= 21) return 'Medium-Low'
  return 'Low'
}

function riskScoreColor(score: number): string {
  if (score >= 80) return 'text-red-600'
  if (score >= 60) return 'text-orange-600'
  if (score >= 40) return 'text-yellow-600'
  return 'text-green-600'
}

export function RiskDashboardPage() {
  const { data: riskData, isLoading: riskLoading, isError: riskError, error: riskErrorObj } = useQuery<{ risk: RiskOverview } | { risk: null }>({
    queryKey: ['risk-overview'],
    queryFn: async () => {
      const res = await api.get<{ risk: RiskOverview }>('/api/v1/analytics/risk')
      if (!res.risk) return { risk: null }
      return {
        risk: {
          avg_risk_score: res.risk.avg_risk_score ?? 0,
          high_risk_logins_24h: res.risk.high_risk_logins_24h ?? 0,
          active_alerts: res.risk.active_alerts ?? 0,
          impossible_travel_events: res.risk.impossible_travel_events ?? 0,
          risk_distribution: (res.risk.risk_distribution ?? []).map((b) => ({
            bucket: b.bucket ?? '',
            min: b.min ?? 0,
            max: b.max ?? 0,
            count: b.count ?? 0,
          })),
          top_risky_users: (res.risk.top_risky_users ?? []).map((u) => ({
            user_id: u.user_id ?? '',
            email: u.email ?? '',
            username: u.username ?? '',
            avg_risk_score: u.avg_risk_score ?? 0,
            last_login: u.last_login ?? '',
            anomaly_count: u.anomaly_count ?? 0,
          })),
        },
      }
    },
  })

  const { data: timelineData, isLoading: timelineLoading } = useQuery<{ timeline: RiskTimeline }>({
    queryKey: ['risk-timeline'],
    queryFn: async () => {
      const res = await api.get<{ timeline: RiskTimeline }>('/api/v1/analytics/risk-timeline?days=30')
      return {
        timeline: {
          days: (res.timeline?.days ?? []).map((d) => ({
            date: d.date ?? '',
            avg_score: d.avg_score ?? 0,
            max_score: d.max_score ?? 0,
            login_count: d.login_count ?? 0,
          })),
        },
      }
    },
  })

  const { data: alertsData, isLoading: alertsLoading } = useQuery<{ alerts: SecurityAlert[] }>({
    queryKey: ['security-alerts-recent'],
    queryFn: async () => {
      const res = await api.get<{ alerts: SecurityAlert[] }>('/api/v1/security-alerts?limit=10')
      return {
        alerts: (res.alerts ?? []).map((a) => ({
          id: a.id ?? '',
          alert_type: a.alert_type ?? '',
          severity: a.severity ?? '',
          status: a.status ?? '',
          title: a.title ?? '',
          description: a.description ?? '',
          source_ip: a.source_ip ?? '',
          created_at: a.created_at ?? '',
        })),
      }
    },
  })

  const risk = riskData?.risk
  const timeline = timelineData?.timeline
  const alerts = alertsData?.alerts || []

  const isLoading = riskLoading || timelineLoading || alertsLoading

  if (isLoading) {
    return (
      <div className="flex justify-center py-12">
        <LoadingSpinner size="lg" />
      </div>
    )
  }

  if (riskError) {
    return <QueryError error={riskErrorObj} resource="the risk dashboard" />
  }

  if (!risk) {
    return (
      <div className="text-center py-12 text-muted-foreground">
        No risk data available
      </div>
    )
  }

  const totalDistribution = risk.risk_distribution?.reduce((sum, b) => sum + b.count, 0) || 0
  const maxTimelineScore = Math.max(
    ...(timeline?.days?.map((d) => d.avg_score) || [1]),
    1
  )

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Risk Dashboard</h1>
        <p className="text-muted-foreground">
          Security risk overview, threat indicators, and anomaly detection
        </p>
      </div>

      {/* Summary Cards */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Avg Risk Score</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className={`text-2xl font-bold ${riskScoreColor(risk.avg_risk_score)}`}>
              {risk.avg_risk_score.toFixed(1)}
            </div>
            <div className="mt-2 h-2 bg-muted rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full transition-all ${
                  risk.avg_risk_score >= 60
                    ? 'bg-red-500'
                    : risk.avg_risk_score >= 40
                      ? 'bg-yellow-500'
                      : 'bg-green-500'
                }`}
                style={{ width: `${risk.avg_risk_score}%` }}
              />
            </div>
            <p className="text-xs text-muted-foreground mt-1">Out of 100</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">High Risk Logins (24h)</CardTitle>
            <AlertTriangle className="h-4 w-4 text-orange-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-orange-600">
              {risk.high_risk_logins_24h}
            </div>
            <p className="text-xs text-muted-foreground mt-1">
              Risk score above 60
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Alerts</CardTitle>
            <ShieldAlert className="h-4 w-4 text-red-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-600">
              {risk.active_alerts}
            </div>
            <p className="text-xs text-muted-foreground mt-1">
              Open or investigating
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Impossible Travel</CardTitle>
            <Plane className="h-4 w-4 text-purple-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-purple-600">
              {risk.impossible_travel_events}
            </div>
            <p className="text-xs text-muted-foreground mt-1">
              Geographically implausible logins
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Risk Distribution + Timeline */}
      <div className="grid gap-6 md:grid-cols-2">
        {/* Risk Score Distribution */}
        <Card>
          <CardHeader>
            <CardTitle>Risk Score Distribution</CardTitle>
            <CardDescription>Login distribution by risk score bucket</CardDescription>
          </CardHeader>
          <CardContent>
            {risk.risk_distribution && risk.risk_distribution.length > 0 ? (
              <div className="space-y-4">
                {risk.risk_distribution.map((bucket) => {
                  const percentage =
                    totalDistribution > 0
                      ? (bucket.count / totalDistribution) * 100
                      : 0
                  return (
                    <div key={bucket.bucket} className="space-y-2">
                      <div className="flex items-center justify-between text-sm">
                        <div className="flex items-center gap-2">
                          <div
                            className={`w-3 h-3 rounded-full ${bucketColor(bucket.min)}`}
                          />
                          <span className="font-medium">
                            {bucket.min}-{bucket.max}
                          </span>
                          <span className="text-muted-foreground">
                            ({bucketLabel(bucket.min)})
                          </span>
                        </div>
                        <span className="text-muted-foreground">
                          {bucket.count.toLocaleString()} ({percentage.toFixed(1)}%)
                        </span>
                      </div>
                      <div className="h-3 bg-muted rounded-full overflow-hidden">
                        <div
                          className={`h-full ${bucketColor(bucket.min)} transition-all rounded-full`}
                          style={{ width: `${percentage}%` }}
                        />
                      </div>
                    </div>
                  )
                })}
              </div>
            ) : (
              <p className="text-center text-muted-foreground py-6">
                No distribution data available
              </p>
            )}
          </CardContent>
        </Card>

        {/* Risk Timeline */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <TrendingUp className="h-5 w-5" />
              Risk Score Timeline
            </CardTitle>
            <CardDescription>Daily average risk scores over the last 30 days</CardDescription>
          </CardHeader>
          <CardContent>
            {timeline?.days && timeline.days.length > 0 ? (
              <>
                <div className="flex items-end gap-1 h-40">
                  {timeline.days.map((day) => {
                    const height =
                      maxTimelineScore > 0
                        ? (day.avg_score / maxTimelineScore) * 100
                        : 0
                    const color =
                      day.avg_score >= 60
                        ? 'bg-red-500 hover:bg-red-600'
                        : day.avg_score >= 40
                          ? 'bg-yellow-500 hover:bg-yellow-600'
                          : 'bg-green-500 hover:bg-green-600'
                    return (
                      <div
                        key={day.date}
                        className="flex-1 flex flex-col items-center"
                        title={`${day.date}: avg ${day.avg_score.toFixed(1)}, max ${day.max_score}, ${day.login_count} logins`}
                      >
                        <div
                          className={`w-full ${color} rounded-t transition-all`}
                          style={{
                            height: `${height}%`,
                            minHeight: day.avg_score > 0 ? '4px' : '0',
                          }}
                        />
                      </div>
                    )
                  })}
                </div>
                <div className="flex justify-between text-xs text-muted-foreground mt-2">
                  <span>{timeline.days[0]?.date.slice(5)}</span>
                  <span>
                    {timeline.days[timeline.days.length - 1]?.date.slice(5)}
                  </span>
                </div>
                <div className="flex items-center gap-4 mt-3 text-xs text-muted-foreground">
                  <div className="flex items-center gap-1">
                    <div className="w-3 h-3 bg-green-500 rounded" />
                    Low (&lt;40)
                  </div>
                  <div className="flex items-center gap-1">
                    <div className="w-3 h-3 bg-yellow-500 rounded" />
                    Medium (40-59)
                  </div>
                  <div className="flex items-center gap-1">
                    <div className="w-3 h-3 bg-red-500 rounded" />
                    High (60+)
                  </div>
                </div>
              </>
            ) : (
              <p className="text-center text-muted-foreground py-6">
                No timeline data available
              </p>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Alerts + Risky Users */}
      <div className="grid gap-6 md:grid-cols-2">
        {/* Active Security Alerts */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ShieldAlert className="h-5 w-5 text-red-500" />
              Active Security Alerts
            </CardTitle>
            <CardDescription>Recent alerts requiring attention</CardDescription>
          </CardHeader>
          <CardContent>
            {alerts.length > 0 ? (
              <div className="space-y-3">
                {alerts.slice(0, 10).map((alert) => (
                  <Link
                    key={alert.id}
                    to="/security-alerts"
                    className="flex items-start justify-between p-3 border rounded-lg hover:bg-muted/50 transition-colors"
                  >
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <Badge
                          className={`${severityStyles[alert.severity] || 'bg-muted text-foreground'} hover:${severityStyles[alert.severity] || 'bg-muted'}`}
                        >
                          {alert.severity}
                        </Badge>
                        <Badge
                          className={`${statusStyles[alert.status] || 'bg-muted text-foreground'} hover:${statusStyles[alert.status] || 'bg-muted'}`}
                        >
                          {alert.status}
                        </Badge>
                      </div>
                      <p className="font-medium text-sm">{alert.title}</p>
                      <p className="text-xs text-muted-foreground mt-1 truncate">
                        {alert.description}
                      </p>
                    </div>
                    <div className="text-xs text-muted-foreground whitespace-nowrap ml-3 flex items-center gap-1">
                      <Clock className="h-3 w-3" />
                      {new Date(alert.created_at).toLocaleDateString()}
                    </div>
                  </Link>
                ))}
              </div>
            ) : (
              <div className="text-center text-muted-foreground py-6">
                <ShieldAlert className="h-8 w-8 mx-auto mb-2 text-muted-foreground/40" />
                <p>No active security alerts</p>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Top Risky Users */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Users className="h-5 w-5" />
              Top Risky Users
            </CardTitle>
            <CardDescription>Users with highest average risk scores</CardDescription>
          </CardHeader>
          <CardContent>
            {risk.top_risky_users && risk.top_risky_users.length > 0 ? (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>User</TableHead>
                    <TableHead className="text-right">Avg Risk</TableHead>
                    <TableHead className="text-right">Anomalies</TableHead>
                    <TableHead>Last Login</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {risk.top_risky_users.map((user) => (
                    <TableRow key={user.user_id}>
                      <TableCell>
                        <div>
                          <p className="font-medium text-sm">{user.username}</p>
                          <p className="text-xs text-muted-foreground truncate max-w-[150px]">
                            {user.email}
                          </p>
                        </div>
                      </TableCell>
                      <TableCell className="text-right">
                        <span
                          className={`font-bold ${riskScoreColor(user.avg_risk_score)}`}
                        >
                          {user.avg_risk_score.toFixed(1)}
                        </span>
                      </TableCell>
                      <TableCell className="text-right">
                        <Badge
                          variant={user.anomaly_count > 5 ? 'destructive' : 'secondary'}
                        >
                          {user.anomaly_count}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {user.last_login
                          ? new Date(user.last_login).toLocaleDateString()
                          : 'Never'}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <div className="text-center text-muted-foreground py-6">
                <Users className="h-8 w-8 mx-auto mb-2 text-muted-foreground/40" />
                <p>No risky users detected</p>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
