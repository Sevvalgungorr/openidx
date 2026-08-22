import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Activity,
  Shield,
  AlertTriangle,
  Globe,
  Monitor,
  Smartphone,
  TrendingUp,
  TrendingDown,
  CheckCircle2,
  XCircle,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '../components/ui/select'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'
import { RelatedLinks } from '../components/related-links'
import { api } from '../lib/api'

interface LoginAnalytics {
  period: string
  start_date: string
  end_date: string
  summary: {
    total_logins: number
    successful_logins: number
    failed_logins: number
    unique_users: number
    new_devices: number
    high_risk_logins: number
    mfa_challenges: number
    average_risk_score: number
    trusted_browser_logins: number
  }
  daily_trends: Array<{
    date: string
    successful: number
    failed: number
    high_risk: number
  }>
  hourly_pattern: Array<{
    hour: number
    successful: number
    failed: number
  }>
  geo_distribution: Array<{
    country: string
    city: string
    count: number
    failed: number
    avg_risk: number
  }>
  risk_distribution: Array<{
    bucket: string
    min: number
    max: number
    count: number
  }>
  auth_methods: Array<{
    method: string
    count: number
  }>
  top_failed_users: Array<{
    user_id: string
    email: string
    failed_count: number
    last_attempt: string
  }>
  device_types: Array<{
    device_type: string
    browser: string
    count: number
  }>
}

const periodLabels: Record<string, string> = {
  '24h': 'Last 24 Hours',
  '7d': 'Last 7 Days',
  '30d': 'Last 30 Days',
  '90d': 'Last 90 Days',
}

export function LoginAnalyticsPage() {
  const [period, setPeriod] = useState('7d')

  const { data, isLoading, isError, error } = useQuery<{ analytics: LoginAnalytics }>({
    queryKey: ['login-analytics', period],
    queryFn: async () => {
      return api.get<{ analytics: LoginAnalytics }>(`/api/v1/identity/analytics/logins?period=${period}`)
    }
  })

  const analytics = data?.analytics

  if (isLoading) {
    return (
      <div className="flex justify-center py-12">
        <LoadingSpinner size="lg" />
      </div>
    )
  }

  if (isError) {
    return <QueryError error={error} resource="login analytics" />
  }

  if (!analytics) {
    return (
      <div className="text-center py-12 text-muted-foreground">
        No analytics data available
      </div>
    )
  }

  const successRate = analytics.summary.total_logins > 0
    ? ((analytics.summary.successful_logins / analytics.summary.total_logins) * 100).toFixed(1)
    : '0'

  // Calculate max for charts
  const maxDaily = Math.max(...(analytics.daily_trends?.map(d => d.successful + d.failed) || [1]))
  const maxHourly = Math.max(...(analytics.hourly_pattern?.map(h => h.successful + h.failed) || [1]))

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Login Analytics</h1>
          <p className="text-muted-foreground">Authentication patterns and security insights</p>
        </div>
        <Select value={period} onValueChange={setPeriod}>
          <SelectTrigger className="w-[180px]">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {Object.entries(periodLabels).map(([value, label]) => (
              <SelectItem key={value} value={value}>{label}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <RelatedLinks links={[{ to: '/auth-analytics', label: 'Auth Analytics' }]} />

      {/* Summary Stats */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Logins</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{analytics.summary.total_logins.toLocaleString()}</div>
            <div className="flex items-center gap-2 mt-1">
              <Badge variant="outline" className="text-green-600">
                <CheckCircle2 className="h-3 w-3 mr-1" />
                {analytics.summary.successful_logins}
              </Badge>
              <Badge variant="outline" className="text-red-600">
                <XCircle className="h-3 w-3 mr-1" />
                {analytics.summary.failed_logins}
              </Badge>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Success Rate</CardTitle>
            {parseFloat(successRate) >= 95 ? (
              <TrendingUp className="h-4 w-4 text-green-600" />
            ) : (
              <TrendingDown className="h-4 w-4 text-red-600" />
            )}
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{successRate}%</div>
            <p className="text-xs text-muted-foreground mt-1">
              {analytics.summary.unique_users} unique users
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">High Risk Logins</CardTitle>
            <AlertTriangle className="h-4 w-4 text-amber-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-amber-600">{analytics.summary.high_risk_logins}</div>
            <p className="text-xs text-muted-foreground mt-1">
              Avg risk score: {analytics.summary.average_risk_score.toFixed(1)}
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">MFA Challenges</CardTitle>
            <Shield className="h-4 w-4 text-blue-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{analytics.summary.mfa_challenges}</div>
            <p className="text-xs text-muted-foreground mt-1">
              {analytics.summary.new_devices} new devices
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Charts Row */}
      <div className="grid gap-6 md:grid-cols-2">
        {/* Daily Trend */}
        <Card>
          <CardHeader>
            <CardTitle>Daily Login Trend</CardTitle>
            <CardDescription>Successful vs failed logins over time</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {analytics.daily_trends?.slice(-7).map((day) => (
                <div key={day.date} className="flex items-center gap-2">
                  <span className="text-xs text-muted-foreground w-20">{day.date.slice(5)}</span>
                  <div className="flex-1 flex items-center gap-1 h-6">
                    <div
                      className="bg-green-500 h-full rounded-l"
                      style={{ width: `${(day.successful / maxDaily) * 100}%` }}
                      title={`${day.successful} successful`}
                    />
                    <div
                      className="bg-red-500 h-full rounded-r"
                      style={{ width: `${(day.failed / maxDaily) * 100}%` }}
                      title={`${day.failed} failed`}
                    />
                  </div>
                  <span className="text-xs text-muted-foreground w-16 text-right">
                    {day.successful + day.failed}
                  </span>
                </div>
              ))}
            </div>
            <div className="flex items-center gap-4 mt-4 text-xs text-muted-foreground">
              <div className="flex items-center gap-1">
                <div className="w-3 h-3 bg-green-500 rounded" />
                Successful
              </div>
              <div className="flex items-center gap-1">
                <div className="w-3 h-3 bg-red-500 rounded" />
                Failed
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Hourly Pattern */}
        <Card>
          <CardHeader>
            <CardTitle>Hourly Pattern</CardTitle>
            <CardDescription>Login activity by hour of day (UTC)</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex items-end gap-1 h-32">
              {analytics.hourly_pattern?.map((hour) => {
                const total = hour.successful + hour.failed
                const height = maxHourly > 0 ? (total / maxHourly) * 100 : 0
                return (
                  <div
                    key={hour.hour}
                    className="flex-1 flex flex-col items-center"
                    title={`${hour.hour}:00 - ${total} logins`}
                  >
                    <div
                      className="w-full bg-blue-500 rounded-t transition-all"
                      style={{ height: `${height}%`, minHeight: total > 0 ? '4px' : '0' }}
                    />
                    {hour.hour % 4 === 0 && (
                      <span className="text-[10px] text-muted-foreground mt-1">{hour.hour}</span>
                    )}
                  </div>
                )
              })}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Risk and Geo Distribution */}
      <div className="grid gap-6 md:grid-cols-2">
        {/* Risk Distribution */}
        <Card>
          <CardHeader>
            <CardTitle>Risk Distribution</CardTitle>
            <CardDescription>Login risk score breakdown</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {analytics.risk_distribution?.map((bucket) => {
                const percentage = analytics.summary.total_logins > 0
                  ? (bucket.count / analytics.summary.total_logins) * 100
                  : 0
                const color = bucket.min >= 70 ? 'bg-red-500' :
                             bucket.min >= 50 ? 'bg-amber-500' :
                             bucket.min >= 30 ? 'bg-yellow-500' : 'bg-green-500'
                return (
                  <div key={bucket.bucket} className="space-y-1">
                    <div className="flex justify-between text-sm">
                      <span>{bucket.bucket}</span>
                      <span className="text-muted-foreground">{bucket.count} ({percentage.toFixed(1)}%)</span>
                    </div>
                    <div className="h-2 bg-muted rounded-full overflow-hidden">
                      <div
                        className={`h-full ${color} transition-all`}
                        style={{ width: `${percentage}%` }}
                      />
                    </div>
                  </div>
                )
              })}
            </div>
          </CardContent>
        </Card>

        {/* Geographic Distribution */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Globe className="h-5 w-5" />
              Top Locations
            </CardTitle>
            <CardDescription>Geographic distribution of logins</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {analytics.geo_distribution?.slice(0, 6).map((geo, i) => (
                <div key={i} className="flex items-center justify-between p-2 hover:bg-muted/50 rounded">
                  <div>
                    <p className="font-medium">{geo.city || geo.country}</p>
                    <p className="text-xs text-muted-foreground">
                      Avg risk: {geo.avg_risk.toFixed(1)}
                    </p>
                  </div>
                  <div className="text-right">
                    <p className="font-medium">{geo.count}</p>
                    {geo.failed > 0 && (
                      <p className="text-xs text-red-600">{geo.failed} failed</p>
                    )}
                  </div>
                </div>
              ))}
              {(!analytics.geo_distribution || analytics.geo_distribution.length === 0) && (
                <p className="text-center text-muted-foreground py-4">No location data available</p>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Auth Methods and Device Types */}
      <div className="grid gap-6 md:grid-cols-3">
        {/* Auth Methods */}
        <Card>
          <CardHeader>
            <CardTitle>Authentication Methods</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {analytics.auth_methods?.map((method) => (
                <div key={method.method} className="flex items-center justify-between">
                  <span className="capitalize">{method.method}</span>
                  <Badge variant="secondary">{method.count}</Badge>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* Device Types */}
        <Card>
          <CardHeader>
            <CardTitle>Device Types</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {analytics.device_types?.slice(0, 5).map((device, i) => (
                <div key={i} className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    {device.device_type === 'Mobile' ? (
                      <Smartphone className="h-4 w-4 text-muted-foreground" />
                    ) : (
                      <Monitor className="h-4 w-4 text-muted-foreground" />
                    )}
                    <span>{device.browser}</span>
                  </div>
                  <Badge variant="secondary">{device.count}</Badge>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* Top Failed Users */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-amber-500" />
              Failed Logins
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {analytics.top_failed_users?.slice(0, 5).map((user) => (
                <div key={user.user_id} className="flex items-center justify-between text-sm">
                  <span className="truncate max-w-[150px]" title={user.email}>
                    {user.email}
                  </span>
                  <Badge variant="destructive">{user.failed_count}</Badge>
                </div>
              ))}
              {(!analytics.top_failed_users || analytics.top_failed_users.length === 0) && (
                <p className="text-center text-muted-foreground py-4">No failed logins</p>
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
