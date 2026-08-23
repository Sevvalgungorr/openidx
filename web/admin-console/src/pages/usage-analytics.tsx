import { useQuery } from '@tanstack/react-query'
import {
  Users, UserCheck, UserPlus, Layers, Shield, Key, Fingerprint,
  Smartphone, Link2, Globe, BarChart3, ArrowUpRight,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '../components/ui/table'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'
import { api } from '../lib/api'

interface UsageData {
  dau: number
  wau: number
  mau: number
  total_users: number
  total_groups: number
  total_apps: number
  new_registrations: Array<{
    date: string
    count: number
  }>
}

interface FeatureAdoption {
  features: Array<{
    name: string
    category: string
    total_users: number
    adopted_users: number
    adoption_percentage: number
  }>
}

interface APIUsage {
  endpoints: Array<{
    method: string
    path: string
    request_count: number
    avg_latency_ms: number
    error_rate: number
  }>
}

const featureIcons: Record<string, React.ReactNode> = {
  totp: <Key className="h-4 w-4" />,
  webauthn: <Fingerprint className="h-4 w-4" />,
  sms: <Smartphone className="h-4 w-4" />,
  passkey: <Fingerprint className="h-4 w-4" />,
  magic_link: <Link2 className="h-4 w-4" />,
  api_keys: <Key className="h-4 w-4" />,
  social_login: <Globe className="h-4 w-4" />,
}

function featureColor(percentage: number): string {
  if (percentage >= 75) return 'bg-green-500'
  if (percentage >= 50) return 'bg-blue-500'
  if (percentage >= 25) return 'bg-yellow-500'
  return 'bg-gray-400'
}

function methodBadge(method: string) {
  const colors: Record<string, string> = {
    GET: 'bg-blue-100 text-blue-800',
    POST: 'bg-green-100 text-green-800',
    PUT: 'bg-yellow-100 text-yellow-800',
    DELETE: 'bg-red-100 text-red-800',
    PATCH: 'bg-purple-100 text-purple-800',
  }
  return colors[method] || 'bg-muted text-foreground'
}

export function UsageAnalyticsPage() {
  const {
    data: usageData,
    isLoading: usageLoading,
    isError: usageError,
    error: usageErrorObj,
  } = useQuery<{ usage: UsageData }>({
    queryKey: ['usage-analytics'],
    // Normalize: the analytics endpoints can omit numeric fields per row (a Go
    // zero/absent value serializes to null or is dropped), and the cards call
    // .toLocaleString()/.toFixed() on them, which crashed the page with "Cannot
    // read properties of undefined (reading 'toLocaleString')". Default every
    // rendered field so the typed shape holds at runtime, not just in TS.
    queryFn: async () => {
      const res = await api.get<{ usage: UsageData }>('/api/v1/analytics/usage')
      const u = res.usage
      return {
        usage: {
          ...u,
          new_registrations: (u?.new_registrations ?? []).map((r) => ({
            date: r.date ?? '',
            count: r.count ?? 0,
          })),
        },
      }
    },
  })

  const { data: adoptionData, isLoading: adoptionLoading } = useQuery<{ adoption: FeatureAdoption }>({
    queryKey: ['feature-adoption'],
    queryFn: async () => {
      const res = await api.get<{ adoption: FeatureAdoption }>(
        '/api/v1/analytics/feature-adoption'
      )
      return {
        adoption: {
          features: (res.adoption?.features ?? []).map((f) => ({
            name: f.name ?? '',
            category: f.category ?? '',
            total_users: f.total_users ?? 0,
            adopted_users: f.adopted_users ?? 0,
            adoption_percentage: f.adoption_percentage ?? 0,
          })),
        },
      }
    },
  })

  const { data: apiData, isLoading: apiLoading } = useQuery<{ api_usage: APIUsage }>({
    queryKey: ['api-usage'],
    queryFn: async () => {
      const res = await api.get<{ api_usage: APIUsage }>('/api/v1/analytics/api-usage')
      return {
        api_usage: {
          endpoints: (res.api_usage?.endpoints ?? []).map((e) => ({
            method: e.method ?? '',
            path: e.path ?? '',
            request_count: e.request_count ?? 0,
            avg_latency_ms: e.avg_latency_ms ?? 0,
            error_rate: e.error_rate ?? 0,
          })),
        },
      }
    },
  })

  const usage = usageData?.usage
  const adoption = adoptionData?.adoption
  const apiUsage = apiData?.api_usage

  const isLoading = usageLoading || adoptionLoading || apiLoading

  if (isLoading) {
    return (
      <div className="flex justify-center py-12">
        <LoadingSpinner size="lg" />
      </div>
    )
  }

  // The primary usage query drives the whole dashboard; a 401/403 here must not
  // fall through to an all-zeros "no usage" view.
  if (usageError) {
    return <QueryError error={usageErrorObj} resource="usage analytics" />
  }

  const maxRegistration = Math.max(
    ...(usage?.new_registrations?.map((r) => r.count) || [1])
  )

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Usage Analytics</h1>
        <p className="text-muted-foreground">
          User engagement, feature adoption, and platform utilization
        </p>
      </div>

      {/* Active User Stats */}
      <div className="grid gap-4 md:grid-cols-3 lg:grid-cols-6">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">DAU</CardTitle>
            <UserCheck className="h-4 w-4 text-green-600" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {(usage?.dau ?? 0).toLocaleString()}
            </div>
            <p className="text-xs text-muted-foreground mt-1">Daily active</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">WAU</CardTitle>
            <UserCheck className="h-4 w-4 text-primary" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {(usage?.wau ?? 0).toLocaleString()}
            </div>
            <p className="text-xs text-muted-foreground mt-1">Weekly active</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">MAU</CardTitle>
            <UserCheck className="h-4 w-4 text-purple-600" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {(usage?.mau ?? 0).toLocaleString()}
            </div>
            <p className="text-xs text-muted-foreground mt-1">Monthly active</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Users</CardTitle>
            <Users className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {(usage?.total_users ?? 0).toLocaleString()}
            </div>
            <p className="text-xs text-muted-foreground mt-1">All registered</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Groups</CardTitle>
            <Layers className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {(usage?.total_groups ?? 0).toLocaleString()}
            </div>
            <p className="text-xs text-muted-foreground mt-1">Active groups</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Apps</CardTitle>
            <ArrowUpRight className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {(usage?.total_apps ?? 0).toLocaleString()}
            </div>
            <p className="text-xs text-muted-foreground mt-1">Registered apps</p>
          </CardContent>
        </Card>
      </div>

      {/* Feature Adoption */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Feature Adoption
          </CardTitle>
          <CardDescription>
            Security and authentication feature usage across your user base
          </CardDescription>
        </CardHeader>
        <CardContent>
          {adoption?.features && adoption.features.length > 0 ? (
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
              {adoption.features.map((feature) => (
                <div
                  key={feature.name}
                  className="p-4 border rounded-lg space-y-3"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      {featureIcons[feature.name.toLowerCase()] || (
                        <Shield className="h-4 w-4" />
                      )}
                      <span className="font-medium capitalize">
                        {feature.name.replace(/_/g, ' ')}
                      </span>
                    </div>
                    <Badge variant="outline" className="text-xs">
                      {feature.category}
                    </Badge>
                  </div>
                  <div className="space-y-1">
                    <div className="flex justify-between text-sm">
                      <span className="text-muted-foreground">
                        {feature.adopted_users.toLocaleString()} of{' '}
                        {feature.total_users.toLocaleString()} users
                      </span>
                      <span className="font-medium">
                        {feature.adoption_percentage.toFixed(1)}%
                      </span>
                    </div>
                    <div className="h-2 bg-muted rounded-full overflow-hidden">
                      <div
                        className={`h-full rounded-full transition-all ${featureColor(feature.adoption_percentage)}`}
                        style={{ width: `${feature.adoption_percentage}%` }}
                      />
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-center text-muted-foreground py-6">
              No feature adoption data available
            </p>
          )}
        </CardContent>
      </Card>

      {/* Bottom Row: API Usage + Registrations Trend */}
      <div className="grid gap-6 md:grid-cols-2">
        {/* API Usage */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <BarChart3 className="h-5 w-5" />
              Top API Endpoints
            </CardTitle>
            <CardDescription>Most-used endpoints by request volume</CardDescription>
          </CardHeader>
          <CardContent>
            {apiUsage?.endpoints && apiUsage.endpoints.length > 0 ? (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Method</TableHead>
                    <TableHead>Path</TableHead>
                    <TableHead className="text-right">Requests</TableHead>
                    <TableHead className="text-right">Avg Latency</TableHead>
                    <TableHead className="text-right">Error Rate</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {apiUsage.endpoints.slice(0, 10).map((ep, i) => (
                    <TableRow key={i}>
                      <TableCell>
                        <Badge className={`${methodBadge(ep.method)} hover:${methodBadge(ep.method)}`}>
                          {ep.method}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <span className="font-mono text-xs" title={ep.path}>
                          {ep.path.length > 40 ? ep.path.slice(0, 40) + '...' : ep.path}
                        </span>
                      </TableCell>
                      <TableCell className="text-right font-medium">
                        {ep.request_count.toLocaleString()}
                      </TableCell>
                      <TableCell className="text-right text-muted-foreground">
                        {ep.avg_latency_ms.toFixed(0)}ms
                      </TableCell>
                      <TableCell className="text-right">
                        <span
                          className={
                            ep.error_rate > 5
                              ? 'text-red-600 font-medium'
                              : 'text-muted-foreground'
                          }
                        >
                          {ep.error_rate.toFixed(1)}%
                        </span>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <p className="text-center text-muted-foreground py-6">
                No API usage data available
              </p>
            )}
          </CardContent>
        </Card>

        {/* New User Registrations Trend */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <UserPlus className="h-5 w-5" />
              New User Registrations
            </CardTitle>
            <CardDescription>Daily registration trend over the last 30 days</CardDescription>
          </CardHeader>
          <CardContent>
            {usage?.new_registrations && usage.new_registrations.length > 0 ? (
              <>
                <div className="flex items-end gap-1 h-40">
                  {usage.new_registrations.map((day) => {
                    const height =
                      maxRegistration > 0
                        ? (day.count / maxRegistration) * 100
                        : 0
                    return (
                      <div
                        key={day.date}
                        className="flex-1 flex flex-col items-center"
                        title={`${day.date}: ${day.count} registrations`}
                      >
                        <div
                          className="w-full bg-emerald-500 rounded-t transition-all hover:bg-emerald-600"
                          style={{
                            height: `${height}%`,
                            minHeight: day.count > 0 ? '4px' : '0',
                          }}
                        />
                      </div>
                    )
                  })}
                </div>
                <div className="flex justify-between text-xs text-muted-foreground mt-2">
                  <span>
                    {usage.new_registrations[0]?.date.slice(5)}
                  </span>
                  <span>
                    {usage.new_registrations[usage.new_registrations.length - 1]?.date.slice(5)}
                  </span>
                </div>
                <p className="text-xs text-muted-foreground text-center mt-1">
                  Total:{' '}
                  {usage.new_registrations
                    .reduce((sum, d) => sum + d.count, 0)
                    .toLocaleString()}{' '}
                  new users
                </p>
              </>
            ) : (
              <p className="text-center text-muted-foreground py-6">
                No registration data available
              </p>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
