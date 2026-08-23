import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Activity, ShieldAlert, Users, BarChart3, Clock, Globe, Monitor } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '../components/ui/dialog'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/select'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { api } from '../lib/api'
import { QueryError } from '../components/query-error'

interface LoginAnomaly {
  id: string
  user_id: string
  username: string
  ip_address: string
  user_agent: string
  location: string
  risk_score: number
  success: boolean
  auth_methods: string[]
  created_at: string
}

interface RiskOverview {
  avg_risk_score: number
  high_risk_count: number
  total_logins_7d: number
  risk_distribution: {
    low: number
    medium: number
    high: number
    critical: number
  }
}

interface UserRiskProfile {
  user_id: string
  username: string
  baseline: {
    typical_login_hours: number[]
    typical_countries: string[]
    typical_ips: string[]
    avg_risk_score: number
    login_count: number
  }
  recent_logins: LoginAnomaly[]
}

const riskScoreBadge = (score: number) => {
  if (score >= 90) return { label: 'Critical', className: 'bg-red-100 text-red-800' }
  if (score >= 70) return { label: 'High', className: 'bg-orange-100 text-orange-800' }
  if (score >= 30) return { label: 'Medium', className: 'bg-yellow-100 text-yellow-800' }
  return { label: 'Low', className: 'bg-green-100 text-green-800' }
}

const avgScoreColor = (score: number) => {
  if (score >= 70) return 'text-red-600'
  if (score >= 30) return 'text-yellow-600'
  return 'text-green-600'
}

export default function LoginAnomalies() {
  const [days, setDays] = useState('7')
  const [minScore, setMinScore] = useState('50')
  const [selectedUserId, setSelectedUserId] = useState<string | null>(null)

  const { data: overview, isLoading: overviewLoading } = useQuery({
    queryKey: ['risk-overview'],
    queryFn: () => api.get<RiskOverview>('/api/v1/risk/overview'),
  })

  const { data: anomaliesData, isLoading: anomaliesLoading, isError: anomaliesError, error: anomaliesErrorObj } = useQuery({
    queryKey: ['risk-anomalies', days, minScore],
    queryFn: async () => {
      const params = new URLSearchParams()
      params.set('days', days)
      params.set('min_score', minScore)
      params.set('page', '1')
      params.set('page_size', '20')
      const raw = await api.get<{ anomalies: LoginAnomaly[]; total: number; page: number; page_size: number }>(
        `/api/v1/risk/anomalies?${params.toString()}`
      )
      return {
        ...raw,
        anomalies: (raw?.anomalies ?? []).map(a => ({
          ...a,
          risk_score: a?.risk_score ?? 0,
          auth_methods: a?.auth_methods ?? [],
        })),
      }
    },
  })
  const anomalies = anomaliesData?.anomalies || []

  const { data: userProfile, isLoading: profileLoading } = useQuery({
    queryKey: ['risk-user-profile', selectedUserId],
    queryFn: async () => {
      const raw = await api.get<UserRiskProfile>(`/api/v1/risk/user-profile/${selectedUserId}`)
      return {
        ...raw,
        baseline: {
          typical_login_hours: raw?.baseline?.typical_login_hours ?? [],
          typical_countries: raw?.baseline?.typical_countries ?? [],
          typical_ips: raw?.baseline?.typical_ips ?? [],
          avg_risk_score: raw?.baseline?.avg_risk_score ?? 0,
          login_count: raw?.baseline?.login_count ?? 0,
        },
        recent_logins: (raw?.recent_logins ?? []).map(l => ({
          ...l,
          risk_score: l?.risk_score ?? 0,
        })),
      }
    },
    enabled: !!selectedUserId,
  })

  const formatDate = (d: string) => new Date(d).toLocaleString()

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Login Anomalies</h1>
        <p className="text-muted-foreground">Monitor login risk scores and detect anomalous authentication patterns</p>
      </div>

      {/* Summary Cards */}
      {overviewLoading ? (
        <div className="flex flex-col items-center justify-center py-12">
          <LoadingSpinner size="lg" />
          <p className="mt-4 text-sm text-muted-foreground">Loading risk overview...</p>
        </div>
      ) : (
        <div className="grid gap-4 md:grid-cols-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">Average Risk Score</CardTitle>
            </CardHeader>
            <CardContent>
              <div className={`text-2xl font-bold ${avgScoreColor(overview?.avg_risk_score || 0)}`}>
                {overview?.avg_risk_score?.toFixed(1) || '0.0'}
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">High-Risk Logins (7d)</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-red-600">{overview?.high_risk_count || 0}</div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">Total Logins (7d)</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{overview?.total_logins_7d || 0}</div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">Risk Distribution</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex flex-wrap gap-2">
                <Badge className="bg-green-100 text-green-800">Low: {overview?.risk_distribution?.low || 0}</Badge>
                <Badge className="bg-yellow-100 text-yellow-800">Med: {overview?.risk_distribution?.medium || 0}</Badge>
                <Badge className="bg-orange-100 text-orange-800">High: {overview?.risk_distribution?.high || 0}</Badge>
                <Badge className="bg-red-100 text-red-800">Crit: {overview?.risk_distribution?.critical || 0}</Badge>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Filter Bar */}
      <Card>
        <CardContent className="pt-6">
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <span className="text-sm font-medium">Days:</span>
              <Select value={days} onValueChange={setDays}>
                <SelectTrigger className="w-[120px]"><SelectValue placeholder="Days" /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="1">1 day</SelectItem>
                  <SelectItem value="3">3 days</SelectItem>
                  <SelectItem value="7">7 days</SelectItem>
                  <SelectItem value="14">14 days</SelectItem>
                  <SelectItem value="30">30 days</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-sm font-medium">Min Risk Score:</span>
              <Select value={minScore} onValueChange={setMinScore}>
                <SelectTrigger className="w-[120px]"><SelectValue placeholder="Min Score" /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="0">0+</SelectItem>
                  <SelectItem value="30">30+</SelectItem>
                  <SelectItem value="50">50+</SelectItem>
                  <SelectItem value="70">70+</SelectItem>
                  <SelectItem value="90">90+</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Recent Anomalies Table */}
      <Card>
        <CardHeader>
          <CardTitle>Recent Anomalies</CardTitle>
        </CardHeader>
        <CardContent>
          {anomaliesLoading ? (
            <div className="flex flex-col items-center justify-center py-12">
              <LoadingSpinner size="lg" />
              <p className="mt-4 text-sm text-muted-foreground">Loading anomalies...</p>
            </div>
          ) : anomaliesError ? (
            <QueryError error={anomaliesErrorObj} resource="login anomalies" />
          ) : anomalies.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <Activity className="h-12 w-12 text-muted-foreground/40 mb-3" />
              <p className="font-medium">No anomalies found</p>
              <p className="text-sm">Login anomalies matching your filters will appear here</p>
            </div>
          ) : (
            <div className="rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>User</TableHead>
                    <TableHead>IP Address</TableHead>
                    <TableHead>Location</TableHead>
                    <TableHead>Risk Score</TableHead>
                    <TableHead>Auth Methods</TableHead>
                    <TableHead>Time</TableHead>
                    <TableHead>Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {anomalies.map(a => {
                    const risk = riskScoreBadge(a.risk_score)
                    return (
                      <TableRow key={a.id} className="cursor-pointer" onClick={() => setSelectedUserId(a.user_id)}>
                        <TableCell className="font-medium">{a.username}</TableCell>
                        <TableCell className="font-mono text-sm">{a.ip_address}</TableCell>
                        <TableCell>{a.location}</TableCell>
                        <TableCell>
                          <Badge className={risk.className}>{a.risk_score} - {risk.label}</Badge>
                        </TableCell>
                        <TableCell>
                          <div className="flex flex-wrap gap-1">
                            {a.auth_methods.map(m => (
                              <Badge key={m} variant="outline">{m}</Badge>
                            ))}
                          </div>
                        </TableCell>
                        <TableCell className="text-sm text-muted-foreground">{formatDate(a.created_at)}</TableCell>
                        <TableCell>
                          {a.success ? (
                            <Badge className="bg-green-100 text-green-800">Success</Badge>
                          ) : (
                            <Badge className="bg-red-100 text-red-800">Failed</Badge>
                          )}
                        </TableCell>
                      </TableRow>
                    )
                  })}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* User Risk Profile Dialog */}
      <Dialog open={!!selectedUserId} onOpenChange={open => !open && setSelectedUserId(null)}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>User Risk Profile - {userProfile?.username || 'Loading...'}</DialogTitle>
          </DialogHeader>
          {profileLoading ? (
            <div className="flex flex-col items-center justify-center py-8">
              <LoadingSpinner size="lg" />
              <p className="mt-4 text-sm text-muted-foreground">Loading user profile...</p>
            </div>
          ) : userProfile ? (
            <div className="space-y-6">
              {/* Baseline Info */}
              <div className="space-y-3">
                <h3 className="text-sm font-semibold">Baseline Profile</h3>
                <div className="grid grid-cols-2 gap-3 text-sm">
                  <div className="flex items-start gap-2">
                    <Clock className="h-4 w-4 mt-0.5 text-muted-foreground" />
                    <div>
                      <p className="font-medium">Typical Login Hours</p>
                      <p className="text-muted-foreground">
                        {userProfile.baseline.typical_login_hours.length > 0
                          ? userProfile.baseline.typical_login_hours.map(h => `${h}:00`).join(', ')
                          : 'No data'}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-start gap-2">
                    <Globe className="h-4 w-4 mt-0.5 text-muted-foreground" />
                    <div>
                      <p className="font-medium">Typical Countries</p>
                      <p className="text-muted-foreground">
                        {userProfile.baseline.typical_countries.length > 0
                          ? userProfile.baseline.typical_countries.join(', ')
                          : 'No data'}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-start gap-2">
                    <Monitor className="h-4 w-4 mt-0.5 text-muted-foreground" />
                    <div>
                      <p className="font-medium">Typical IPs</p>
                      <p className="text-muted-foreground font-mono text-xs">
                        {userProfile.baseline.typical_ips.length > 0
                          ? userProfile.baseline.typical_ips.join(', ')
                          : 'No data'}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-start gap-2">
                    <BarChart3 className="h-4 w-4 mt-0.5 text-muted-foreground" />
                    <div>
                      <p className="font-medium">Avg Risk Score</p>
                      <p className={avgScoreColor(userProfile.baseline.avg_risk_score)}>
                        {userProfile.baseline.avg_risk_score.toFixed(1)}
                      </p>
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-2 text-sm">
                  <Users className="h-4 w-4 text-muted-foreground" />
                  <span className="font-medium">Total Logins:</span>
                  <span className="text-muted-foreground">{userProfile.baseline.login_count}</span>
                </div>
              </div>

              {/* Recent Logins */}
              <div className="space-y-3">
                <h3 className="text-sm font-semibold">Recent Logins</h3>
                {userProfile.recent_logins.length === 0 ? (
                  <p className="text-sm text-muted-foreground">No recent logins</p>
                ) : (
                  <div className="rounded-md border">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>IP Address</TableHead>
                          <TableHead>Location</TableHead>
                          <TableHead>Risk</TableHead>
                          <TableHead>Status</TableHead>
                          <TableHead>Time</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {userProfile.recent_logins.map(login => {
                          const risk = riskScoreBadge(login.risk_score)
                          return (
                            <TableRow key={login.id}>
                              <TableCell className="font-mono text-sm">{login.ip_address}</TableCell>
                              <TableCell>{login.location}</TableCell>
                              <TableCell>
                                <Badge className={risk.className}>{login.risk_score}</Badge>
                              </TableCell>
                              <TableCell>
                                {login.success ? (
                                  <Badge className="bg-green-100 text-green-800">Success</Badge>
                                ) : (
                                  <Badge className="bg-red-100 text-red-800">Failed</Badge>
                                )}
                              </TableCell>
                              <TableCell className="text-sm text-muted-foreground">{formatDate(login.created_at)}</TableCell>
                            </TableRow>
                          )
                        })}
                      </TableBody>
                    </Table>
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
              <ShieldAlert className="h-12 w-12 text-muted-foreground/40 mb-3" />
              <p className="font-medium">Unable to load user profile</p>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  )
}
