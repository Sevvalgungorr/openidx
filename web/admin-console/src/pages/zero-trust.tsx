import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import {
  Shield,
  ShieldAlert,
  Globe,
  Network,
  MonitorSmartphone,
  Activity,
  ExternalLink,
  Lock,
  Unlock,
  Fingerprint,
  ScanFace,
  MapPin,
  Users,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Switch } from '../components/ui/switch'
import { Button } from '../components/ui/button'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'
import { useToast } from '../hooks/use-toast'
import { api } from '../lib/api'

interface FeatureHealth {
  feature_name: string
  enabled: boolean
  status: string
  health_status: string
}

interface OverviewRoute {
  id: string
  name: string
  from_url: string
  to_url: string
  enabled: boolean
  route_type: string
  ziti_enabled: boolean
  ziti_service_name?: string
  browzer_enabled: boolean
  guacamole_enabled: boolean
  require_auth: boolean
  allowed_roles_count: number
  allowed_groups_count: number
  require_device_trust: boolean
  posture_check_count: number
  max_risk_score: number
  allowed_countries_count: number
  has_inline_policy: boolean
  active_sessions: number
  features: FeatureHealth[]
}

interface OverviewResponse {
  summary: {
    total_routes: number
    enabled_routes: number
    via_http_proxy: number
    via_ziti: number
    via_browzer: number
    via_guacamole: number
    missing_auth: number
    missing_device_trust: number
    missing_posture: number
    missing_risk_cap: number
    active_sessions: number
  }
  routes: OverviewRoute[]
  ziti: { configured: boolean; controller_reachable: boolean }
}

interface ProxySession {
  id: string
  user_id: string
  route_id: string
  ip_address: string
  user_agent: string
  last_active_at: string
}

interface AuditEvent {
  source: string
  event_type: string
  user_email: string
  actor_ip: string
  route_id: string
  created_at: string
}

// Access-method badges for one resource.
function MethodBadges({ r }: { r: OverviewRoute }) {
  const methods: { label: string; cls: string; icon: typeof Globe }[] = []
  if (r.route_type === '' || r.route_type === 'http') methods.push({ label: 'Proxy', cls: 'bg-slate-100 text-slate-700', icon: Globe })
  if (r.ziti_enabled) methods.push({ label: 'Ziti', cls: 'bg-purple-100 text-purple-700', icon: Network })
  if (r.browzer_enabled) methods.push({ label: 'BrowZer', cls: 'bg-blue-100 text-blue-700', icon: Globe })
  if (r.guacamole_enabled) methods.push({ label: 'Guacamole', cls: 'bg-amber-100 text-amber-800', icon: MonitorSmartphone })
  return (
    <div className="flex flex-wrap gap-1">
      {methods.map((m) => (
        <Badge key={m.label} className={`${m.cls} text-xs gap-1`}>
          <m.icon className="h-3 w-3" />
          {m.label}
        </Badge>
      ))}
    </div>
  )
}

// Zero-trust control chips for one resource.
function PolicyBadges({ r }: { r: OverviewRoute }) {
  return (
    <div className="flex flex-wrap gap-1">
      {r.require_auth ? (
        <Badge variant="outline" className="text-xs gap-1"><Lock className="h-3 w-3" />auth</Badge>
      ) : (
        <Badge className="bg-red-100 text-red-700 text-xs gap-1"><Unlock className="h-3 w-3" />no auth</Badge>
      )}
      {r.allowed_roles_count > 0 && (
        <Badge variant="outline" className="text-xs gap-1"><Users className="h-3 w-3" />roles:{r.allowed_roles_count}</Badge>
      )}
      {r.require_device_trust && (
        <Badge variant="outline" className="text-xs gap-1"><Fingerprint className="h-3 w-3" />device</Badge>
      )}
      {r.posture_check_count > 0 && (
        <Badge variant="outline" className="text-xs gap-1"><ScanFace className="h-3 w-3" />posture:{r.posture_check_count}</Badge>
      )}
      {r.max_risk_score < 100 && (
        <Badge variant="outline" className="text-xs gap-1"><Activity className="h-3 w-3" />risk≤{r.max_risk_score}</Badge>
      )}
      {r.allowed_countries_count > 0 && (
        <Badge variant="outline" className="text-xs gap-1"><MapPin className="h-3 w-3" />geo:{r.allowed_countries_count}</Badge>
      )}
      {r.has_inline_policy && <Badge variant="outline" className="text-xs">inline</Badge>}
    </div>
  )
}

function healthColor(h: string) {
  if (h === 'healthy') return 'bg-green-500'
  if (h === 'degraded') return 'bg-amber-500'
  if (h === 'unhealthy') return 'bg-red-500'
  return 'bg-gray-300'
}

export function ZeroTrustPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [tab, setTab] = useState('resources')

  const overviewQuery = useQuery({
    queryKey: ['access-overview'],
    queryFn: () => api.get<OverviewResponse>('/api/v1/access/overview'),
  })
  const sessionsQuery = useQuery({
    queryKey: ['access-sessions'],
    queryFn: () => api.get<{ sessions: ProxySession[] }>('/api/v1/access/sessions'),
    enabled: tab === 'live',
  })
  const auditQuery = useQuery({
    queryKey: ['access-audit-recent'],
    queryFn: () => api.get<{ events: AuditEvent[] }>('/api/v1/access/audit/unified?limit=50'),
    enabled: tab === 'live',
  })

  const toggleFeature = useMutation({
    mutationFn: ({ id, feature, on }: { id: string; feature: 'ziti' | 'browzer'; on: boolean }) =>
      api.post(`/api/v1/access/services/${id}/features/${feature}/${on ? 'enable' : 'disable'}`),
    onSuccess: (_d, v) => {
      queryClient.invalidateQueries({ queryKey: ['access-overview'] })
      toast({ title: 'Updated', description: `${v.feature === 'ziti' ? 'OpenZiti' : 'BrowZer'} ${v.on ? 'enabled' : 'disabled'}.` })
    },
    onError: (e: Error) => toast({ title: 'Failed', description: e.message, variant: 'destructive' }),
  })

  const data = overviewQuery.data
  const s = data?.summary
  const routes = data?.routes || []
  const gapRoutes = routes.filter(
    (r) => !r.require_auth || !r.require_device_trust || r.posture_check_count === 0 || r.max_risk_score >= 100,
  )

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight flex items-center gap-2">
            <Shield className="h-7 w-7" />
            Zero Trust Access
          </h1>
          <p className="text-muted-foreground">
            Every protected resource, how it's reached, the controls guarding it, and who's connected.
          </p>
        </div>
        <Badge variant={data?.ziti.configured ? 'secondary' : 'outline'} className="gap-1">
          <Network className="h-3 w-3" />
          Ziti: {!data?.ziti.configured ? 'not configured' : data?.ziti.controller_reachable ? 'reachable' : 'unreachable'}
        </Badge>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        <SummaryCard label="Resources" value={s?.total_routes} sub={`${s?.enabled_routes ?? 0} enabled`} icon={Shield} />
        <SummaryCard label="Via Ziti" value={s?.via_ziti} icon={Network} />
        <SummaryCard label="Via BrowZer" value={s?.via_browzer} icon={Globe} />
        <SummaryCard label="Via Guacamole" value={s?.via_guacamole} icon={MonitorSmartphone} />
        <SummaryCard label="Active sessions" value={s?.active_sessions} icon={Activity} />
        <SummaryCard
          label="Need hardening"
          value={(s?.missing_auth ?? 0) + (s?.missing_device_trust ?? 0) + (s?.missing_posture ?? 0)}
          icon={ShieldAlert}
          danger
        />
      </div>

      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="resources">Resources</TabsTrigger>
          <TabsTrigger value="live">Live Access</TabsTrigger>
          <TabsTrigger value="gaps">Coverage Gaps {gapRoutes.length ? `(${gapRoutes.length})` : ''}</TabsTrigger>
        </TabsList>

        {/* ---- Resources (spine) ---- */}
        <TabsContent value="resources" className="space-y-4">
          {overviewQuery.isLoading ? (
            <LoadingSpinner />
          ) : overviewQuery.isError ? (
            <QueryError error={overviewQuery.error} resource="the access overview" />
          ) : routes.length === 0 ? (
            <EmptyState />
          ) : (
            <Card>
              <CardContent className="p-0">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Resource</TableHead>
                      <TableHead>Access methods</TableHead>
                      <TableHead>Zero-trust policy</TableHead>
                      <TableHead>Sessions</TableHead>
                      <TableHead>Health</TableHead>
                      <TableHead className="text-right">Controls</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {routes.map((r) => (
                      <TableRow key={r.id} className={!r.enabled ? 'opacity-50' : ''}>
                        <TableCell>
                          <div className="font-medium">{r.name}</div>
                          <div className="font-mono text-xs text-muted-foreground truncate max-w-[240px]">{r.from_url}</div>
                        </TableCell>
                        <TableCell><MethodBadges r={r} /></TableCell>
                        <TableCell><PolicyBadges r={r} /></TableCell>
                        <TableCell>
                          <span className={r.active_sessions > 0 ? 'font-semibold' : 'text-muted-foreground'}>
                            {r.active_sessions}
                          </span>
                        </TableCell>
                        <TableCell>
                          <div className="flex gap-1">
                            {r.features.length === 0 ? (
                              <span className="text-xs text-muted-foreground">—</span>
                            ) : (
                              r.features.map((f) => (
                                <span
                                  key={f.feature_name}
                                  title={`${f.feature_name}: ${f.health_status || f.status}`}
                                  className={`h-2.5 w-2.5 rounded-full ${healthColor(f.health_status)}`}
                                />
                              ))
                            )}
                          </div>
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center justify-end gap-3">
                            <label className="flex items-center gap-1 text-xs text-muted-foreground">
                              Ziti
                              <Switch
                                checked={r.ziti_enabled}
                                disabled={toggleFeature.isPending}
                                onCheckedChange={(on) => toggleFeature.mutate({ id: r.id, feature: 'ziti', on })}
                              />
                            </label>
                            <label className="flex items-center gap-1 text-xs text-muted-foreground">
                              BrowZer
                              <Switch
                                checked={r.browzer_enabled}
                                disabled={toggleFeature.isPending || !r.ziti_enabled}
                                onCheckedChange={(on) => toggleFeature.mutate({ id: r.id, feature: 'browzer', on })}
                              />
                            </label>
                            <Link to="/proxy-routes" title="Manage route">
                              <Button variant="ghost" size="sm"><ExternalLink className="h-4 w-4" /></Button>
                            </Link>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          )}
          <div className="flex gap-3 text-sm text-muted-foreground">
            <Link to="/ziti-network" className="hover:underline flex items-center gap-1"><Network className="h-3 w-3" />Ziti Network</Link>
            <Link to="/app-publish" className="hover:underline flex items-center gap-1"><ExternalLink className="h-3 w-3" />App Publish</Link>
            <Link to="/devices" className="hover:underline flex items-center gap-1"><MonitorSmartphone className="h-3 w-3" />Devices</Link>
          </div>
        </TabsContent>

        {/* ---- Live access ---- */}
        <TabsContent value="live" className="space-y-4">
          <Card>
            <CardHeader><CardTitle className="text-base">Active sessions</CardTitle></CardHeader>
            <CardContent className="p-0">
              {sessionsQuery.isLoading ? (
                <div className="p-4"><LoadingSpinner /></div>
              ) : sessionsQuery.isError ? (
                <QueryError error={sessionsQuery.error} resource="active sessions" />
              ) : (sessionsQuery.data?.sessions || []).length === 0 ? (
                <p className="p-4 text-sm text-muted-foreground">No active sessions.</p>
              ) : (
                <Table>
                  <TableHeader><TableRow>
                    <TableHead>User</TableHead><TableHead>Resource</TableHead><TableHead>IP</TableHead><TableHead>Last active</TableHead>
                  </TableRow></TableHeader>
                  <TableBody>
                    {(sessionsQuery.data?.sessions || []).map((sess) => (
                      <TableRow key={sess.id}>
                        <TableCell className="font-mono text-xs">{sess.user_id}</TableCell>
                        <TableCell className="text-xs">{routeName(routes, sess.route_id)}</TableCell>
                        <TableCell className="font-mono text-xs">{sess.ip_address}</TableCell>
                        <TableCell className="text-xs">{fmt(sess.last_active_at)}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
          <Card>
            <CardHeader><CardTitle className="text-base">Recent access events</CardTitle></CardHeader>
            <CardContent className="p-0">
              {auditQuery.isLoading ? (
                <div className="p-4"><LoadingSpinner /></div>
              ) : auditQuery.isError ? (
                <QueryError error={auditQuery.error} resource="recent access events" />
              ) : (auditQuery.data?.events || []).length === 0 ? (
                <p className="p-4 text-sm text-muted-foreground">No recent events.</p>
              ) : (
                <Table>
                  <TableHeader><TableRow>
                    <TableHead>When</TableHead><TableHead>Event</TableHead><TableHead>User</TableHead><TableHead>IP</TableHead><TableHead>Source</TableHead>
                  </TableRow></TableHeader>
                  <TableBody>
                    {(auditQuery.data?.events || []).map((e, i) => (
                      <TableRow key={i} className={e.event_type.includes('denied') ? 'bg-red-50' : ''}>
                        <TableCell className="text-xs">{fmt(e.created_at)}</TableCell>
                        <TableCell className="text-xs">
                          <Badge variant={e.event_type.includes('denied') ? 'destructive' : 'outline'} className="text-xs">{e.event_type}</Badge>
                        </TableCell>
                        <TableCell className="text-xs">{e.user_email}</TableCell>
                        <TableCell className="font-mono text-xs">{e.actor_ip}</TableCell>
                        <TableCell className="text-xs">{e.source}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
          <Link to="/unified-audit" className="text-sm text-muted-foreground hover:underline flex items-center gap-1">
            <ExternalLink className="h-3 w-3" />Full unified audit log
          </Link>
        </TabsContent>

        {/* ---- Coverage gaps ---- */}
        <TabsContent value="gaps" className="space-y-4">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <SummaryCard label="No authentication" value={s?.missing_auth} icon={Unlock} danger />
            <SummaryCard label="No device trust" value={s?.missing_device_trust} icon={Fingerprint} />
            <SummaryCard label="No posture checks" value={s?.missing_posture} icon={ScanFace} />
            <SummaryCard label="No risk cap" value={s?.missing_risk_cap} icon={Activity} />
          </div>
          {gapRoutes.length === 0 ? (
            <Card><CardContent className="py-12 text-center text-muted-foreground">
              <Shield className="h-10 w-10 mx-auto mb-3 text-green-600" />
              Every resource has auth, device-trust, posture and a risk cap. No gaps.
            </CardContent></Card>
          ) : (
            <Card>
              <CardContent className="p-0">
                <Table>
                  <TableHeader><TableRow>
                    <TableHead>Resource</TableHead><TableHead>Gaps</TableHead><TableHead className="text-right">Fix</TableHead>
                  </TableRow></TableHeader>
                  <TableBody>
                    {gapRoutes.map((r) => (
                      <TableRow key={r.id}>
                        <TableCell>
                          <div className="font-medium">{r.name}</div>
                          <div className="font-mono text-xs text-muted-foreground truncate max-w-[240px]">{r.from_url}</div>
                        </TableCell>
                        <TableCell>
                          <div className="flex flex-wrap gap-1">
                            {!r.require_auth && <Badge className="bg-red-100 text-red-700 text-xs">no auth</Badge>}
                            {!r.require_device_trust && <Badge variant="outline" className="text-xs">no device trust</Badge>}
                            {r.posture_check_count === 0 && <Badge variant="outline" className="text-xs">no posture</Badge>}
                            {r.max_risk_score >= 100 && <Badge variant="outline" className="text-xs">no risk cap</Badge>}
                          </div>
                        </TableCell>
                        <TableCell className="text-right">
                          <Link to="/proxy-routes"><Button variant="outline" size="sm">Harden</Button></Link>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          )}
        </TabsContent>
      </Tabs>
    </div>
  )
}

function SummaryCard({
  label,
  value,
  sub,
  icon: Icon,
  danger,
}: {
  label: string
  value?: number
  sub?: string
  icon: typeof Shield
  danger?: boolean
}) {
  return (
    <Card className={danger && (value ?? 0) > 0 ? 'border-red-200' : ''}>
      <CardHeader className="pb-2">
        <CardDescription className="flex items-center gap-1">
          <Icon className={`h-4 w-4 ${danger && (value ?? 0) > 0 ? 'text-red-600' : ''}`} />
          {label}
        </CardDescription>
        <CardTitle className={`text-2xl ${danger && (value ?? 0) > 0 ? 'text-red-600' : ''}`}>{value ?? 0}</CardTitle>
      </CardHeader>
      {sub && <CardContent className="pt-0 text-xs text-muted-foreground">{sub}</CardContent>}
    </Card>
  )
}

function EmptyState() {
  return (
    <Card>
      <CardContent className="py-12 text-center">
        <Shield className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
        <p className="text-lg font-medium">No protected resources yet</p>
        <p className="text-muted-foreground">
          Publish an app or add a proxy route to start enforcing zero-trust access.
        </p>
        <Link to="/app-publish"><Button className="mt-4">Go to App Publish</Button></Link>
      </CardContent>
    </Card>
  )
}

function routeName(routes: OverviewRoute[], id: string) {
  return routes.find((r) => r.id === id)?.name || id || '—'
}

function fmt(ts?: string) {
  if (!ts) return '—'
  const d = new Date(ts)
  return isNaN(d.getTime()) ? ts : d.toLocaleString()
}
