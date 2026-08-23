import { useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Plus, Trash2, Network, Server, Users2, Copy, CheckCircle,
  Shield, Router, Fingerprint, RefreshCw, FileKey, AlertTriangle,
  Monitor, ExternalLink, MoreHorizontal, Search, ChevronDown, ChevronRight,
  LayoutDashboard, Clock, Link2, Key, Terminal, MonitorPlay, Lock, Pencil, ScrollText,
  Settings, Zap, Upload, Download,
} from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs'
import { Switch } from '../components/ui/switch'
import {
  Dialog, DialogContent, DialogHeader, DialogTitle,
} from '../components/ui/dialog'
import { Label } from '../components/ui/label'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '../components/ui/alert-dialog'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '../components/ui/table'
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem,
  DropdownMenuSeparator, DropdownMenuTrigger,
} from '../components/ui/dropdown-menu'
import { api } from '../lib/api'
import { QueryError } from '../components/query-error'
import { useToast } from '../hooks/use-toast'
import { ConfirmAction } from '../components/confirm-action'

// ─── Types ───────────────────────────────────────────────────────────────────

interface ZitiService {
  id: string
  ziti_id: string
  name: string
  description?: string
  protocol: string
  host: string
  port: number
  route_id?: string
  enabled: boolean
  created_at: string
  browzer_path?: string
  browzer_domain?: string
}

interface ZitiIdentity {
  id: string
  ziti_id: string
  name: string
  display_name?: string
  identity_type: string
  user_id?: string
  enrolled: boolean
  attributes: string[]
  created_at: string
}

interface ZitiEndpointStatus {
  url: string
  active: boolean
  healthy: boolean
}

interface ZitiStatus {
  enabled: boolean
  sdk_ready: boolean
  controller_reachable?: boolean
  controller_error?: string
  controller_version?: Record<string, unknown>
  console_url?: string
  services_count: number
  identities_count: number
  // Present on the fabric/health-derived status; optional here so the overview
  // cards can fall back to it when the overview payload is unavailable.
  routers_online?: number
  routers_total?: number
  /** true when ZITI_CTRL_URLS configures >1 management endpoint (HA cluster) */
  ha?: boolean
  controller_endpoints?: ZitiEndpointStatus[]
}

interface ZitiSyncStatus {
  status: string
  last_full_sync_at?: string
  last_auto_sync_at?: string
  users_synced: number
  users_failed: number
  groups_synced: number
  unsynced_users: number
  total_users: number
  total_identities: number
}

interface FabricRouter {
  id: string
  name: string
  // The controller returns camelCase fields straight from the Ziti mgmt API
  // (isOnline/isVerified/versionInfo), and does NOT send fingerprint/created_at.
  // Matching the real shape here fixes the router showing as "Offline" and the
  // "Invalid Date" created cell.
  isOnline: boolean
  isVerified?: boolean
  hostname: string
  roleAttributes?: string[]
  versionInfo?: { os?: string; arch?: string; version?: string }
}

// The /ziti/fabric/overview endpoint returns { health: {...}, recent_metrics }.
// The FE previously expected a flat {controller_online, router_count,
// healthy_routers, ...} object whose keys never matched, so the overview cards
// all read 0 / Offline even though the fabric was healthy.
interface FabricHealth {
  controller_reachable: boolean
  controller_version?: string
  sdk_ready?: boolean
  routers_online: number
  routers_total: number
  services_count: number
  identities_count: number
  policies_count: number
  last_checked?: string
}
interface FabricOverview {
  health?: FabricHealth
}

interface PostureCheck {
  id: string
  name: string
  check_type: string
  parameters: Record<string, unknown>
  enabled: boolean
  severity: string
  platforms?: string[] | null
  created_at: string
}

interface PostureSummary {
  total_checks: number
  enabled_checks: number
  disabled_checks: number
  by_type: Record<string, number>
  by_severity: Record<string, number>
}

interface PostureResult {
  id: string
  identity_id: string
  check_id: string
  passed: boolean
  details: Record<string, unknown>
  checked_at: string
  expires_at?: string
}

interface IdentityPostureReport {
  identity_id: string
  overall_passed: boolean
  results: PostureResult[]
  evaluated_at: string
}

interface PolicySync {
  id: string
  governance_policy_id: string
  ziti_policy_id: string
  sync_status: string
  last_synced_at: string
  error_message: string
}

interface ServicePolicy {
  id: string
  name: string
  type: string
  serviceRoles: string[]
  identityRoles: string[]
}

interface EdgeRouterPolicy {
  id: string
  name: string
  edgeRouterRoles: string[]
  identityRoles: string[]
}

interface Certificate {
  id: string
  name: string
  cert_type: string
  subject: string
  issuer: string
  fingerprint: string
  not_before: string
  not_after: string
  auto_renew: boolean
  status: string
  days_until_expiry: number
}

interface GuacConnection {
  id: string
  route_id: string
  guacamole_connection_id: string
  protocol: string
  hostname: string
  port: number
  parameters: Record<string, string>
  created_at: string
  updated_at: string
}

interface BrowZerStatus {
  enabled: boolean
  configured?: boolean
  external_jwt_signer_id?: string
  auth_policy_id?: string
  dial_policy_id?: string
  oidc_issuer?: string
  oidc_client_id?: string
  bootstrapper_url?: string
  reason?: string
}

interface TempAccessLink {
  id: string
  token: string
  name: string
  description?: string
  protocol: string
  target_host: string
  target_port: number
  username?: string
  created_by: string
  created_by_email: string
  expires_at: string
  max_uses: number
  current_uses: number
  allowed_ips?: string[]
  require_mfa: boolean
  notify_on_use: boolean
  notify_email?: string
  access_url: string
  status: 'active' | 'expired' | 'revoked' | 'used'
  last_used_at?: string
  last_used_ip?: string
  created_at: string
}

interface ZitiConfigType {
  id: string
  name: string
  schema?: Record<string, unknown>
}

interface ZitiConfig {
  id: string
  name: string
  configTypeId: string
  configType?: { id: string; name: string }
  data: Record<string, unknown>
}

interface ZitiAuthPolicy {
  id: string
  name: string
  primary: Record<string, Record<string, unknown>>
  secondary: Record<string, unknown>
}

interface ZitiJWTSigner {
  id: string
  name: string
  issuer: string
  audience: string
  jwksEndpoint: string
  claimsProperty: string
  useExternalId: boolean
  enabled: boolean
}

interface ZitiTerminator {
  id: string
  serviceId: string
  service?: { id: string; name: string }
  routerId: string
  router?: { id: string; name: string }
  binding: string
  address: string
  cost: number
  precedence: string
  createdAt: string
}

interface ZitiSessionEntry {
  id: string
  type: 'Dial' | 'Bind'
  identity?: { id: string; name: string }
  service?: { id: string; name: string }
  createdAt: string
}

interface AppZitiService {
  id: string
  ziti_id: string
  name: string
  protocol: string
  host: string
  port: number
  enabled: boolean
  linked_path: string
  classification: string
  route_name: string
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// Render a possibly-missing/invalid timestamp without printing "Invalid Date"
// (some Ziti entities arrive with an empty or unparseable created_at).
function safeDate(v?: string | null): string {
  if (!v) return '—'
  const d = new Date(v)
  return isNaN(d.getTime()) ? '—' : d.toLocaleDateString()
}

function TruncatedId({ value, label }: { value: string; label?: string }) {
  const { toast } = useToast()
  if (!value) return <span className="text-xs text-muted-foreground">—</span>
  const short = value.length > 12 ? value.slice(0, 8) + '...' : value
  return (
    <button
      onClick={() => {
        navigator.clipboard.writeText(value)
        toast({ title: 'Copied', description: `${label || 'ID'} copied to clipboard.` })
      }}
      className="inline-flex items-center gap-1 font-mono text-xs text-muted-foreground hover:text-foreground transition-colors"
      title={value}
    >
      {short}
      <Copy className="h-3 w-3" />
    </button>
  )
}

function Spinner() {
  return (
    <div className="flex justify-center py-12">
      <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
    </div>
  )
}

function EmptyState({ icon: Icon, title, description }: { icon: React.ElementType; title: string; description: string }) {
  return (
    <Card>
      <CardContent className="flex flex-col items-center justify-center py-12">
        <Icon className="h-12 w-12 text-muted-foreground mb-4" />
        <h3 className="text-lg font-medium">{title}</h3>
        <p className="text-muted-foreground mt-1 text-center max-w-md">{description}</p>
      </CardContent>
    </Card>
  )
}

function SearchInput({ value, onChange, placeholder }: { value: string; onChange: (v: string) => void; placeholder: string }) {
  return (
    <div className="relative flex-1 max-w-sm">
      <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
      <Input
        placeholder={placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="pl-9"
      />
    </div>
  )
}

// ─── Page ────────────────────────────────────────────────────────────────────

const ZITI_TABS = ['connection', 'overview', 'services', 'identities', 'security', 'remote-access']

export function ZitiNetworkPage() {
  // Deep-linkable tabs (e.g. /ziti-network?tab=connection from Network Setup).
  const [searchParams] = useSearchParams()
  const requestedTab = searchParams.get('tab') ?? ''
  const [activeTab, setActiveTab] = useState(ZITI_TABS.includes(requestedTab) ? requestedTab : 'overview')

  const { data: status } = useQuery({
    queryKey: ['ziti-status'],
    queryFn: () => api.get<ZitiStatus>('/api/v1/access/ziti/status'),
    refetchInterval: 10000,
  })

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Ziti Network</h1>
          <p className="text-muted-foreground">Manage your OpenZiti zero-trust network overlay</p>
        </div>
        <div className="flex items-center gap-3">
          {status && (
            <>
              <div className="flex items-center gap-1.5 text-sm">
                {status.controller_reachable ? (
                  <span className="flex items-center gap-1.5 text-green-600">
                    <span className="h-2 w-2 rounded-full bg-green-500 animate-pulse" />
                    Connected
                  </span>
                ) : (
                  <span className="flex items-center gap-1.5 text-red-500">
                    <span className="h-2 w-2 rounded-full bg-red-500" />
                    Disconnected
                  </span>
                )}
              </div>
              <Badge variant="outline">{status.services_count} services</Badge>
              <Badge variant="outline">{status.identities_count} identities</Badge>
              {status.console_url && (
                <Button variant="outline" size="sm" asChild>
                  <a href={status.console_url} target="_blank" rel="noreferrer">
                    <ExternalLink className="h-4 w-4 mr-1.5" />
                    Ziti Console
                  </a>
                </Button>
              )}
            </>
          )}
        </div>
      </div>

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="connection" className="gap-1.5">
            <Settings className="h-4 w-4" />
            Connection
          </TabsTrigger>
          <TabsTrigger value="overview" className="gap-1.5">
            <LayoutDashboard className="h-4 w-4" />
            Overview
          </TabsTrigger>
          <TabsTrigger value="services" className="gap-1.5">
            <Server className="h-4 w-4" />
            Services
          </TabsTrigger>
          <TabsTrigger value="identities" className="gap-1.5">
            <Users2 className="h-4 w-4" />
            Identities
          </TabsTrigger>
          <TabsTrigger value="security" className="gap-1.5">
            <Shield className="h-4 w-4" />
            Security
          </TabsTrigger>
          <TabsTrigger value="remote-access" className="gap-1.5">
            <Monitor className="h-4 w-4" />
            Remote Access
          </TabsTrigger>
        </TabsList>

        <TabsContent value="connection">
          <ConnectionTab />
        </TabsContent>
        <TabsContent value="overview">
          <OverviewTab onNavigate={setActiveTab} />
        </TabsContent>
        <TabsContent value="services">
          <ServicesTab />
        </TabsContent>
        <TabsContent value="identities">
          <IdentitiesTab />
        </TabsContent>
        <TabsContent value="security">
          <SecurityTab />
        </TabsContent>
        <TabsContent value="remote-access">
          <RemoteAccessTab />
        </TabsContent>
      </Tabs>
    </div>
  )
}

// ─── Overview Tab ────────────────────────────────────────────────────────────

interface ZitiConnSettings {
  enabled: boolean
  controller_url: string
  admin_user: string
  admin_password: string
  identity_dir: string
  insecure_skip_verify: boolean
}

// ConnectionTab manages the OpenZiti controller connection from the admin panel:
// view/edit the URL + admin creds, test reachability, and connect/disconnect the
// live manager at runtime (no service restart).
function ConnectionTab() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [form, setForm] = useState<ZitiConnSettings | null>(null)

  const { data: status } = useQuery({
    queryKey: ['ziti-status'],
    queryFn: () => api.get<ZitiStatus>('/api/v1/access/ziti/status'),
    refetchInterval: 10000,
  })
  const { isLoading } = useQuery({
    queryKey: ['ziti-settings'],
    queryFn: async () => {
      const s = await api.get<ZitiConnSettings>('/api/v1/access/ziti/settings')
      setForm(s)
      return s
    },
  })

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ['ziti-status'] })
    queryClient.invalidateQueries({ queryKey: ['ziti-fabric-overview'] })
    queryClient.invalidateQueries({ queryKey: ['access-overview'] })
  }

  const save = useMutation({
    mutationFn: (s: ZitiConnSettings) => api.put('/api/v1/access/ziti/settings', s),
    onSuccess: () => toast({ title: 'Saved', description: 'Ziti connection settings stored.' }),
    onError: (e: Error) => toast({ title: 'Save failed', description: e.message, variant: 'destructive' }),
  })
  const test = useMutation({
    mutationFn: (s: ZitiConnSettings) =>
      api.post<{ reachable: boolean; authenticated: boolean; error?: string; controller_version?: { data?: { version?: string } } }>(
        '/api/v1/access/ziti/settings/test', s),
    onSuccess: (r) =>
      toast({
        title: r.reachable ? 'Connection OK' : 'Connection failed',
        description: r.reachable
          ? `Controller ${r.controller_version?.data?.version || 'reachable'}`
          : r.error || 'unreachable',
        variant: r.reachable ? undefined : 'destructive',
      }),
    onError: (e: Error) => toast({ title: 'Test failed', description: e.message, variant: 'destructive' }),
  })
  const connect = useMutation({
    mutationFn: async (s: ZitiConnSettings) => { await api.put('/api/v1/access/ziti/settings', s); return api.post('/api/v1/access/ziti/connect', {}) },
    onSuccess: () => { invalidate(); toast({ title: 'Connected', description: 'OpenZiti controller connected.' }) },
    onError: (e: Error) => toast({ title: 'Connect failed', description: e.message, variant: 'destructive' }),
  })
  const disconnect = useMutation({
    mutationFn: () => api.post('/api/v1/access/ziti/disconnect', {}),
    onSuccess: () => { invalidate(); toast({ title: 'Disconnected', description: 'OpenZiti controller disconnected.' }) },
    onError: (e: Error) => toast({ title: 'Disconnect failed', description: e.message, variant: 'destructive' }),
  })

  if (isLoading || !form) return <div className="py-8 text-center text-muted-foreground">Loading…</div>

  const reachable = !!status?.controller_reachable
  const ctrlVer = (status?.controller_version as { data?: { version?: string } } | undefined)?.data?.version
  const set = (k: keyof ZitiConnSettings, v: string | boolean) => setForm({ ...form, [k]: v })

  return (
    <div className="space-y-4 max-w-2xl">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Network className="h-5 w-5" />
            Controller Connection
            <Badge className={`ml-auto ${reachable ? 'bg-green-100 text-green-700' : 'bg-muted text-muted-foreground'}`}>
              {!status?.enabled ? 'not configured' : reachable ? 'connected' : 'unreachable'}
            </Badge>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="ctrl">Controller URL</Label>
            <Input id="ctrl" placeholder="https://ziti-controller.example.com:1280"
              value={form.controller_url} onChange={(e) => set('controller_url', e.target.value)} />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <Label htmlFor="user">Admin user</Label>
              <Input id="user" value={form.admin_user} onChange={(e) => set('admin_user', e.target.value)} />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="pw">Admin password</Label>
              <Input id="pw" type="password" placeholder="••••••••"
                value={form.admin_password} onChange={(e) => set('admin_password', e.target.value)} />
            </div>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="dir">Identity directory</Label>
            <Input id="dir" value={form.identity_dir} onChange={(e) => set('identity_dir', e.target.value)} />
          </div>
          <div className="flex items-center gap-2">
            <Switch id="insecure" checked={form.insecure_skip_verify}
              onCheckedChange={(v) => set('insecure_skip_verify', v)} />
            <Label htmlFor="insecure" className="text-sm">Skip TLS verification (dev only)</Label>
          </div>
          {ctrlVer && (
            <p className="text-xs text-muted-foreground">Controller version: {ctrlVer}</p>
          )}
          {status?.ha && status.controller_endpoints && (
            <div className="rounded-lg border p-3 space-y-2">
              <div className="flex items-center gap-2 text-sm font-medium">
                HA controller cluster
                <Badge className="bg-blue-100 text-blue-700">
                  {status.controller_endpoints.filter((e) => e.healthy).length}/{status.controller_endpoints.length} healthy
                </Badge>
              </div>
              <div className="space-y-1">
                {status.controller_endpoints.map((ep) => (
                  <div key={ep.url} className="flex items-center gap-2 text-xs font-mono">
                    <span className={`h-2 w-2 rounded-full shrink-0 ${ep.healthy ? 'bg-green-500' : 'bg-red-500'}`} />
                    <span className="truncate">{ep.url}</span>
                    {ep.active && <Badge className="bg-green-100 text-green-700 ml-auto shrink-0">active</Badge>}
                  </div>
                ))}
              </div>
              <p className="text-xs text-muted-foreground">
                Management calls fail over automatically between cluster members (set via ZITI_CTRL_URLS).
              </p>
            </div>
          )}
          <div className="flex flex-wrap gap-2 pt-2">
            <Button variant="outline" disabled={test.isPending} onClick={() => test.mutate(form)}>Test</Button>
            <Button variant="outline" disabled={save.isPending} onClick={() => save.mutate(form)}>Save</Button>
            <Button disabled={connect.isPending} onClick={() => connect.mutate(form)}>Save &amp; Connect</Button>
            <Button variant="ghost" className="text-red-600" disabled={disconnect.isPending}
              onClick={() => disconnect.mutate()}>Disconnect</Button>
          </div>
        </CardContent>
      </Card>
      <p className="text-xs text-muted-foreground">
        Connect / disconnect takes effect immediately — no service restart. The password is stored encrypted and shown masked.
      </p>
    </div>
  )
}

function OverviewTab({ onNavigate }: { onNavigate: (tab: string) => void }) {
  const { toast } = useToast()

  const { data: status, isLoading: statusLoading } = useQuery({
    queryKey: ['ziti-status'],
    queryFn: () => api.get<ZitiStatus>('/api/v1/access/ziti/status'),
    refetchInterval: 10000,
  })

  const { data: overview } = useQuery({
    queryKey: ['ziti-fabric-overview'],
    queryFn: () => api.get<FabricOverview>('/api/v1/access/ziti/fabric/overview'),
    refetchInterval: 15000,
  })

  const { data: routersData } = useQuery({
    queryKey: ['ziti-fabric-routers'],
    queryFn: () => api.get<FabricRouter[]>('/api/v1/access/ziti/fabric/routers'),
  })

  const reconnectMutation = useMutation({
    mutationFn: () => api.post('/api/v1/access/ziti/fabric/reconnect', {}),
    onSuccess: () => toast({ title: 'Reconnect initiated', description: 'Fabric reconnect has been triggered.' }),
    onError: () => toast({ title: 'Error', description: 'Failed to trigger reconnect.', variant: 'destructive' }),
  })

  const healthCheckMutation = useMutation({
    mutationFn: () => api.get('/api/v1/access/ziti/fabric/health'),
    onSuccess: () => toast({ title: 'Health check passed', description: 'Fabric health check completed successfully.' }),
    onError: () => toast({ title: 'Health check failed', description: 'Fabric health check reported issues.', variant: 'destructive' }),
  })

  const routers = Array.isArray(routersData) ? routersData : []

  if (statusLoading) return <Spinner />

  // The overview endpoint nests everything under `health`. Fall back to the
  // separate `status` (fabric/health) source when present.
  const h = overview?.health
  const controllerUp = (h?.controller_reachable ?? status?.controller_reachable) ?? false
  const routersOnline = h?.routers_online ?? status?.routers_online ?? 0
  const routersTotal = h?.routers_total ?? status?.routers_total ?? routers.length
  const servicesCount = h?.services_count ?? status?.services_count ?? 0
  const identitiesCount = h?.identities_count ?? status?.identities_count ?? 0

  const statCards = [
    {
      title: 'Controller',
      value: controllerUp ? 'Online' : 'Offline',
      description: (h?.sdk_ready ?? status?.sdk_ready) ? 'SDK Ready' : 'SDK Not Ready',
      icon: Network,
      color: controllerUp ? 'text-green-600' : 'text-red-500',
      isStatus: true,
    },
    {
      title: 'Routers',
      value: routersTotal,
      description: `${routersOnline} online, ${Math.max(0, routersTotal - routersOnline)} offline`,
      icon: Router,
      color: 'text-primary',
    },
    {
      title: 'Services',
      value: servicesCount,
      description: 'Registered services',
      icon: Server,
      color: 'text-purple-600',
      onClick: () => onNavigate('services'),
    },
    {
      title: 'Identities',
      value: identitiesCount,
      description: 'Registered identities',
      icon: Users2,
      color: 'text-orange-600',
      onClick: () => onNavigate('identities'),
    },
  ]

  return (
    <div className="space-y-6 mt-4">
      {/* Stat cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {statCards.map((stat) => (
          <Card
            key={stat.title}
            className={stat.onClick ? 'cursor-pointer hover:shadow-md transition-all hover:scale-[1.02]' : ''}
            onClick={stat.onClick}
          >
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium">{stat.title}</CardTitle>
              <stat.icon className={`h-4 w-4 ${stat.color}`} />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">
                {stat.isStatus ? (
                  <span className={stat.color}>{stat.value}</span>
                ) : (
                  String(stat.value)
                )}
              </div>
              <p className="text-xs text-muted-foreground">{stat.description}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Routers section */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-semibold">Edge Routers</h3>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={() => healthCheckMutation.mutate()} disabled={healthCheckMutation.isPending}>
              <CheckCircle className="mr-2 h-4 w-4" />
              {healthCheckMutation.isPending ? 'Checking...' : 'Health Check'}
            </Button>
            <Button variant="outline" size="sm" onClick={() => reconnectMutation.mutate()} disabled={reconnectMutation.isPending}>
              <RefreshCw className="mr-2 h-4 w-4" />
              {reconnectMutation.isPending ? 'Reconnecting...' : 'Reconnect'}
            </Button>
          </div>
        </div>

        {routers.length === 0 ? (
          <EmptyState icon={Router} title="No edge routers" description="No routers are registered in the Ziti fabric." />
        ) : (
          <Card>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Hostname</TableHead>
                  <TableHead>Verified</TableHead>
                  <TableHead>Version</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {routers.map((router) => (
                  <TableRow key={router.id} className="hover:bg-muted/50">
                    <TableCell className="font-medium">{router.name}</TableCell>
                    <TableCell>
                      <Badge variant={router.isOnline ? 'default' : 'destructive'}>
                        {router.isOnline ? 'Online' : 'Offline'}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">{router.hostname}</TableCell>
                    <TableCell>
                      <Badge variant={router.isVerified ? 'default' : 'secondary'}>
                        {router.isVerified ? 'Verified' : 'Unverified'}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {router.versionInfo?.version ?? '—'}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Card>
        )}
      </div>
    </div>
  )
}

// ─── Services Tab ────────────────────────────────────────────────────────────

interface ServiceTestResult {
  success: boolean
  service_name: string
  tests: Record<string, { success: boolean; latency_ms: number; error?: string }>
}

function ServicesTab() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [search, setSearch] = useState('')
  const [createModal, setCreateModal] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<ZitiService | null>(null)
  const [testingService, setTestingService] = useState<string | null>(null)
  // "How this works": the behind-the-scenes chain for one resource, so an
  // admin can see which link is broken without dropping to the CLI.
  const [explainName, setExplainName] = useState<string | null>(null)
  // intercept_address / dial_roles let the form provision a service that is
  // actually dialable, instead of a bare service object nobody can reach.
  const [form, setForm] = useState({ name: '', description: '', host: '', port: 8080, protocol: 'tcp', intercept_address: '', dial_roles: '' })

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['ziti-services'],
    queryFn: () => api.get<{ services: ZitiService[] }>('/api/v1/access/ziti/services'),
  })

  const createMutation = useMutation({
    mutationFn: (data: typeof form) => {
      // dial_roles is a comma-separated UI field; send an array of role
      // attributes (each normalized to "#role"). Empty → backend defaults to
      // "#<name>-clients".
      const dial_roles = data.dial_roles
        .split(',')
        .map((r) => r.trim())
        .filter(Boolean)
        .map((r) => (r.startsWith('#') ? r : `#${r}`))
      return api.post('/api/v1/access/ziti/services', {
        name: data.name,
        description: data.description,
        host: data.host,
        port: data.port,
        protocol: data.protocol,
        intercept_address: data.intercept_address.trim(),
        dial_roles,
      })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-services'] })
      queryClient.invalidateQueries({ queryKey: ['ziti-status'] })
      setCreateModal(false)
      setForm({ name: '', description: '', host: '', port: 8080, protocol: 'tcp', intercept_address: '', dial_roles: '' })
      toast({ title: 'Service created', description: 'Ziti service is now dialable over the overlay.' })
    },
    onError: () => toast({ title: 'Error', description: 'Failed to create Ziti service.', variant: 'destructive' }),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/access/ziti/services/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-services'] })
      queryClient.invalidateQueries({ queryKey: ['ziti-status'] })
      setDeleteTarget(null)
      toast({ title: 'Service deleted', description: 'Ziti service has been deleted.' })
    },
    onError: () => toast({ title: 'Error', description: 'Failed to delete Ziti service.', variant: 'destructive' }),
  })

  const testConnection = async (svc: ZitiService) => {
    setTestingService(svc.id)
    try {
      const result = await api.post<ServiceTestResult>(`/api/v1/access/ziti/services/${svc.id}/test`, {})
      if (result.success) {
        const latencies = Object.values(result.tests).map(t => t.latency_ms).filter(Boolean)
        const avgLatency = latencies.length > 0 ? Math.round(latencies.reduce((a, b) => a + b, 0) / latencies.length) : 0
        toast({ title: 'Connection OK', description: `${svc.name} is reachable (${avgLatency}ms).` })
      } else {
        const failedTests = Object.entries(result.tests).filter(([, t]) => !t.success).map(([k, t]) => `${k}: ${t.error || 'failed'}`).join(', ')
        toast({ title: 'Connection failed', description: failedTests || 'Service is not reachable.', variant: 'destructive' })
      }
    } catch {
      toast({ title: 'Error', description: 'Failed to test connection.', variant: 'destructive' })
    } finally {
      setTestingService(null)
    }
  }

  const services = (data?.services || []).filter((svc) =>
    !search || svc.name.toLowerCase().includes(search.toLowerCase()) ||
    svc.host.toLowerCase().includes(search.toLowerCase()) ||
    svc.description?.toLowerCase().includes(search.toLowerCase())
  )

  if (isLoading) return <Spinner />
  if (isError) return <QueryError error={error} resource="Ziti services" />

  return (
    <div className="space-y-4 mt-4">
      <div className="flex items-center justify-between gap-4">
        <SearchInput value={search} onChange={setSearch} placeholder="Search services..." />
        <Button onClick={() => setCreateModal(true)}>
          <Plus className="mr-2 h-4 w-4" /> Add Service
        </Button>
      </div>

      {services.length === 0 ? (
        <EmptyState
          icon={Server}
          title={search ? 'No matching services' : 'No Ziti services'}
          description={search ? 'Try a different search term.' : 'Register upstream services to route traffic through the Ziti overlay.'}
        />
      ) : (
        <Card>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Service</TableHead>
                <TableHead>Protocol</TableHead>
                <TableHead>Target</TableHead>
                <TableHead>Ziti ID</TableHead>
                <TableHead>Created</TableHead>
                <TableHead className="w-[50px]" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {services.map((svc) => (
                <TableRow key={svc.id} className="hover:bg-muted/50">
                  <TableCell>
                    <div>
                      <p className="font-medium">{svc.name}</p>
                      {svc.description && (
                        <p className="text-xs text-muted-foreground">{svc.description}</p>
                      )}
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline">{svc.protocol.toUpperCase()}</Badge>
                  </TableCell>
                  <TableCell>
                    <code className="text-sm bg-muted px-1.5 py-0.5 rounded">{svc.host}:{svc.port}</code>
                  </TableCell>
                  <TableCell><TruncatedId value={svc.ziti_id} label="Ziti ID" /></TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {safeDate(svc.created_at)}
                  </TableCell>
                  <TableCell>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="icon" className="h-8 w-8">
                          <MoreHorizontal className="h-4 w-4" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem onClick={() => testConnection(svc)} disabled={testingService === svc.id}>
                          <CheckCircle className="mr-2 h-4 w-4" />
                          {testingService === svc.id ? 'Testing...' : 'Test Connection'}
                        </DropdownMenuItem>
                        <DropdownMenuItem onClick={() => setExplainName(svc.name)}>
                          <ScrollText className="mr-2 h-4 w-4" /> How this works
                        </DropdownMenuItem>
                        <DropdownMenuItem onClick={() => {
                          navigator.clipboard.writeText(svc.ziti_id)
                          toast({ title: 'Copied', description: 'Ziti ID copied to clipboard.' })
                        }}>
                          <Copy className="mr-2 h-4 w-4" /> Copy Ziti ID
                        </DropdownMenuItem>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem className="text-red-600" onClick={() => setDeleteTarget(svc)}>
                          <Trash2 className="mr-2 h-4 w-4" /> Delete
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      )}

      {/* Create Dialog */}
      <Dialog open={createModal} onOpenChange={setCreateModal}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Add a resource</DialogTitle>
          </DialogHeader>
          <form onSubmit={(e) => { e.preventDefault(); createMutation.mutate(form) }} className="space-y-4">
            <div className="space-y-2">
              <Label>Name</Label>
              <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="internal-app" required />
              <p className="text-xs text-muted-foreground">What people will see in their list.</p>
            </div>
            <div className="space-y-2">
              <Label>Description</Label>
              <Input value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} placeholder="Optional description" />
            </div>
            <div className="grid grid-cols-3 gap-4">
              <div className="space-y-2">
                <Label>Target host</Label>
                <Input value={form.host} onChange={(e) => setForm({ ...form, host: e.target.value })} placeholder="10.0.0.5" required />
              </div>
              <div className="space-y-2">
                <Label>Port</Label>
                <Input type="number" min={1} max={65535} value={form.port} onChange={(e) => setForm({ ...form, port: Math.max(1, Math.min(65535, parseInt(e.target.value) || 1)) })} required />
              </div>
              <div className="space-y-2">
                <Label>Protocol</Label>
                <select
                  value={form.protocol}
                  onChange={(e) => setForm({ ...form, protocol: e.target.value })}
                  className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                >
                  <option value="tcp">TCP</option>
                  <option value="udp">UDP</option>
                </select>
              </div>
            </div>
            <div className="space-y-2">
              <Label>Intercept Address</Label>
              <Input value={form.intercept_address} onChange={(e) => setForm({ ...form, intercept_address: e.target.value })} placeholder={form.name ? `${form.name}.ziti (default)` : 'internal-app.ziti'} />
              <p className="text-xs text-muted-foreground">The overlay hostname clients dial (what the tunneler resolves). Leave blank to use <code>&lt;name&gt;.ziti</code>.</p>
            </div>
            <div className="space-y-2">
              <Label>Dial Roles</Label>
              <Input value={form.dial_roles} onChange={(e) => setForm({ ...form, dial_roles: e.target.value })} placeholder={form.name ? `${form.name}-clients (default)` : 'ci-clients, partner-x'} />
              <p className="text-xs text-muted-foreground">Comma-separated identity role attributes allowed to reach this service (least-privilege). Leave blank to use <code>#&lt;name&gt;-clients</code>. Assign the same role to the identities that should dial it.</p>
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <Button type="button" variant="outline" onClick={() => setCreateModal(false)}>Cancel</Button>
              <Button type="submit" disabled={createMutation.isPending}>
                {createMutation.isPending ? 'Creating...' : 'Create Service'}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* "How this works" — the real chain, and which link is broken. */}
      <ExplainServiceDialog name={explainName} onClose={() => setExplainName(null)} />

      {/* Delete Confirmation */}
      <AlertDialog open={!!deleteTarget} onOpenChange={() => setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Ziti Service</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete &quot;{deleteTarget?.name}&quot;? This will remove it from the Ziti controller.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction className="bg-red-600 hover:bg-red-700" onClick={() => deleteTarget && deleteMutation.mutate(deleteTarget.id)}>
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <PublishedAppServicesSection />
    </div>
  )
}

// ─── F15: Published App Services Section ─────────────────────────────────────

function PublishedAppServicesSection() {
  const [expandedApp, setExpandedApp] = useState<string | null>(null)

  const { data: appsResp } = useQuery({
    queryKey: ['published-apps'],
    queryFn: () => api.get<{ apps: Array<{ id: string; name: string; target_url: string; total_paths_published: number; status: string }> }>('/api/v1/access/apps'),
  })

  const { data: appServicesResp } = useQuery({
    queryKey: ['app-ziti-services', expandedApp],
    queryFn: () => api.get<{ services: AppZitiService[]; app_name: string }>(`/api/v1/access/apps/${expandedApp}/ziti-services`),
    enabled: !!expandedApp,
  })

  const publishedApps = appsResp?.apps?.filter((a) => a.total_paths_published > 0) ?? []

  if (publishedApps.length === 0) return null

  return (
    <div className="mt-6">
      <h3 className="text-sm font-semibold mb-2 flex items-center gap-2">
        <Upload className="h-4 w-4" /> Published App Services
      </h3>
      <p className="text-xs text-muted-foreground mb-3">Ziti services automatically created when publishing apps.</p>
      <div className="space-y-2">
        {publishedApps.map((app) => (
          <div key={app.id} className="border rounded-lg">
            <button
              className="w-full flex items-center justify-between px-4 py-2 text-sm hover:bg-muted/50"
              onClick={() => setExpandedApp(expandedApp === app.id ? null : app.id)}
            >
              <div className="flex items-center gap-2">
                {expandedApp === app.id ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                <span className="font-medium">{app.name}</span>
                <span className="text-xs text-muted-foreground">{app.target_url}</span>
              </div>
              <Badge variant="outline">{app.total_paths_published} paths</Badge>
            </button>
            {expandedApp === app.id && (
              <div className="px-4 pb-3">
                {!appServicesResp?.services || appServicesResp.services.length === 0 ? (
                  <p className="text-xs text-muted-foreground py-2">No Ziti services linked to this app.</p>
                ) : (
                  <Table>
                    <TableHeader><TableRow>
                      <TableHead>Service</TableHead>
                      <TableHead>Path</TableHead>
                      <TableHead>Classification</TableHead>
                      <TableHead>Status</TableHead>
                    </TableRow></TableHeader>
                    <TableBody>
                      {appServicesResp.services.map((svc) => (
                        <TableRow key={svc.id}>
                          <TableCell className="font-medium text-xs">{svc.name}</TableCell>
                          <TableCell className="text-xs font-mono">{svc.linked_path}</TableCell>
                          <TableCell>
                            <Badge variant="outline" className={`text-[10px] ${
                              svc.classification === 'critical' ? 'bg-red-50 text-red-700 border-red-200' :
                              svc.classification === 'sensitive' ? 'bg-orange-50 text-orange-700 border-orange-200' :
                              svc.classification === 'public' ? 'bg-green-50 text-green-700 border-green-200' :
                              'bg-blue-50 text-blue-700 border-blue-200'
                            }`}>{svc.classification}</Badge>
                          </TableCell>
                          <TableCell>{svc.enabled ? <Badge className="bg-green-100 text-green-700 text-[10px]">Active</Badge> : <Badge variant="secondary" className="text-[10px]">Disabled</Badge>}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

// ─── Identities Tab ──────────────────────────────────────────────────────────

interface UnsyncedUser {
  id: string
  username: string
  email: string
  first_name: string
  last_name: string
}

function IdentitiesTab() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [search, setSearch] = useState('')
  const [createModal, setCreateModal] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<ZitiIdentity | null>(null)
  const [jwtModal, setJwtModal] = useState<{ jwt: string; name: string } | null>(null)
  const [editAttrsTarget, setEditAttrsTarget] = useState<ZitiIdentity | null>(null)
  const [editAttrsValue, setEditAttrsValue] = useState('')
  const [form, setForm] = useState({ name: '', identity_type: 'Device', user_id: '', attributes: '' })
  const [showUnsynced, setShowUnsynced] = useState(false)

  const { data, isLoading } = useQuery({
    queryKey: ['ziti-identities'],
    queryFn: () => api.get<{ identities: ZitiIdentity[] }>('/api/v1/access/ziti/identities'),
  })

  const createMutation = useMutation({
    mutationFn: async (data: typeof form) => {
      const payload: Record<string, unknown> = {
        name: data.name,
        identity_type: data.identity_type,
        attributes: data.attributes ? data.attributes.split(',').map(s => s.trim()).filter(Boolean) : [],
      }
      if (data.user_id) payload.user_id = data.user_id
      return api.post<{ enrollment_jwt: string; name: string }>('/api/v1/access/ziti/identities', payload)
    },
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ['ziti-identities'] })
      queryClient.invalidateQueries({ queryKey: ['ziti-status'] })
      setCreateModal(false)
      setForm({ name: '', identity_type: 'Device', user_id: '', attributes: '' })
      const data = result as { enrollment_jwt?: string; name?: string }
      if (data.enrollment_jwt) {
        setJwtModal({ jwt: data.enrollment_jwt, name: data.name || form.name })
      }
      toast({ title: 'Identity created', description: 'Ziti identity has been created.' })
    },
    onError: () => toast({ title: 'Error', description: 'Failed to create Ziti identity.', variant: 'destructive' }),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/access/ziti/identities/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-identities'] })
      queryClient.invalidateQueries({ queryKey: ['ziti-status'] })
      setDeleteTarget(null)
      toast({ title: 'Identity deleted', description: 'Ziti identity has been deleted.' })
    },
    onError: () => toast({ title: 'Error', description: 'Failed to delete Ziti identity.', variant: 'destructive' }),
  })

  const updateAttrsMutation = useMutation({
    mutationFn: ({ id, attributes }: { id: string; attributes: string[] }) =>
      api.patch(`/api/v1/access/ziti/identities/${id}/attributes`, { attributes }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-identities'] })
      setEditAttrsTarget(null)
      toast({ title: 'Attributes updated', description: 'Identity role attributes have been updated.' })
    },
    onError: () => toast({ title: 'Error', description: 'Failed to update identity attributes.', variant: 'destructive' }),
  })

  const { data: syncStatus } = useQuery({
    queryKey: ['ziti-sync-status'],
    queryFn: () => api.get<ZitiSyncStatus>('/api/v1/access/ziti/sync/status'),
    refetchInterval: 5000,
  })

  const syncAllMutation = useMutation({
    mutationFn: () => api.post<{ users_synced: number; users_failed: number; groups_synced: number }>('/api/v1/access/ziti/sync/users'),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ['ziti-identities'] })
      queryClient.invalidateQueries({ queryKey: ['ziti-sync-status'] })
      queryClient.invalidateQueries({ queryKey: ['ziti-status'] })
      toast({
        title: 'Sync complete',
        description: `Synced ${result.users_synced} users, ${result.groups_synced} group attributes.${result.users_failed > 0 ? ` ${result.users_failed} failed.` : ''}`,
      })
    },
    onError: () => toast({ title: 'Error', description: 'User sync failed.', variant: 'destructive' }),
  })

  const syncGroupsMutation = useMutation({
    mutationFn: () => api.post<{ groups_synced: number }>('/api/v1/access/ziti/sync/groups'),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ['ziti-identities'] })
      queryClient.invalidateQueries({ queryKey: ['ziti-sync-status'] })
      toast({ title: 'Group sync complete', description: `Updated role attributes for ${result.groups_synced} identities.` })
    },
    onError: () => toast({ title: 'Error', description: 'Group attribute sync failed.', variant: 'destructive' }),
  })

  const syncSingleMutation = useMutation({
    mutationFn: (userId: string) => api.post(`/api/v1/access/ziti/sync/users/${userId}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-identities'] })
      queryClient.invalidateQueries({ queryKey: ['ziti-sync-status'] })
      queryClient.invalidateQueries({ queryKey: ['ziti-unsynced-users'] })
      toast({ title: 'User synced', description: 'Ziti identity created for user.' })
    },
    onError: () => toast({ title: 'Error', description: 'Failed to sync user.', variant: 'destructive' }),
  })

  const { data: unsyncedUsers } = useQuery({
    queryKey: ['ziti-unsynced-users'],
    queryFn: () => api.get<UnsyncedUser[]>('/api/v1/access/ziti/sync/unsynced'),
    enabled: showUnsynced,
  })

  const openEditAttrs = (ident: ZitiIdentity) => {
    setEditAttrsValue((ident.attributes || []).join(', '))
    setEditAttrsTarget(ident)
  }

  const fetchJWT = async (identity: ZitiIdentity) => {
    try {
      const data = await api.get<{ enrollment_jwt: string }>(`/api/v1/access/ziti/identities/${identity.id}/enrollment-jwt`)
      if (data.enrollment_jwt) {
        setJwtModal({ jwt: data.enrollment_jwt, name: identity.display_name || identity.name })
      } else {
        toast({ title: 'No JWT', description: 'Enrollment JWT is not available.', variant: 'destructive' })
      }
    } catch {
      toast({ title: 'Error', description: 'Failed to fetch enrollment JWT.', variant: 'destructive' })
    }
  }

  const identities = (data?.identities || []).filter((ident) =>
    !search ||
    (ident.display_name || '').toLowerCase().includes(search.toLowerCase()) ||
    ident.name.toLowerCase().includes(search.toLowerCase()) ||
    ident.identity_type.toLowerCase().includes(search.toLowerCase())
  )

  if (isLoading) return <Spinner />

  return (
    <div className="space-y-4 mt-4">
      {/* Sync Status Card */}
      <Card className="border-blue-200 bg-blue-50/50">
        <CardContent className="py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2">
                <RefreshCw className={`h-4 w-4 ${syncAllMutation.isPending || syncGroupsMutation.isPending ? 'animate-spin' : ''} text-primary`} />
                <span className="text-sm font-medium">Identity Sync</span>
              </div>
              {syncStatus && (
                <div className="flex items-center gap-3 text-xs text-muted-foreground">
                  <span>{syncStatus.total_identities} identities / {syncStatus.total_users} users</span>
                  {syncStatus.unsynced_users > 0 && (
                    <button
                      onClick={() => setShowUnsynced(!showUnsynced)}
                      className="inline-flex items-center gap-1"
                    >
                      <Badge variant="secondary" className="text-orange-700 bg-orange-100 cursor-pointer hover:bg-orange-200">
                        {syncStatus.unsynced_users} unsynced
                        {showUnsynced ? <ChevronDown className="h-3 w-3 ml-0.5" /> : <ChevronRight className="h-3 w-3 ml-0.5" />}
                      </Badge>
                    </button>
                  )}
                  {syncStatus.last_auto_sync_at && (
                    <span>Auto: {new Date(syncStatus.last_auto_sync_at).toLocaleTimeString()}</span>
                  )}
                </div>
              )}
            </div>
            <div className="flex gap-2">
              <Button variant="outline" size="sm" onClick={() => syncGroupsMutation.mutate()} disabled={syncGroupsMutation.isPending || syncAllMutation.isPending}>
                {syncGroupsMutation.isPending ? 'Syncing...' : 'Sync Groups'}
              </Button>
              <Button size="sm" onClick={() => syncAllMutation.mutate()} disabled={syncAllMutation.isPending || syncGroupsMutation.isPending}>
                <RefreshCw className={`mr-2 h-3 w-3 ${syncAllMutation.isPending ? 'animate-spin' : ''}`} />
                {syncAllMutation.isPending ? 'Syncing...' : 'Sync All Users'}
              </Button>
            </div>
          </div>
          {/* Expandable unsynced users list */}
          {showUnsynced && unsyncedUsers && unsyncedUsers.length > 0 && (
            <div className="mt-3 border-t border-blue-200 pt-3">
              <p className="text-xs font-medium text-muted-foreground mb-2">Users without Ziti identities:</p>
              <div className="space-y-1.5 max-h-48 overflow-y-auto">
                {unsyncedUsers.map((user) => (
                  <div key={user.id} className="flex items-center justify-between bg-background rounded px-3 py-1.5 text-sm">
                    <div className="flex items-center gap-2">
                      <Users2 className="h-3.5 w-3.5 text-muted-foreground" />
                      <span className="font-medium">{user.first_name || user.username} {user.last_name || ''}</span>
                      <span className="text-xs text-muted-foreground">@{user.username}</span>
                    </div>
                    <Button
                      variant="outline"
                      size="sm"
                      className="h-6 text-xs"
                      onClick={() => syncSingleMutation.mutate(user.id)}
                      disabled={syncSingleMutation.isPending}
                    >
                      Sync
                    </Button>
                  </div>
                ))}
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      <div className="flex items-center justify-between gap-4">
        <SearchInput value={search} onChange={setSearch} placeholder="Search identities..." />
        <Button onClick={() => setCreateModal(true)}>
          <Plus className="mr-2 h-4 w-4" /> Add Identity
        </Button>
      </div>

      {identities.length === 0 ? (
        <EmptyState
          icon={Users2}
          title={search ? 'No matching identities' : 'No Ziti identities'}
          description={search ? 'Try a different search term.' : 'Create identities for desktop tunneler enrollment.'}
        />
      ) : (
        <Card>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Identity</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Roles</TableHead>
                <TableHead>Ziti ID</TableHead>
                <TableHead>Created</TableHead>
                <TableHead className="w-[50px]" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {identities.map((ident) => (
                <TableRow key={ident.id} className="hover:bg-muted/50">
                  <TableCell>
                    <div className="flex items-center gap-3">
                      <div className={`h-8 w-8 rounded-full flex items-center justify-center ${ident.enrolled ? 'bg-green-100' : 'bg-yellow-100'}`}>
                        <Shield className={`h-4 w-4 ${ident.enrolled ? 'text-green-700' : 'text-yellow-700'}`} />
                      </div>
                      <div>
                        <p className="font-medium">{ident.display_name || ident.name}</p>
                        {ident.user_id && <p className="text-xs text-muted-foreground">User: {ident.user_id.slice(0, 8)}...</p>}
                      </div>
                    </div>
                  </TableCell>
                  <TableCell><Badge variant="outline">{ident.identity_type}</Badge></TableCell>
                  <TableCell>
                    <Badge variant={ident.enrolled ? 'default' : 'secondary'}>
                      {ident.enrolled ? 'Enrolled' : 'Pending'}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {(ident.attributes || []).map((attr) => (
                        <Badge key={attr} variant="outline" className="text-xs">{attr}</Badge>
                      ))}
                      {(!ident.attributes || ident.attributes.length === 0) && (
                        <span className="text-xs text-muted-foreground">none</span>
                      )}
                    </div>
                  </TableCell>
                  <TableCell><TruncatedId value={ident.ziti_id} label="Ziti ID" /></TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {safeDate(ident.created_at)}
                  </TableCell>
                  <TableCell>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="icon" className="h-8 w-8">
                          <MoreHorizontal className="h-4 w-4" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem onClick={() => {
                          navigator.clipboard.writeText(ident.ziti_id)
                          toast({ title: 'Copied', description: 'Ziti ID copied to clipboard.' })
                        }}>
                          <Copy className="mr-2 h-4 w-4" /> Copy Ziti ID
                        </DropdownMenuItem>
                        <DropdownMenuItem onClick={() => openEditAttrs(ident)}>
                          <Pencil className="mr-2 h-4 w-4" /> Edit Attributes
                        </DropdownMenuItem>
                        {!ident.enrolled && (
                          <DropdownMenuItem onClick={() => fetchJWT(ident)}>
                            <FileKey className="mr-2 h-4 w-4" /> Get Enrollment JWT
                          </DropdownMenuItem>
                        )}
                        <DropdownMenuSeparator />
                        <DropdownMenuItem className="text-red-600" onClick={() => setDeleteTarget(ident)}>
                          <Trash2 className="mr-2 h-4 w-4" /> Delete
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      )}

      {/* Create Dialog */}
      <Dialog open={createModal} onOpenChange={setCreateModal}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Create Ziti Identity</DialogTitle>
          </DialogHeader>
          <form onSubmit={(e) => { e.preventDefault(); createMutation.mutate(form) }} className="space-y-4">
            <div className="space-y-2">
              <Label>Identity Name</Label>
              <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="john-laptop" required />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>Type</Label>
                <select
                  value={form.identity_type}
                  onChange={(e) => setForm({ ...form, identity_type: e.target.value })}
                  className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                >
                  <option value="Device">Device</option>
                  <option value="User">User</option>
                  <option value="Service">Service</option>
                </select>
              </div>
              <div className="space-y-2">
                <Label>User ID (optional)</Label>
                <Input value={form.user_id} onChange={(e) => setForm({ ...form, user_id: e.target.value })} placeholder="UUID of OpenIDX user" />
              </div>
            </div>
            <div className="space-y-2">
              <Label>Role Attributes (comma-separated)</Label>
              <Input value={form.attributes} onChange={(e) => setForm({ ...form, attributes: e.target.value })} placeholder="developers, vpn-users" />
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <Button type="button" variant="outline" onClick={() => setCreateModal(false)}>Cancel</Button>
              <Button type="submit" disabled={createMutation.isPending}>
                {createMutation.isPending ? 'Creating...' : 'Create Identity'}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* JWT Modal */}
      <Dialog open={!!jwtModal} onOpenChange={() => setJwtModal(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Enrollment JWT for {jwtModal?.name}</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <p className="text-sm text-muted-foreground">
              Use this token to enroll a native OpenZiti client (Ziti Desktop Edge,
              or <code className="text-xs">ziti-edge-tunnel enroll --jwt &lt;file&gt;</code>) so the
              device reaches dark services directly over the overlay — no browser required.
              This is a one-time token.
            </p>
            <div className="relative">
              <textarea
                readOnly
                value={jwtModal?.jwt || ''}
                className="w-full h-32 rounded-md border bg-muted p-3 text-xs font-mono"
              />
              <div className="absolute top-2 right-2 flex gap-1">
                <Button
                  variant="outline"
                  size="sm"
                  title="Download as .jwt file for ziti-edge-tunnel"
                  onClick={() => {
                    if (!jwtModal) return
                    const blob = new Blob([jwtModal.jwt], { type: 'application/jwt' })
                    const url = URL.createObjectURL(blob)
                    const a = document.createElement('a')
                    a.href = url
                    a.download = `${jwtModal.name.replace(/[^a-zA-Z0-9_.-]/g, '_')}.jwt`
                    a.click()
                    URL.revokeObjectURL(url)
                    toast({ title: 'Downloaded', description: 'Enrollment token saved as a .jwt file.' })
                  }}
                >
                  <Download className="h-4 w-4" />
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  title="Copy to clipboard"
                  onClick={() => {
                    if (jwtModal) {
                      navigator.clipboard.writeText(jwtModal.jwt)
                      toast({ title: 'Copied', description: 'Enrollment JWT copied to clipboard.' })
                    }
                  }}
                >
                  <Copy className="h-4 w-4" />
                </Button>
              </div>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {/* Edit Attributes Dialog */}
      <Dialog open={!!editAttrsTarget} onOpenChange={(v) => { if (!v) setEditAttrsTarget(null) }}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Edit Role Attributes — {editAttrsTarget?.name}</DialogTitle>
          </DialogHeader>
          <form onSubmit={(e) => {
            e.preventDefault()
            if (editAttrsTarget) {
              updateAttrsMutation.mutate({
                id: editAttrsTarget.id,
                attributes: editAttrsValue.split(',').map(s => s.trim()).filter(Boolean),
              })
            }
          }} className="space-y-4">
            <div className="space-y-2">
              <Label>Role Attributes (comma-separated)</Label>
              <Input
                value={editAttrsValue}
                onChange={(e) => setEditAttrsValue(e.target.value)}
                placeholder="engineering, vpn-users, finance"
              />
              <p className="text-xs text-muted-foreground">
                These attributes determine which service policies apply to this identity.
                Use the same names referenced in your Dial/Bind policies (e.g., engineering, vpn-users).
              </p>
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <Button type="button" variant="outline" onClick={() => setEditAttrsTarget(null)}>Cancel</Button>
              <Button type="submit" disabled={updateAttrsMutation.isPending}>
                {updateAttrsMutation.isPending ? 'Saving...' : 'Save Attributes'}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <AlertDialog open={!!deleteTarget} onOpenChange={() => setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Ziti Identity</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete &quot;{deleteTarget?.name}&quot;? This will revoke the identity from the Ziti controller.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction className="bg-red-600 hover:bg-red-700" onClick={() => deleteTarget && deleteMutation.mutate(deleteTarget.id)}>
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}

// ─── Security Tab ────────────────────────────────────────────────────────────

function CollapsibleSection({ title, count, icon: Icon, defaultOpen, children }: {
  title: string; count: number; icon: React.ElementType; defaultOpen?: boolean; children: React.ReactNode
}) {
  const [open, setOpen] = useState(defaultOpen ?? true)
  return (
    <div className="border rounded-lg">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between px-4 py-3 hover:bg-muted/50 transition-colors"
      >
        <div className="flex items-center gap-2">
          <Icon className="h-4 w-4 text-muted-foreground" />
          <span className="font-semibold">{title}</span>
          <Badge variant="secondary" className="ml-1">{count}</Badge>
        </div>
        {open ? <ChevronDown className="h-4 w-4 text-muted-foreground" /> : <ChevronRight className="h-4 w-4 text-muted-foreground" />}
      </button>
      {open && <div className="px-4 pb-4 pt-1">{children}</div>}
    </div>
  )
}

function SecurityTab() {
  return (
    <div className="space-y-4 mt-4">
      <ActiveSessionsSection />
      <ServicePoliciesSection />
      <EdgeRouterPoliciesSection />
      <ConfigurationsSection />
      <AuthPoliciesSection />
      <TerminatorsSection />
      <PostureSection />
      <CertificatesSection />
      <PolicySyncSection />
    </div>
  )
}

// ─── F14: Active Sessions Section ────────────────────────────────────────────

function ActiveSessionsSection() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [deleteTarget, setDeleteTarget] = useState<ZitiSessionEntry | null>(null)

  const { data: sessions } = useQuery({
    queryKey: ['ziti-sessions'],
    queryFn: () => api.get<ZitiSessionEntry[]>('/api/v1/access/ziti/sessions'),
    refetchInterval: 10000,
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/access/ziti/sessions/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-sessions'] })
      toast({ title: 'Session terminated' })
      setDeleteTarget(null)
    },
  })

  const batchTerminateMutation = useMutation({
    mutationFn: (identityId: string) => api.post('/api/v1/access/ziti/sessions/batch-terminate', { identity_id: identityId }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-sessions'] })
      toast({ title: 'All sessions terminated for identity' })
    },
  })

  // Get unique identities for batch terminate
  const uniqueIdentities = sessions ? [...new Map(sessions.filter(s => s.identity?.id).map(s => [s.identity!.id, s.identity!])).values()] : []

  return (
    <>
      <CollapsibleSection title="Active Sessions" count={sessions?.length ?? 0} icon={Zap} defaultOpen>
        <p className="text-xs text-muted-foreground mb-3">Currently active Ziti overlay connections. Dial = accessing a service; Bind = hosting a service endpoint.</p>
        {uniqueIdentities.length > 1 && (
          <div className="flex flex-wrap gap-2 mb-3">
            {uniqueIdentities.map(ident => (
              <Button key={ident.id} variant="outline" size="sm" className="text-red-600 border-red-200 hover:bg-red-50" onClick={() => batchTerminateMutation.mutate(ident.id)} disabled={batchTerminateMutation.isPending}>
                Terminate All: {ident.name || ident.id}
              </Button>
            ))}
          </div>
        )}
        {!sessions || sessions.length === 0 ? (
          <EmptyState icon={Clock} title="No active sessions" description="No one is currently connected through the Ziti overlay." />
        ) : (
          <Table>
            <TableHeader><TableRow>
              <TableHead>Identity</TableHead>
              <TableHead>Service</TableHead>
              <TableHead>Type</TableHead>
              <TableHead>Connected Since</TableHead>
              <TableHead className="w-10" />
            </TableRow></TableHeader>
            <TableBody>
              {sessions.map((s) => (
                <TableRow key={s.id}>
                  <TableCell className="font-medium">{s.identity?.name || s.identity?.id || '—'}</TableCell>
                  <TableCell>{s.service?.name || s.service?.id || '—'}</TableCell>
                  <TableCell>
                    <Badge variant={s.type === 'Dial' ? 'default' : 'secondary'}>{s.type}</Badge>
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">{s.createdAt ? new Date(s.createdAt).toLocaleString() : '—'}</TableCell>
                  <TableCell>
                    <Button variant="ghost" size="icon" className="h-7 w-7 text-red-500" onClick={() => setDeleteTarget(s)} title="Force disconnect">
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CollapsibleSection>

      <AlertDialog open={!!deleteTarget} onOpenChange={() => setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Force Disconnect Session?</AlertDialogTitle>
            <AlertDialogDescription>
              This will immediately disconnect {deleteTarget?.identity?.name || 'this identity'} from {deleteTarget?.service?.name || 'the service'}.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction className="bg-red-600 hover:bg-red-700" onClick={() => deleteTarget && deleteMutation.mutate(deleteTarget.id)}>Disconnect</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}

// ─── F11: Configurations Section ─────────────────────────────────────────────

function ConfigurationsSection() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [createModal, setCreateModal] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<ZitiConfig | null>(null)
  const [form, setForm] = useState({ name: '', configTypeId: '', data: '{}' })

  const { data: configs } = useQuery({
    queryKey: ['ziti-configs'],
    queryFn: () => api.get<ZitiConfig[]>('/api/v1/access/ziti/configs'),
  })
  const { data: configTypes } = useQuery({
    queryKey: ['ziti-config-types'],
    queryFn: () => api.get<ZitiConfigType[]>('/api/v1/access/ziti/config-types'),
  })

  const createMutation = useMutation({
    mutationFn: (data: { name: string; configTypeId: string; data: string }) =>
      api.post('/api/v1/access/ziti/configs', { name: data.name, configTypeId: data.configTypeId, data: JSON.parse(data.data) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-configs'] })
      toast({ title: 'Config created' })
      setCreateModal(false)
      setForm({ name: '', configTypeId: '', data: '{}' })
    },
    onError: (e: Error) => toast({ title: 'Error', description: e.message, variant: 'destructive' }),
  })
  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/access/ziti/configs/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-configs'] })
      toast({ title: 'Config deleted' })
      setDeleteTarget(null)
    },
  })

  const isSystem = (name: string) => name.startsWith('openidx-')

  return (
    <>
      <CollapsibleSection title="Configurations" count={configs?.length ?? 0} icon={Settings} defaultOpen={false}>
        <div className="flex justify-between items-center mb-3">
          <p className="text-xs text-muted-foreground">Ziti config objects (host.v1, intercept.v1, etc.) that define service behavior.</p>
          <Button size="sm" onClick={() => setCreateModal(true)}><Plus className="h-4 w-4 mr-1" /> Add Config</Button>
        </div>
        {!configs || configs.length === 0 ? (
          <EmptyState icon={Settings} title="No configurations" description="No Ziti config objects found." />
        ) : (
          <Table>
            <TableHeader><TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Config Type</TableHead>
              <TableHead>Data</TableHead>
              <TableHead className="w-10" />
            </TableRow></TableHeader>
            <TableBody>
              {configs.map((cfg) => (
                <TableRow key={cfg.id}>
                  <TableCell className="font-medium">{cfg.name}</TableCell>
                  <TableCell><Badge variant="outline">{typeof cfg.configType === 'object' && cfg.configType?.name ? cfg.configType.name : cfg.configTypeId}</Badge></TableCell>
                  <TableCell className="text-xs text-muted-foreground max-w-[200px] truncate">{JSON.stringify(cfg.data).slice(0, 80)}</TableCell>
                  <TableCell>
                    {!isSystem(cfg.name) && (
                      <Button variant="ghost" size="icon" className="h-7 w-7 text-red-500" onClick={() => setDeleteTarget(cfg)}>
                        <Trash2 className="h-3.5 w-3.5" />
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CollapsibleSection>

      <Dialog open={createModal} onOpenChange={setCreateModal}>
        <DialogContent>
          <DialogHeader><DialogTitle>Create Configuration</DialogTitle></DialogHeader>
          <form onSubmit={(e) => { e.preventDefault(); createMutation.mutate(form) }} className="space-y-4">
            <div><Label>Name</Label><Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required /></div>
            <div><Label>Config Type</Label>
              <select className="w-full border rounded-md p-2 text-sm" value={form.configTypeId} onChange={(e) => setForm({ ...form, configTypeId: e.target.value })} required>
                <option value="">Select config type...</option>
                {configTypes?.map((ct) => <option key={ct.id} value={ct.id}>{ct.name}</option>)}
              </select>
            </div>
            <div><Label>Data (JSON)</Label><textarea className="w-full border rounded-md p-2 text-sm font-mono h-32" value={form.data} onChange={(e) => setForm({ ...form, data: e.target.value })} /></div>
            <div className="flex justify-end gap-2">
              <Button type="button" variant="outline" onClick={() => setCreateModal(false)}>Cancel</Button>
              <Button type="submit" disabled={createMutation.isPending}>Create</Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      <AlertDialog open={!!deleteTarget} onOpenChange={() => setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Configuration?</AlertDialogTitle>
            <AlertDialogDescription>This will delete &quot;{deleteTarget?.name}&quot;. Services using this config may break.</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction className="bg-red-600 hover:bg-red-700" onClick={() => deleteTarget && deleteMutation.mutate(deleteTarget.id)}>Delete</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}

// ─── F12: Auth Policies & JWT Signers Section ────────────────────────────────

function AuthPoliciesSection() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [deleteAPTarget, setDeleteAPTarget] = useState<ZitiAuthPolicy | null>(null)
  const [deleteJSTarget, setDeleteJSTarget] = useState<ZitiJWTSigner | null>(null)

  const { data: authPolicies } = useQuery({
    queryKey: ['ziti-auth-policies'],
    queryFn: () => api.get<ZitiAuthPolicy[]>('/api/v1/access/ziti/auth-policies'),
  })
  const { data: jwtSigners } = useQuery({
    queryKey: ['ziti-jwt-signers'],
    queryFn: () => api.get<ZitiJWTSigner[]>('/api/v1/access/ziti/jwt-signers'),
  })

  const deleteAPMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/access/ziti/auth-policies/${id}`),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['ziti-auth-policies'] }); toast({ title: 'Auth policy deleted' }); setDeleteAPTarget(null) },
  })
  const deleteJSMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/access/ziti/jwt-signers/${id}`),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['ziti-jwt-signers'] }); toast({ title: 'JWT signer deleted' }); setDeleteJSTarget(null) },
  })

  const isSystem = (name: string) => name.startsWith('openidx-') || name === 'default'
  const totalCount = (authPolicies?.length ?? 0) + (jwtSigners?.length ?? 0)

  const authMethods = (p: ZitiAuthPolicy) => {
    const methods: string[] = []
    if (p.primary?.cert?.allowed) methods.push('Cert')
    if (p.primary?.updb?.allowed) methods.push('UPDB')
    if (p.primary?.extJwt?.allowed) methods.push('ExtJWT')
    return methods
  }

  return (
    <>
      <CollapsibleSection title="Auth Policies & JWT Signers" count={totalCount} icon={Key} defaultOpen={false}>
        <p className="text-xs text-muted-foreground mb-3">Authentication policies control how identities authenticate to Ziti. JWT signers enable external JWT-based authentication.</p>

        <h4 className="text-sm font-semibold mb-2">Auth Policies</h4>
        {!authPolicies || authPolicies.length === 0 ? (
          <p className="text-xs text-muted-foreground mb-4">No auth policies found.</p>
        ) : (
          <Table>
            <TableHeader><TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Primary Auth</TableHead>
              <TableHead>TOTP</TableHead>
              <TableHead className="w-10" />
            </TableRow></TableHeader>
            <TableBody>
              {authPolicies.map((ap) => (
                <TableRow key={ap.id}>
                  <TableCell className="font-medium">{ap.name}{isSystem(ap.name) && <Badge variant="outline" className="ml-2 text-[10px]">system</Badge>}</TableCell>
                  <TableCell className="flex gap-1 flex-wrap">
                    {authMethods(ap).map((m) => (
                      <Badge key={m} variant="secondary" className="text-[10px]">{m}</Badge>
                    ))}
                    {authMethods(ap).length === 0 && <span className="text-xs text-muted-foreground">none</span>}
                  </TableCell>
                  <TableCell>{ap.secondary?.requireTotp ? <Badge className="text-[10px]">Required</Badge> : <span className="text-xs text-muted-foreground">No</span>}</TableCell>
                  <TableCell>
                    {!isSystem(ap.name) && (
                      <Button variant="ghost" size="icon" className="h-7 w-7 text-red-500" onClick={() => setDeleteAPTarget(ap)}>
                        <Trash2 className="h-3.5 w-3.5" />
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}

        <h4 className="text-sm font-semibold mt-4 mb-2">JWT Signers</h4>
        {!jwtSigners || jwtSigners.length === 0 ? (
          <p className="text-xs text-muted-foreground">No external JWT signers found.</p>
        ) : (
          <Table>
            <TableHeader><TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Issuer</TableHead>
              <TableHead>Audience</TableHead>
              <TableHead>Enabled</TableHead>
              <TableHead className="w-10" />
            </TableRow></TableHeader>
            <TableBody>
              {jwtSigners.map((js) => (
                <TableRow key={js.id}>
                  <TableCell className="font-medium">{js.name}{isSystem(js.name) && <Badge variant="outline" className="ml-2 text-[10px]">system</Badge>}</TableCell>
                  <TableCell className="text-xs max-w-[150px] truncate">{js.issuer}</TableCell>
                  <TableCell className="text-xs">{js.audience}</TableCell>
                  <TableCell>{js.enabled ? <Badge className="bg-green-100 text-green-700 text-[10px]">Yes</Badge> : <Badge variant="secondary" className="text-[10px]">No</Badge>}</TableCell>
                  <TableCell>
                    {!isSystem(js.name) && (
                      <Button variant="ghost" size="icon" className="h-7 w-7 text-red-500" onClick={() => setDeleteJSTarget(js)}>
                        <Trash2 className="h-3.5 w-3.5" />
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CollapsibleSection>

      <AlertDialog open={!!deleteAPTarget} onOpenChange={() => setDeleteAPTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader><AlertDialogTitle>Delete Auth Policy?</AlertDialogTitle>
            <AlertDialogDescription>This will delete &quot;{deleteAPTarget?.name}&quot;. Identities using this policy may lose authentication.</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction className="bg-red-600 hover:bg-red-700" onClick={() => deleteAPTarget && deleteAPMutation.mutate(deleteAPTarget.id)}>Delete</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
      <AlertDialog open={!!deleteJSTarget} onOpenChange={() => setDeleteJSTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader><AlertDialogTitle>Delete JWT Signer?</AlertDialogTitle>
            <AlertDialogDescription>This will delete &quot;{deleteJSTarget?.name}&quot;. Auth policies referencing this signer will break.</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction className="bg-red-600 hover:bg-red-700" onClick={() => deleteJSTarget && deleteJSMutation.mutate(deleteJSTarget.id)}>Delete</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}

// ─── F13: Terminators Section ────────────────────────────────────────────────

function TerminatorsSection() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [deleteTarget, setDeleteTarget] = useState<ZitiTerminator | null>(null)

  const { data: terminators } = useQuery({
    queryKey: ['ziti-terminators'],
    queryFn: () => api.get<ZitiTerminator[]>('/api/v1/access/ziti/terminators'),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/access/ziti/terminators/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-terminators'] })
      toast({ title: 'Terminator deleted' })
      setDeleteTarget(null)
    },
  })

  return (
    <>
      <CollapsibleSection title="Terminators" count={terminators?.length ?? 0} icon={Link2} defaultOpen={false}>
        <p className="text-xs text-muted-foreground mb-3">Terminators connect Ziti services to backend servers. They are auto-created when services are hosted.</p>
        {!terminators || terminators.length === 0 ? (
          <EmptyState icon={Link2} title="No terminators" description="No service terminators found on the Ziti controller." />
        ) : (
          <Table>
            <TableHeader><TableRow>
              <TableHead>Service</TableHead>
              <TableHead>Router</TableHead>
              <TableHead>Binding</TableHead>
              <TableHead>Address</TableHead>
              <TableHead>Cost</TableHead>
              <TableHead>Precedence</TableHead>
              <TableHead className="w-10" />
            </TableRow></TableHeader>
            <TableBody>
              {terminators.map((t) => (
                <TableRow key={t.id}>
                  <TableCell className="font-medium">{t.service?.name || t.serviceId}</TableCell>
                  <TableCell>{t.router?.name || t.routerId}</TableCell>
                  <TableCell><Badge variant="outline" className="text-[10px]">{t.binding}</Badge></TableCell>
                  <TableCell className="text-xs font-mono">{t.address}</TableCell>
                  <TableCell>{t.cost}</TableCell>
                  <TableCell><Badge variant="secondary" className="text-[10px]">{t.precedence}</Badge></TableCell>
                  <TableCell>
                    <Button variant="ghost" size="icon" className="h-7 w-7 text-red-500" onClick={() => setDeleteTarget(t)} title="Delete terminator">
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CollapsibleSection>

      <AlertDialog open={!!deleteTarget} onOpenChange={() => setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Terminator?</AlertDialogTitle>
            <AlertDialogDescription>
              Deleting this terminator for &quot;{deleteTarget?.service?.name}&quot; may disrupt active connections to the backend server.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction className="bg-red-600 hover:bg-red-700" onClick={() => deleteTarget && deleteMutation.mutate(deleteTarget.id)}>Delete</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}

// ─── Existing Security Sections ──────────────────────────────────────────────

function ServicePoliciesSection() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [search, setSearch] = useState('')
  const [createModal, setCreateModal] = useState(false)
  const [editTarget, setEditTarget] = useState<ServicePolicy | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<ServicePolicy | null>(null)
  const [form, setForm] = useState({ name: '', type: 'Dial', service_roles: '', identity_roles: '' })

  const { data: policiesData, isLoading } = useQuery({
    queryKey: ['ziti-service-policies'],
    queryFn: () => api.get<ServicePolicy[]>('/api/v1/access/ziti/fabric/service-policies'),
  })

  const createMutation = useMutation({
    mutationFn: (data: typeof form) => api.post('/api/v1/access/ziti/service-policies', {
      name: data.name,
      type: data.type,
      service_roles: data.service_roles.split(',').map(s => s.trim()).filter(Boolean),
      identity_roles: data.identity_roles.split(',').map(s => s.trim()).filter(Boolean),
    }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-service-policies'] })
      setCreateModal(false)
      resetForm()
      toast({ title: 'Service policy created' })
    },
    onError: () => toast({ title: 'Error', description: 'Failed to create service policy.', variant: 'destructive' }),
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: typeof form }) => api.put(`/api/v1/access/ziti/service-policies/${id}`, {
      name: data.name,
      type: data.type,
      service_roles: data.service_roles.split(',').map(s => s.trim()).filter(Boolean),
      identity_roles: data.identity_roles.split(',').map(s => s.trim()).filter(Boolean),
    }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-service-policies'] })
      setEditTarget(null)
      resetForm()
      toast({ title: 'Service policy updated' })
    },
    onError: (err: Error & { response?: { data?: { error?: string } } }) => {
      const msg = err?.response?.data?.error || 'Failed to update service policy.'
      toast({ title: 'Error', description: msg, variant: 'destructive' })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/access/ziti/service-policies/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-service-policies'] })
      setDeleteTarget(null)
      toast({ title: 'Service policy deleted' })
    },
    onError: (err: Error & { response?: { data?: { error?: string } } }) => {
      const msg = err?.response?.data?.error || 'Failed to delete service policy.'
      toast({ title: 'Error', description: msg, variant: 'destructive' })
    },
  })

  const resetForm = () => setForm({ name: '', type: 'Dial', service_roles: '', identity_roles: '' })

  const openEditModal = (policy: ServicePolicy) => {
    setForm({
      name: policy.name,
      type: policy.type,
      service_roles: (policy.serviceRoles || []).join(', '),
      identity_roles: (policy.identityRoles || []).join(', '),
    })
    setEditTarget(policy)
  }

  const isSystemPolicy = (name: string) => name.startsWith('openidx-')

  const policies = (Array.isArray(policiesData) ? policiesData : []).filter((p) =>
    !search || p.name.toLowerCase().includes(search.toLowerCase()) ||
    p.type.toLowerCase().includes(search.toLowerCase())
  )

  return (
    <CollapsibleSection title="Service Policies" count={policies.length} icon={ScrollText} defaultOpen>
      <p className="text-sm text-muted-foreground mb-3">
        Control which identities can Dial (access) or Bind (host) services. Policies use role attributes prefixed with <code className="text-xs bg-muted px-1 py-0.5 rounded">#</code> for matching.
      </p>

      <div className="flex items-center justify-between gap-4 mb-3">
        <SearchInput value={search} onChange={setSearch} placeholder="Search policies..." />
        <Button size="sm" onClick={() => { resetForm(); setCreateModal(true) }}>
          <Plus className="mr-2 h-4 w-4" /> Add Policy
        </Button>
      </div>

      {isLoading ? <Spinner /> : policies.length === 0 ? (
        <EmptyState icon={ScrollText} title="No service policies" description="Create policies to control identity access to services." />
      ) : (
        <Card>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Service Roles</TableHead>
                <TableHead>Identity Roles</TableHead>
                <TableHead className="w-[50px]" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {policies.map((policy) => (
                <TableRow key={policy.id} className="hover:bg-muted/50">
                  <TableCell>
                    <div className="flex items-center gap-2">
                      {isSystemPolicy(policy.name) && <span title="System policy"><Lock className="h-3.5 w-3.5 text-muted-foreground" /></span>}
                      <span className="font-medium">{policy.name}</span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge variant={policy.type === 'Dial' ? 'default' : 'secondary'}>
                      {policy.type}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {(policy.serviceRoles || []).map((role) => {
                        const isAttr = role.startsWith('#')
                        const isId = role.startsWith('@')
                        const label = isAttr ? role.slice(1) : isId ? role.slice(1) : role
                        return (
                          <Badge key={role} variant="outline" className={`text-xs ${isAttr ? 'bg-purple-50 text-purple-700 border-purple-200' : isId ? 'bg-blue-50 text-blue-700 border-blue-200' : ''}`}
                            title={isAttr ? `Attribute: matches services with role "${label}"` : isId ? `Specific service ID: ${label}` : role}
                          >
                            {isAttr && <span className="text-purple-400 mr-0.5">#</span>}
                            {isId && <span className="text-blue-400 mr-0.5">@</span>}
                            {label}
                          </Badge>
                        )
                      })}
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {(policy.identityRoles || []).map((role) => {
                        const isAttr = role.startsWith('#')
                        const isId = role.startsWith('@')
                        const label = isAttr ? role.slice(1) : isId ? role.slice(1) : role
                        return (
                          <Badge key={role} variant="outline" className={`text-xs ${isAttr ? 'bg-orange-50 text-orange-700 border-orange-200' : isId ? 'bg-blue-50 text-blue-700 border-blue-200' : ''}`}
                            title={isAttr ? `Attribute: matches identities with role "${label}"` : isId ? `Specific identity ID: ${label}` : role}
                          >
                            {isAttr && <span className="text-orange-400 mr-0.5">#</span>}
                            {isId && <span className="text-blue-400 mr-0.5">@</span>}
                            {label}
                          </Badge>
                        )
                      })}
                    </div>
                  </TableCell>
                  <TableCell>
                    {!isSystemPolicy(policy.name) && (
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" size="icon" className="h-8 w-8">
                            <MoreHorizontal className="h-4 w-4" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuItem onClick={() => openEditModal(policy)}>
                            <Pencil className="mr-2 h-4 w-4" /> Edit
                          </DropdownMenuItem>
                          <DropdownMenuSeparator />
                          <DropdownMenuItem className="text-red-600" onClick={() => setDeleteTarget(policy)}>
                            <Trash2 className="mr-2 h-4 w-4" /> Delete
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      )}

      {/* Create/Edit Dialogs */}
      {[
        { open: createModal, onOpenChange: (v: boolean) => { if (!v) setCreateModal(false) }, title: 'Create Service Policy', onSubmit: () => createMutation.mutate(form), pending: createMutation.isPending, submitLabel: 'Create Policy' },
        { open: !!editTarget, onOpenChange: (v: boolean) => { if (!v) { setEditTarget(null); resetForm() } }, title: 'Edit Service Policy', onSubmit: () => editTarget && updateMutation.mutate({ id: editTarget.id, data: form }), pending: updateMutation.isPending, submitLabel: 'Update Policy' },
      ].map((dlg, i) => (
        <Dialog key={i} open={dlg.open} onOpenChange={dlg.onOpenChange}>
          <DialogContent className="sm:max-w-md">
            <DialogHeader><DialogTitle>{dlg.title}</DialogTitle></DialogHeader>
            <form onSubmit={(e) => { e.preventDefault(); dlg.onSubmit() }} className="space-y-4">
              <div className="space-y-2">
                <Label>Policy Name</Label>
                <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="allow-engineering-gitlab" required />
              </div>
              <div className="space-y-2">
                <Label>Type</Label>
                <select value={form.type} onChange={(e) => setForm({ ...form, type: e.target.value })} className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm">
                  <option value="Dial">Dial (access service)</option>
                  <option value="Bind">Bind (host service)</option>
                </select>
              </div>
              <div className="space-y-2">
                <Label>Service Roles</Label>
                <Input value={form.service_roles} onChange={(e) => setForm({ ...form, service_roles: e.target.value })} placeholder="#gitlab, #internal-apps" required />
                <p className="text-xs text-muted-foreground">Comma-separated. <span className="text-purple-600 font-medium">#attribute</span> matches services by role, <span className="text-primary font-medium">@id</span> targets a specific service.</p>
              </div>
              <div className="space-y-2">
                <Label>Identity Roles</Label>
                <Input value={form.identity_roles} onChange={(e) => setForm({ ...form, identity_roles: e.target.value })} placeholder="#engineering, #vpn-users" required />
                <p className="text-xs text-muted-foreground">Comma-separated. <span className="text-orange-600 font-medium">#attribute</span> matches identities by role (e.g., group names), <span className="text-primary font-medium">@id</span> targets a specific identity.</p>
              </div>
              <div className="flex justify-end gap-2 pt-2">
                <Button type="button" variant="outline" onClick={() => dlg.onOpenChange(false)}>Cancel</Button>
                <Button type="submit" disabled={dlg.pending}>
                  {dlg.pending ? 'Saving...' : dlg.submitLabel}
                </Button>
              </div>
            </form>
          </DialogContent>
        </Dialog>
      ))}

      <AlertDialog open={!!deleteTarget} onOpenChange={() => setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Service Policy</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete &quot;{deleteTarget?.name}&quot;? Identities matched by this policy will lose access.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction className="bg-red-600 hover:bg-red-700" onClick={() => deleteTarget && deleteMutation.mutate(deleteTarget.id)}>
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </CollapsibleSection>
  )
}

function EdgeRouterPoliciesSection() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [search, setSearch] = useState('')
  const [createModal, setCreateModal] = useState(false)
  const [editTarget, setEditTarget] = useState<EdgeRouterPolicy | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<EdgeRouterPolicy | null>(null)
  const [form, setForm] = useState({ name: '', edge_router_roles: '', identity_roles: '' })

  const { data: policiesData, isLoading } = useQuery({
    queryKey: ['ziti-edge-router-policies'],
    queryFn: () => api.get<EdgeRouterPolicy[]>('/api/v1/access/ziti/edge-router-policies'),
  })

  const createMutation = useMutation({
    mutationFn: (data: typeof form) => api.post('/api/v1/access/ziti/edge-router-policies', {
      name: data.name,
      edgeRouterRoles: data.edge_router_roles.split(',').map(s => s.trim()).filter(Boolean),
      identityRoles: data.identity_roles.split(',').map(s => s.trim()).filter(Boolean),
    }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-edge-router-policies'] })
      setCreateModal(false)
      resetForm()
      toast({ title: 'Edge router policy created' })
    },
    onError: () => toast({ title: 'Error', description: 'Failed to create edge router policy.', variant: 'destructive' }),
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: typeof form }) => api.put(`/api/v1/access/ziti/edge-router-policies/${id}`, {
      name: data.name,
      edgeRouterRoles: data.edge_router_roles.split(',').map(s => s.trim()).filter(Boolean),
      identityRoles: data.identity_roles.split(',').map(s => s.trim()).filter(Boolean),
    }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-edge-router-policies'] })
      setEditTarget(null)
      resetForm()
      toast({ title: 'Edge router policy updated' })
    },
    onError: () => toast({ title: 'Error', description: 'Failed to update edge router policy.', variant: 'destructive' }),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/access/ziti/edge-router-policies/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-edge-router-policies'] })
      setDeleteTarget(null)
      toast({ title: 'Edge router policy deleted' })
    },
    onError: () => toast({ title: 'Error', description: 'Failed to delete edge router policy.', variant: 'destructive' }),
  })

  const resetForm = () => setForm({ name: '', edge_router_roles: '', identity_roles: '' })

  const openEditModal = (policy: EdgeRouterPolicy) => {
    setForm({
      name: policy.name,
      edge_router_roles: (policy.edgeRouterRoles || []).join(', '),
      identity_roles: (policy.identityRoles || []).join(', '),
    })
    setEditTarget(policy)
  }

  const isSystemPolicy = (name: string) => name.startsWith('allEdgeRouters') || name.startsWith('openidx-')

  const policies = (Array.isArray(policiesData) ? policiesData : []).filter((p) =>
    !search || p.name.toLowerCase().includes(search.toLowerCase())
  )

  return (
    <CollapsibleSection title="Edge Router Policies" count={policies.length} icon={Router} defaultOpen={false}>
      <p className="text-sm text-muted-foreground mb-3">
        Control which identities can connect through which edge routers. Use role attributes to match identities and routers.
      </p>

      <div className="flex items-center justify-between gap-4 mb-3">
        <SearchInput value={search} onChange={setSearch} placeholder="Search router policies..." />
        <Button size="sm" onClick={() => { resetForm(); setCreateModal(true) }}>
          <Plus className="mr-2 h-4 w-4" /> Add Policy
        </Button>
      </div>

      {isLoading ? <Spinner /> : policies.length === 0 ? (
        <EmptyState icon={Router} title="No edge router policies" description="Create policies to control identity access to edge routers." />
      ) : (
        <Card>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Edge Router Roles</TableHead>
                <TableHead>Identity Roles</TableHead>
                <TableHead className="w-[50px]" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {policies.map((policy) => (
                <TableRow key={policy.id} className="hover:bg-muted/50">
                  <TableCell>
                    <div className="flex items-center gap-2">
                      {isSystemPolicy(policy.name) && <span title="System policy"><Lock className="h-3.5 w-3.5 text-muted-foreground" /></span>}
                      <span className="font-medium">{policy.name}</span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {(policy.edgeRouterRoles || []).map((role) => {
                        const isAttr = role.startsWith('#')
                        const label = isAttr ? role.slice(1) : role
                        return (
                          <Badge key={role} variant="outline" className={`text-xs ${isAttr ? 'bg-teal-50 text-teal-700 border-teal-200' : ''}`}
                            title={isAttr ? `Attribute: matches routers with role "${label}"` : role}>
                            {isAttr && <span className="text-teal-400 mr-0.5">#</span>}{label}
                          </Badge>
                        )
                      })}
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {(policy.identityRoles || []).map((role) => {
                        const isAttr = role.startsWith('#')
                        const label = isAttr ? role.slice(1) : role
                        return (
                          <Badge key={role} variant="outline" className={`text-xs ${isAttr ? 'bg-orange-50 text-orange-700 border-orange-200' : ''}`}
                            title={isAttr ? `Attribute: matches identities with role "${label}"` : role}>
                            {isAttr && <span className="text-orange-400 mr-0.5">#</span>}{label}
                          </Badge>
                        )
                      })}
                    </div>
                  </TableCell>
                  <TableCell>
                    {!isSystemPolicy(policy.name) && (
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" size="icon" className="h-8 w-8">
                            <MoreHorizontal className="h-4 w-4" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuItem onClick={() => openEditModal(policy)}>
                            <Pencil className="mr-2 h-4 w-4" /> Edit
                          </DropdownMenuItem>
                          <DropdownMenuSeparator />
                          <DropdownMenuItem className="text-red-600" onClick={() => setDeleteTarget(policy)}>
                            <Trash2 className="mr-2 h-4 w-4" /> Delete
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      )}

      {/* Create/Edit Dialogs */}
      {[
        { open: createModal, onOpenChange: (v: boolean) => { if (!v) setCreateModal(false) }, title: 'Create Edge Router Policy', onSubmit: () => createMutation.mutate(form), pending: createMutation.isPending, submitLabel: 'Create Policy' },
        { open: !!editTarget, onOpenChange: (v: boolean) => { if (!v) { setEditTarget(null); resetForm() } }, title: 'Edit Edge Router Policy', onSubmit: () => editTarget && updateMutation.mutate({ id: editTarget.id, data: form }), pending: updateMutation.isPending, submitLabel: 'Update Policy' },
      ].map((dlg, i) => (
        <Dialog key={i} open={dlg.open} onOpenChange={dlg.onOpenChange}>
          <DialogContent className="sm:max-w-md">
            <DialogHeader><DialogTitle>{dlg.title}</DialogTitle></DialogHeader>
            <form onSubmit={(e) => { e.preventDefault(); dlg.onSubmit() }} className="space-y-4">
              <div className="space-y-2">
                <Label>Policy Name</Label>
                <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="allow-all-routers" required />
              </div>
              <div className="space-y-2">
                <Label>Edge Router Roles</Label>
                <Input value={form.edge_router_roles} onChange={(e) => setForm({ ...form, edge_router_roles: e.target.value })} placeholder="#public, #datacenter-us" required />
                <p className="text-xs text-muted-foreground"><span className="text-teal-600 font-medium">#attribute</span> matches routers by role. Use <code className="text-xs bg-muted px-1 rounded">#all</code> for all routers.</p>
              </div>
              <div className="space-y-2">
                <Label>Identity Roles</Label>
                <Input value={form.identity_roles} onChange={(e) => setForm({ ...form, identity_roles: e.target.value })} placeholder="#engineering, #vpn-users" required />
                <p className="text-xs text-muted-foreground"><span className="text-orange-600 font-medium">#attribute</span> matches identities by role (e.g., group names).</p>
              </div>
              <div className="flex justify-end gap-2 pt-2">
                <Button type="button" variant="outline" onClick={() => dlg.onOpenChange(false)}>Cancel</Button>
                <Button type="submit" disabled={dlg.pending}>
                  {dlg.pending ? 'Saving...' : dlg.submitLabel}
                </Button>
              </div>
            </form>
          </DialogContent>
        </Dialog>
      ))}

      <AlertDialog open={!!deleteTarget} onOpenChange={() => setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Edge Router Policy</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete &quot;{deleteTarget?.name}&quot;? Identities matched by this policy may lose router connectivity.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction className="bg-red-600 hover:bg-red-700" onClick={() => deleteTarget && deleteMutation.mutate(deleteTarget.id)}>
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </CollapsibleSection>
  )
}

function PostureSection() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [search, setSearch] = useState('')
  const [createModal, setCreateModal] = useState(false)
  const [editTarget, setEditTarget] = useState<PostureCheck | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<PostureCheck | null>(null)
  const [form, setForm] = useState({ name: '', check_type: 'OS', parameters: '{}', severity: 'medium', enabled: true, platforms: [] as string[] })

  const { data: summary } = useQuery({
    queryKey: ['ziti-posture-summary'],
    queryFn: () => api.get<PostureSummary>('/api/v1/access/ziti/posture/summary'),
  })

  const { data: checksData, isLoading } = useQuery({
    queryKey: ['ziti-posture-checks'],
    queryFn: () => api.get<PostureCheck[]>('/api/v1/access/ziti/posture/checks'),
  })

  const createMutation = useMutation({
    mutationFn: (data: typeof form) => api.post('/api/v1/access/ziti/posture/checks', { ...data, parameters: JSON.parse(data.parameters) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-posture-checks'] })
      queryClient.invalidateQueries({ queryKey: ['ziti-posture-summary'] })
      setCreateModal(false)
      resetForm()
      toast({ title: 'Posture check created' })
    },
    onError: () => toast({ title: 'Error', description: 'Failed to create posture check.', variant: 'destructive' }),
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: typeof form }) =>
      api.put(`/api/v1/access/ziti/posture/checks/${id}`, { ...data, parameters: JSON.parse(data.parameters) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-posture-checks'] })
      queryClient.invalidateQueries({ queryKey: ['ziti-posture-summary'] })
      setEditTarget(null)
      resetForm()
      toast({ title: 'Posture check updated' })
    },
    onError: () => toast({ title: 'Error', description: 'Failed to update posture check.', variant: 'destructive' }),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/access/ziti/posture/checks/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-posture-checks'] })
      queryClient.invalidateQueries({ queryKey: ['ziti-posture-summary'] })
      setDeleteTarget(null)
      toast({ title: 'Posture check deleted' })
    },
    onError: () => toast({ title: 'Error', description: 'Failed to delete posture check.', variant: 'destructive' }),
  })

  const resetForm = () => setForm({ name: '', check_type: 'OS', parameters: '{}', severity: 'medium', enabled: true, platforms: [] })

  const openEditModal = (check: PostureCheck) => {
    setForm({
      name: check.name,
      check_type: check.check_type,
      parameters: JSON.stringify(check.parameters, null, 2),
      severity: check.severity,
      enabled: check.enabled,
      platforms: Array.isArray(check.platforms) ? check.platforms : [],
    })
    setEditTarget(check)
  }

  const checks = (Array.isArray(checksData) ? checksData : []).filter((c) =>
    !search || c.name.toLowerCase().includes(search.toLowerCase()) || c.check_type.toLowerCase().includes(search.toLowerCase())
  )

  const severityColor = (severity: string): 'default' | 'destructive' | 'secondary' | 'outline' => {
    if (severity === 'critical' || severity === 'high') return 'destructive'
    if (severity === 'medium') return 'default'
    return 'secondary'
  }

  const totalChecks = summary?.total_checks || (Array.isArray(checksData) ? checksData.length : 0)

  return (
    <CollapsibleSection title="Posture Checks" count={totalChecks} icon={Fingerprint} defaultOpen>
      {/* Summary row */}
      {summary && (
        <div className="flex gap-4 mb-4 text-sm">
          <span className="text-green-600 font-medium">{summary.enabled_checks} enabled</span>
          <span className="text-muted-foreground">{summary.disabled_checks} disabled</span>
          {summary.by_type && Object.entries(summary.by_type).map(([type, count]) => (
            <Badge key={type} variant="outline" className="text-xs">{type}: {count}</Badge>
          ))}
        </div>
      )}

      <div className="flex items-center justify-between gap-4 mb-3">
        <SearchInput value={search} onChange={setSearch} placeholder="Search posture checks..." />
        <Button size="sm" onClick={() => { resetForm(); setCreateModal(true) }}>
          <Plus className="mr-2 h-4 w-4" /> Add Check
        </Button>
      </div>

      {isLoading ? <Spinner /> : checks.length === 0 ? (
        <EmptyState icon={Fingerprint} title="No posture checks" description="Create posture checks to enforce device compliance." />
      ) : (
        <Card>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Severity</TableHead>
                <TableHead>Platforms</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Created</TableHead>
                <TableHead className="w-[50px]" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {checks.map((check) => (
                <TableRow key={check.id} className="hover:bg-muted/50">
                  <TableCell className="font-medium">{check.name}</TableCell>
                  <TableCell><Badge variant="outline">{check.check_type}</Badge></TableCell>
                  <TableCell><Badge variant={severityColor(check.severity)}>{check.severity}</Badge></TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {Array.isArray(check.platforms) && check.platforms.length > 0
                      ? check.platforms.join(', ')
                      : 'all'}
                  </TableCell>
                  <TableCell>
                    <Badge variant={check.enabled ? 'default' : 'secondary'}>
                      {check.enabled ? 'Enabled' : 'Disabled'}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {safeDate(check.created_at)}
                  </TableCell>
                  <TableCell>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="icon" className="h-8 w-8">
                          <MoreHorizontal className="h-4 w-4" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem onClick={() => openEditModal(check)}>Edit</DropdownMenuItem>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem className="text-red-600" onClick={() => setDeleteTarget(check)}>
                          <Trash2 className="mr-2 h-4 w-4" /> Delete
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      )}

      {/* Identity Posture Viewer */}
      <IdentityPostureViewer />

      {/* Create/Edit Dialogs */}
      {[
        { open: createModal, onOpenChange: (v: boolean) => { if (!v) setCreateModal(false) }, title: 'Create Posture Check', onSubmit: () => createMutation.mutate(form), pending: createMutation.isPending, submitLabel: 'Create Check' },
        { open: !!editTarget, onOpenChange: (v: boolean) => { if (!v) { setEditTarget(null); resetForm() } }, title: 'Edit Posture Check', onSubmit: () => editTarget && updateMutation.mutate({ id: editTarget.id, data: form }), pending: updateMutation.isPending, submitLabel: 'Update Check' },
      ].map((dlg, i) => (
        <Dialog key={i} open={dlg.open} onOpenChange={dlg.onOpenChange}>
          <DialogContent className="sm:max-w-md">
            <DialogHeader><DialogTitle>{dlg.title}</DialogTitle></DialogHeader>
            <form onSubmit={(e) => { e.preventDefault(); dlg.onSubmit() }} className="space-y-4">
              <div className="space-y-2">
                <Label>Name</Label>
                <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="Posture check name" required />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>Check Type</Label>
                  <select value={form.check_type} onChange={(e) => setForm({ ...form, check_type: e.target.value })} className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm">
                    <option value="OS">OS</option>
                    <option value="Domain">Domain</option>
                    <option value="MFA">MFA</option>
                    <option value="Process">Process</option>
                    <option value="MAC">MAC</option>
                  </select>
                </div>
                <div className="space-y-2">
                  <Label>Severity</Label>
                  <select value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value })} className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm">
                    <option value="low">Low</option>
                    <option value="medium">Medium</option>
                    <option value="high">High</option>
                    <option value="critical">Critical</option>
                  </select>
                </div>
              </div>
              <div className="space-y-2">
                <Label>Parameters (JSON)</Label>
                <textarea
                  value={form.parameters}
                  onChange={(e) => setForm({ ...form, parameters: e.target.value })}
                  className="w-full h-24 rounded-md border border-input bg-background px-3 py-2 text-sm font-mono"
                  placeholder='{"os_type": "Windows", "min_version": "10"}'
                />
              </div>
              <div className="space-y-2">
                <Label>Platforms</Label>
                <div className="flex flex-wrap gap-3">
                  {['android', 'ios', 'windows', 'macos', 'linux'].map((p) => (
                    <label key={p} className="flex items-center gap-1.5 text-sm">
                      <input
                        type="checkbox"
                        checked={form.platforms.includes(p)}
                        onChange={(e) =>
                          setForm({
                            ...form,
                            platforms: e.target.checked
                              ? [...form.platforms, p]
                              : form.platforms.filter((x) => x !== p),
                          })
                        }
                      />
                      {p}
                    </label>
                  ))}
                </div>
                <p className="text-xs text-muted-foreground">
                  Leave all unchecked to apply to every platform. Select android/ios to scope a
                  check to mobile devices only.
                </p>
              </div>
              <div className="flex items-center gap-2">
                <Switch checked={form.enabled} onCheckedChange={(checked) => setForm({ ...form, enabled: checked })} />
                <Label>Enabled</Label>
              </div>
              <div className="flex justify-end gap-2 pt-2">
                <Button type="button" variant="outline" onClick={() => dlg.onOpenChange(false)}>Cancel</Button>
                <Button type="submit" disabled={dlg.pending}>
                  {dlg.pending ? 'Saving...' : dlg.submitLabel}
                </Button>
              </div>
            </form>
          </DialogContent>
        </Dialog>
      ))}

      <AlertDialog open={!!deleteTarget} onOpenChange={() => setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Posture Check</AlertDialogTitle>
            <AlertDialogDescription>Are you sure you want to delete &quot;{deleteTarget?.name}&quot;?</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction className="bg-red-600 hover:bg-red-700" onClick={() => deleteTarget && deleteMutation.mutate(deleteTarget.id)}>Delete</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </CollapsibleSection>
  )
}

function IdentityPostureViewer() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [identityId, setIdentityId] = useState('')
  const [searchId, setSearchId] = useState('')

  const { data: postureData, isLoading, isFetching } = useQuery({
    queryKey: ['ziti-identity-posture', searchId],
    queryFn: () => api.get<IdentityPostureReport>(`/api/v1/access/ziti/posture/identities/${searchId}`),
    enabled: !!searchId,
  })

  const evaluateMutation = useMutation({
    mutationFn: (id: string) => api.post(`/api/v1/access/ziti/posture/identities/${id}/evaluate`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-identity-posture', searchId] })
      queryClient.invalidateQueries({ queryKey: ['ziti-posture-summary'] })
      toast({ title: 'Posture evaluation triggered' })
    },
    onError: () => toast({ title: 'Error', description: 'Failed to evaluate posture.', variant: 'destructive' }),
  })

  const handleLookup = (e: React.FormEvent) => {
    e.preventDefault()
    if (identityId.trim()) setSearchId(identityId.trim())
  }

  return (
    <div className="mt-6 border-t pt-4">
      <h4 className="text-sm font-semibold mb-3 flex items-center gap-2">
        <Search className="h-4 w-4" /> Identity Posture Lookup
      </h4>
      <form onSubmit={handleLookup} className="flex gap-2 mb-3">
        <Input
          value={identityId}
          onChange={(e) => setIdentityId(e.target.value)}
          placeholder="Enter identity ID..."
          className="max-w-sm"
        />
        <Button type="submit" size="sm" variant="outline" disabled={!identityId.trim()}>
          Lookup
        </Button>
        {searchId && (
          <Button
            type="button"
            size="sm"
            variant="outline"
            onClick={() => evaluateMutation.mutate(searchId)}
            disabled={evaluateMutation.isPending}
          >
            <RefreshCw className={`mr-2 h-4 w-4 ${evaluateMutation.isPending ? 'animate-spin' : ''}`} />
            Evaluate Now
          </Button>
        )}
      </form>

      {isLoading || isFetching ? <Spinner /> : postureData && (
        <div className="space-y-3">
          <div className="flex items-center gap-3 text-sm">
            <Badge variant={postureData.overall_passed ? 'default' : 'destructive'}>
              {postureData.overall_passed ? 'Passed' : 'Failed'}
            </Badge>
            <span className="text-muted-foreground">
              {postureData.results?.length || 0} check(s) evaluated
            </span>
            {postureData.evaluated_at && (
              <span className="text-muted-foreground">
                at {new Date(postureData.evaluated_at).toLocaleString()}
              </span>
            )}
          </div>

          {postureData.results && postureData.results.length > 0 && (
            <Card>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Check ID</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Details</TableHead>
                    <TableHead>Checked At</TableHead>
                    <TableHead>Expires At</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {postureData.results.map((r) => (
                    <TableRow key={r.id}>
                      <TableCell className="font-mono text-xs">{r.check_id}</TableCell>
                      <TableCell>
                        <Badge variant={r.passed ? 'default' : 'destructive'}>
                          {r.passed ? 'Passed' : 'Failed'}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-xs max-w-[300px] truncate">
                        {r.details ? JSON.stringify(r.details) : '-'}
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {new Date(r.checked_at).toLocaleString()}
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {r.expires_at ? new Date(r.expires_at).toLocaleString() : '-'}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </Card>
          )}
        </div>
      )}
    </div>
  )
}

function CertificatesSection() {
  const queryClient = useQueryClient()
  const { toast } = useToast()

  const { data: certsData, isLoading } = useQuery({
    queryKey: ['ziti-certificates'],
    queryFn: () => api.get<Certificate[]>('/api/v1/access/ziti/certificates'),
  })

  const { data: expiryAlerts } = useQuery({
    queryKey: ['ziti-certificates-expiry'],
    queryFn: () => api.get<Certificate[]>('/api/v1/access/ziti/certificates/expiry-alerts?threshold_days=30'),
  })

  const rotateMutation = useMutation({
    mutationFn: (id: string) => api.post(`/api/v1/access/ziti/certificates/${id}/rotate`, {}),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-certificates'] })
      queryClient.invalidateQueries({ queryKey: ['ziti-certificates-expiry'] })
      toast({ title: 'Certificate rotated', description: 'Certificate rotation has been initiated.' })
    },
    onError: () => toast({ title: 'Error', description: 'Failed to rotate certificate.', variant: 'destructive' }),
  })

  const certs = Array.isArray(certsData) ? certsData : []
  const alerts = Array.isArray(expiryAlerts) ? expiryAlerts : []

  const expiryBadge = (days: number) => {
    const variant: 'default' | 'destructive' | 'secondary' = days < 30 ? 'destructive' : days <= 60 ? 'secondary' : 'default'
    const label = days < 0 ? 'Expired' : days === 0 ? 'Expires today' : `${days}d remaining`
    return <Badge variant={variant}>{label}</Badge>
  }

  return (
    <CollapsibleSection title="Certificates" count={certs.length} icon={FileKey}>
      {/* Expiry alerts */}
      {alerts.length > 0 && (
        <div className="mb-4 p-3 rounded-lg border border-yellow-300 bg-yellow-50">
          <div className="flex items-center gap-2 mb-2">
            <AlertTriangle className="h-4 w-4 text-yellow-600" />
            <span className="text-sm font-medium text-yellow-800">Certificates Expiring Soon ({alerts.length})</span>
          </div>
          <div className="space-y-1">
            {alerts.map((cert) => (
              <div key={cert.id} className="flex items-center justify-between text-sm">
                <span className="font-medium text-yellow-900">{cert.name}</span>
                <div className="flex items-center gap-2">
                  <span className="text-yellow-700">
                    {cert.days_until_expiry < 0 ? `Expired ${Math.abs(cert.days_until_expiry)} days ago` : `${cert.days_until_expiry} days left`}
                  </span>
                  <ConfirmAction
                    title="Rotate this certificate?"
                    description="A new Ziti certificate is issued and the old certificate stops working once rotated. Any component still presenting the old certificate will fail until it picks up the new one."
                    destructive
                    confirmLabel="Rotate"
                    onConfirm={() => rotateMutation.mutate(cert.id)}
                  >
                    {(open) => (
                      <Button variant="outline" size="sm" onClick={open} disabled={rotateMutation.isPending}>
                        Rotate
                      </Button>
                    )}
                  </ConfirmAction>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {isLoading ? <Spinner /> : certs.length === 0 ? (
        <EmptyState icon={FileKey} title="No certificates" description="No Ziti certificates are being managed." />
      ) : (
        <Card>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Subject</TableHead>
                <TableHead>Expiry</TableHead>
                <TableHead>Auto Renew</TableHead>
                <TableHead className="w-[50px]" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {certs.map((cert) => (
                <TableRow key={cert.id} className="hover:bg-muted/50">
                  <TableCell className="font-medium">{cert.name}</TableCell>
                  <TableCell><Badge variant="outline">{cert.cert_type}</Badge></TableCell>
                  <TableCell className="text-sm text-muted-foreground max-w-[200px] truncate" title={cert.subject}>{cert.subject}</TableCell>
                  <TableCell>{expiryBadge(cert.days_until_expiry)}</TableCell>
                  <TableCell>
                    <Badge variant={cert.auto_renew ? 'default' : 'secondary'}>{cert.auto_renew ? 'Yes' : 'No'}</Badge>
                  </TableCell>
                  <TableCell>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="icon" className="h-8 w-8"><MoreHorizontal className="h-4 w-4" /></Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem onClick={() => {
                          navigator.clipboard.writeText(cert.fingerprint)
                          toast({ title: 'Copied', description: 'Fingerprint copied.' })
                        }}>
                          <Copy className="mr-2 h-4 w-4" /> Copy Fingerprint
                        </DropdownMenuItem>
                        <ConfirmAction
                          title="Rotate this certificate?"
                          description="A new Ziti certificate is issued and the old certificate stops working once rotated. Any component still presenting the old certificate will fail until it picks up the new one."
                          destructive
                          confirmLabel="Rotate"
                          onConfirm={() => rotateMutation.mutate(cert.id)}
                        >
                          {(open) => (
                            <DropdownMenuItem onSelect={(e) => { e.preventDefault(); open() }}>
                              <RefreshCw className="mr-2 h-4 w-4" /> Rotate
                            </DropdownMenuItem>
                          )}
                        </ConfirmAction>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      )}
    </CollapsibleSection>
  )
}

function PolicySyncSection() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [createModal, setCreateModal] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<PolicySync | null>(null)
  const [form, setForm] = useState({ governance_policy_id: '', config: '{}', auto_fetch: true })

  const { data: syncsData, isLoading } = useQuery({
    queryKey: ['ziti-policy-sync'],
    queryFn: () => api.get<PolicySync[]>('/api/v1/access/ziti/policy-sync'),
  })

  // Fetch governance policies for dropdown and name lookup
  const { data: governancePolicies } = useQuery({
    queryKey: ['governance-policies-for-sync'],
    queryFn: () => api.get<{ id: string; name: string; description?: string }[]>('/api/v1/governance/policies'),
  })

  const createMutation = useMutation({
    mutationFn: (data: typeof form) => api.post('/api/v1/access/ziti/policy-sync', {
      governance_policy_id: data.governance_policy_id,
      auto_fetch: data.auto_fetch,
      ...(data.auto_fetch ? {} : { config: JSON.parse(data.config) }),
    }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-policy-sync'] })
      setCreateModal(false)
      setForm({ governance_policy_id: '', config: '{}', auto_fetch: true })
      toast({ title: 'Policy sync created' })
    },
    onError: () => toast({ title: 'Error', description: 'Failed to create policy sync.', variant: 'destructive' }),
  })

  const triggerMutation = useMutation({
    mutationFn: (id: string) => api.post(`/api/v1/access/ziti/policy-sync/${id}/trigger`, {}),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-policy-sync'] })
      toast({ title: 'Re-sync triggered' })
    },
    onError: () => toast({ title: 'Error', description: 'Failed to trigger re-sync.', variant: 'destructive' }),
  })

  const syncAllMutation = useMutation({
    mutationFn: async () => {
      const results = []
      for (const sync of syncs) {
        try {
          await api.post(`/api/v1/access/ziti/policy-sync/${sync.id}/trigger`, {})
          results.push({ id: sync.id, success: true })
        } catch {
          results.push({ id: sync.id, success: false })
        }
      }
      return results
    },
    onSuccess: (results) => {
      queryClient.invalidateQueries({ queryKey: ['ziti-policy-sync'] })
      const succeeded = results.filter(r => r.success).length
      const failed = results.filter(r => !r.success).length
      toast({
        title: 'Sync All complete',
        description: `${succeeded} synced${failed > 0 ? `, ${failed} failed` : ''}`,
        variant: failed > 0 ? 'destructive' : undefined,
      })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/access/ziti/policy-sync/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-policy-sync'] })
      setDeleteTarget(null)
      toast({ title: 'Policy sync deleted' })
    },
    onError: () => toast({ title: 'Error', description: 'Failed to delete policy sync.', variant: 'destructive' }),
  })

  const syncs = Array.isArray(syncsData) ? syncsData : []

  const statusVariant = (status: string): 'default' | 'destructive' | 'secondary' => {
    if (status === 'synced') return 'default'
    if (status === 'error') return 'destructive'
    return 'secondary'
  }

  // Map governance policy IDs to names
  const govPolicyMap = new Map((Array.isArray(governancePolicies) ? governancePolicies : []).map(p => [p.id, p.name]))

  return (
    <CollapsibleSection title="Governance → Ziti Sync" count={syncs.length} icon={RefreshCw} defaultOpen={false}>
      <p className="text-sm text-muted-foreground mb-3">
        Link governance access policies to Ziti service policies. When access reviews grant or revoke access, the corresponding Ziti policies update automatically.
      </p>
      <div className="flex items-center justify-between gap-4 mb-3">
        <div className="flex items-center gap-2">
          {syncs.length > 0 && (
            <Button variant="outline" size="sm" onClick={() => syncAllMutation.mutate()} disabled={syncAllMutation.isPending}>
              <RefreshCw className={`mr-2 h-3 w-3 ${syncAllMutation.isPending ? 'animate-spin' : ''}`} />
              {syncAllMutation.isPending ? 'Syncing...' : 'Sync All'}
            </Button>
          )}
        </div>
        <Button size="sm" onClick={() => setCreateModal(true)}>
          <Plus className="mr-2 h-4 w-4" /> Link Policy
        </Button>
      </div>

      {isLoading ? <Spinner /> : syncs.length === 0 ? (
        <EmptyState icon={RefreshCw} title="No policy sync mappings" description="Sync governance policies to Ziti network policies." />
      ) : (
        <Card>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Governance Policy</TableHead>
                <TableHead>Ziti Policy</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Last Synced</TableHead>
                <TableHead className="w-[50px]" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {syncs.map((sync) => (
                <TableRow key={sync.id} className="hover:bg-muted/50">
                  <TableCell>
                    <div>
                      {govPolicyMap.get(sync.governance_policy_id) ? (
                        <span className="font-medium">{govPolicyMap.get(sync.governance_policy_id)}</span>
                      ) : (
                        <TruncatedId value={sync.governance_policy_id} label="Governance Policy ID" />
                      )}
                    </div>
                  </TableCell>
                  <TableCell>
                    {sync.ziti_policy_id ? <TruncatedId value={sync.ziti_policy_id} label="Ziti Policy ID" /> : <span className="text-muted-foreground">-</span>}
                  </TableCell>
                  <TableCell>
                    <Badge variant={statusVariant(sync.sync_status)}>{sync.sync_status}</Badge>
                    {sync.error_message && (
                      <p className="text-xs text-red-500 mt-0.5 max-w-[200px] truncate" title={sync.error_message}>{sync.error_message}</p>
                    )}
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {sync.last_synced_at ? new Date(sync.last_synced_at).toLocaleString() : 'Never'}
                  </TableCell>
                  <TableCell>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="icon" className="h-8 w-8"><MoreHorizontal className="h-4 w-4" /></Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem onClick={() => triggerMutation.mutate(sync.id)}>
                          <RefreshCw className="mr-2 h-4 w-4" /> Re-sync
                        </DropdownMenuItem>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem className="text-red-600" onClick={() => setDeleteTarget(sync)}>
                          <Trash2 className="mr-2 h-4 w-4" /> Delete
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      )}

      {/* Create Dialog */}
      <Dialog open={createModal} onOpenChange={setCreateModal}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader><DialogTitle>Link Governance Policy to Ziti</DialogTitle></DialogHeader>
          <form onSubmit={(e) => { e.preventDefault(); createMutation.mutate(form) }} className="space-y-4">
            <div className="space-y-2">
              <Label>Governance Policy</Label>
              {Array.isArray(governancePolicies) && governancePolicies.length > 0 ? (
                <select
                  value={form.governance_policy_id}
                  onChange={(e) => setForm({ ...form, governance_policy_id: e.target.value })}
                  className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                  required
                >
                  <option value="">Select a governance policy...</option>
                  {governancePolicies.map((p) => (
                    <option key={p.id} value={p.id}>{p.name}{p.description ? ` — ${p.description}` : ''}</option>
                  ))}
                </select>
              ) : (
                <Input value={form.governance_policy_id} onChange={(e) => setForm({ ...form, governance_policy_id: e.target.value })} placeholder="UUID of governance policy" required />
              )}
              <p className="text-xs text-muted-foreground">Access review decisions on this policy will auto-update Ziti service policies.</p>
            </div>
            <div className="flex items-center gap-2">
              <Switch checked={form.auto_fetch} onCheckedChange={(checked) => setForm({ ...form, auto_fetch: checked })} />
              <Label>Auto-detect policy rules</Label>
            </div>
            <p className="text-xs text-muted-foreground -mt-2">
              {form.auto_fetch
                ? 'Policy type and rules will be automatically fetched and transformed into Ziti roles.'
                : 'Manually specify how governance decisions map to Ziti policy rules.'}
            </p>
            {!form.auto_fetch && (
              <div className="space-y-2">
                <Label>Mapping Config (JSON)</Label>
                <textarea
                  value={form.config}
                  onChange={(e) => setForm({ ...form, config: e.target.value })}
                  className="w-full h-32 rounded-md border border-input bg-background px-3 py-2 text-sm font-mono"
                  placeholder='{"action": "allow", "service_roles": ["#web"], "identity_roles": ["#engineering"]}'
                />
                <p className="text-xs text-muted-foreground">Defines how governance decisions map to Ziti policy rules.</p>
              </div>
            )}
            <div className="flex justify-end gap-2 pt-2">
              <Button type="button" variant="outline" onClick={() => setCreateModal(false)}>Cancel</Button>
              <Button type="submit" disabled={createMutation.isPending}>
                {createMutation.isPending ? 'Linking...' : 'Link Policy'}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      <AlertDialog open={!!deleteTarget} onOpenChange={() => setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Policy Sync</AlertDialogTitle>
            <AlertDialogDescription>Are you sure? The Ziti policy will also be removed.</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction className="bg-red-600 hover:bg-red-700" onClick={() => deleteTarget && deleteMutation.mutate(deleteTarget.id)}>Delete</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </CollapsibleSection>
  )
}

// ─── Remote Access Tab ───────────────────────────────────────────────────────

function RemoteAccessTab() {
  const { toast } = useToast()
  const queryClient = useQueryClient()

  // BrowZer status
  const { data: browzerStatus, isLoading: browzerLoading } = useQuery<BrowZerStatus>({
    queryKey: ['browzer-status'],
    queryFn: () => api.get<BrowZerStatus>('/api/v1/access/ziti/browzer/status'),
  })

  // Guacamole connections
  const { data: connData, isLoading: connLoading } = useQuery({
    queryKey: ['guacamole-connections'],
    queryFn: () => api.get<{ connections: GuacConnection[] }>('/api/v1/access/guacamole/connections'),
  })

  // Services for per-service BrowZer toggle
  const { data: servicesData } = useQuery({
    queryKey: ['ziti-services-browzer'],
    queryFn: () => api.get<{ services: ZitiService[] }>('/api/v1/access/ziti/services'),
  })

  const enableMutation = useMutation({
    mutationFn: () => api.post('/api/v1/access/ziti/browzer/enable'),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['browzer-status'] }); toast({ title: 'BrowZer enabled' }) },
    onError: () => toast({ title: 'Failed to enable BrowZer', variant: 'destructive' }),
  })

  const disableMutation = useMutation({
    mutationFn: () => api.post('/api/v1/access/ziti/browzer/disable'),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['browzer-status'] }); toast({ title: 'BrowZer disabled' }) },
    onError: () => toast({ title: 'Failed to disable BrowZer', variant: 'destructive' }),
  })

  const connectMutation = useMutation({
    mutationFn: async (routeId: string) => api.post<{ connect_url: string }>(`/api/v1/access/guacamole/connections/${routeId}/connect`, {}),
    onSuccess: (resp) => {
      const connectUrl = (resp as Record<string, string>)?.connect_url
      if (connectUrl) window.open(connectUrl, '_blank', 'noopener,noreferrer')
    },
    onError: () => toast({ title: 'Error', description: 'Failed to get connection URL.', variant: 'destructive' }),
  })

  const enableOnServiceMutation = useMutation({
    mutationFn: ({ serviceId, path, domain }: { serviceId: string; path?: string; domain?: string }) => {
      const body: Record<string, string> = {}
      if (path) body.path = path
      if (domain) body.domain = domain
      return api.post(`/api/v1/access/ziti/browzer/services/${serviceId}/enable`, Object.keys(body).length > 0 ? body : undefined)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-services'] })
      queryClient.invalidateQueries({ queryKey: ['ziti-services-browzer'] })
      setInitialized(false)
      toast({ title: 'BrowZer enabled on service' })
    },
    onError: (err: Error) => toast({ title: 'Failed to enable BrowZer on service', description: err.message, variant: 'destructive' }),
  })

  const disableOnServiceMutation = useMutation({
    mutationFn: (serviceId: string) => api.post(`/api/v1/access/ziti/browzer/services/${serviceId}/disable`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ziti-services'] })
      queryClient.invalidateQueries({ queryKey: ['ziti-services-browzer'] })
      setInitialized(false)
      toast({ title: 'BrowZer disabled on service' })
    },
    onError: (err: Error) => toast({ title: 'Failed to disable BrowZer on service', description: err.message, variant: 'destructive' }),
  })

  const connections = connData?.connections || []
  const services = servicesData?.services || []
  const [showHowItWorks, setShowHowItWorks] = useState(false)
  const [browzerPaths, setBrowzerPaths] = useState<Record<string, string>>({})
  const [browzerDomains, setBrowzerDomains] = useState<Record<string, string>>({})

  // Initialize paths/domains from API data when services load
  const [initialized, setInitialized] = useState(false)
  if (!initialized && services.length > 0) {
    const paths: Record<string, string> = {}
    const domains: Record<string, string> = {}
    for (const svc of services) {
      if (svc.browzer_path) paths[svc.id] = svc.browzer_path
      if (svc.browzer_domain) domains[svc.id] = svc.browzer_domain
    }
    if (Object.keys(paths).length > 0) setBrowzerPaths(prev => ({ ...prev, ...paths }))
    if (Object.keys(domains).length > 0) setBrowzerDomains(prev => ({ ...prev, ...domains }))
    setInitialized(true)
  }

  if (browzerLoading || connLoading) return <Spinner />

  const protocolColor = (protocol: string) => {
    switch (protocol.toLowerCase()) {
      case 'ssh': return 'bg-green-600'
      case 'rdp': return 'bg-primary'
      case 'vnc': return 'bg-purple-600'
      default: return 'bg-gray-600'
    }
  }

  return (
    <div className="space-y-6 mt-4">
      {/* BrowZer Status Banner */}
      <Card className={browzerStatus?.enabled ? 'border-green-200 bg-green-50/50' : ''}>
        <CardContent className="flex items-center justify-between py-4">
          <div className="flex items-center gap-4">
            <div className={`p-2.5 rounded-lg ${browzerStatus?.enabled ? 'bg-green-100' : 'bg-muted'}`}>
              <Monitor className={`h-5 w-5 ${browzerStatus?.enabled ? 'text-green-700' : 'text-muted-foreground'}`} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="font-semibold">BrowZer</h3>
                <Badge variant={browzerStatus?.enabled ? 'default' : 'secondary'}>
                  {browzerStatus?.enabled ? 'Enabled' : 'Disabled'}
                </Badge>
              </div>
              <p className="text-sm text-muted-foreground">
                Browser-native zero-trust access via Ziti Service Worker
              </p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            {browzerStatus?.enabled && browzerStatus.bootstrapper_url && (
              <a
                href={browzerStatus.bootstrapper_url}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-1 text-sm text-primary hover:underline"
              >
                Open Bootstrapper <ExternalLink className="h-3 w-3" />
              </a>
            )}
            <Button
              variant={browzerStatus?.enabled ? 'destructive' : 'default'}
              size="sm"
              onClick={() => browzerStatus?.enabled ? disableMutation.mutate() : enableMutation.mutate()}
              disabled={enableMutation.isPending || disableMutation.isPending}
            >
              {browzerStatus?.enabled ? 'Disable' : 'Enable'}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* BrowZer Config Details (when enabled) */}
      {browzerStatus?.enabled && (browzerStatus.oidc_issuer || browzerStatus.external_jwt_signer_id) && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {browzerStatus.bootstrapper_url && (
            <div className="text-sm">
              <span className="text-muted-foreground block text-xs">Bootstrapper URL</span>
              <code className="text-xs bg-muted px-1.5 py-0.5 rounded">{browzerStatus.bootstrapper_url}</code>
            </div>
          )}
          {browzerStatus.oidc_issuer && (
            <div className="text-sm">
              <span className="text-muted-foreground block text-xs">OIDC Issuer</span>
              <code className="text-xs bg-muted px-1.5 py-0.5 rounded">{browzerStatus.oidc_issuer}</code>
            </div>
          )}
          {browzerStatus.oidc_client_id && (
            <div className="text-sm">
              <span className="text-muted-foreground block text-xs">OIDC Client ID</span>
              <code className="text-xs bg-muted px-1.5 py-0.5 rounded">{browzerStatus.oidc_client_id}</code>
            </div>
          )}
          {browzerStatus.external_jwt_signer_id && (
            <div className="text-sm">
              <span className="text-muted-foreground block text-xs">JWT Signer</span>
              <TruncatedId value={browzerStatus.external_jwt_signer_id} label="JWT Signer ID" />
            </div>
          )}
        </div>
      )}

      {/* Guacamole Connections */}
      <div className="space-y-3">
        <h3 className="text-lg font-semibold">Connections</h3>
        {connections.length === 0 ? (
          <EmptyState
            icon={Monitor}
            title="No remote access connections"
            description="Create a proxy route with type SSH, RDP, or VNC to auto-provision Guacamole connections."
          />
        ) : (
          <Card>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Protocol</TableHead>
                  <TableHead>Target</TableHead>
                  <TableHead>Guacamole ID</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {connections.map((conn) => (
                  <TableRow key={conn.id} className="hover:bg-muted/50">
                    <TableCell>
                      <Badge variant="default" className={protocolColor(conn.protocol)}>
                        {conn.protocol.toUpperCase()}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <code className="text-sm bg-muted px-1.5 py-0.5 rounded">{conn.hostname}:{conn.port}</code>
                    </TableCell>
                    <TableCell><TruncatedId value={conn.guacamole_connection_id} label="Guacamole ID" /></TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {safeDate(conn.created_at)}
                    </TableCell>
                    <TableCell className="text-right">
                      <Button size="sm" onClick={() => connectMutation.mutate(conn.route_id)} disabled={connectMutation.isPending}>
                        <ExternalLink className="mr-1 h-3 w-3" /> Connect
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Card>
        )}
      </div>

      {/* Per-Service BrowZer Toggle */}
      {browzerStatus?.enabled && services.length > 0 && (
        <div className="space-y-3">
          <h3 className="text-lg font-semibold">BrowZer-Enabled Services</h3>
          <p className="text-sm text-muted-foreground">
            Toggle BrowZer access per service. Enabled services get the &quot;browzer-enabled&quot; role attribute.
          </p>
          <Card>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Service</TableHead>
                  <TableHead>Target</TableHead>
                  <TableHead>Path</TableHead>
                  <TableHead>Domain</TableHead>
                  <TableHead>BrowZer</TableHead>
                  <TableHead className="text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {services.map((svc) => {
                  const isBrowzerEnabled = !!(svc.browzer_path || svc.browzer_domain)
                  return (
                    <TableRow key={svc.id} className="hover:bg-muted/50">
                      <TableCell className="font-medium">{svc.name}</TableCell>
                      <TableCell className="text-sm text-muted-foreground">{svc.host}:{svc.port}</TableCell>
                      <TableCell>
                        <Input
                          placeholder={`/${svc.name}`}
                          value={browzerPaths[svc.id] ?? ''}
                          onChange={(e) => setBrowzerPaths(prev => ({ ...prev, [svc.id]: e.target.value }))}
                          className="h-8 w-32 text-sm"
                          disabled={isBrowzerEnabled}
                        />
                      </TableCell>
                      <TableCell>
                        <Input
                          placeholder={`${svc.name}.localtest.me`}
                          value={browzerDomains[svc.id] ?? ''}
                          onChange={(e) => setBrowzerDomains(prev => ({ ...prev, [svc.id]: e.target.value }))}
                          className="h-8 w-44 text-sm"
                          disabled={isBrowzerEnabled}
                        />
                      </TableCell>
                      <TableCell>
                        <Badge variant={isBrowzerEnabled ? 'default' : 'secondary'}>
                          {isBrowzerEnabled ? 'Enabled' : 'Disabled'}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-right">
                        <Button
                          size="sm"
                          variant={isBrowzerEnabled ? 'destructive' : 'outline'}
                          onClick={() => {
                            if (isBrowzerEnabled) {
                              disableOnServiceMutation.mutate(svc.ziti_id)
                            } else {
                              const path = browzerPaths[svc.id] || `/${svc.name}`
                              const domain = browzerDomains[svc.id] || undefined
                              enableOnServiceMutation.mutate({ serviceId: svc.ziti_id, path, domain })
                            }
                          }}
                        >
                          {isBrowzerEnabled ? 'Disable' : 'Enable'}
                        </Button>
                      </TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
          </Card>
        </div>
      )}

      {/* Temporary Access Links Section */}
      <TempAccessLinksSection />

      {/* How it works - collapsible */}
      <button
        onClick={() => setShowHowItWorks(!showHowItWorks)}
        className="flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground transition-colors"
      >
        {showHowItWorks ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
        How BrowZer Works
      </button>
      {showHowItWorks && (
        <Card>
          <CardContent className="pt-4 space-y-3">
            <ol className="text-sm space-y-1.5 list-decimal list-inside text-muted-foreground">
              <li>User visits the BrowZer Bootstrapper URL</li>
              <li>Bootstrapper redirects to OpenIDX OAuth for OIDC login</li>
              <li>After authentication, the Ziti BrowZer Runtime (ZBR) is injected into the browser</li>
              <li>ZBR registers a Service Worker that intercepts HTTP requests</li>
              <li>The browser gets an ephemeral Ziti identity from the JWT token</li>
              <li>All traffic flows through the Ziti overlay via WebSocket to the edge router</li>
              <li>Press <kbd className="bg-muted px-1 py-0.5 rounded text-xs">Alt+F12</kbd> to open the ZBR debug panel</li>
            </ol>
            <div className="p-3 bg-muted rounded-lg">
              <p className="text-xs font-medium mb-1">Connection Flow</p>
              <code className="text-xs text-muted-foreground">
                Browser (ZBR + SW) &rarr; WSS &rarr; Edge Router &rarr; Ziti Circuit &rarr; Access Service &rarr; Upstream
              </code>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}

// ─── Temporary Access Links Section ──────────────────────────────────────────

function TempAccessLinksSection() {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [createModal, setCreateModal] = useState(false)
  const [copiedId, setCopiedId] = useState<string | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<TempAccessLink | null>(null)

  const [form, setForm] = useState({
    name: '',
    description: '',
    protocol: 'ssh',
    target_host: '',
    target_port: 22,
    username: '',
    duration_mins: 120,
    max_uses: 0,
    allowed_ips: '',
    notify_on_use: false,
    notify_email: '',
  })

  // Fetch temp access links
  const { data: linksData, isLoading } = useQuery({
    queryKey: ['temp-access-links'],
    queryFn: () => api.get<{ links: TempAccessLink[] }>('/api/v1/access/temp-access'),
  })

  // Create mutation
  const createMutation = useMutation({
    mutationFn: (data: typeof form) => api.post<TempAccessLink>('/api/v1/access/temp-access', {
      ...data,
      target_port: Number(data.target_port),
      duration_mins: Number(data.duration_mins),
      max_uses: Number(data.max_uses),
      allowed_ips: data.allowed_ips ? data.allowed_ips.split(',').map(ip => ip.trim()).filter(Boolean) : [],
    }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['temp-access-links'] })
      setCreateModal(false)
      resetForm()
      toast({ title: 'Temporary access link created', description: 'Share the URL with your support vendor.' })
    },
    onError: () => toast({ title: 'Error', description: 'Failed to create access link.', variant: 'destructive' }),
  })

  // Revoke mutation
  const revokeMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/access/temp-access/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['temp-access-links'] })
      setDeleteTarget(null)
      toast({ title: 'Access link revoked' })
    },
    onError: () => toast({ title: 'Error', description: 'Failed to revoke access link.', variant: 'destructive' }),
  })

  const resetForm = () => setForm({
    name: '',
    description: '',
    protocol: 'ssh',
    target_host: '',
    target_port: 22,
    username: '',
    duration_mins: 120,
    max_uses: 0,
    allowed_ips: '',
    notify_on_use: false,
    notify_email: '',
  })

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text)
    setCopiedId(id)
    toast({ title: 'Copied to clipboard' })
    setTimeout(() => setCopiedId(null), 2000)
  }

  const links = linksData?.links || []

  const getStatusBadge = (link: TempAccessLink) => {
    const now = new Date()
    const expires = new Date(link.expires_at)
    if (link.status === 'revoked') return <Badge variant="destructive">Revoked</Badge>
    if (link.status === 'expired' || expires < now) return <Badge variant="secondary">Expired</Badge>
    if (link.max_uses > 0 && link.current_uses >= link.max_uses) return <Badge variant="secondary">Used</Badge>
    return <Badge className="bg-green-600">Active</Badge>
  }

  const getTimeRemaining = (expiresAt: string) => {
    const now = new Date()
    const expires = new Date(expiresAt)
    const diff = expires.getTime() - now.getTime()
    if (diff <= 0) return 'Expired'
    const hours = Math.floor(diff / (1000 * 60 * 60))
    const mins = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60))
    if (hours > 24) return `${Math.floor(hours / 24)}d ${hours % 24}h`
    if (hours > 0) return `${hours}h ${mins}m`
    return `${mins}m`
  }

  const protocolIcon = (protocol: string) => {
    switch (protocol) {
      case 'ssh': return <Terminal className="h-4 w-4" />
      case 'rdp': return <MonitorPlay className="h-4 w-4" />
      case 'vnc': return <Monitor className="h-4 w-4" />
      default: return <Server className="h-4 w-4" />
    }
  }

  const protocolColor = (protocol: string) => {
    switch (protocol) {
      case 'ssh': return 'bg-green-600'
      case 'rdp': return 'bg-primary'
      case 'vnc': return 'bg-purple-600'
      default: return 'bg-gray-600'
    }
  }

  return (
    <div className="space-y-4" data-testid="temp-access-section">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Key className="h-5 w-5 text-muted-foreground" />
          <h3 className="text-lg font-semibold">Temporary Access Links</h3>
          <Badge variant="outline" className="ml-2">{links.length}</Badge>
        </div>
        <Button size="sm" onClick={() => setCreateModal(true)}>
          <Plus className="h-4 w-4 mr-1" />
          Create Temp Access
        </Button>
      </div>

      <p className="text-sm text-muted-foreground">
        Generate time-limited access URLs for support vendors or temporary access needs.
      </p>

      {isLoading ? (
        <Spinner />
      ) : links.length === 0 ? (
        <EmptyState
          icon={Link2}
          title="No temporary access links"
          description="Create a temporary access link to share with support vendors."
        />
      ) : (
        <Card>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Target</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Usage</TableHead>
                <TableHead>Expires</TableHead>
                <TableHead>Access URL</TableHead>
                <TableHead className="w-[50px]"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {links.map((link) => (
                <TableRow key={link.id}>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <div className={`p-1.5 rounded ${protocolColor(link.protocol)}`}>
                        {protocolIcon(link.protocol)}
                      </div>
                      <div>
                        <p className="font-medium">{link.name}</p>
                        {link.description && (
                          <p className="text-xs text-muted-foreground">{link.description}</p>
                        )}
                      </div>
                    </div>
                  </TableCell>
                  <TableCell>
                    <code className="text-sm bg-muted px-1.5 py-0.5 rounded">
                      {link.target_host}:{link.target_port}
                    </code>
                  </TableCell>
                  <TableCell>{getStatusBadge(link)}</TableCell>
                  <TableCell>
                    <span className="text-sm">
                      {link.current_uses}{link.max_uses > 0 ? `/${link.max_uses}` : ''} uses
                    </span>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-1">
                      <Clock className="h-3.5 w-3.5 text-muted-foreground" />
                      <span className="text-sm">{getTimeRemaining(link.expires_at)}</span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-1">
                      <code className="text-xs bg-muted px-1.5 py-0.5 rounded max-w-[200px] truncate">
                        {link.access_url}
                      </code>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-7 w-7"
                        onClick={() => copyToClipboard(link.access_url, link.id)}
                      >
                        {copiedId === link.id ? (
                          <CheckCircle className="h-3.5 w-3.5 text-green-600" />
                        ) : (
                          <Copy className="h-3.5 w-3.5" />
                        )}
                      </Button>
                    </div>
                  </TableCell>
                  <TableCell>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="icon" className="h-8 w-8">
                          <MoreHorizontal className="h-4 w-4" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem onClick={() => copyToClipboard(link.access_url, link.id)}>
                          <Copy className="h-4 w-4 mr-2" />
                          Copy URL
                        </DropdownMenuItem>
                        <DropdownMenuItem onClick={() => window.open(link.access_url, '_blank')}>
                          <ExternalLink className="h-4 w-4 mr-2" />
                          Open Link
                        </DropdownMenuItem>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem
                          className="text-red-600"
                          onClick={() => setDeleteTarget(link)}
                          disabled={link.status !== 'active'}
                        >
                          <Trash2 className="h-4 w-4 mr-2" />
                          Revoke Access
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      )}

      {/* Create Dialog */}
      <Dialog open={createModal} onOpenChange={setCreateModal}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>Create Temporary Access Link</DialogTitle>
          </DialogHeader>
          <form onSubmit={(e) => { e.preventDefault(); createMutation.mutate(form) }} className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div className="col-span-2">
                <Label>Name</Label>
                <Input
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                  placeholder="Vendor SSH Access"
                  required
                />
              </div>
              <div className="col-span-2">
                <Label>Description (optional)</Label>
                <Input
                  value={form.description}
                  onChange={(e) => setForm({ ...form, description: e.target.value })}
                  placeholder="Temporary access for ABC Corp support"
                />
              </div>
              <div>
                <Label>Protocol</Label>
                <select
                  value={form.protocol}
                  onChange={(e) => {
                    const proto = e.target.value
                    const port = proto === 'ssh' ? 22 : proto === 'rdp' ? 3389 : proto === 'vnc' ? 5900 : 22
                    setForm({ ...form, protocol: proto, target_port: port })
                  }}
                  className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                >
                  <option value="ssh">SSH</option>
                  <option value="rdp">RDP</option>
                  <option value="vnc">VNC</option>
                </select>
              </div>
              <div>
                <Label>Target Host</Label>
                <Input
                  value={form.target_host}
                  onChange={(e) => setForm({ ...form, target_host: e.target.value })}
                  placeholder="10.0.0.10"
                  required
                />
              </div>
              <div>
                <Label>Port</Label>
                <Input
                  type="number"
                  value={form.target_port}
                  onChange={(e) => setForm({ ...form, target_port: parseInt(e.target.value) || 22 })}
                  required
                />
              </div>
              <div>
                <Label>Username (optional)</Label>
                <Input
                  value={form.username}
                  onChange={(e) => setForm({ ...form, username: e.target.value })}
                  placeholder="support"
                />
              </div>
              <div>
                <Label>Duration (minutes)</Label>
                <Input
                  type="number"
                  value={form.duration_mins}
                  onChange={(e) => setForm({ ...form, duration_mins: parseInt(e.target.value) || 120 })}
                  min={5}
                  max={10080}
                  required
                />
                <p className="text-xs text-muted-foreground mt-1">
                  {form.duration_mins >= 60 ? `${Math.floor(form.duration_mins / 60)}h ${form.duration_mins % 60}m` : `${form.duration_mins}m`}
                </p>
              </div>
              <div>
                <Label>Max Uses (0 = unlimited)</Label>
                <Input
                  type="number"
                  value={form.max_uses}
                  onChange={(e) => setForm({ ...form, max_uses: parseInt(e.target.value) || 0 })}
                  min={0}
                />
              </div>
              <div className="col-span-2">
                <Label>Allowed IPs (comma-separated, optional)</Label>
                <Input
                  value={form.allowed_ips}
                  onChange={(e) => setForm({ ...form, allowed_ips: e.target.value })}
                  placeholder="1.2.3.4, 5.6.7.8"
                />
              </div>
              <div className="col-span-2 flex items-center gap-4">
                <div className="flex items-center gap-2">
                  <Switch
                    checked={form.notify_on_use}
                    onCheckedChange={(v) => setForm({ ...form, notify_on_use: v })}
                  />
                  <Label className="text-sm">Notify on use</Label>
                </div>
                {form.notify_on_use && (
                  <Input
                    value={form.notify_email}
                    onChange={(e) => setForm({ ...form, notify_email: e.target.value })}
                    placeholder="admin@company.com"
                    className="flex-1"
                  />
                )}
              </div>
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <Button type="button" variant="outline" onClick={() => { setCreateModal(false); resetForm() }}>
                Cancel
              </Button>
              <Button type="submit" disabled={createMutation.isPending}>
                {createMutation.isPending ? 'Creating...' : 'Create Access Link'}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* Revoke Confirmation */}
      <AlertDialog open={!!deleteTarget} onOpenChange={() => setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Revoke Temporary Access</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to revoke &quot;{deleteTarget?.name}&quot;? The link will no longer work.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="bg-red-600 hover:bg-red-700"
              onClick={() => deleteTarget && revokeMutation.mutate(deleteTarget.id)}
            >
              Revoke Access
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}

// ---------------------------------------------------------------------------
// "How this works" — behind the scenes for one resource.
//
// End users get a single Open/Connect button and never see the overlay. Admins
// need the opposite: the actual chain a connection traverses, which hop is
// missing, and what to do about it — without opening a terminal.
// ---------------------------------------------------------------------------

interface ChainHop {
  step: number
  title: string
  detail: string
  technical?: string
  status: 'ok' | 'missing' | 'unknown'
  fix?: string
}

interface ResourceDiagnosis {
  name: string
  reachable: boolean
  summary: string
  chain: ChainHop[]
}

function ExplainServiceDialog({ name, onClose }: { name: string | null; onClose: () => void }) {
  const { data, isLoading } = useQuery({
    queryKey: ['ziti-explain', name],
    queryFn: () =>
      api.get<ResourceDiagnosis>(
        `/api/v1/access/ziti/services/by-name/${encodeURIComponent(name!)}/explain`
      ),
    enabled: !!name,
  })

  return (
    <Dialog open={!!name} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>How “{name}” works</DialogTitle>
        </DialogHeader>

        {isLoading || !data ? (
          <p className="py-8 text-center text-muted-foreground">Checking…</p>
        ) : (
          <div className="space-y-4">
            <div
              className={`rounded-md p-3 text-sm ${
                data.reachable
                  ? 'bg-green-50 text-green-900 border border-green-200'
                  : 'bg-amber-50 text-amber-900 border border-amber-200'
              }`}
            >
              {data.summary}
            </div>

            <ol className="space-y-2">
              {data.chain.map((hop) => (
                <li key={hop.step} className="flex gap-3 rounded-md border p-3">
                  <div className="mt-0.5 shrink-0">
                    {hop.status === 'ok' ? (
                      <CheckCircle className="h-4 w-4 text-green-600" />
                    ) : (
                      <AlertTriangle className="h-4 w-4 text-amber-600" />
                    )}
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-medium">{hop.title}</p>
                    <p className="text-sm text-muted-foreground">{hop.detail}</p>
                    {hop.fix && (
                      <p className="mt-1 text-xs font-medium text-amber-700">→ {hop.fix}</p>
                    )}
                    {hop.technical && (
                      <code className="mt-1 inline-block rounded bg-muted px-1.5 py-0.5 text-[11px] text-muted-foreground">
                        {hop.technical}
                      </code>
                    )}
                  </div>
                </li>
              ))}
            </ol>
          </div>
        )}
      </DialogContent>
    </Dialog>
  )
}
