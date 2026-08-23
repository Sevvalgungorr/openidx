import { useState } from 'react'
import { complianceTooltip, formatCompliancePercent } from '../lib/compliance'
import { useParams, Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  ArrowLeft, Shield, Key, Network, Server, Laptop, Clock,
  Zap, AlertTriangle, Activity, Lock, Fingerprint, RefreshCw,
  ShieldCheck, ShieldX, ShieldAlert, Link2, MonitorSmartphone, Ban,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Button } from '../components/ui/button'
import { Badge } from '../components/ui/badge'
import { Checkbox } from '../components/ui/checkbox'
import { Textarea } from '../components/ui/textarea'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '../components/ui/dialog'
import { api } from '../lib/api'
import { ConfirmAction } from '../components/confirm-action'
import { QueryError } from '../components/query-error'
import { useToast } from '../hooks/use-toast'

interface NamedRef { id: string; name: string }

interface VaultGrant {
  secret_id: string
  secret_name: string
  secret_type: string
  actions: string[]
  via: string
  expires_at?: string
}

interface Checkout { id: string; secret_name: string; mode: string; leased_at: string; expires_at?: string }
interface JITGrant { id: string; role_name: string; expires_at: string }
interface PrivSession { id: string; route_name: string; protocol: string; started_at: string; over_ziti: boolean }
interface Device {
  agent_id: string
  platform: string
  status: string
  compliance_status: string
  ziti_identity_id?: string
  last_seen_at?: string
}
interface DialPolicy { name: string; services: string[] }
interface AuditEvent { source: string; event_type: string; actor_ip?: string; created_at: string }

interface AccessMap {
  user: {
    id: string
    username: string
    email: string
    enabled: boolean
    created_at: string
    last_login_at?: string
  }
  iam: {
    roles: NamedRef[]
    groups: NamedRef[]
    active_sessions: number
    active_api_keys: number
    pending_access_requests: number
  }
  pam: {
    vault_grants: VaultGrant[]
    active_checkouts: Checkout[]
    active_jit_grants: JITGrant[]
    active_sessions: PrivSession[]
    sessions_30d: number
    pending_session_requests: number
    pending_credential_requests: number
  }
  ziti: {
    identity: { ziti_id: string; name: string; enrolled: boolean; attributes: string[] } | null
    devices: Device[]
    dial_policies: DialPolicy[]
    reachable_services: string[]
    trusted_device: boolean
  }
  activity: AuditEvent[]
  generated_at: string
}

interface DevicePostureSummary {
  check_type: string
  status: string
  severity: string
  reported_at?: string
}

interface DeviceIAM {
  known_device_id: string
  fingerprint: string
  name: string
  device_type: string
  ip_address?: string
  trusted: boolean
  last_seen_at?: string
}

interface DeviceZiti {
  agent_id: string
  ziti_identity_id?: string
  status: string
  platform?: string
  management_mode?: string
  compliance_status: string
  compliance_score: number
  posture: DevicePostureSummary[]
  last_seen_at?: string
}

interface UserDeviceEntry {
  source: 'linked' | 'iam' | 'ziti'
  iam?: DeviceIAM
  ziti?: DeviceZiti
}

interface UserDevicesResponse {
  user_id: string
  username: string
  devices: UserDeviceEntry[]
  generated_at: string
}

interface DeviceRevokeResult {
  agent_id: string
  agent_revoked: boolean
  ziti_identity_deleted: boolean
  ziti_edge_sessions_terminated: number
  ziti_api_sessions_terminated: number
  known_device_untrusted: boolean
  warnings?: string[]
}

interface KillSwitchResult {
  user_id: string
  username: string
  user_disabled: boolean
  iam_sessions_revoked: number
  iam_api_keys_revoked: number
  pam_checkouts_revoked: number
  pam_vault_grants_expired: number
  pam_jit_grants_revoked: number
  pam_privileged_sessions_terminated: number
  ziti_edge_sessions_terminated: number
  ziti_api_sessions_terminated: number
  ziti_identity_deleted: boolean
  ziti_controller_online: boolean
  warnings?: string[]
}

const sourceBadgeClass: Record<string, string> = {
  openidx: 'bg-blue-50 text-blue-700 border-blue-200',
  ziti: 'bg-green-50 text-green-700 border-green-200',
  guacamole: 'bg-purple-50 text-purple-700 border-purple-200',
}

function complianceBadge(status: string) {
  switch (status) {
    case 'compliant':
      return { cls: 'bg-green-50 text-green-700 border-green-200', Icon: ShieldCheck }
    case 'non_compliant':
      return { cls: 'bg-red-50 text-red-700 border-red-200', Icon: ShieldX }
    case 'grace_period':
      return { cls: 'bg-yellow-50 text-yellow-700 border-yellow-200', Icon: ShieldAlert }
    default:
      return { cls: 'bg-slate-50 text-slate-600 border-slate-200', Icon: Shield }
  }
}

function deviceSourceLabel(source: string): { label: string; cls: string } {
  switch (source) {
    case 'linked':
      return { label: 'IAM + Ziti', cls: 'bg-blue-50 text-blue-700 border-blue-200' }
    case 'iam':
      return { label: 'IAM only', cls: 'bg-slate-50 text-slate-600 border-slate-200' }
    default:
      return { label: 'Ziti only', cls: 'bg-green-50 text-green-700 border-green-200' }
  }
}

export function UserAccess360Page() {
  const { id } = useParams<{ id: string }>()
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [killOpen, setKillOpen] = useState(false)
  const [reason, setReason] = useState('')
  const [disableUser, setDisableUser] = useState(false)

  const { data: map, isLoading, isError, error, refetch, isFetching } = useQuery({
    queryKey: ['user-access-map', id],
    queryFn: () => api.get<AccessMap>(`/api/v1/access/users/${id}/access-map`),
    enabled: !!id,
  })

  const { data: devicesData } = useQuery({
    queryKey: ['user-devices', id],
    queryFn: () => api.get<UserDevicesResponse>(`/api/v1/access/users/${id}/devices`),
    enabled: !!id,
  })

  const revokeDeviceMutation = useMutation({
    mutationFn: ({ agentId, reason }: { agentId: string; reason: string }) =>
      api.post<DeviceRevokeResult>(`/api/v1/access/users/${id}/devices/${agentId}/revoke`, { reason }),
    onSuccess: (res) => {
      queryClient.invalidateQueries({ queryKey: ['user-devices', id] })
      queryClient.invalidateQueries({ queryKey: ['user-access-map', id] })
      const net = res.ziti_edge_sessions_terminated + res.ziti_api_sessions_terminated
      toast({
        title: 'Device revoked',
        description: `Severed ${net} network session(s)${res.ziti_identity_deleted ? ', deleted Ziti identity' : ''}${res.known_device_untrusted ? ', untrusted the device' : ''}.`,
      })
    },
    onError: () => toast({ title: 'Device revoke failed', variant: 'destructive' }),
  })

  const killMutation = useMutation({
    mutationFn: (body: { reason: string; disable_user: boolean }) =>
      api.post<KillSwitchResult>(`/api/v1/access/users/${id}/kill-switch`, body),
    onSuccess: (res) => {
      queryClient.invalidateQueries({ queryKey: ['user-access-map', id] })
      queryClient.invalidateQueries({ queryKey: ['users'] })
      const parts = [
        `${res.iam_sessions_revoked} sessions`,
        `${res.pam_checkouts_revoked} checkouts`,
        `${res.pam_jit_grants_revoked} JIT grants`,
        `${res.pam_privileged_sessions_terminated} privileged sessions`,
        `${res.ziti_edge_sessions_terminated + res.ziti_api_sessions_terminated} network sessions`,
      ]
      toast({
        title: res.user_disabled ? 'Kill switch executed — account disabled' : 'Kill switch executed',
        description: `Severed: ${parts.join(', ')}${res.warnings?.length ? ` (${res.warnings.length} warnings)` : ''}`,
      })
      setKillOpen(false)
      setReason('')
      setDisableUser(false)
    },
    onError: () => toast({ title: 'Kill switch failed', variant: 'destructive' }),
  })

  if (isError) {
    return (
      <div className="space-y-6">
        <div className="flex items-center gap-3">
          <Link to="/users"><Button variant="ghost" size="icon"><ArrowLeft className="h-4 w-4" /></Button></Link>
          <h1 className="text-3xl font-bold tracking-tight">Access 360</h1>
        </div>
        <QueryError error={error} resource="the user access map" />
      </div>
    )
  }

  if (isLoading || !map) {
    return (
      <div className="space-y-6">
        <div className="flex items-center gap-3">
          <Link to="/users"><Button variant="ghost" size="icon"><ArrowLeft className="h-4 w-4" /></Button></Link>
          <h1 className="text-3xl font-bold tracking-tight">Access 360</h1>
        </div>
        <p className="text-muted-foreground">{isLoading ? 'Correlating access across IAM, PAM and Ziti…' : 'User not found'}</p>
      </div>
    )
  }

  const { user, iam, pam, ziti, activity } = map
  const liveTotal =
    iam.active_sessions + pam.active_checkouts.length + pam.active_jit_grants.length + pam.active_sessions.length

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-3">
          <Link to="/users"><Button variant="ghost" size="icon"><ArrowLeft className="h-4 w-4" /></Button></Link>
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-3xl font-bold tracking-tight">{user.username}</h1>
              <Badge className={user.enabled ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}>
                {user.enabled ? 'Active' : 'Disabled'}
              </Badge>
            </div>
            <p className="text-muted-foreground">
              {user.email} · One view of everything this user can reach across IAM, PAM and the Ziti network
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isFetching}>
            <RefreshCw className={`mr-2 h-4 w-4 ${isFetching ? 'animate-spin' : ''}`} />Refresh
          </Button>
          <Button variant="destructive" onClick={() => setKillOpen(true)}>
            <Zap className="mr-2 h-4 w-4" />Kill Switch
          </Button>
        </div>
      </div>

      {/* Live access summary */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-blue-100 rounded-lg"><Shield className="h-6 w-6 text-primary" /></div>
              <div>
                <p className="text-2xl font-bold">{iam.active_sessions}</p>
                <p className="text-sm text-muted-foreground">IAM Sessions</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-amber-100 rounded-lg"><Key className="h-6 w-6 text-amber-600" /></div>
              <div>
                <p className="text-2xl font-bold">{pam.active_checkouts.length}</p>
                <p className="text-sm text-muted-foreground">Checkouts</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-purple-100 rounded-lg"><Lock className="h-6 w-6 text-purple-600" /></div>
              <div>
                <p className="text-2xl font-bold">{pam.active_sessions.length}</p>
                <p className="text-sm text-muted-foreground">Priv. Sessions</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-green-100 rounded-lg"><Network className="h-6 w-6 text-green-600" /></div>
              <div>
                <p className="text-2xl font-bold">{ziti.reachable_services.length}</p>
                <p className="text-sm text-muted-foreground">Network Services</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-slate-100 rounded-lg"><Laptop className="h-6 w-6 text-slate-600" /></div>
              <div>
                <p className="text-2xl font-bold">{ziti.devices.length}</p>
                <p className="text-sm text-muted-foreground">Devices</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Three pillars */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* IAM */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-lg">
              <Shield className="h-5 w-5 text-primary" />Identity (IAM)
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <p className="text-sm font-medium mb-2">Roles ({iam.roles.length})</p>
              <div className="flex flex-wrap gap-1.5">
                {iam.roles.length > 0
                  ? iam.roles.map(r => <Badge key={r.id} variant="outline" className="bg-blue-50">{r.name}</Badge>)
                  : <span className="text-sm text-muted-foreground">None</span>}
              </div>
            </div>
            <div>
              <p className="text-sm font-medium mb-2">Groups ({iam.groups.length})</p>
              <div className="flex flex-wrap gap-1.5">
                {iam.groups.length > 0
                  ? iam.groups.map(g => <Badge key={g.id} variant="outline" className="bg-green-50">{g.name}</Badge>)
                  : <span className="text-sm text-muted-foreground">None</span>}
              </div>
              <p className="text-xs text-muted-foreground mt-1.5">
                Groups become Ziti role attributes via the identity sync
              </p>
            </div>
            <div className="grid grid-cols-3 gap-2 text-center border rounded-lg p-2">
              <div>
                <p className="text-lg font-semibold">{iam.active_sessions}</p>
                <p className="text-xs text-muted-foreground">Sessions</p>
              </div>
              <div>
                <p className="text-lg font-semibold">{iam.active_api_keys}</p>
                <p className="text-xs text-muted-foreground">API Keys</p>
              </div>
              <div>
                <p className="text-lg font-semibold">{iam.pending_access_requests}</p>
                <p className="text-xs text-muted-foreground">Pending Req.</p>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* PAM */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-lg">
              <Key className="h-5 w-5 text-amber-600" />Privileged (PAM)
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <p className="text-sm font-medium mb-2">Vault Access ({pam.vault_grants.length})</p>
              {pam.vault_grants.length > 0 ? (
                <div className="space-y-1.5 max-h-40 overflow-y-auto">
                  {pam.vault_grants.map((g, i) => (
                    <div key={`${g.secret_id}-${g.via}-${i}`} className="flex items-center justify-between p-2 rounded bg-muted/50 text-sm">
                      <span className="font-medium truncate">{g.secret_name}</span>
                      <span className="flex gap-1 shrink-0">
                        <Badge variant="secondary" className="text-xs">{g.via}</Badge>
                        {g.actions.includes('reveal') && <Badge variant="outline" className="text-xs text-amber-700">reveal</Badge>}
                      </span>
                    </div>
                  ))}
                </div>
              ) : <span className="text-sm text-muted-foreground">No vault grants</span>}
            </div>
            <div>
              <p className="text-sm font-medium mb-2">Active Checkouts ({pam.active_checkouts.length})</p>
              {pam.active_checkouts.length > 0 ? (
                <div className="space-y-1.5">
                  {pam.active_checkouts.map(co => (
                    <div key={co.id} className="flex items-center justify-between p-2 rounded bg-amber-50 text-sm">
                      <span className="font-medium">{co.secret_name}</span>
                      <span className="text-xs text-muted-foreground">
                        {co.expires_at ? `expires ${new Date(co.expires_at).toLocaleTimeString()}` : co.mode}
                      </span>
                    </div>
                  ))}
                </div>
              ) : <span className="text-sm text-muted-foreground">None</span>}
            </div>
            <div>
              <p className="text-sm font-medium mb-2">JIT Elevations ({pam.active_jit_grants.length})</p>
              {pam.active_jit_grants.length > 0 ? (
                <div className="space-y-1.5">
                  {pam.active_jit_grants.map(j => (
                    <div key={j.id} className="flex items-center justify-between p-2 rounded bg-muted/50 text-sm">
                      <span className="font-medium">{j.role_name}</span>
                      <span className="text-xs text-muted-foreground flex items-center gap-1">
                        <Clock className="h-3 w-3" />{new Date(j.expires_at).toLocaleString()}
                      </span>
                    </div>
                  ))}
                </div>
              ) : <span className="text-sm text-muted-foreground">None</span>}
            </div>
            <div>
              <p className="text-sm font-medium mb-2">Live Privileged Sessions ({pam.active_sessions.length})</p>
              {pam.active_sessions.length > 0 ? (
                <div className="space-y-1.5">
                  {pam.active_sessions.map(ps => (
                    <div key={ps.id} className="flex items-center justify-between p-2 rounded bg-purple-50 text-sm">
                      <span className="font-medium truncate">{ps.route_name || ps.protocol || 'session'}</span>
                      {ps.over_ziti && (
                        <Badge variant="outline" className="text-xs bg-green-50 text-green-700 border-green-200">
                          <Network className="mr-1 h-3 w-3" />over Ziti
                        </Badge>
                      )}
                    </div>
                  ))}
                </div>
              ) : <span className="text-sm text-muted-foreground">None</span>}
              <p className="text-xs text-muted-foreground mt-1.5">{pam.sessions_30d} sessions in the last 30 days</p>
            </div>
          </CardContent>
        </Card>

        {/* Ziti */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-lg">
              <Network className="h-5 w-5 text-green-600" />Network (Ziti)
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <p className="text-sm font-medium mb-2">Ziti Identity</p>
              {ziti.identity ? (
                <div className="p-2 rounded bg-muted/50 space-y-1.5">
                  <div className="flex items-center justify-between text-sm">
                    <span className="font-medium truncate">{ziti.identity.name}</span>
                    <Badge variant="outline" className={ziti.identity.enrolled
                      ? 'bg-green-50 text-green-700 border-green-200'
                      : 'bg-yellow-50 text-yellow-700 border-yellow-200'}>
                      {ziti.identity.enrolled ? 'Enrolled' : 'Awaiting enrollment'}
                    </Badge>
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {ziti.identity.attributes.map(a => (
                      <Badge key={a} variant="secondary" className="text-xs">#{a}</Badge>
                    ))}
                    {ziti.trusted_device && (
                      <Badge variant="outline" className="text-xs bg-blue-50 text-blue-700 border-blue-200">
                        <Fingerprint className="mr-1 h-3 w-3" />trusted device
                      </Badge>
                    )}
                  </div>
                </div>
              ) : (
                <span className="text-sm text-muted-foreground">Not synced to Ziti (sync runs every 30s for enabled users)</span>
              )}
            </div>
            <div>
              <p className="text-sm font-medium mb-2">Reachable Services ({ziti.reachable_services.length})</p>
              {ziti.reachable_services.length > 0 ? (
                <div className="flex flex-wrap gap-1.5 max-h-28 overflow-y-auto">
                  {ziti.reachable_services.map(svc => (
                    <Badge key={svc} variant="outline" className="bg-green-50 text-green-800">
                      <Server className="mr-1 h-3 w-3" />{svc}
                    </Badge>
                  ))}
                </div>
              ) : <span className="text-sm text-muted-foreground">No dial policies match this identity</span>}
              {ziti.dial_policies.length > 0 && (
                <p className="text-xs text-muted-foreground mt-1.5">
                  Via {ziti.dial_policies.length} dial {ziti.dial_policies.length === 1 ? 'policy' : 'policies'}:{' '}
                  {ziti.dial_policies.map(p => p.name).join(', ')}
                </p>
              )}
            </div>
            <div>
              <p className="text-sm font-medium mb-2">Devices ({ziti.devices.length})</p>
              {ziti.devices.length > 0 ? (
                <div className="space-y-1.5 max-h-36 overflow-y-auto">
                  {ziti.devices.map(d => (
                    <div key={d.agent_id} className="flex items-center justify-between p-2 rounded bg-muted/50 text-sm">
                      <span className="flex items-center gap-2 min-w-0">
                        <Laptop className="h-3.5 w-3.5 shrink-0" />
                        <span className="font-medium truncate">{d.agent_id}</span>
                      </span>
                      <span className="flex gap-1 shrink-0">
                        {d.platform && <Badge variant="secondary" className="text-xs">{d.platform}</Badge>}
                        <Badge variant="outline" className={`text-xs ${d.compliance_status === 'compliant'
                          ? 'bg-green-50 text-green-700' : 'bg-yellow-50 text-yellow-700'}`}>
                          {d.compliance_status}
                        </Badge>
                      </span>
                    </div>
                  ))}
                </div>
              ) : <span className="text-sm text-muted-foreground">No enrolled agents</span>}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Cross-pillar devices */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-lg">
            <MonitorSmartphone className="h-5 w-5" />Devices — IAM Trust ⇄ Ziti Compliance
          </CardTitle>
        </CardHeader>
        <CardContent>
          {!devicesData?.devices?.length ? (
            <p className="text-center py-6 text-muted-foreground">No devices registered for this user</p>
          ) : (
            <div className="space-y-3">
              {devicesData.devices.map((d, i) => {
                const comp = d.ziti ? complianceBadge(d.ziti.compliance_status) : null
                const src = deviceSourceLabel(d.source)
                const failing = (d.ziti?.posture || []).filter(p => p.status !== 'pass')
                return (
                  <div key={i} className="flex items-start justify-between gap-3 p-3 border rounded-lg">
                    <div className="min-w-0 space-y-1.5">
                      <div className="flex items-center gap-2 flex-wrap">
                        <Laptop className="h-4 w-4 shrink-0" />
                        <span className="font-medium truncate">
                          {d.iam?.name || d.ziti?.agent_id || 'device'}
                        </span>
                        <Badge variant="outline" className={`text-xs ${src.cls}`}>
                          {d.source === 'linked' && <Link2 className="mr-1 h-3 w-3" />}{src.label}
                        </Badge>
                        {d.iam && (
                          <Badge variant="outline" className={`text-xs ${d.iam.trusted
                            ? 'bg-green-50 text-green-700 border-green-200'
                            : 'bg-slate-50 text-slate-600 border-slate-200'}`}>
                            {d.iam.trusted ? <ShieldCheck className="mr-1 h-3 w-3" /> : <Shield className="mr-1 h-3 w-3" />}
                            {d.iam.trusted ? 'Trusted' : 'Untrusted'}
                          </Badge>
                        )}
                        {comp && d.ziti && (
                          <Badge variant="outline" className={`text-xs ${comp.cls}`}>
                            <comp.Icon className="mr-1 h-3 w-3" />
                            {d.ziti.compliance_status.replace('_', ' ')}
                          </Badge>
                        )}
                      </div>
                      <div className="text-xs text-muted-foreground flex flex-wrap gap-x-3 gap-y-0.5">
                        {d.ziti?.platform && <span>{d.ziti.platform}</span>}
                        {d.ziti?.management_mode && <span>{d.ziti.management_mode}</span>}
                        {d.iam?.ip_address && <span>{d.iam.ip_address}</span>}
                        {d.ziti && <span title={complianceTooltip(d.ziti.compliance_status)}>score {formatCompliancePercent(d.ziti.compliance_status, d.ziti.compliance_score)}</span>}
                        {d.ziti?.status && d.ziti.status !== 'active' && (
                          <span className="text-red-600">agent {d.ziti.status}</span>
                        )}
                      </div>
                      {failing.length > 0 && (
                        <div className="flex flex-wrap gap-1">
                          {failing.map((p, j) => (
                            <Badge key={j} variant="outline" className="text-xs bg-red-50 text-red-700 border-red-200">
                              {p.check_type}: {p.status}
                            </Badge>
                          ))}
                        </div>
                      )}
                    </div>
                    {d.ziti && d.ziti.status !== 'revoked' && (
                      <ConfirmAction
                        title="Revoke this device's access?"
                        description="This severs the device's Ziti network sessions and revokes its access. The user may need to re-enroll the device to regain access."
                        destructive
                        requireReason
                        confirmLabel="Revoke"
                        onConfirm={(reason) => revokeDeviceMutation.mutateAsync({ agentId: d.ziti!.agent_id, reason: reason || '' })}
                      >
                        {(open) => (
                          <Button variant="outline" size="sm" className="shrink-0 text-red-600 hover:text-red-700"
                            disabled={revokeDeviceMutation.isPending}
                            onClick={open}>
                            <Ban className="mr-1 h-3.5 w-3.5" />Revoke
                          </Button>
                        )}
                      </ConfirmAction>
                    )}
                  </div>
                )
              })}
            </div>
          )}
          <p className="text-xs text-muted-foreground mt-3">
            Devices marked <span className="font-medium">IAM + Ziti</span> are the same physical machine seen by both
            pillars (agent enrolled while signed in). Revoke severs the device's Ziti sessions, deletes its network
            identity, and untrusts it in IAM.
          </p>
        </CardContent>
      </Card>

      {/* Cross-pillar activity */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-lg">
            <Activity className="h-5 w-5" />Recent Activity Across Pillars
          </CardTitle>
        </CardHeader>
        <CardContent>
          {activity.length === 0 ? (
            <p className="text-center py-6 text-muted-foreground">No unified audit events for this user yet</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Source</TableHead>
                  <TableHead>Event</TableHead>
                  <TableHead>IP</TableHead>
                  <TableHead>When</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {activity.map((e, i) => (
                  <TableRow key={i}>
                    <TableCell>
                      <Badge variant="outline" className={sourceBadgeClass[e.source] || ''}>{e.source}</Badge>
                    </TableCell>
                    <TableCell className="font-medium">{e.event_type}</TableCell>
                    <TableCell className="text-muted-foreground">{e.actor_ip || '—'}</TableCell>
                    <TableCell>{new Date(e.created_at).toLocaleString()}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Kill switch dialog */}
      <Dialog open={killOpen} onOpenChange={setKillOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-red-500" />Kill Switch — {user.username}
            </DialogTitle>
            <DialogDescription>
              Severs this user's live access across all three pillars at once: IAM sessions are revoked,
              vault checkouts and JIT elevations are revoked, live privileged sessions are terminated,
              and Ziti network sessions are severed on the controller.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="p-3 rounded-lg bg-red-50 text-sm text-red-800">
              Will sever now: {iam.active_sessions} IAM sessions, {pam.active_checkouts.length} checkouts,{' '}
              {pam.active_jit_grants.length} JIT grants, {pam.active_sessions.length} privileged sessions
              {ziti.identity ? `, and all Ziti sessions for ${ziti.identity.name}` : ''}.
              {liveTotal === 0 && ' (nothing live right now — still safe to run)'}
            </div>
            <div>
              <label className="text-sm font-medium">Reason</label>
              <Textarea value={reason} onChange={e => setReason(e.target.value)} rows={2}
                placeholder="Why is this user's access being severed?" className="mt-1" />
            </div>
            <label className="flex items-center gap-2 text-sm">
              <Checkbox checked={disableUser} onCheckedChange={v => setDisableUser(v === true)} />
              <span>
                Also <span className="font-medium">disable the account</span> and delete the Ziti identity
                (full deprovision, blocks new logins)
              </span>
            </label>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setKillOpen(false)}>Cancel</Button>
            <Button variant="destructive" disabled={killMutation.isPending}
              onClick={() => killMutation.mutate({ reason, disable_user: disableUser })}>
              <Zap className="mr-2 h-4 w-4" />
              {killMutation.isPending ? 'Severing…' : 'Sever All Access'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
