import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Search, Smartphone, Tablet, Monitor, Server, CheckCircle, AlertTriangle,
  ShieldCheck, Trash2, QrCode, Copy, MoreHorizontal, Download,
} from 'lucide-react'
import { QRCodeCanvas } from 'qrcode.react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '../components/ui/table'
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from '../components/ui/dialog'
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '../components/ui/dropdown-menu'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '../components/ui/alert-dialog'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

/**
 * Agent fleet management page — surface for the endpoint-agent system shipped
 * in Phases 1, 3, and 4. Distinct from /devices, which is about browser-based
 * device-trust signals; this page lists native agents (Linux / macOS /
 * Windows Go agents + Android unified agent) and exposes the operations that
 * only apply to them (approval, revocation, enrollment-QR generation).
 */

interface AgentRecord {
  agent_id: string
  device_id: string
  hostname?: string
  status: string
  compliance_status: string
  compliance_score: number
  last_seen_at: string | null
  enrolled_at: string | null
  platform?: string
  form_factor?: string
}

interface QrPayloadResponse {
  id: string
  token: string
  expires_at: string
  server_url: string
  apk_url: string
  apk_checksum: string
  qr_payload: Record<string, unknown>
  qr_payload_json: string
}

interface AgentPostureRow {
  check_type: string
  status: string
  score: number
  severity: string
  message: string
  enforced: boolean
  enforcement_action: string
  reported_at: string
  expires_at: string
}

interface AgentPosture {
  agent_id: string
  compliant: boolean
  device_trusted: boolean
  tier: string
  results: AgentPostureRow[]
}

export function AgentFleetPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [search, setSearch] = useState('')
  const [platformFilter, setPlatformFilter] = useState<string>('all')
  const [confirmRevoke, setConfirmRevoke] = useState<AgentRecord | null>(null)
  const [qrOpen, setQrOpen] = useState(false)
  const [qrData, setQrData] = useState<QrPayloadResponse | null>(null)
  const [qrDescription, setQrDescription] = useState('')
  const [qrTTLMinutes, setQrTTLMinutes] = useState(60)
  const [postureAgent, setPostureAgent] = useState<AgentRecord | null>(null)

  const { data: postureData, isLoading: postureLoading } = useQuery({
    queryKey: ['agent-posture', postureAgent?.agent_id],
    queryFn: () => api.get<AgentPosture>(`/api/v1/access/agents/${postureAgent!.agent_id}/posture`),
    enabled: !!postureAgent,
  })

  const { data: agents = [], isLoading, isError, error } = useQuery({
    queryKey: ['agent-fleet'],
    queryFn: () => api.get<AgentRecord[]>('/api/v1/access/agents'),
  })

  const generateQrMutation = useMutation({
    mutationFn: () =>
      api.post<QrPayloadResponse>('/api/v1/access/agent/qr', {
        description: qrDescription || 'Admin-generated QR',
        ttl_minutes: qrTTLMinutes,
        // server_url + package_name + receiver_name default server-side.
      }),
    onSuccess: (data) => {
      setQrData(data)
      toast({ title: 'Enrollment QR generated' })
    },
    onError: () => toast({ title: 'Failed to generate QR', variant: 'destructive' }),
  })

  const approveMutation = useMutation({
    mutationFn: (agentId: string) =>
      api.post<{ status: string }>(`/api/v1/access/agents/${agentId}/approve`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['agent-fleet'] })
      toast({ title: 'Agent approved' })
    },
    onError: () => toast({ title: 'Failed to approve', variant: 'destructive' }),
  })

  const revokeMutation = useMutation({
    mutationFn: (agentId: string) =>
      api.delete<{ status: string }>(`/api/v1/access/agents/${agentId}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['agent-fleet'] })
      setConfirmRevoke(null)
      toast({ title: 'Agent revoked' })
    },
    onError: () => toast({ title: 'Failed to revoke', variant: 'destructive' }),
  })

  const filtered = agents.filter((a) => {
    const q = search.toLowerCase()
    const matchesSearch =
      a.agent_id.toLowerCase().includes(q) ||
      a.device_id.toLowerCase().includes(q) ||
      (a.hostname?.toLowerCase().includes(q) ?? false)
    const matchesPlatform = platformFilter === 'all' || a.platform === platformFilter
    return matchesSearch && matchesPlatform
  })

  const counts = {
    total: agents.length,
    active: agents.filter((a) => a.status === 'active').length,
    pending: agents.filter((a) => a.status === 'pending').length,
    nonCompliant: agents.filter((a) => a.compliance_status === 'non_compliant').length,
  }

  function openQrDialog() {
    setQrData(null)
    setQrDescription('')
    setQrTTLMinutes(60)
    setQrOpen(true)
  }

  function copyToClipboard(text: string) {
    navigator.clipboard.writeText(text)
    toast({ title: 'Copied to clipboard' })
  }

  return (
    <div className="space-y-6 p-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Agent Fleet</h1>
          <p className="text-muted-foreground">
            Endpoint agents enrolled in OpenIDX — desktop Go agent and Android unified agent.
          </p>
        </div>
        <Button onClick={openQrDialog}>
          <QrCode className="mr-2 h-4 w-4" />
          Generate Android enrollment QR
        </Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <SummaryCard label="Total agents" value={counts.total} icon={<Smartphone className="h-5 w-5" />} />
        <SummaryCard label="Active" value={counts.active} icon={<CheckCircle className="h-5 w-5 text-green-600" />} />
        <SummaryCard label="Pending approval" value={counts.pending} icon={<AlertTriangle className="h-5 w-5 text-amber-600" />} />
        <SummaryCard label="Non-compliant" value={counts.nonCompliant} icon={<ShieldCheck className="h-5 w-5 text-red-600" />} />
      </div>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-3">
          <CardTitle>Enrolled agents</CardTitle>
          <div className="flex items-center gap-2">
            <select
              value={platformFilter}
              onChange={(e) => setPlatformFilter(e.target.value)}
              className="h-9 rounded-md border border-input bg-background px-3 text-sm"
            >
              <option value="all">All platforms</option>
              <option value="linux">Linux</option>
              <option value="macos">macOS</option>
              <option value="windows">Windows</option>
              <option value="android">Android</option>
              <option value="ios">iOS</option>
            </select>
            <div className="relative">
              <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search hostname / agent / device id…"
                className="pl-8 w-64"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="py-12 flex justify-center"><LoadingSpinner /></div>
          ) : isError ? (
            <QueryError error={error} resource="agents" />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Agent</TableHead>
                  <TableHead>Platform</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Compliance</TableHead>
                  <TableHead>Last seen</TableHead>
                  <TableHead className="w-12" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.map((agent) => (
                  <TableRow key={agent.agent_id}>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <PlatformIcon platform={agent.platform} formFactor={agent.form_factor} />
                        <div>
                          <div className="font-medium">{agent.hostname || agent.agent_id}</div>
                          <div className="text-xs text-muted-foreground">
                            {agent.hostname ? agent.agent_id : agent.device_id}
                          </div>
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline">
                        {agent.platform ? `${agent.platform}${agent.form_factor ? ` · ${agent.form_factor}` : ''}` : 'unknown'}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <StatusBadge status={agent.status} />
                    </TableCell>
                    <TableCell>
                      <ComplianceBadge status={agent.compliance_status} score={agent.compliance_score} />
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {agent.last_seen_at ? new Date(agent.last_seen_at).toLocaleString() : '—'}
                    </TableCell>
                    <TableCell>
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" size="icon"><MoreHorizontal className="h-4 w-4" /></Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          {agent.status === 'pending' && (
                            <DropdownMenuItem onSelect={() => approveMutation.mutate(agent.agent_id)}>
                              Approve agent
                            </DropdownMenuItem>
                          )}
                          <DropdownMenuItem onSelect={() => setPostureAgent(agent)}>
                            View posture &amp; tier
                          </DropdownMenuItem>
                          <DropdownMenuItem onSelect={() => copyToClipboard(agent.agent_id)}>
                            <Copy className="mr-2 h-4 w-4" /> Copy agent ID
                          </DropdownMenuItem>
                          <DropdownMenuSeparator />
                          <DropdownMenuItem
                            className="text-destructive"
                            onSelect={() => setConfirmRevoke(agent)}
                          >
                            <Trash2 className="mr-2 h-4 w-4" /> Revoke
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </TableCell>
                  </TableRow>
                ))}
                {filtered.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={6} className="text-center py-8 text-muted-foreground">
                      No agents match the current filters.
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* QR generator dialog */}
      <Dialog open={qrOpen} onOpenChange={setQrOpen}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Generate Android enrollment QR</DialogTitle>
          </DialogHeader>
          {!qrData ? (
            <div className="space-y-4">
              <p className="text-sm text-muted-foreground">
                Factory-reset an Android device, tap the welcome screen 6 times, scan
                the QR. The device installs the OpenIDX agent as Device Owner.
              </p>
              <div>
                <label className="text-sm font-medium">Description</label>
                <Input
                  placeholder="e.g. front-desk-kiosks"
                  value={qrDescription}
                  onChange={(e) => setQrDescription(e.target.value)}
                />
              </div>
              <div>
                <label className="text-sm font-medium">Expires in (minutes)</label>
                <Input
                  type="number"
                  min={1}
                  max={1440}
                  value={qrTTLMinutes}
                  onChange={(e) => setQrTTLMinutes(parseInt(e.target.value, 10) || 60)}
                />
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => setQrOpen(false)}>Cancel</Button>
                <Button
                  onClick={() => generateQrMutation.mutate()}
                  disabled={generateQrMutation.isPending}
                >
                  {generateQrMutation.isPending ? 'Generating…' : 'Generate'}
                </Button>
              </DialogFooter>
            </div>
          ) : (
            <div className="space-y-4">
              <div className="flex justify-center bg-white p-4 rounded">
                <QRCodeCanvas value={qrData.qr_payload_json} size={280} level="M" includeMargin />
              </div>
              <div className="grid grid-cols-2 gap-3 text-sm">
                <div>
                  <div className="text-muted-foreground">Token</div>
                  <div className="flex items-center gap-1 font-mono text-xs">
                    <span className="truncate">{qrData.token}</span>
                    <Button variant="ghost" size="icon" onClick={() => copyToClipboard(qrData.token)}>
                      <Copy className="h-3 w-3" />
                    </Button>
                  </div>
                </div>
                <div>
                  <div className="text-muted-foreground">Expires</div>
                  <div>{new Date(qrData.expires_at).toLocaleString()}</div>
                </div>
                <div className="col-span-2">
                  <div className="text-muted-foreground">APK</div>
                  <a
                    href={qrData.apk_url}
                    className="inline-flex items-center gap-1 text-primary hover:underline"
                    download
                  >
                    <Download className="h-4 w-4" /> Download APK ({qrData.apk_checksum ? qrData.apk_checksum.slice(0, 12) + '…' : 'no checksum'})
                  </a>
                </div>
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => copyToClipboard(qrData.qr_payload_json)}>
                  Copy JSON
                </Button>
                <Button onClick={() => setQrOpen(false)}>Done</Button>
              </DialogFooter>
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Posture & tier detail dialog */}
      <Dialog open={!!postureAgent} onOpenChange={(open) => !open && setPostureAgent(null)}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Device posture &amp; Ziti tier</DialogTitle>
          </DialogHeader>
          {postureLoading ? (
            <div className="py-8 text-center text-muted-foreground">Loading…</div>
          ) : (
            <div className="space-y-4">
              <div className="flex flex-wrap items-center gap-2 text-sm">
                <Badge variant={postureData?.compliant ? 'default' : 'destructive'}>
                  {postureData?.compliant ? 'Compliant' : 'Non-compliant'}
                </Badge>
                <Badge variant={postureData?.device_trusted ? 'default' : 'outline'}>
                  {postureData?.device_trusted ? 'Tier 2 · device-trusted' : 'Tier 1 · minimum access'}
                </Badge>
                <span className="text-muted-foreground font-mono text-xs">{postureAgent?.agent_id}</span>
              </div>
              {!postureData?.device_trusted && (
                <p className="text-xs text-muted-foreground">
                  Tier 2 (remote/PAM + admin surfaces) is granted only while the device reports
                  compliant posture. Tier 1 devices reach self-service + console only.
                </p>
              )}
              <div className="rounded-md border divide-y">
                {(postureData?.results ?? []).map((r) => (
                  <div key={r.check_type} className="flex items-start gap-3 p-3 text-sm">
                    <span>
                      {r.status === 'pass' ? '🟢' : r.status === 'fail' ? '🔴' : '⚪'}
                    </span>
                    <div className="flex-1">
                      <div className="font-medium">
                        {r.check_type}
                        <Badge variant="outline" className="ml-2 text-xs">{r.severity}</Badge>
                        {r.enforced && r.enforcement_action !== 'none' && (
                          <Badge variant="destructive" className="ml-1 text-xs">{r.enforcement_action}</Badge>
                        )}
                      </div>
                      {r.message && <div className="text-xs text-muted-foreground mt-0.5">{r.message}</div>}
                      <div className="text-xs text-muted-foreground mt-0.5">
                        reported {r.reported_at ? new Date(r.reported_at).toLocaleString() : '—'}
                      </div>
                    </div>
                  </div>
                ))}
                {(postureData?.results ?? []).length === 0 && (
                  <div className="p-6 text-center text-muted-foreground text-sm">
                    No posture reports yet from this device.
                  </div>
                )}
              </div>
              <DialogFooter>
                <Button onClick={() => setPostureAgent(null)}>Close</Button>
              </DialogFooter>
            </div>
          )}
        </DialogContent>
      </Dialog>

      <AlertDialog open={!!confirmRevoke} onOpenChange={(open) => !open && setConfirmRevoke(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Revoke agent?</AlertDialogTitle>
            <AlertDialogDescription>
              {confirmRevoke?.agent_id} will lose Ziti network access immediately and
              its identity will be removed. This is reversible only by re-enrolling
              the device.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => confirmRevoke && revokeMutation.mutate(confirmRevoke.agent_id)}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              Revoke
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}

function SummaryCard({ label, value, icon }: { label: string; value: number; icon: React.ReactNode }) {
  return (
    <Card>
      <CardContent className="pt-6 flex items-center justify-between">
        <div>
          <div className="text-sm text-muted-foreground">{label}</div>
          <div className="text-2xl font-semibold">{value}</div>
        </div>
        {icon}
      </CardContent>
    </Card>
  )
}

function PlatformIcon({ platform, formFactor }: { platform?: string; formFactor?: string }) {
  const cls = 'h-4 w-4 text-muted-foreground'
  if (platform === 'android' || platform === 'ios') {
    return formFactor === 'tablet' ? <Tablet className={cls} /> : <Smartphone className={cls} />
  }
  if (platform === 'linux' && formFactor === 'server') return <Server className={cls} />
  return <Monitor className={cls} />
}

function StatusBadge({ status }: { status: string }) {
  const variant = status === 'active' ? 'success'
    : status === 'pending' ? 'warning'
    : status === 'revoked' ? 'destructive' : 'secondary'
  return <Badge variant={variant as any}>{status}</Badge>
}

function ComplianceBadge({ status, score }: { status: string; score: number }) {
  const pct = Math.round((score || 0) * 100)
  const variant = status === 'compliant' ? 'success'
    : status === 'grace_period' ? 'warning'
    : status === 'non_compliant' ? 'destructive' : 'secondary'
  return (
    <div className="flex items-center gap-2">
      <Badge variant={variant as any}>{status}</Badge>
      <span className="text-xs text-muted-foreground">{pct}%</span>
    </div>
  )
}
