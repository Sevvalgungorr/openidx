import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { ShieldAlert, Plus, Trash2, MoreHorizontal, CheckCircle, Search as SearchIcon, Eye } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Badge } from '../components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table'
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '../components/ui/dialog'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/select'
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem,
  DropdownMenuSeparator, DropdownMenuTrigger,
} from '../components/ui/dropdown-menu'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'
import { QueryError } from '../components/query-error'
import { ConfirmAction } from '../components/confirm-action'

interface SecurityAlert {
  id: string
  user_id?: string
  alert_type: string
  severity: string
  status: string
  title: string
  description: string
  source_ip: string
  created_at: string
}

interface IPThreat {
  id: string
  ip_address: string
  threat_type: string
  reason: string
  blocked_until?: string
  permanent: boolean
  created_at: string
}

const severityBadge = (severity: string) => {
  const map: Record<string, string> = {
    critical: 'bg-red-100 text-red-800',
    high: 'bg-orange-100 text-orange-800',
    medium: 'bg-yellow-100 text-yellow-800',
    low: 'bg-blue-100 text-blue-800',
  }
  return map[severity] || 'bg-gray-100 text-gray-800'
}

const statusBadge = (status: string) => {
  const map: Record<string, string> = {
    open: 'bg-red-100 text-red-800',
    investigating: 'bg-yellow-100 text-yellow-800',
    resolved: 'bg-green-100 text-green-800',
    false_positive: 'bg-gray-100 text-gray-800',
  }
  return map[status] || 'bg-gray-100 text-gray-800'
}

export function SecurityAlertsPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [statusFilter, setStatusFilter] = useState('all')
  const [severityFilter, setSeverityFilter] = useState('all')
  const [detailAlert, setDetailAlert] = useState<SecurityAlert | null>(null)
  const [blockOpen, setBlockOpen] = useState(false)
  const [newIP, setNewIP] = useState({ ip_address: '', threat_type: 'manual', reason: '', permanent: false })

  const { data: alertsData, isLoading: alertsLoading, isError: alertsError, error: alertsErrorObj } = useQuery({
    queryKey: ['security-alerts', statusFilter, severityFilter],
    queryFn: () => {
      const params = new URLSearchParams()
      if (statusFilter !== 'all') params.set('status', statusFilter)
      if (severityFilter !== 'all') params.set('severity', severityFilter)
      return api.get<{ alerts: SecurityAlert[]; total: number }>(`/api/v1/security-alerts?${params.toString()}`)
    },
  })
  const alerts = alertsData?.alerts || []

  const { data: threatsData, isLoading: threatsLoading } = useQuery({
    queryKey: ['ip-threats'],
    queryFn: () => api.get<{ threats: IPThreat[]; total: number }>('/api/v1/ip-threats'),
  })
  const threats = threatsData?.threats || []

  const updateStatusMutation = useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) =>
      api.put(`/api/v1/security-alerts/${id}/status`, { status }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['security-alerts'] })
      toast({ title: 'Alert status updated' })
      setDetailAlert(null)
    },
  })

  const blockIPMutation = useMutation({
    mutationFn: (data: typeof newIP) => api.post('/api/v1/ip-threats', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ip-threats'] })
      toast({ title: 'IP address blocked' })
      setBlockOpen(false)
      setNewIP({ ip_address: '', threat_type: 'manual', reason: '', permanent: false })
    },
    onError: () => toast({ title: 'Failed to block IP', variant: 'destructive' }),
  })

  const removeIPMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/ip-threats/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ip-threats'] })
      toast({ title: 'IP threat removed' })
    },
  })

  const formatDate = (d: string) => new Date(d).toLocaleString()

  const openCount = alerts.filter(a => a.status === 'open').length
  const criticalCount = alerts.filter(a => a.severity === 'critical' && a.status === 'open').length

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Security Alerts</h1>
        <p className="text-muted-foreground">Monitor security threats and manage IP blocklists</p>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Open Alerts</CardTitle></CardHeader>
          <CardContent><div className="text-2xl font-bold">{openCount}</div></CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Critical</CardTitle></CardHeader>
          <CardContent><div className="text-2xl font-bold text-red-600">{criticalCount}</div></CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Blocked IPs</CardTitle></CardHeader>
          <CardContent><div className="text-2xl font-bold">{threats.length}</div></CardContent>
        </Card>
      </div>

      <Tabs defaultValue="alerts">
        <TabsList>
          <TabsTrigger value="alerts"><ShieldAlert className="mr-2 h-4 w-4" />Security Alerts</TabsTrigger>
          <TabsTrigger value="ip-threats">IP Threat List</TabsTrigger>
        </TabsList>

        <TabsContent value="alerts">
          <Card>
            <CardHeader>
              <div className="flex items-center gap-4">
                <Select value={statusFilter} onValueChange={setStatusFilter}>
                  <SelectTrigger className="w-[150px]"><SelectValue placeholder="Status" /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Status</SelectItem>
                    <SelectItem value="open">Open</SelectItem>
                    <SelectItem value="investigating">Investigating</SelectItem>
                    <SelectItem value="resolved">Resolved</SelectItem>
                    <SelectItem value="false_positive">False Positive</SelectItem>
                  </SelectContent>
                </Select>
                <Select value={severityFilter} onValueChange={setSeverityFilter}>
                  <SelectTrigger className="w-[150px]"><SelectValue placeholder="Severity" /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Severity</SelectItem>
                    <SelectItem value="critical">Critical</SelectItem>
                    <SelectItem value="high">High</SelectItem>
                    <SelectItem value="medium">Medium</SelectItem>
                    <SelectItem value="low">Low</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </CardHeader>
            <CardContent>
              {alertsLoading ? (
                <div className="flex flex-col items-center justify-center py-12">
                  <LoadingSpinner size="lg" />
                  <p className="mt-4 text-sm text-muted-foreground">Loading alerts...</p>
                </div>
              ) : alertsError ? (
                <QueryError error={alertsErrorObj} resource="security alerts" />
              ) : alerts.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                  <ShieldAlert className="h-12 w-12 text-muted-foreground/40 mb-3" />
                  <p className="font-medium">No alerts found</p>
                  <p className="text-sm">Security alerts will appear here when threats are detected</p>
                </div>
              ) : (
                <div className="rounded-md border">
                  <Table>
                    <TableHeader><TableRow>
                      <TableHead>Severity</TableHead><TableHead>Type</TableHead><TableHead>Title</TableHead>
                      <TableHead>Source IP</TableHead><TableHead>Status</TableHead><TableHead>Created</TableHead>
                      <TableHead className="w-[50px]"></TableHead>
                    </TableRow></TableHeader>
                    <TableBody>
                      {alerts.map(a => (
                        <TableRow key={a.id}>
                          <TableCell><Badge className={severityBadge(a.severity)}>{a.severity}</Badge></TableCell>
                          <TableCell><Badge variant="outline">{a.alert_type}</Badge></TableCell>
                          <TableCell className="font-medium">{a.title}</TableCell>
                          <TableCell className="font-mono text-sm">{a.source_ip}</TableCell>
                          <TableCell><Badge className={statusBadge(a.status)}>{a.status}</Badge></TableCell>
                          <TableCell className="text-sm text-muted-foreground">{formatDate(a.created_at)}</TableCell>
                          <TableCell>
                            <DropdownMenu>
                              <DropdownMenuTrigger asChild>
                                <Button variant="ghost" size="sm" className="h-8 w-8 p-0">
                                  <MoreHorizontal className="h-4 w-4" />
                                </Button>
                              </DropdownMenuTrigger>
                              <DropdownMenuContent align="end">
                                <DropdownMenuItem onClick={() => setDetailAlert(a)}>
                                  <Eye className="mr-2 h-4 w-4" />
                                  View Details
                                </DropdownMenuItem>
                                {a.status === 'open' && (
                                  <>
                                    <DropdownMenuSeparator />
                                    <DropdownMenuItem onClick={() => updateStatusMutation.mutate({ id: a.id, status: 'investigating' })}>
                                      <SearchIcon className="mr-2 h-4 w-4" />
                                      Investigating
                                    </DropdownMenuItem>
                                    <DropdownMenuItem onClick={() => updateStatusMutation.mutate({ id: a.id, status: 'resolved' })}>
                                      <CheckCircle className="mr-2 h-4 w-4 text-green-600" />
                                      Resolve
                                    </DropdownMenuItem>
                                    <DropdownMenuItem onClick={() => updateStatusMutation.mutate({ id: a.id, status: 'false_positive' })}>
                                      False Positive
                                    </DropdownMenuItem>
                                  </>
                                )}
                              </DropdownMenuContent>
                            </DropdownMenu>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="ip-threats">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle>IP Threat List</CardTitle>
                <Button onClick={() => setBlockOpen(true)}><Plus className="mr-2 h-4 w-4" />Block IP</Button>
              </div>
            </CardHeader>
            <CardContent>
              {threatsLoading ? (
                <div className="flex flex-col items-center justify-center py-12">
                  <LoadingSpinner size="lg" />
                  <p className="mt-4 text-sm text-muted-foreground">Loading threat list...</p>
                </div>
              ) : threats.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                  <ShieldAlert className="h-12 w-12 text-muted-foreground/40 mb-3" />
                  <p className="font-medium">No blocked IPs</p>
                  <p className="text-sm">Blocked IP addresses will appear here</p>
                </div>
              ) : (
                <Table>
                  <TableHeader><TableRow>
                    <TableHead>IP Address</TableHead><TableHead>Type</TableHead><TableHead>Reason</TableHead>
                    <TableHead>Permanent</TableHead><TableHead>Blocked Until</TableHead><TableHead>Actions</TableHead>
                  </TableRow></TableHeader>
                  <TableBody>
                    {threats.map(t => (
                      <TableRow key={t.id}>
                        <TableCell className="font-mono">{t.ip_address}</TableCell>
                        <TableCell><Badge variant="outline">{t.threat_type}</Badge></TableCell>
                        <TableCell>{t.reason}</TableCell>
                        <TableCell>{t.permanent ? <Badge>Permanent</Badge> : 'No'}</TableCell>
                        <TableCell>{t.blocked_until ? formatDate(t.blocked_until) : '-'}</TableCell>
                        <TableCell>
                          <ConfirmAction
                            title="Unblock this IP address?"
                            description={`This removes ${t.ip_address} from the IP blocklist. Traffic from this address will be allowed again. This cannot be undone (you would need to re-block it manually).`}
                            destructive
                            confirmLabel="Unblock"
                            onConfirm={() => removeIPMutation.mutateAsync(t.id)}
                          >
                            {(open) => (
                              <Button variant="ghost" size="sm" onClick={open}>
                                <Trash2 className="h-4 w-4 text-red-500" />
                              </Button>
                            )}
                          </ConfirmAction>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Alert Detail Dialog */}
      <Dialog open={!!detailAlert} onOpenChange={open => !open && setDetailAlert(null)}>
        <DialogContent>
          <DialogHeader><DialogTitle>{detailAlert?.title}</DialogTitle></DialogHeader>
          {detailAlert && (
            <div className="space-y-3 text-sm">
              <p>{detailAlert.description}</p>
              <div className="grid grid-cols-2 gap-2">
                <p><span className="font-medium">Type:</span> {detailAlert.alert_type}</p>
                <p><span className="font-medium">Severity:</span> {detailAlert.severity}</p>
                <p><span className="font-medium">Status:</span> {detailAlert.status}</p>
                <p><span className="font-medium">Source IP:</span> {detailAlert.source_ip}</p>
              </div>
              {detailAlert.status === 'open' && (
                <div className="flex gap-2 pt-2">
                  <Button size="sm" onClick={() => updateStatusMutation.mutate({ id: detailAlert.id, status: 'investigating' })}>Investigating</Button>
                  <Button size="sm" onClick={() => updateStatusMutation.mutate({ id: detailAlert.id, status: 'resolved' })}>Resolve</Button>
                  <Button size="sm" variant="outline" onClick={() => updateStatusMutation.mutate({ id: detailAlert.id, status: 'false_positive' })}>False Positive</Button>
                </div>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Block IP Dialog */}
      <Dialog open={blockOpen} onOpenChange={setBlockOpen}>
        <DialogContent>
          <DialogHeader><DialogTitle>Block IP Address</DialogTitle></DialogHeader>
          <div className="space-y-4">
            <div>
              <label className="text-sm font-medium">IP Address</label>
              <Input placeholder="192.168.1.1" value={newIP.ip_address}
                onChange={e => setNewIP(p => ({ ...p, ip_address: e.target.value }))} />
            </div>
            <div>
              <label className="text-sm font-medium">Threat Type</label>
              <Select value={newIP.threat_type} onValueChange={v => setNewIP(p => ({ ...p, threat_type: v }))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="manual">Manual Block</SelectItem>
                  <SelectItem value="brute_force">Brute Force</SelectItem>
                  <SelectItem value="suspicious">Suspicious Activity</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <label className="text-sm font-medium">Reason</label>
              <Input placeholder="Reason for blocking" value={newIP.reason}
                onChange={e => setNewIP(p => ({ ...p, reason: e.target.value }))} />
            </div>
            <label className="flex items-center gap-2 text-sm">
              <input type="checkbox" checked={newIP.permanent} onChange={e => setNewIP(p => ({ ...p, permanent: e.target.checked }))} />
              Permanent block
            </label>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setBlockOpen(false)}>Cancel</Button>
            <Button disabled={!newIP.ip_address || blockIPMutation.isPending}
              onClick={() => blockIPMutation.mutate(newIP)}>
              {blockIPMutation.isPending ? 'Blocking...' : 'Block IP'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
