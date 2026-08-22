import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Shield, Users, Key, Clock, CheckCircle, XCircle, Lock, Network, Laptop, ArrowRight, Fingerprint } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Button } from '../components/ui/button'
import { Badge } from '../components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table'
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '../components/ui/dialog'
import { QueryError } from '../components/query-error'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

interface AccessOverview {
  roles_count: number
  groups_count: number
  apps_count: number
  pending_requests: number
  roles: { id: string; name: string }[]
  groups: { id: string; name: string }[]
  privileged: {
    vault_grants: number
    active_checkouts: number
    active_jit_grants: number
    active_sessions: number
    pending_session_requests: number
  }
  network: {
    ziti_linked: boolean
    ziti_enrolled: boolean
    devices: number
    trusted_device: boolean
  }
}

interface AvailableGroup {
  id: string
  name: string
  description: string
  allow_self_join: boolean
  require_approval: boolean
  is_member: boolean
  has_pending_request: boolean
}

interface GroupRequest {
  id: string
  user_id: string
  group_id: string
  group_name: string
  justification: string
  status: string
  reviewed_by?: string
  reviewed_at?: string
  review_comments?: string
  created_at: string
}

export function MyAccessPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [requestOpen, setRequestOpen] = useState(false)
  const [selectedGroup, setSelectedGroup] = useState<AvailableGroup | null>(null)
  const [justification, setJustification] = useState('')

  const { data: overview, isError: overviewIsError, error: overviewError } = useQuery({
    queryKey: ['access-overview'],
    queryFn: () => api.get<AccessOverview>('/api/v1/identity/portal/access-overview'),
  })

  const { data: groupsData } = useQuery({
    queryKey: ['available-groups'],
    queryFn: () => api.get<{ groups: AvailableGroup[] }>('/api/v1/identity/portal/groups/available'),
  })
  const availableGroups = groupsData?.groups || []

  const { data: requestsData } = useQuery({
    queryKey: ['my-group-requests'],
    queryFn: () => api.get<{ requests: GroupRequest[] }>('/api/v1/identity/portal/groups/requests'),
  })
  const myRequests = requestsData?.requests || []

  const requestMutation = useMutation({
    mutationFn: (body: { group_id: string; justification: string }) =>
      api.post('/api/v1/identity/portal/groups/request', body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['available-groups'] })
      queryClient.invalidateQueries({ queryKey: ['my-group-requests'] })
      queryClient.invalidateQueries({ queryKey: ['access-overview'] })
      toast({ title: 'Group request submitted' })
      setRequestOpen(false)
    },
    onError: () => toast({ title: 'Failed to submit request', variant: 'destructive' }),
  })

  const openRequest = (group: AvailableGroup) => {
    setSelectedGroup(group)
    setJustification('')
    setRequestOpen(true)
  }

  const statusIcon = (status: string) => {
    switch (status) {
      case 'approved': return <CheckCircle className="h-4 w-4 text-green-500" />
      case 'denied': return <XCircle className="h-4 w-4 text-red-500" />
      default: return <Clock className="h-4 w-4 text-yellow-500" />
    }
  }

  const statusColor = (status: string): 'default' | 'secondary' | 'destructive' | 'outline' => {
    switch (status) {
      case 'approved': return 'default'
      case 'denied': return 'destructive'
      default: return 'secondary'
    }
  }

  if (overviewIsError) {
    return (
      <div className="space-y-6">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">My Access</h1>
          <p className="text-muted-foreground">Everything you can reach — identity, privileged access, and zero-trust network — in one place</p>
        </div>
        <QueryError error={overviewError} resource="your access overview" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">My Access</h1>
        <p className="text-muted-foreground">Everything you can reach — identity, privileged access, and zero-trust network — in one place</p>
      </div>

      {/* Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-blue-100 rounded-lg"><Shield className="h-6 w-6 text-blue-600" /></div>
              <div>
                <p className="text-2xl font-bold">{overview?.roles_count || 0}</p>
                <p className="text-sm text-muted-foreground">Roles</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-green-100 rounded-lg"><Users className="h-6 w-6 text-green-600" /></div>
              <div>
                <p className="text-2xl font-bold">{overview?.groups_count || 0}</p>
                <p className="text-sm text-muted-foreground">Groups</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-purple-100 rounded-lg"><Key className="h-6 w-6 text-purple-600" /></div>
              <div>
                <p className="text-2xl font-bold">{overview?.apps_count || 0}</p>
                <p className="text-sm text-muted-foreground">Applications</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-yellow-100 rounded-lg"><Clock className="h-6 w-6 text-yellow-600" /></div>
              <div>
                <p className="text-2xl font-bold">{overview?.pending_requests || 0}</p>
                <p className="text-sm text-muted-foreground">Pending</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Current Access */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <Card>
          <CardHeader><CardTitle className="text-lg">My Roles</CardTitle></CardHeader>
          <CardContent>
            {overview?.roles && overview.roles.length > 0 ? (
              <div className="space-y-2">
                {overview.roles.map((r: { id: string; name: string }) => (
                  <div key={r.id} className="flex items-center gap-2 p-2 rounded-lg bg-muted/50">
                    <Shield className="h-4 w-4 text-blue-500" />
                    <span className="font-medium text-sm">{r.name}</span>
                  </div>
                ))}
              </div>
            ) : <p className="text-sm text-muted-foreground">No roles assigned</p>}
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle className="text-lg">My Groups</CardTitle></CardHeader>
          <CardContent>
            {overview?.groups && overview.groups.length > 0 ? (
              <div className="space-y-2">
                {overview.groups.map((g: { id: string; name: string }) => (
                  <div key={g.id} className="flex items-center gap-2 p-2 rounded-lg bg-muted/50">
                    <Users className="h-4 w-4 text-green-500" />
                    <span className="font-medium text-sm">{g.name}</span>
                  </div>
                ))}
              </div>
            ) : <p className="text-sm text-muted-foreground">No groups assigned</p>}
          </CardContent>
        </Card>
      </div>

      {/* Cross-pillar: Privileged Access (PAM) + Zero-Trust Network (Ziti) */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="flex items-center gap-2 text-lg">
                <Lock className="h-5 w-5 text-amber-600" />My Privileged Access
              </CardTitle>
              <Link to="/my-privileged-access">
                <Button variant="ghost" size="sm">Manage<ArrowRight className="ml-1 h-4 w-4" /></Button>
              </Link>
            </div>
          </CardHeader>
          <CardContent>
            {overview?.privileged ? (
              <div className="grid grid-cols-2 gap-3">
                <div className="flex items-center gap-3 p-3 rounded-lg bg-muted/50">
                  <Key className="h-5 w-5 text-amber-600" />
                  <div>
                    <p className="text-xl font-bold">{overview.privileged.vault_grants}</p>
                    <p className="text-xs text-muted-foreground">Vault secrets</p>
                  </div>
                </div>
                <div className="flex items-center gap-3 p-3 rounded-lg bg-muted/50">
                  <Clock className="h-5 w-5 text-blue-600" />
                  <div>
                    <p className="text-xl font-bold">{overview.privileged.active_checkouts}</p>
                    <p className="text-xs text-muted-foreground">Active checkouts</p>
                  </div>
                </div>
                <div className="flex items-center gap-3 p-3 rounded-lg bg-muted/50">
                  <Shield className="h-5 w-5 text-purple-600" />
                  <div>
                    <p className="text-xl font-bold">{overview.privileged.active_jit_grants}</p>
                    <p className="text-xs text-muted-foreground">JIT elevations</p>
                  </div>
                </div>
                <div className="flex items-center gap-3 p-3 rounded-lg bg-muted/50">
                  <Lock className="h-5 w-5 text-red-600" />
                  <div>
                    <p className="text-xl font-bold">{overview.privileged.active_sessions}</p>
                    <p className="text-xs text-muted-foreground">Live sessions</p>
                  </div>
                </div>
                {overview.privileged.pending_session_requests > 0 && (
                  <div className="col-span-2">
                    <Badge variant="secondary">
                      <Clock className="mr-1 h-3 w-3" />
                      {overview.privileged.pending_session_requests} session request(s) pending approval
                    </Badge>
                  </div>
                )}
              </div>
            ) : <p className="text-sm text-muted-foreground">No privileged access</p>}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="flex items-center gap-2 text-lg">
                <Network className="h-5 w-5 text-green-600" />My Network Access
              </CardTitle>
              <Link to="/my-devices">
                <Button variant="ghost" size="sm">Devices<ArrowRight className="ml-1 h-4 w-4" /></Button>
              </Link>
            </div>
          </CardHeader>
          <CardContent>
            {overview?.network ? (
              <div className="space-y-3">
                <div className="flex items-center justify-between p-3 rounded-lg bg-muted/50">
                  <span className="flex items-center gap-2 text-sm font-medium">
                    <Network className="h-4 w-4 text-green-600" />Zero-Trust Identity
                  </span>
                  {overview.network.ziti_linked ? (
                    <Badge variant="outline" className={overview.network.ziti_enrolled
                      ? 'bg-green-50 text-green-700 border-green-200'
                      : 'bg-yellow-50 text-yellow-700 border-yellow-200'}>
                      {overview.network.ziti_enrolled ? 'Enrolled' : 'Awaiting enrollment'}
                    </Badge>
                  ) : (
                    <Badge variant="outline" className="text-muted-foreground">Not linked</Badge>
                  )}
                </div>
                <div className="flex items-center justify-between p-3 rounded-lg bg-muted/50">
                  <span className="flex items-center gap-2 text-sm font-medium">
                    <Laptop className="h-4 w-4 text-slate-600" />Enrolled Devices
                  </span>
                  <span className="text-xl font-bold">{overview.network.devices}</span>
                </div>
                {overview.network.trusted_device && (
                  <Badge variant="outline" className="bg-blue-50 text-blue-700 border-blue-200">
                    <Fingerprint className="mr-1 h-3 w-3" />You have a trusted device
                  </Badge>
                )}
                {!overview.network.ziti_enrolled && overview.network.ziti_linked && (
                  <p className="text-xs text-muted-foreground">
                    Enroll a device to activate your zero-trust network access.
                  </p>
                )}
              </div>
            ) : <p className="text-sm text-muted-foreground">No network access</p>}
          </CardContent>
        </Card>
      </div>

      {/* Available Groups */}
      <Card>
        <CardHeader><CardTitle>Available Groups to Join</CardTitle></CardHeader>
        <CardContent>
          {availableGroups.length === 0 ? (
            <p className="text-center py-6 text-muted-foreground">No groups available for self-join</p>
          ) : (
            <div className="space-y-3">
              {availableGroups.map(g => (
                <div key={g.id} className="flex items-center justify-between p-3 border rounded-lg">
                  <div>
                    <p className="font-medium">{g.name}</p>
                    <p className="text-sm text-muted-foreground">{g.description}</p>
                    {g.require_approval && <Badge variant="outline" className="mt-1 text-xs">Requires Approval</Badge>}
                  </div>
                  {g.is_member ? (
                    <Badge>Member</Badge>
                  ) : g.has_pending_request ? (
                    <Badge variant="secondary"><Clock className="mr-1 h-3 w-3" />Pending</Badge>
                  ) : (
                    <Button size="sm" onClick={() => openRequest(g)}>Request to Join</Button>
                  )}
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* My Requests */}
      <Card>
        <CardHeader><CardTitle>My Group Requests</CardTitle></CardHeader>
        <CardContent>
          {myRequests.length === 0 ? (
            <p className="text-center py-6 text-muted-foreground">No group requests</p>
          ) : (
            <Table>
              <TableHeader><TableRow>
                <TableHead>Group</TableHead><TableHead>Justification</TableHead>
                <TableHead>Status</TableHead><TableHead>Requested</TableHead>
              </TableRow></TableHeader>
              <TableBody>
                {myRequests.map(r => (
                  <TableRow key={r.id}>
                    <TableCell className="font-medium">{r.group_name}</TableCell>
                    <TableCell className="max-w-xs truncate">{r.justification || '-'}</TableCell>
                    <TableCell>
                      <div className="flex items-center gap-1">
                        {statusIcon(r.status)}
                        <Badge variant={statusColor(r.status)}>{r.status}</Badge>
                      </div>
                    </TableCell>
                    <TableCell>{new Date(r.created_at).toLocaleDateString()}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Request Dialog */}
      <Dialog open={requestOpen} onOpenChange={setRequestOpen}>
        <DialogContent>
          <DialogHeader><DialogTitle>Request to Join: {selectedGroup?.name}</DialogTitle></DialogHeader>
          <div className="space-y-4">
            <p className="text-sm text-muted-foreground">{selectedGroup?.description}</p>
            {selectedGroup?.require_approval && (
              <p className="text-sm text-yellow-600">This group requires admin approval.</p>
            )}
            <div>
              <label className="text-sm font-medium">Justification</label>
              <textarea className="w-full rounded-md border p-2 text-sm mt-1" rows={3}
                value={justification} onChange={e => setJustification(e.target.value)}
                placeholder="Why do you need access to this group?" />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRequestOpen(false)}>Cancel</Button>
            <Button disabled={requestMutation.isPending} onClick={() => selectedGroup && requestMutation.mutate({
              group_id: selectedGroup.id, justification
            })}>Submit Request</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
