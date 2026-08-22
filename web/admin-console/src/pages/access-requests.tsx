import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { GitPullRequest, Plus, Clock, CheckCircle, XCircle, Ban, Timer, KeyRound, Undo2, Copy } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Badge } from '../components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '../components/ui/dialog'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/select'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger,
} from '../components/ui/alert-dialog'
import { QueryError } from '../components/query-error'
import { api, VaultSecretMeta } from '../lib/api'
import { useToast } from '../hooks/use-toast'

interface AccessRequest {
  id: string
  requester_id: string
  requester_name: string
  resource_name: string
  resource_type: string
  resource_id?: string
  status: string
  priority: string
  justification: string
  expires_at?: string
  created_at: string
  updated_at: string
}

// Minimal shapes for the resource pickers (role / group / application).
interface Role {
  id: string
  name: string
}
// Groups can come back SCIM-shaped (displayName) or flat (name).
type RawResource = { id?: unknown; name?: unknown; displayName?: unknown }
interface AppResource {
  id: string
  name: string
}

const statusBadge = (status: string) => {
  const map: Record<string, string> = {
    pending: 'bg-yellow-100 text-yellow-800',
    approved: 'bg-green-100 text-green-800',
    fulfilled: 'bg-green-100 text-green-800',
    denied: 'bg-red-100 text-red-800',
    cancelled: 'bg-muted text-foreground',
    expired: 'bg-orange-100 text-orange-800',
  }
  return map[status] || 'bg-muted text-foreground'
}

const DURATION_OPTIONS = [
  { value: '', label: 'Permanent' },
  { value: '4h', label: '4 hours' },
  { value: '8h', label: '8 hours' },
  { value: '1d', label: '1 day' },
  { value: '3d', label: '3 days' },
  { value: '7d', label: '7 days' },
  { value: '30d', label: '30 days' },
  { value: '90d', label: '90 days' },
]

export function AccessRequestsPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [activeTab, setActiveTab] = useState('my-requests')
  const [createOpen, setCreateOpen] = useState(false)
  const [approvalOpen, setApprovalOpen] = useState(false)
  const [approvalAction, setApprovalAction] = useState<'approve' | 'deny'>('approve')
  const [selectedRequest, setSelectedRequest] = useState<AccessRequest | null>(null)
  const [comments, setComments] = useState('')
  const [statusFilter, setStatusFilter] = useState('all')

  const [newReq, setNewReq] = useState({ resource_type: '', resource_name: '', justification: '', priority: 'normal', duration: '', secretId: '' })

  // Retrieve modal state (mirrors vault-secrets reveal pattern)
  const [retrieveOpen, setRetrieveOpen] = useState(false)
  const [selectedRetrieveId, setSelectedRetrieveId] = useState<string | null>(null)
  const [retrievedValue, setRetrievedValue] = useState<string | null>(null)

  const { data: myRequestsData, isLoading: myLoading, isError: myError, error: myErrorObj } = useQuery({
    queryKey: ['my-requests'],
    queryFn: () => api.get<{ requests: AccessRequest[] }>('/api/v1/governance/requests?requester_id=me'),
  })
  const myRequests = myRequestsData?.requests || []

  const { data: pendingData, isLoading: pendingLoading, isError: pendingError, error: pendingErrorObj } = useQuery({
    queryKey: ['my-approvals'],
    queryFn: () => api.get<{ pending_approvals: AccessRequest[] }>('/api/v1/governance/my-approvals'),
  })
  const pendingApprovals = pendingData?.pending_approvals || []

  const { data: allData, isLoading: allLoading, isError: allError, error: allErrorObj } = useQuery({
    queryKey: ['all-requests', statusFilter],
    queryFn: () => {
      const params = statusFilter !== 'all' ? `?status=${statusFilter}` : ''
      return api.get<{ requests: AccessRequest[] }>(`/api/v1/governance/requests${params}`)
    },
  })
  const allRequests = allData?.requests || []

  const { data: vaultSecretsData } = useQuery({
    queryKey: ['vault-secrets'],
    queryFn: () => api.vault.listSecrets(),
    enabled: newReq.resource_type === 'vault_credential',
  })
  const vaultSecrets: VaultSecretMeta[] = vaultSecretsData?.secrets || []

  // Resource pickers for the non-vault types. Requesters should choose a real,
  // existing resource rather than free-typing a name (a typo produces a request
  // that references nothing and stores a throwaway resource_id). Each list loads
  // only when its type is selected.
  const { data: rolesData } = useQuery({
    queryKey: ['ar-roles'],
    queryFn: () => api.get<Role[]>('/api/v1/identity/roles'),
    enabled: newReq.resource_type === 'role',
  })
  const { data: groupsData } = useQuery({
    queryKey: ['ar-groups'],
    queryFn: () => api.get<RawResource[]>('/api/v1/identity/groups'),
    enabled: newReq.resource_type === 'group',
  })
  const { data: appsData } = useQuery({
    queryKey: ['ar-apps'],
    queryFn: () => api.getWithHeaders<AppResource[]>('/api/v1/applications'),
    enabled: newReq.resource_type === 'application',
  })

  // Normalize each type's list to { id, name } picker options. Guard against
  // non-array payloads (some list endpoints wrap in {data:[]} / {items:[]}).
  const asArray = <T,>(v: unknown): T[] =>
    Array.isArray(v)
      ? (v as T[])
      : Array.isArray((v as { data?: unknown })?.data)
        ? ((v as { data: T[] }).data)
        : []
  const resourceOptions: { id: string; name: string }[] =
    newReq.resource_type === 'role'
      ? asArray<Role>(rolesData).map(r => ({ id: r.id, name: r.name }))
      : newReq.resource_type === 'group'
        ? asArray<RawResource>(groupsData).map(g => ({
            id: String(g.id ?? ''),
            name: String(g.displayName ?? g.name ?? ''),
          }))
        : newReq.resource_type === 'application'
          ? asArray<AppResource>(appsData?.data).map(a => ({ id: a.id, name: a.name }))
          : []
  const isPickerType =
    newReq.resource_type === 'role' ||
    newReq.resource_type === 'group' ||
    newReq.resource_type === 'application'

  const createMutation = useMutation({
    mutationFn: (data: typeof newReq) => {
      if (data.resource_type === 'vault_credential') {
        const payload = {
          resource_type: data.resource_type,
          resource_id: data.secretId,
          resource_name: data.resource_name,
          justification: data.justification,
          priority: data.priority,
          duration: data.duration,
        }
        return api.post('/api/v1/governance/requests', payload)
      }
      // role / group / application: send the picked resource_id alongside the
      // name so the request references a real resource (not a throwaway UUID).
      const payload = {
        resource_type: data.resource_type,
        resource_id: data.secretId || undefined,
        resource_name: data.resource_name,
        justification: data.justification,
        priority: data.priority,
        duration: data.duration === 'permanent' ? '' : data.duration,
      }
      return api.post('/api/v1/governance/requests', payload)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['my-requests'] })
      queryClient.invalidateQueries({ queryKey: ['all-requests'] })
      toast({ title: 'Access request submitted' })
      setCreateOpen(false)
      setNewReq({ resource_type: '', resource_name: '', justification: '', priority: 'normal', duration: '', secretId: '' })
    },
    onError: () => toast({ title: 'Failed to submit request', variant: 'destructive' }),
  })

  const cancelMutation = useMutation({
    mutationFn: (id: string) => api.post(`/api/v1/governance/requests/${id}/cancel`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['my-requests'] })
      toast({ title: 'Request cancelled' })
    },
  })

  const approveMutation = useMutation({
    mutationFn: ({ id, comments }: { id: string; comments: string }) =>
      api.post(`/api/v1/governance/requests/${id}/approve`, { comments }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['my-approvals'] })
      queryClient.invalidateQueries({ queryKey: ['all-requests'] })
      toast({ title: 'Request approved' })
      setApprovalOpen(false)
    },
  })

  const denyMutation = useMutation({
    mutationFn: ({ id, comments }: { id: string; comments: string }) =>
      api.post(`/api/v1/governance/requests/${id}/deny`, { comments }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['my-approvals'] })
      queryClient.invalidateQueries({ queryKey: ['all-requests'] })
      toast({ title: 'Request denied' })
      setApprovalOpen(false)
    },
  })

  const retrieveMutation = useMutation({
    mutationFn: (id: string) => api.post<{ value: string }>(`/api/v1/governance/requests/${id}/credential`),
    onSuccess: (data) => setRetrievedValue(data.value),
    onError: (err: { response?: { data?: { error?: string } } }) => {
      const msg = err.response?.data?.error || 'Failed to retrieve credential'
      toast({ title: msg, variant: 'destructive' })
    },
  })

  const returnMutation = useMutation({
    mutationFn: (id: string) => api.post(`/api/v1/governance/requests/${id}/return`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['my-requests'] })
      queryClient.invalidateQueries({ queryKey: ['all-requests'] })
      toast({ title: 'Credential returned' })
    },
    onError: (err: { response?: { data?: { error?: string } } }) => {
      const msg = err.response?.data?.error || 'Failed to return credential'
      toast({ title: msg, variant: 'destructive' })
    },
  })

  const formatDate = (d: string) => new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' })

  const openApproval = (req: AccessRequest, action: 'approve' | 'deny') => {
    setSelectedRequest(req)
    setApprovalAction(action)
    setComments('')
    setApprovalOpen(true)
  }

  const isVaultType = newReq.resource_type === 'vault_credential'
  const submitDisabled = isVaultType
    ? (!newReq.secretId || !newReq.duration || createMutation.isPending)
    : (!newReq.resource_type || !newReq.resource_name || createMutation.isPending)

  const durationOptions = isVaultType
    ? DURATION_OPTIONS.filter(opt => opt.value !== '')
    : DURATION_OPTIONS

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Access Requests</h1>
          <p className="text-muted-foreground">Request access to resources and manage approvals</p>
        </div>
        <Button onClick={() => setCreateOpen(true)}>
          <Plus className="mr-2 h-4 w-4" /> Request Access
        </Button>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="my-requests"><GitPullRequest className="mr-2 h-4 w-4" />My Requests</TabsTrigger>
          <TabsTrigger value="pending-approvals">
            <Clock className="mr-2 h-4 w-4" />Pending Approvals
            {pendingApprovals.length > 0 && <Badge variant="secondary" className="ml-1">{pendingApprovals.length}</Badge>}
          </TabsTrigger>
          <TabsTrigger value="all-requests">All Requests</TabsTrigger>
        </TabsList>

        <TabsContent value="my-requests">
          <Card>
            <CardHeader><CardTitle>My Access Requests</CardTitle></CardHeader>
            <CardContent>
              {myLoading ? <p className="text-center py-8 text-muted-foreground">Loading...</p> :
               myError ? <QueryError error={myErrorObj} resource="access requests" /> :
               myRequests.length === 0 ? <p className="text-center py-8 text-muted-foreground">No requests found</p> : (
                <Table>
                  <TableHeader><TableRow>
                    <TableHead>Resource</TableHead><TableHead>Type</TableHead><TableHead>Status</TableHead>
                    <TableHead>Priority</TableHead><TableHead>Created</TableHead><TableHead>Actions</TableHead>
                  </TableRow></TableHeader>
                  <TableBody>
                    {myRequests.map(r => (
                      <TableRow key={r.id}>
                        <TableCell className="font-medium">{r.resource_name}</TableCell>
                        <TableCell><Badge variant="outline">{r.resource_type}</Badge></TableCell>
                        <TableCell>
                          <span className={`px-2 py-1 rounded-full text-xs font-medium ${statusBadge(r.status)}`}>{r.status}</span>
                          {r.expires_at && r.status !== 'expired' && (
                            <span className="ml-1 inline-flex items-center gap-0.5 text-xs text-orange-600" title={`Expires ${new Date(r.expires_at).toLocaleString()}`}>
                              <Timer className="h-3 w-3" />{new Date(r.expires_at).toLocaleDateString()}
                            </span>
                          )}
                        </TableCell>
                        <TableCell>{r.priority}</TableCell>
                        <TableCell>{formatDate(r.created_at)}</TableCell>
                        <TableCell>
                          <div className="flex gap-2">
                            {r.status === 'pending' && (
                              <AlertDialog>
                                <AlertDialogTrigger asChild>
                                  <Button variant="outline" size="sm"><Ban className="h-3 w-3 mr-1" />Cancel</Button>
                                </AlertDialogTrigger>
                                <AlertDialogContent>
                                  <AlertDialogHeader>
                                    <AlertDialogTitle>Cancel Request?</AlertDialogTitle>
                                    <AlertDialogDescription>Cancel this access request for {r.resource_name}?</AlertDialogDescription>
                                  </AlertDialogHeader>
                                  <AlertDialogFooter>
                                    <AlertDialogCancel>Keep</AlertDialogCancel>
                                    <AlertDialogAction onClick={() => cancelMutation.mutate(r.id)}>Cancel Request</AlertDialogAction>
                                  </AlertDialogFooter>
                                </AlertDialogContent>
                              </AlertDialog>
                            )}
                            {r.resource_type === 'vault_credential' && r.status === 'fulfilled' && (
                              <>
                                <Button variant="outline" size="sm" onClick={() => { setSelectedRetrieveId(r.id); setRetrieveOpen(true) }}>
                                  <KeyRound className="h-3 w-3 mr-1" />Retrieve
                                </Button>
                                <AlertDialog>
                                  <AlertDialogTrigger asChild>
                                    <Button variant="outline" size="sm"><Undo2 className="h-3 w-3 mr-1" />Return</Button>
                                  </AlertDialogTrigger>
                                  <AlertDialogContent>
                                    <AlertDialogHeader>
                                      <AlertDialogTitle>Return Credential?</AlertDialogTitle>
                                      <AlertDialogDescription>Return {r.resource_name} early? This immediately revokes access and triggers credential rotation.</AlertDialogDescription>
                                    </AlertDialogHeader>
                                    <AlertDialogFooter>
                                      <AlertDialogCancel>Keep</AlertDialogCancel>
                                      <AlertDialogAction onClick={() => returnMutation.mutate(r.id)}>Return</AlertDialogAction>
                                    </AlertDialogFooter>
                                  </AlertDialogContent>
                                </AlertDialog>
                              </>
                            )}
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="pending-approvals">
          <Card>
            <CardHeader><CardTitle>Pending Approvals</CardTitle></CardHeader>
            <CardContent>
              {pendingLoading ? <p className="text-center py-8 text-muted-foreground">Loading...</p> :
               pendingError ? <QueryError error={pendingErrorObj} resource="pending approvals" /> :
               pendingApprovals.length === 0 ? <p className="text-center py-8 text-muted-foreground">No pending approvals</p> : (
                <Table>
                  <TableHeader><TableRow>
                    <TableHead>Requester</TableHead><TableHead>Resource</TableHead><TableHead>Type</TableHead>
                    <TableHead>Priority</TableHead><TableHead>Submitted</TableHead><TableHead>Actions</TableHead>
                  </TableRow></TableHeader>
                  <TableBody>
                    {pendingApprovals.map(r => (
                      <TableRow key={r.id}>
                        <TableCell className="font-medium">{r.requester_name}</TableCell>
                        <TableCell>{r.resource_name}</TableCell>
                        <TableCell><Badge variant="outline">{r.resource_type}</Badge></TableCell>
                        <TableCell>{r.priority}</TableCell>
                        <TableCell>{formatDate(r.created_at)}</TableCell>
                        <TableCell>
                          <div className="flex gap-2">
                            <Button size="sm" onClick={() => openApproval(r, 'approve')}><CheckCircle className="h-3 w-3 mr-1" />Approve</Button>
                            <Button variant="destructive" size="sm" onClick={() => openApproval(r, 'deny')}><XCircle className="h-3 w-3 mr-1" />Deny</Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="all-requests">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle>All Access Requests</CardTitle>
                <Select value={statusFilter} onValueChange={setStatusFilter}>
                  <SelectTrigger className="w-[180px]"><SelectValue placeholder="Filter by status" /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Statuses</SelectItem>
                    <SelectItem value="pending">Pending</SelectItem>
                    <SelectItem value="approved">Approved</SelectItem>
                    <SelectItem value="denied">Denied</SelectItem>
                    <SelectItem value="fulfilled">Fulfilled</SelectItem>
                    <SelectItem value="cancelled">Cancelled</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </CardHeader>
            <CardContent>
              {allLoading ? <p className="text-center py-8 text-muted-foreground">Loading...</p> :
               allError ? <QueryError error={allErrorObj} resource="access requests" /> :
               allRequests.length === 0 ? <p className="text-center py-8 text-muted-foreground">No requests found</p> : (
                <Table>
                  <TableHeader><TableRow>
                    <TableHead>Requester</TableHead><TableHead>Resource</TableHead><TableHead>Type</TableHead>
                    <TableHead>Status</TableHead><TableHead>Priority</TableHead><TableHead>Created</TableHead>
                  </TableRow></TableHeader>
                  <TableBody>
                    {allRequests.map(r => (
                      <TableRow key={r.id}>
                        <TableCell className="font-medium">{r.requester_name}</TableCell>
                        <TableCell>{r.resource_name}</TableCell>
                        <TableCell><Badge variant="outline">{r.resource_type}</Badge></TableCell>
                        <TableCell>
                          <span className={`px-2 py-1 rounded-full text-xs font-medium ${statusBadge(r.status)}`}>{r.status}</span>
                          {r.expires_at && r.status !== 'expired' && (
                            <span className="ml-1 inline-flex items-center gap-0.5 text-xs text-orange-600" title={`Expires ${new Date(r.expires_at).toLocaleString()}`}>
                              <Timer className="h-3 w-3" />{new Date(r.expires_at).toLocaleDateString()}
                            </span>
                          )}
                        </TableCell>
                        <TableCell>{r.priority}</TableCell>
                        <TableCell>{formatDate(r.created_at)}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Create Dialog */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader><DialogTitle>Request Access</DialogTitle></DialogHeader>
          <div className="space-y-4">
            <div>
              <label className="text-sm font-medium">Resource Type</label>
              <Select value={newReq.resource_type} onValueChange={v => setNewReq(p => ({ ...p, resource_type: v, resource_name: '', secretId: '', duration: '' }))}>
                <SelectTrigger aria-label="Resource Type"><SelectValue placeholder="Select type" /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="role">Role</SelectItem>
                  <SelectItem value="group">Group</SelectItem>
                  <SelectItem value="application">Application</SelectItem>
                  <SelectItem value="vault_credential">Vault Credential</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <label className="text-sm font-medium">Resource Name</label>
              {isVaultType ? (
                <Select value={newReq.secretId} onValueChange={v => {
                  const secret = vaultSecrets.find(s => s.id === v)
                  setNewReq(p => ({ ...p, secretId: v, resource_name: secret?.name || '' }))
                }}>
                  <SelectTrigger aria-label="Resource Name"><SelectValue placeholder="Select a vault secret" /></SelectTrigger>
                  <SelectContent>
                    {vaultSecrets.map(s => (
                      <SelectItem key={s.id} value={s.id}>{s.name}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              ) : isPickerType && resourceOptions.length > 0 ? (
                <Select value={newReq.secretId} onValueChange={v => {
                  const res = resourceOptions.find(r => r.id === v)
                  setNewReq(p => ({ ...p, secretId: v, resource_name: res?.name || '' }))
                }}>
                  <SelectTrigger aria-label="Resource Name">
                    <SelectValue placeholder={`Select a ${newReq.resource_type}`} />
                  </SelectTrigger>
                  <SelectContent>
                    {resourceOptions.map(r => (
                      <SelectItem key={r.id} value={r.id}>{r.name}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              ) : (
                <Input
                  placeholder={newReq.resource_type ? 'Enter resource name' : 'Select a resource type first'}
                  disabled={!newReq.resource_type}
                  value={newReq.resource_name}
                  onChange={e => setNewReq(p => ({ ...p, resource_name: e.target.value, secretId: '' }))} />
              )}
            </div>
            <div>
              <label className="text-sm font-medium">Justification</label>
              <textarea className="w-full rounded-md border p-2 text-sm" rows={3} placeholder="Explain why you need access..."
                value={newReq.justification} onChange={e => setNewReq(p => ({ ...p, justification: e.target.value }))} />
            </div>
            <div>
              <label className="text-sm font-medium">Priority</label>
              <Select value={newReq.priority} onValueChange={v => setNewReq(p => ({ ...p, priority: v }))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="low">Low</SelectItem>
                  <SelectItem value="normal">Normal</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="urgent">Urgent</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <label className="text-sm font-medium">Access Duration{isVaultType && <span className="text-red-500 ml-1">*</span>}</label>
              <Select value={newReq.duration} onValueChange={v => setNewReq(p => ({ ...p, duration: v }))}>
                <SelectTrigger aria-label="Access Duration"><SelectValue placeholder={isVaultType ? 'Select duration (required)' : 'Permanent'} /></SelectTrigger>
                <SelectContent>
                  {durationOptions.map(opt => (
                    <SelectItem key={opt.value || 'permanent'} value={opt.value || 'permanent'}>
                      {opt.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground mt-1">
                {isVaultType
                  ? 'Vault credentials require a time-bound duration.'
                  : newReq.duration ? 'Access will be automatically revoked after the duration expires.' : 'Access will not expire automatically.'}
              </p>
            </div>
            <div className="flex justify-end gap-2">
              <Button variant="outline" onClick={() => setCreateOpen(false)}>Cancel</Button>
              <Button disabled={submitDisabled}
                onClick={() => createMutation.mutate(newReq)}>
                {createMutation.isPending ? 'Submitting...' : 'Submit Request'}
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {/* Approve/Deny Dialog */}
      <Dialog open={approvalOpen} onOpenChange={setApprovalOpen}>
        <DialogContent>
          <DialogHeader><DialogTitle>{approvalAction === 'approve' ? 'Approve' : 'Deny'} Request</DialogTitle></DialogHeader>
          {selectedRequest && (
            <div className="space-y-4">
              <div className="rounded-lg border p-3 text-sm space-y-1">
                <p><span className="font-medium">Requester:</span> {selectedRequest.requester_name}</p>
                <p><span className="font-medium">Resource:</span> {selectedRequest.resource_name}</p>
                <p><span className="font-medium">Type:</span> {selectedRequest.resource_type}</p>
                {selectedRequest.justification && <p><span className="font-medium">Justification:</span> {selectedRequest.justification}</p>}
              </div>
              <div>
                <label className="text-sm font-medium">Comments</label>
                <textarea className="w-full rounded-md border p-2 text-sm" rows={3} placeholder="Add comments..."
                  value={comments} onChange={e => setComments(e.target.value)} />
              </div>
              <div className="flex justify-end gap-2">
                <Button variant="outline" onClick={() => setApprovalOpen(false)}>Cancel</Button>
                <Button variant={approvalAction === 'approve' ? 'default' : 'destructive'}
                  disabled={approveMutation.isPending || denyMutation.isPending}
                  onClick={() => {
                    if (approvalAction === 'approve') approveMutation.mutate({ id: selectedRequest.id, comments })
                    else denyMutation.mutate({ id: selectedRequest.id, comments })
                  }}>
                  {approvalAction === 'approve' ? 'Approve' : 'Deny'}
                </Button>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Retrieve Credential Modal — one-shot reveal (mirrors the vault-secrets reveal) */}
      <Dialog
        open={retrieveOpen}
        onOpenChange={(open) => {
          if (!open) {
            setRetrievedValue(null)
            setSelectedRetrieveId(null)
          }
          setRetrieveOpen(open)
        }}
      >
        <DialogContent>
          <DialogHeader><DialogTitle>Retrieve Credential</DialogTitle></DialogHeader>
          <div className="space-y-4">
            {!retrievedValue ? (
              <>
                <p className="text-sm text-muted-foreground">
                  The credential will be shown once. This action is audited.
                </p>
                <Button
                  onClick={() => selectedRetrieveId && retrieveMutation.mutate(selectedRetrieveId)}
                  disabled={retrieveMutation.isPending || !selectedRetrieveId}
                  className="w-full"
                >
                  {retrieveMutation.isPending ? 'Retrieving...' : 'Get Credential'}
                </Button>
              </>
            ) : (
              <div className="space-y-3">
                <div className="flex items-center gap-2 p-3 bg-amber-50 border border-amber-200 rounded-md">
                  <p className="text-xs text-amber-800 font-medium">
                    Value shown once — not stored after this dialog closes.
                  </p>
                </div>
                <div className="flex gap-2">
                  <Input
                    value={retrievedValue}
                    readOnly
                    className="font-mono text-sm"
                    type="text"
                    data-testid="retrieved-credential-value"
                  />
                  <Button
                    variant="outline"
                    size="icon"
                    onClick={() => {
                      navigator.clipboard.writeText(retrievedValue)
                      toast({ title: 'Copied' })
                    }}
                  >
                    <Copy className="h-4 w-4" />
                  </Button>
                </div>
              </div>
            )}
          </div>
        </DialogContent>
      </Dialog>
    </div>
  )
}
