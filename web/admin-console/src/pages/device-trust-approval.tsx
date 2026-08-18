import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Smartphone, Check, X, Clock, Settings, CheckCircle2, XCircle, AlertCircle } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '../components/ui/dialog'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '../components/ui/select'
import { Label } from '../components/ui/label'
import { Textarea } from '../components/ui/textarea'
import { Switch } from '../components/ui/switch'
import { Checkbox } from '../components/ui/checkbox'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'
import { QueryError } from '../components/query-error'

interface TrustRequest {
  id: string
  user_id: string
  user_email: string
  user_name: string
  device_name: string
  device_type: string
  ip_address: string
  justification: string
  status: string
  reviewed_by?: string
  reviewed_at?: string
  review_notes?: string
  created_at: string
}

interface TrustSettings {
  id: string
  require_approval: boolean
  auto_approve_known_ips: boolean
  auto_approve_corporate_devices: boolean
  request_expiry_hours: number
  notify_admins: boolean
  notify_user_on_decision: boolean
}

export function DeviceTrustApprovalPage() {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [statusFilter, setStatusFilter] = useState('pending')
  const [selectedRequests, setSelectedRequests] = useState<string[]>([])
  const [reviewDialog, setReviewDialog] = useState(false)
  const [settingsDialog, setSettingsDialog] = useState(false)
  const [selectedRequest, setSelectedRequest] = useState<TrustRequest | null>(null)
  const [reviewNotes, setReviewNotes] = useState('')
  const [reviewAction, setReviewAction] = useState<'approve' | 'reject'>('approve')

  // Fetch requests
  const { data: requestsData, isLoading, isError, error } = useQuery({
    queryKey: ['device-trust-requests', statusFilter],
    queryFn: async () => {
      const params = new URLSearchParams()
      if (statusFilter) params.append('status', statusFilter)
      return api.get<{ requests: TrustRequest[] }>(`/api/v1/identity/device-trust-requests?${params}`)
    }
  })

  const requests: TrustRequest[] = requestsData?.requests || []

  // Fetch settings
  const { data: settings } = useQuery({
    queryKey: ['device-trust-settings'],
    queryFn: async () => {
      return api.get<TrustSettings>('/api/v1/identity/device-trust-settings')
    }
  })

  // Fetch pending count
  const { data: pendingData } = useQuery({
    queryKey: ['device-trust-pending-count'],
    queryFn: async () => {
      return api.get<{ count: number }>('/api/v1/identity/device-trust-requests/pending-count')
    }
  })

  const pendingCount = pendingData?.count || 0

  // Mutations
  const approveMutation = useMutation({
    mutationFn: ({ requestId, notes }: { requestId: string; notes: string }) =>
      api.post(`/api/v1/identity/device-trust-requests/${requestId}/approve`, { notes }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['device-trust-requests'] })
      queryClient.invalidateQueries({ queryKey: ['device-trust-pending-count'] })
      // Sync Ziti attributes so network access is granted immediately
      if (selectedRequest?.user_id) {
        api.post(`/api/v1/access/ziti/sync/device-trust/${selectedRequest.user_id}`).catch(() => {})
      }
      toast({ title: 'Request Approved', description: 'Device trust granted — network access updated.' })
      setReviewDialog(false)
    }
  })

  const rejectMutation = useMutation({
    mutationFn: ({ requestId, notes }: { requestId: string; notes: string }) =>
      api.post(`/api/v1/identity/device-trust-requests/${requestId}/reject`, { notes }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['device-trust-requests'] })
      queryClient.invalidateQueries({ queryKey: ['device-trust-pending-count'] })
      toast({ title: 'Request Rejected', description: 'Device trust has been denied.' })
      setReviewDialog(false)
    }
  })

  const bulkApproveMutation = useMutation({
    mutationFn: (requestIds: string[]) =>
      api.post<{ approved: number }>('/api/v1/identity/device-trust-requests/bulk-approve', { request_ids: requestIds, notes: 'Bulk approved' }),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['device-trust-requests'] })
      queryClient.invalidateQueries({ queryKey: ['device-trust-pending-count'] })
      toast({ title: 'Bulk Approve', description: `Approved ${data.approved} requests.` })
      setSelectedRequests([])
    }
  })

  const bulkRejectMutation = useMutation({
    mutationFn: (requestIds: string[]) =>
      api.post<{ rejected: number }>('/api/v1/identity/device-trust-requests/bulk-reject', { request_ids: requestIds, notes: 'Bulk rejected' }),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['device-trust-requests'] })
      queryClient.invalidateQueries({ queryKey: ['device-trust-pending-count'] })
      toast({ title: 'Bulk Reject', description: `Rejected ${data.rejected} requests.` })
      setSelectedRequests([])
    }
  })

  const updateSettingsMutation = useMutation({
    mutationFn: (newSettings: TrustSettings) =>
      api.put('/api/v1/identity/device-trust-settings', newSettings),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['device-trust-settings'] })
      toast({ title: 'Settings Updated' })
      setSettingsDialog(false)
    }
  })

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'pending':
        return <Badge className="bg-amber-100 text-amber-800"><Clock className="h-3 w-3 mr-1" />Pending</Badge>
      case 'approved':
        return <Badge className="bg-green-100 text-green-800"><CheckCircle2 className="h-3 w-3 mr-1" />Approved</Badge>
      case 'rejected':
        return <Badge className="bg-red-100 text-red-800"><XCircle className="h-3 w-3 mr-1" />Rejected</Badge>
      case 'expired':
        return <Badge className="bg-gray-100 text-gray-800"><AlertCircle className="h-3 w-3 mr-1" />Expired</Badge>
      default:
        return <Badge>{status}</Badge>
    }
  }

  const handleReview = (request: TrustRequest, action: 'approve' | 'reject') => {
    setSelectedRequest(request)
    setReviewAction(action)
    setReviewNotes('')
    setReviewDialog(true)
  }

  const submitReview = () => {
    if (!selectedRequest) return
    if (reviewAction === 'approve') {
      approveMutation.mutate({ requestId: selectedRequest.id, notes: reviewNotes })
    } else {
      rejectMutation.mutate({ requestId: selectedRequest.id, notes: reviewNotes })
    }
  }

  const toggleSelectRequest = (id: string) => {
    setSelectedRequests(prev =>
      prev.includes(id) ? prev.filter(r => r !== id) : [...prev, id]
    )
  }

  const selectAll = () => {
    if (selectedRequests.length === requests.length) {
      setSelectedRequests([])
    } else {
      setSelectedRequests(requests.map(r => r.id))
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Device Trust Approval</h1>
          <p className="text-muted-foreground">Review and approve device trust requests</p>
        </div>
        <Button variant="outline" onClick={() => setSettingsDialog(true)}>
          <Settings className="h-4 w-4 mr-2" />
          Settings
        </Button>
      </div>

      {/* Stats */}
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Pending Requests</CardTitle>
            <Clock className="h-4 w-4 text-amber-600" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-amber-600">{pendingCount}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Approval Required</CardTitle>
            <Smartphone className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{settings?.require_approval ? 'Yes' : 'No'}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Auto-Approve</CardTitle>
            <Check className="h-4 w-4 text-green-600" />
          </CardHeader>
          <CardContent>
            <div className="text-sm">
              {settings?.auto_approve_known_ips && <span className="mr-2">Known IPs</span>}
              {settings?.auto_approve_corporate_devices && <span>Corporate</span>}
              {!settings?.auto_approve_known_ips && !settings?.auto_approve_corporate_devices && 'Disabled'}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Filters and Bulk Actions */}
      <div className="flex items-center justify-between">
        <Select value={statusFilter || 'all'} onValueChange={(v) => setStatusFilter(v === 'all' ? '' : v)}>
          <SelectTrigger className="w-[180px]">
            <SelectValue placeholder="Filter by status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All</SelectItem>
            <SelectItem value="pending">Pending</SelectItem>
            <SelectItem value="approved">Approved</SelectItem>
            <SelectItem value="rejected">Rejected</SelectItem>
            <SelectItem value="expired">Expired</SelectItem>
          </SelectContent>
        </Select>

        {statusFilter === 'pending' && selectedRequests.length > 0 && (
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => bulkApproveMutation.mutate(selectedRequests)}
              className="text-green-600"
            >
              <Check className="h-4 w-4 mr-1" />
              Approve ({selectedRequests.length})
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => bulkRejectMutation.mutate(selectedRequests)}
              className="text-red-600"
            >
              <X className="h-4 w-4 mr-1" />
              Reject ({selectedRequests.length})
            </Button>
          </div>
        )}
      </div>

      {/* Requests List */}
      <Card>
        <CardHeader>
          <CardTitle>Trust Requests</CardTitle>
          <CardDescription>Users requesting to trust their devices</CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex justify-center py-8">
              <LoadingSpinner size="lg" />
            </div>
          ) : isError ? (
            <QueryError error={error} resource="trust requests" />
          ) : requests.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <Smartphone className="h-12 w-12 mx-auto mb-3 opacity-40" />
              <p>No trust requests found</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b">
                    {statusFilter === 'pending' && (
                      <th className="py-3 px-2">
                        <Checkbox
                          checked={selectedRequests.length === requests.length}
                          onCheckedChange={selectAll}
                        />
                      </th>
                    )}
                    <th className="text-left py-3 px-2 font-medium">User</th>
                    <th className="text-left py-3 px-2 font-medium">Device</th>
                    <th className="text-left py-3 px-2 font-medium">IP Address</th>
                    <th className="text-left py-3 px-2 font-medium">Justification</th>
                    <th className="text-left py-3 px-2 font-medium">Status</th>
                    <th className="text-left py-3 px-2 font-medium">Requested</th>
                    <th className="text-left py-3 px-2 font-medium">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {requests.map((request) => (
                    <tr key={request.id} className="border-b hover:bg-muted/50">
                      {statusFilter === 'pending' && (
                        <td className="py-3 px-2">
                          <Checkbox
                            checked={selectedRequests.includes(request.id)}
                            onCheckedChange={() => toggleSelectRequest(request.id)}
                          />
                        </td>
                      )}
                      <td className="py-3 px-2">
                        <div>
                          <p className="font-medium">{request.user_name}</p>
                          <p className="text-xs text-muted-foreground">{request.user_email}</p>
                        </div>
                      </td>
                      <td className="py-3 px-2">
                        <div>
                          <p>{request.device_name}</p>
                          <p className="text-xs text-muted-foreground">{request.device_type}</p>
                        </div>
                      </td>
                      <td className="py-3 px-2 font-mono text-xs">{request.ip_address}</td>
                      <td className="py-3 px-2 max-w-[200px] truncate" title={request.justification}>
                        {request.justification || '-'}
                      </td>
                      <td className="py-3 px-2">{getStatusBadge(request.status)}</td>
                      <td className="py-3 px-2 whitespace-nowrap">
                        {new Date(request.created_at).toLocaleDateString()}
                      </td>
                      <td className="py-3 px-2">
                        {request.status === 'pending' && (
                          <div className="flex gap-1">
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => handleReview(request, 'approve')}
                              className="text-green-600 hover:text-green-700"
                            >
                              <Check className="h-4 w-4" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => handleReview(request, 'reject')}
                              className="text-red-600 hover:text-red-700"
                            >
                              <X className="h-4 w-4" />
                            </Button>
                          </div>
                        )}
                        {request.status !== 'pending' && request.review_notes && (
                          <span className="text-xs text-muted-foreground" title={request.review_notes}>
                            {request.review_notes.substring(0, 20)}...
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Review Dialog */}
      <Dialog open={reviewDialog} onOpenChange={setReviewDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {reviewAction === 'approve' ? 'Approve' : 'Reject'} Trust Request
            </DialogTitle>
          </DialogHeader>
          {selectedRequest && (
            <div className="space-y-4">
              <div className="bg-muted p-4 rounded-lg space-y-2">
                <p><strong>User:</strong> {selectedRequest.user_name} ({selectedRequest.user_email})</p>
                <p><strong>Device:</strong> {selectedRequest.device_name}</p>
                <p><strong>IP:</strong> {selectedRequest.ip_address}</p>
                {selectedRequest.justification && (
                  <p><strong>Justification:</strong> {selectedRequest.justification}</p>
                )}
              </div>
              {reviewAction === 'approve' && (
                <p className="text-sm text-blue-700 bg-blue-50 p-3 rounded-md">
                  Approving will grant the user's Ziti network identity the <code className="font-mono bg-blue-100 px-1 rounded">device-trusted</code> role, enabling access to policies that require trusted devices.
                </p>
              )}
              <div className="space-y-2">
                <Label>Review Notes</Label>
                <Textarea
                  value={reviewNotes}
                  onChange={(e) => setReviewNotes(e.target.value)}
                  placeholder="Optional notes for this decision..."
                  rows={3}
                />
              </div>
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setReviewDialog(false)}>Cancel</Button>
            <Button
              onClick={submitReview}
              className={reviewAction === 'approve' ? 'bg-green-600 hover:bg-green-700' : 'bg-red-600 hover:bg-red-700'}
            >
              {reviewAction === 'approve' ? 'Approve' : 'Reject'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Settings Dialog */}
      <Dialog open={settingsDialog} onOpenChange={setSettingsDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Device Trust Settings</DialogTitle>
          </DialogHeader>
          {settings && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <div>
                  <Label>Require Admin Approval</Label>
                  <p className="text-xs text-muted-foreground">All trust requests need admin approval</p>
                </div>
                <Switch
                  checked={settings.require_approval}
                  onCheckedChange={(checked) =>
                    updateSettingsMutation.mutate({ ...settings, require_approval: checked })
                  }
                />
              </div>
              <div className="flex items-center justify-between">
                <div>
                  <Label>Auto-approve Known IPs</Label>
                  <p className="text-xs text-muted-foreground">Trust devices from previously trusted IPs</p>
                </div>
                <Switch
                  checked={settings.auto_approve_known_ips}
                  onCheckedChange={(checked) =>
                    updateSettingsMutation.mutate({ ...settings, auto_approve_known_ips: checked })
                  }
                />
              </div>
              <div className="flex items-center justify-between">
                <div>
                  <Label>Auto-approve Corporate Devices</Label>
                  <p className="text-xs text-muted-foreground">Trust devices identified as corporate-managed</p>
                </div>
                <Switch
                  checked={settings.auto_approve_corporate_devices}
                  onCheckedChange={(checked) =>
                    updateSettingsMutation.mutate({ ...settings, auto_approve_corporate_devices: checked })
                  }
                />
              </div>
              <div className="flex items-center justify-between">
                <div>
                  <Label>Notify Admins</Label>
                  <p className="text-xs text-muted-foreground">Send notifications for new requests</p>
                </div>
                <Switch
                  checked={settings.notify_admins}
                  onCheckedChange={(checked) =>
                    updateSettingsMutation.mutate({ ...settings, notify_admins: checked })
                  }
                />
              </div>
              <div className="flex items-center justify-between">
                <div>
                  <Label>Notify User on Decision</Label>
                  <p className="text-xs text-muted-foreground">Send email when request is reviewed</p>
                </div>
                <Switch
                  checked={settings.notify_user_on_decision}
                  onCheckedChange={(checked) =>
                    updateSettingsMutation.mutate({ ...settings, notify_user_on_decision: checked })
                  }
                />
              </div>
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setSettingsDialog(false)}>Close</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
