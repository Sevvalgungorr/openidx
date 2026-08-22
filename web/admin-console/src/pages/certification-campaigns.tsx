import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Plus,
  Search,
  Target,
  Clock,
  CheckCircle,
  Pause,
  Play,
  Trash2,
  MoreHorizontal,
  ChevronLeft,
  ChevronRight,
  CalendarClock,
  Eye,
} from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '../components/ui/dialog'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '../components/ui/dropdown-menu'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/select'
import { Label } from '../components/ui/label'
import { Textarea } from '../components/ui/textarea'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'
import { ConfirmAction } from '../components/confirm-action'
import { QueryError } from '../components/query-error'

interface Campaign {
  id: string
  name: string
  description: string
  type: string
  schedule: string
  reviewer_strategy: string
  reviewer_id?: string
  reviewer_role?: string
  auto_revoke: boolean
  grace_period_days: number
  duration_days: number
  status: string
  last_run_at?: string
  next_run_at?: string
  created_at: string
}

interface CampaignRun {
  id: string
  campaign_id: string
  review_id?: string
  status: string
  started_at: string
  deadline: string
  completed_at?: string
  total_items: number
  reviewed_items: number
  auto_revoked_items: number
  created_at: string
}

const statusColors: Record<string, string> = {
  active: 'bg-green-100 text-green-800',
  paused: 'bg-yellow-100 text-yellow-800',
  completed: 'bg-gray-100 text-gray-800',
}

const statusIcons: Record<string, React.ReactNode> = {
  active: <CheckCircle className="h-3 w-3" />,
  paused: <Pause className="h-3 w-3" />,
  completed: <CheckCircle className="h-3 w-3" />,
}

const scheduleLabels: Record<string, string> = {
  once: 'One-time',
  quarterly: 'Quarterly',
  semi_annual: 'Semi-annual',
  annual: 'Annual',
}

const typeLabels: Record<string, string> = {
  user_access: 'User Access',
  role_assignment: 'Role Assignment',
  application_access: 'Application Access',
  privileged_access: 'Privileged Access',
}

const formatDate = (dateStr: string | undefined) => {
  if (!dateStr) return '-'
  return new Date(dateStr).toLocaleDateString('en-US', {
    year: 'numeric', month: 'short', day: 'numeric',
  })
}

export function CertificationCampaignsPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [createModal, setCreateModal] = useState(false)
  const [runsModal, setRunsModal] = useState(false)
  const [selectedCampaign, setSelectedCampaign] = useState<Campaign | null>(null)
  const [page, setPage] = useState(0)
  const [totalCount, setTotalCount] = useState(0)
  const PAGE_SIZE = 20
  const [newCampaign, setNewCampaign] = useState({
    name: '',
    description: '',
    type: 'user_access',
    schedule: 'quarterly',
    reviewer_strategy: 'manager',
    auto_revoke: false,
    grace_period_days: 7,
    duration_days: 30,
  })

  const { data: campaigns, isLoading, isError, error } = useQuery({
    queryKey: ['campaigns', search, statusFilter, page],
    queryFn: async () => {
      const params = new URLSearchParams()
      if (statusFilter) params.set('status', statusFilter)
      params.set('offset', String(page * PAGE_SIZE))
      params.set('limit', String(PAGE_SIZE))
      const result = await api.getWithHeaders<Campaign[]>(`/api/v1/governance/campaigns?${params.toString()}`)
      const total = parseInt(result.headers['x-total-count'] || '0', 10)
      if (!isNaN(total)) setTotalCount(total)
      return result.data
    },
  })

  const { data: runs } = useQuery({
    queryKey: ['campaign-runs', selectedCampaign?.id],
    queryFn: () => api.get<CampaignRun[]>(`/api/v1/governance/campaigns/${selectedCampaign!.id}/runs`),
    enabled: !!selectedCampaign && runsModal,
  })

  const createMutation = useMutation({
    mutationFn: (data: typeof newCampaign) => api.post('/api/v1/governance/campaigns', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['campaigns'] })
      toast({ title: 'Success', description: 'Campaign created', variant: 'success' })
      setCreateModal(false)
      setNewCampaign({ name: '', description: '', type: 'user_access', schedule: 'quarterly', reviewer_strategy: 'manager', auto_revoke: false, grace_period_days: 7, duration_days: 30 })
    },
    onError: (error: Error) => toast({ title: 'Error', description: error.message, variant: 'destructive' }),
  })

  const runMutation = useMutation({
    mutationFn: (id: string) => api.post(`/api/v1/governance/campaigns/${id}/run`, {}),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['campaigns'] })
      toast({ title: 'Success', description: 'Campaign run started', variant: 'success' })
    },
    onError: (error: Error) => toast({ title: 'Error', description: error.message, variant: 'destructive' }),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/governance/campaigns/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['campaigns'] })
      toast({ title: 'Success', description: 'Campaign deleted', variant: 'success' })
    },
    onError: (error: Error) => toast({ title: 'Error', description: error.message, variant: 'destructive' }),
  })

  const filteredCampaigns = campaigns?.filter(c =>
    !search || c.name.toLowerCase().includes(search.toLowerCase())
  )

  const handleViewRuns = (campaign: Campaign) => {
    setSelectedCampaign(campaign)
    setRunsModal(true)
  }

  const getRunProgress = (run: CampaignRun) => {
    if (run.total_items === 0) return 0
    return Math.round((run.reviewed_items / run.total_items) * 100)
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Certification Campaigns</h1>
          <p className="text-muted-foreground">Scheduled access review campaigns with auto-enforcement</p>
        </div>
        <Button onClick={() => setCreateModal(true)}>
          <Plus className="mr-2 h-4 w-4" /> Create Campaign
        </Button>
      </div>

      {/* Stats */}
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="h-10 w-10 rounded-lg bg-green-100 flex items-center justify-center">
                <Target className="h-5 w-5 text-green-700" />
              </div>
              <div>
                <p className="text-2xl font-bold">{campaigns?.filter(c => c.status === 'active').length || 0}</p>
                <p className="text-sm text-gray-500">Active Campaigns</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="h-10 w-10 rounded-lg bg-yellow-100 flex items-center justify-center">
                <Pause className="h-5 w-5 text-yellow-700" />
              </div>
              <div>
                <p className="text-2xl font-bold">{campaigns?.filter(c => c.status === 'paused').length || 0}</p>
                <p className="text-sm text-gray-500">Paused</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="h-10 w-10 rounded-lg bg-blue-100 flex items-center justify-center">
                <CalendarClock className="h-5 w-5 text-blue-700" />
              </div>
              <div>
                <p className="text-2xl font-bold">{campaigns?.filter(c => c.next_run_at).length || 0}</p>
                <p className="text-sm text-gray-500">Scheduled</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Campaign Table */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-500" />
              <Input
                placeholder="Search campaigns..."
                value={search}
                onChange={(e) => { setSearch(e.target.value); setPage(0) }}
                className="pl-9"
              />
            </div>
            <Select value={statusFilter || 'all'} onValueChange={(val) => { setStatusFilter(val === 'all' ? '' : val); setPage(0) }}>
              <SelectTrigger className="w-[160px]">
                <SelectValue placeholder="All Statuses" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Statuses</SelectItem>
                <SelectItem value="active">Active</SelectItem>
                <SelectItem value="paused">Paused</SelectItem>
                <SelectItem value="completed">Completed</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardHeader>
        <CardContent>
          {isError ? (
            <QueryError error={error} resource="certification campaigns" />
          ) : isLoading ? (
            <div className="flex flex-col items-center justify-center py-12">
              <LoadingSpinner size="lg" />
              <p className="mt-4 text-sm text-muted-foreground">Loading campaigns...</p>
            </div>
          ) : !filteredCampaigns || filteredCampaigns.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <Target className="h-12 w-12 text-muted-foreground/40 mb-3" />
              <p className="font-medium">No campaigns found</p>
              <p className="text-sm">Create a certification campaign to get started</p>
            </div>
          ) : (
            <>
              <div className="rounded-md border">
                <table className="w-full">
                  <thead>
                    <tr className="border-b bg-gray-50">
                      <th className="p-3 text-left text-sm font-medium">Campaign</th>
                      <th className="p-3 text-left text-sm font-medium">Type</th>
                      <th className="p-3 text-left text-sm font-medium">Schedule</th>
                      <th className="p-3 text-left text-sm font-medium">Status</th>
                      <th className="p-3 text-left text-sm font-medium">Last Run</th>
                      <th className="p-3 text-left text-sm font-medium">Next Run</th>
                      <th className="p-3 text-right text-sm font-medium">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredCampaigns.map((campaign) => (
                      <tr key={campaign.id} className="border-b hover:bg-gray-50">
                        <td className="p-3">
                          <div className="flex items-center gap-3">
                            <div className="h-9 w-9 rounded-lg bg-indigo-100 flex items-center justify-center">
                              <Target className="h-4 w-4 text-indigo-700" />
                            </div>
                            <div>
                              <p className="font-medium">{campaign.name}</p>
                              <p className="text-sm text-gray-500 max-w-xs truncate">{campaign.description || '-'}</p>
                            </div>
                          </div>
                        </td>
                        <td className="p-3">
                          <Badge variant="outline">{typeLabels[campaign.type] || campaign.type}</Badge>
                        </td>
                        <td className="p-3">
                          <div className="text-sm">
                            <p>{scheduleLabels[campaign.schedule] || campaign.schedule}</p>
                            <p className="text-gray-500">{campaign.duration_days}d duration</p>
                          </div>
                        </td>
                        <td className="p-3">
                          <span className={`inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium ${statusColors[campaign.status] || 'bg-gray-100 text-gray-800'}`}>
                            {statusIcons[campaign.status]}
                            {campaign.status}
                          </span>
                        </td>
                        <td className="p-3 text-sm">{formatDate(campaign.last_run_at)}</td>
                        <td className="p-3 text-sm">{formatDate(campaign.next_run_at)}</td>
                        <td className="p-3 text-right">
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <Button variant="ghost" size="sm" className="h-8 w-8 p-0">
                                <MoreHorizontal className="h-4 w-4" />
                              </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end">
                              <DropdownMenuItem onClick={() => handleViewRuns(campaign)}>
                                <Eye className="h-4 w-4 mr-2" /> View Runs
                              </DropdownMenuItem>
                              {campaign.status === 'active' && (
                                <ConfirmAction
                                  title="Start a campaign run now?"
                                  description={`This starts a certification run for "${campaign.name}".${campaign.auto_revoke ? ' Auto-revoke is enabled: unreviewed access items will be automatically revoked from users when the grace period ends.' : ' Reviewers will be asked to certify access.'} This affects real access decisions.`}
                                  destructive
                                  requireReason
                                  confirmLabel="Run Now"
                                  onConfirm={() => runMutation.mutateAsync(campaign.id)}
                                >
                                  {(open) => (
                                    <DropdownMenuItem onSelect={(e) => { e.preventDefault(); open() }}>
                                      <Play className="h-4 w-4 mr-2" /> Run Now
                                    </DropdownMenuItem>
                                  )}
                                </ConfirmAction>
                              )}
                              <ConfirmAction
                                title="Delete this campaign?"
                                description={`This permanently deletes the "${campaign.name}" certification campaign and its schedule. Run history is retained, but the campaign will no longer run. This cannot be undone.`}
                                destructive
                                confirmLabel="Delete"
                                onConfirm={() => deleteMutation.mutateAsync(campaign.id)}
                              >
                                {(open) => (
                                  <DropdownMenuItem onSelect={(e) => { e.preventDefault(); open() }} className="text-red-600">
                                    <Trash2 className="h-4 w-4 mr-2" /> Delete
                                  </DropdownMenuItem>
                                )}
                              </ConfirmAction>
                            </DropdownMenuContent>
                          </DropdownMenu>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {totalCount > PAGE_SIZE && (
                <div className="flex items-center justify-between pt-4 px-1">
                  <p className="text-sm text-gray-500">
                    Showing {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, totalCount)} of {totalCount}
                  </p>
                  <div className="flex items-center gap-2">
                    <Button variant="outline" size="sm" onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0}>
                      <ChevronLeft className="h-4 w-4 mr-1" /> Previous
                    </Button>
                    <span className="text-sm text-gray-600">Page {page + 1} of {Math.ceil(totalCount / PAGE_SIZE)}</span>
                    <Button variant="outline" size="sm" onClick={() => setPage(p => p + 1)} disabled={(page + 1) * PAGE_SIZE >= totalCount}>
                      Next <ChevronRight className="h-4 w-4 ml-1" />
                    </Button>
                  </div>
                </div>
              )}
            </>
          )}
        </CardContent>
      </Card>

      {/* Create Campaign Modal */}
      <Dialog open={createModal} onOpenChange={setCreateModal}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>Create Certification Campaign</DialogTitle>
          </DialogHeader>
          <form onSubmit={(e) => { e.preventDefault(); createMutation.mutate(newCampaign) }} className="space-y-4">
            <div className="space-y-2">
              <Label>Campaign Name *</Label>
              <Input value={newCampaign.name} onChange={(e) => setNewCampaign(prev => ({ ...prev, name: e.target.value }))} placeholder="Q1 2026 Access Certification" required />
            </div>
            <div className="space-y-2">
              <Label>Description</Label>
              <Textarea value={newCampaign.description} onChange={(e) => setNewCampaign(prev => ({ ...prev, description: e.target.value }))} rows={2} />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>Review Type</Label>
                <Select value={newCampaign.type} onValueChange={(val) => setNewCampaign(prev => ({ ...prev, type: val }))}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="user_access">User Access</SelectItem>
                    <SelectItem value="role_assignment">Role Assignment</SelectItem>
                    <SelectItem value="application_access">App Access</SelectItem>
                    <SelectItem value="privileged_access">Privileged Access</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>Schedule</Label>
                <Select value={newCampaign.schedule} onValueChange={(val) => setNewCampaign(prev => ({ ...prev, schedule: val }))}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="once">One-time</SelectItem>
                    <SelectItem value="quarterly">Quarterly</SelectItem>
                    <SelectItem value="semi_annual">Semi-annual</SelectItem>
                    <SelectItem value="annual">Annual</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>Reviewer Strategy</Label>
                <Select value={newCampaign.reviewer_strategy} onValueChange={(val) => setNewCampaign(prev => ({ ...prev, reviewer_strategy: val }))}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="manager">Manager</SelectItem>
                    <SelectItem value="app_owner">App Owner</SelectItem>
                    <SelectItem value="specific_user">Specific User</SelectItem>
                    <SelectItem value="role_based">Role-based</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>Duration (days)</Label>
                <Input type="number" value={newCampaign.duration_days} onChange={(e) => setNewCampaign(prev => ({ ...prev, duration_days: parseInt(e.target.value) || 30 }))} min={1} />
              </div>
            </div>
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2">
                <input type="checkbox" id="auto_revoke" checked={newCampaign.auto_revoke} onChange={(e) => setNewCampaign(prev => ({ ...prev, auto_revoke: e.target.checked }))} className="rounded border-gray-300" />
                <Label htmlFor="auto_revoke">Auto-revoke unreviewed items</Label>
              </div>
              {newCampaign.auto_revoke && (
                <div className="flex items-center gap-2">
                  <Label>Grace period:</Label>
                  <Input type="number" value={newCampaign.grace_period_days} onChange={(e) => setNewCampaign(prev => ({ ...prev, grace_period_days: parseInt(e.target.value) || 7 }))} className="w-20" min={0} />
                  <span className="text-sm text-gray-500">days</span>
                </div>
              )}
            </div>
            <div className="flex justify-end gap-2 pt-4">
              <Button type="button" variant="outline" onClick={() => setCreateModal(false)}>Cancel</Button>
              <Button type="submit" disabled={createMutation.isPending}>
                {createMutation.isPending ? 'Creating...' : 'Create Campaign'}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* Campaign Runs Modal */}
      <Dialog open={runsModal} onOpenChange={setRunsModal}>
        <DialogContent className="sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>Campaign Runs — {selectedCampaign?.name}</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            {!runs || runs.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">
                <Clock className="h-10 w-10 mx-auto mb-2 opacity-40" />
                <p>No runs yet. Click "Run Now" to start the first campaign run.</p>
              </div>
            ) : (
              <div className="rounded-md border">
                <table className="w-full">
                  <thead>
                    <tr className="border-b bg-gray-50">
                      <th className="p-3 text-left text-sm font-medium">Started</th>
                      <th className="p-3 text-left text-sm font-medium">Deadline</th>
                      <th className="p-3 text-left text-sm font-medium">Status</th>
                      <th className="p-3 text-left text-sm font-medium">Progress</th>
                      <th className="p-3 text-left text-sm font-medium">Auto-Revoked</th>
                    </tr>
                  </thead>
                  <tbody>
                    {runs.map((run) => (
                      <tr key={run.id} className="border-b">
                        <td className="p-3 text-sm">{formatDate(run.started_at)}</td>
                        <td className="p-3 text-sm">{formatDate(run.deadline)}</td>
                        <td className="p-3">
                          <Badge variant={run.status === 'in_progress' ? 'default' : run.status === 'completed' ? 'secondary' : 'destructive'}>
                            {run.status}
                          </Badge>
                        </td>
                        <td className="p-3">
                          <div className="w-28">
                            <div className="flex justify-between text-xs mb-1">
                              <span>{run.reviewed_items}/{run.total_items}</span>
                              <span>{getRunProgress(run)}%</span>
                            </div>
                            <div className="h-2 bg-gray-200 rounded-full overflow-hidden">
                              <div className="h-full bg-indigo-600 rounded-full" style={{ width: `${getRunProgress(run)}%` }} />
                            </div>
                          </div>
                        </td>
                        <td className="p-3 text-sm">{run.auto_revoked_items}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </DialogContent>
      </Dialog>
    </div>
  )
}
