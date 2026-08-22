import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Plus,
  Search,
  Workflow,
  UserPlus,
  UserMinus,
  ArrowRightLeft,
  Clock,
  CheckCircle,
  XCircle,
  Play,
  Trash2,
  MoreHorizontal,
  ChevronLeft,
  ChevronRight,
  Eye,
  LogOut,
  RotateCcw,
} from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '../components/ui/table'
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
import { QueryError } from '../components/query-error'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'
import { ConfirmAction } from '../components/confirm-action'

interface LifecycleWorkflow {
  id: string
  name: string
  description: string
  event_type: string
  trigger_type: string
  actions: Record<string, unknown>[]
  conditions: Record<string, unknown>
  require_approval: boolean
  approval_policy_id?: string
  enabled: boolean
  created_at: string
  updated_at: string
}

interface LifecycleExecution {
  id: string
  workflow_id: string
  user_id: string
  triggered_by?: string
  trigger_type: string
  status: string
  actions_completed: Record<string, unknown>[]
  actions_failed: Record<string, unknown>[]
  error?: string
  started_at: string
  completed_at?: string
  created_at: string
}

const eventIcons: Record<string, React.ReactNode> = {
  onboard: <UserPlus className="h-4 w-4" />,
  transfer: <ArrowRightLeft className="h-4 w-4" />,
  offboard: <UserMinus className="h-4 w-4" />,
  leave: <LogOut className="h-4 w-4" />,
  return: <RotateCcw className="h-4 w-4" />,
}

const eventColors: Record<string, string> = {
  onboard: 'bg-green-100 text-green-800',
  transfer: 'bg-blue-100 text-blue-800',
  offboard: 'bg-red-100 text-red-800',
  leave: 'bg-yellow-100 text-yellow-800',
  return: 'bg-purple-100 text-purple-800',
}

const eventLabels: Record<string, string> = {
  onboard: 'Onboard',
  transfer: 'Transfer',
  offboard: 'Offboard',
  leave: 'Leave',
  return: 'Return',
}

const actionTypeLabels: Record<string, string> = {
  assign_role: 'Assign Role',
  remove_role: 'Remove Role',
  assign_group: 'Add to Group',
  remove_group: 'Remove from Group',
  enable_user: 'Enable User',
  disable_user: 'Disable User',
  revoke_sessions: 'Revoke Sessions',
}

const executionStatusColors: Record<string, string> = {
  pending: 'bg-yellow-100 text-yellow-800',
  in_progress: 'bg-blue-100 text-blue-800',
  completed: 'bg-green-100 text-green-800',
  failed: 'bg-red-100 text-red-800',
  rejected: 'bg-muted text-foreground',
}

interface ActionInput {
  type: string
  role_id?: string
  group_id?: string
}

const formatDate = (dateStr: string | undefined) => {
  if (!dateStr) return '-'
  return new Date(dateStr).toLocaleDateString('en-US', {
    year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
  })
}

export function LifecycleWorkflowsPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [search, setSearch] = useState('')
  const [eventFilter, setEventFilter] = useState('')
  const [createModal, setCreateModal] = useState(false)
  const [executeModal, setExecuteModal] = useState(false)
  const [executionsModal, setExecutionsModal] = useState(false)
  const [selectedWorkflow, setSelectedWorkflow] = useState<LifecycleWorkflow | null>(null)
  const [page, setPage] = useState(0)
  const [totalCount, setTotalCount] = useState(0)
  const PAGE_SIZE = 20
  const [executeUserId, setExecuteUserId] = useState('')
  const [newWorkflow, setNewWorkflow] = useState({
    name: '',
    description: '',
    event_type: 'onboard',
    trigger_type: 'manual',
    actions: [] as ActionInput[],
    require_approval: false,
    enabled: true,
  })
  const [newAction, setNewAction] = useState<ActionInput>({ type: 'assign_role' })

  const { data: workflows, isLoading, isError, error } = useQuery({
    queryKey: ['lifecycle-workflows', search, eventFilter, page],
    queryFn: async () => {
      const params = new URLSearchParams()
      if (eventFilter) params.set('event_type', eventFilter)
      params.set('offset', String(page * PAGE_SIZE))
      params.set('limit', String(PAGE_SIZE))
      const result = await api.getWithHeaders<LifecycleWorkflow[]>(`/api/v1/identity/lifecycle/workflows?${params.toString()}`)
      const total = parseInt(result.headers['x-total-count'] || '0', 10)
      if (!isNaN(total)) setTotalCount(total)
      return result.data
    },
  })

  const { data: executions } = useQuery({
    queryKey: ['lifecycle-executions', selectedWorkflow?.id],
    queryFn: () => {
      const params = new URLSearchParams()
      if (selectedWorkflow) params.set('workflow_id', selectedWorkflow.id)
      params.set('limit', '20')
      return api.get<LifecycleExecution[]>(`/api/v1/identity/lifecycle/executions?${params.toString()}`)
    },
    enabled: !!selectedWorkflow && executionsModal,
  })

  const createMutation = useMutation({
    mutationFn: (data: typeof newWorkflow) => api.post('/api/v1/identity/lifecycle/workflows', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['lifecycle-workflows'] })
      toast({ title: 'Success', description: 'Workflow created', variant: 'success' })
      setCreateModal(false)
      setNewWorkflow({ name: '', description: '', event_type: 'onboard', trigger_type: 'manual', actions: [], require_approval: false, enabled: true })
    },
    onError: (error: Error) => toast({ title: 'Error', description: error.message, variant: 'destructive' }),
  })

  const executeMutation = useMutation({
    mutationFn: ({ id, user_id }: { id: string; user_id: string }) =>
      api.post(`/api/v1/identity/lifecycle/workflows/${id}/execute`, { user_id }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['lifecycle-executions'] })
      toast({ title: 'Success', description: 'Workflow executed', variant: 'success' })
      setExecuteModal(false)
      setExecuteUserId('')
    },
    onError: (error: Error) => toast({ title: 'Error', description: error.message, variant: 'destructive' }),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/identity/lifecycle/workflows/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['lifecycle-workflows'] })
      toast({ title: 'Success', description: 'Workflow deleted', variant: 'success' })
    },
    onError: (error: Error) => toast({ title: 'Error', description: error.message, variant: 'destructive' }),
  })

  const filteredWorkflows = workflows?.filter(w =>
    !search || w.name.toLowerCase().includes(search.toLowerCase())
  )

  const addAction = () => {
    if (newAction.type) {
      setNewWorkflow(prev => ({
        ...prev,
        actions: [...prev.actions, { ...newAction }],
      }))
      setNewAction({ type: 'assign_role' })
    }
  }

  const removeAction = (idx: number) => {
    setNewWorkflow(prev => ({
      ...prev,
      actions: prev.actions.filter((_, i) => i !== idx),
    }))
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Lifecycle Workflows</h1>
          <p className="text-muted-foreground">Joiner/Mover/Leaver workflow automation</p>
        </div>
        <Button onClick={() => setCreateModal(true)}>
          <Plus className="mr-2 h-4 w-4" /> Create Workflow
        </Button>
      </div>

      {/* Stats */}
      <div className="grid gap-4 md:grid-cols-5">
        {(['onboard', 'transfer', 'offboard', 'leave', 'return'] as const).map(evt => (
          <Card key={evt}>
            <CardContent className="pt-6">
              <div className="flex items-center gap-3">
                <div className={`h-9 w-9 rounded-lg ${eventColors[evt].split(' ')[0]} flex items-center justify-center`}>
                  {eventIcons[evt]}
                </div>
                <div>
                  <p className="text-xl font-bold">{workflows?.filter(w => w.event_type === evt).length || 0}</p>
                  <p className="text-xs text-muted-foreground">{eventLabels[evt]}</p>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Workflow Table */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder="Search workflows..."
                value={search}
                onChange={(e) => { setSearch(e.target.value); setPage(0) }}
                className="pl-9"
              />
            </div>
            <Select value={eventFilter || 'all'} onValueChange={(val) => { setEventFilter(val === 'all' ? '' : val); setPage(0) }}>
              <SelectTrigger className="w-[160px]">
                <SelectValue placeholder="All Events" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Events</SelectItem>
                <SelectItem value="onboard">Onboard</SelectItem>
                <SelectItem value="transfer">Transfer</SelectItem>
                <SelectItem value="offboard">Offboard</SelectItem>
                <SelectItem value="leave">Leave</SelectItem>
                <SelectItem value="return">Return</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex flex-col items-center justify-center py-12">
              <LoadingSpinner size="lg" />
              <p className="mt-4 text-sm text-muted-foreground">Loading workflows...</p>
            </div>
          ) : isError ? (
            <QueryError error={error} resource="lifecycle workflows" />
          ) : !filteredWorkflows || filteredWorkflows.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <Workflow className="h-12 w-12 text-muted-foreground/40 mb-3" />
              <p className="font-medium">No workflows found</p>
              <p className="text-sm">Create a lifecycle workflow to automate user provisioning</p>
            </div>
          ) : (
            <>
              <div className="rounded-md border">
                <Table>
                  <TableHeader>
                    <TableRow className="border-b bg-muted">
                      <TableHead className="p-3 text-left text-sm font-medium">Workflow</TableHead>
                      <TableHead className="p-3 text-left text-sm font-medium">Event</TableHead>
                      <TableHead className="p-3 text-left text-sm font-medium">Trigger</TableHead>
                      <TableHead className="p-3 text-left text-sm font-medium">Actions</TableHead>
                      <TableHead className="p-3 text-left text-sm font-medium">Status</TableHead>
                      <TableHead className="p-3 text-right text-sm font-medium">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredWorkflows.map((wf) => (
                      <TableRow key={wf.id} className="border-b hover:bg-muted">
                        <TableCell className="p-3">
                          <div className="flex items-center gap-3">
                            <div className="h-9 w-9 rounded-lg bg-indigo-100 flex items-center justify-center">
                              <Workflow className="h-4 w-4 text-indigo-700" />
                            </div>
                            <div>
                              <p className="font-medium">{wf.name}</p>
                              <p className="text-sm text-muted-foreground max-w-xs truncate">{wf.description || '-'}</p>
                            </div>
                          </div>
                        </TableCell>
                        <TableCell className="p-3">
                          <span className={`inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium ${eventColors[wf.event_type] || 'bg-muted text-foreground'}`}>
                            {eventIcons[wf.event_type]}
                            {eventLabels[wf.event_type] || wf.event_type}
                          </span>
                        </TableCell>
                        <TableCell className="p-3">
                          <Badge variant="outline">{wf.trigger_type}</Badge>
                        </TableCell>
                        <TableCell className="p-3">
                          <div className="flex gap-1 flex-wrap">
                            {(wf.actions || []).slice(0, 3).map((a, i) => (
                              <Badge key={i} variant="secondary" className="text-xs">
                                {actionTypeLabels[(a as Record<string, string>).type] || (a as Record<string, string>).type}
                              </Badge>
                            ))}
                            {(wf.actions || []).length > 3 && (
                              <Badge variant="secondary" className="text-xs">+{wf.actions.length - 3}</Badge>
                            )}
                          </div>
                        </TableCell>
                        <TableCell className="p-3">
                          <Badge variant={wf.enabled ? 'default' : 'secondary'}>
                            {wf.enabled ? 'Enabled' : 'Disabled'}
                          </Badge>
                        </TableCell>
                        <TableCell className="p-3 text-right">
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <Button variant="ghost" size="sm" className="h-8 w-8 p-0">
                                <MoreHorizontal className="h-4 w-4" />
                              </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end">
                              <DropdownMenuItem onClick={() => {
                                setSelectedWorkflow(wf)
                                setExecuteModal(true)
                              }}>
                                <Play className="h-4 w-4 mr-2" /> Execute
                              </DropdownMenuItem>
                              <DropdownMenuItem onClick={() => {
                                setSelectedWorkflow(wf)
                                setExecutionsModal(true)
                              }}>
                                <Eye className="h-4 w-4 mr-2" /> View History
                              </DropdownMenuItem>
                              <ConfirmAction
                                title="Delete this workflow?"
                                description={`This permanently deletes the "${wf.name}" lifecycle workflow and its trigger configuration. Any automation tied to it will stop running. This cannot be undone.`}
                                destructive
                                confirmLabel="Delete"
                                onConfirm={() => deleteMutation.mutateAsync(wf.id)}
                              >
                                {(open) => (
                                  <DropdownMenuItem
                                    onSelect={(e) => { e.preventDefault(); open() }}
                                    className="text-red-600"
                                  >
                                    <Trash2 className="h-4 w-4 mr-2" /> Delete
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
              </div>

              {totalCount > PAGE_SIZE && (
                <div className="flex items-center justify-between pt-4 px-1">
                  <p className="text-sm text-muted-foreground">
                    Showing {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, totalCount)} of {totalCount}
                  </p>
                  <div className="flex items-center gap-2">
                    <Button variant="outline" size="sm" onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0}>
                      <ChevronLeft className="h-4 w-4 mr-1" /> Previous
                    </Button>
                    <span className="text-sm text-muted-foreground">Page {page + 1} of {Math.ceil(totalCount / PAGE_SIZE)}</span>
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

      {/* Create Workflow Modal */}
      <Dialog open={createModal} onOpenChange={setCreateModal}>
        <DialogContent className="sm:max-w-lg max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Create Lifecycle Workflow</DialogTitle>
          </DialogHeader>
          <form onSubmit={(e) => { e.preventDefault(); createMutation.mutate(newWorkflow) }} className="space-y-4">
            <div className="space-y-2">
              <Label>Workflow Name *</Label>
              <Input value={newWorkflow.name} onChange={(e) => setNewWorkflow(prev => ({ ...prev, name: e.target.value }))} placeholder="New Employee Onboarding" required />
            </div>
            <div className="space-y-2">
              <Label>Description</Label>
              <Textarea value={newWorkflow.description} onChange={(e) => setNewWorkflow(prev => ({ ...prev, description: e.target.value }))} rows={2} />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>Event Type</Label>
                <Select value={newWorkflow.event_type} onValueChange={(val) => setNewWorkflow(prev => ({ ...prev, event_type: val }))}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="onboard">Onboard</SelectItem>
                    <SelectItem value="transfer">Transfer</SelectItem>
                    <SelectItem value="offboard">Offboard</SelectItem>
                    <SelectItem value="leave">Leave</SelectItem>
                    <SelectItem value="return">Return</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>Trigger</Label>
                <Select value={newWorkflow.trigger_type} onValueChange={(val) => setNewWorkflow(prev => ({ ...prev, trigger_type: val }))}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="manual">Manual</SelectItem>
                    <SelectItem value="scheduled">Scheduled</SelectItem>
                    <SelectItem value="webhook">Webhook</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            {/* Action Builder */}
            <div className="space-y-2">
              <Label>Actions</Label>
              {newWorkflow.actions.length > 0 && (
                <div className="space-y-2">
                  {newWorkflow.actions.map((action, idx) => (
                    <div key={idx} className="flex items-center gap-2 p-2 bg-muted rounded">
                      <Badge variant="secondary">{idx + 1}</Badge>
                      <span className="text-sm flex-1">{actionTypeLabels[action.type] || action.type}</span>
                      {action.role_id && <span className="text-xs text-muted-foreground">Role: {action.role_id.slice(0, 8)}...</span>}
                      {action.group_id && <span className="text-xs text-muted-foreground">Group: {action.group_id.slice(0, 8)}...</span>}
                      <Button type="button" variant="ghost" size="sm" onClick={() => removeAction(idx)} className="h-6 w-6 p-0">
                        <XCircle className="h-4 w-4 text-red-500" />
                      </Button>
                    </div>
                  ))}
                </div>
              )}
              <div className="flex gap-2">
                <Select value={newAction.type} onValueChange={(val) => setNewAction(prev => ({ ...prev, type: val }))}>
                  <SelectTrigger className="flex-1"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="assign_role">Assign Role</SelectItem>
                    <SelectItem value="remove_role">Remove Role</SelectItem>
                    <SelectItem value="assign_group">Add to Group</SelectItem>
                    <SelectItem value="remove_group">Remove from Group</SelectItem>
                    <SelectItem value="enable_user">Enable User</SelectItem>
                    <SelectItem value="disable_user">Disable User</SelectItem>
                    <SelectItem value="revoke_sessions">Revoke Sessions</SelectItem>
                  </SelectContent>
                </Select>
                {(newAction.type === 'assign_role' || newAction.type === 'remove_role') && (
                  <Input
                    placeholder="Role ID"
                    value={newAction.role_id || ''}
                    onChange={(e) => setNewAction(prev => ({ ...prev, role_id: e.target.value }))}
                    className="w-40"
                  />
                )}
                {(newAction.type === 'assign_group' || newAction.type === 'remove_group') && (
                  <Input
                    placeholder="Group ID"
                    value={newAction.group_id || ''}
                    onChange={(e) => setNewAction(prev => ({ ...prev, group_id: e.target.value }))}
                    className="w-40"
                  />
                )}
                <Button type="button" variant="outline" onClick={addAction}>
                  <Plus className="h-4 w-4" />
                </Button>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <input type="checkbox" id="require_approval" checked={newWorkflow.require_approval} onChange={(e) => setNewWorkflow(prev => ({ ...prev, require_approval: e.target.checked }))} className="rounded border-border" />
              <Label htmlFor="require_approval">Require approval before execution</Label>
            </div>

            <div className="flex justify-end gap-2 pt-4">
              <Button type="button" variant="outline" onClick={() => setCreateModal(false)}>Cancel</Button>
              <Button type="submit" disabled={createMutation.isPending}>
                {createMutation.isPending ? 'Creating...' : 'Create Workflow'}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* Execute Workflow Modal */}
      <Dialog open={executeModal} onOpenChange={setExecuteModal}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Execute Workflow — {selectedWorkflow?.name}</DialogTitle>
          </DialogHeader>
          <form onSubmit={(e) => {
            e.preventDefault()
            if (selectedWorkflow && executeUserId) {
              executeMutation.mutate({ id: selectedWorkflow.id, user_id: executeUserId })
            }
          }} className="space-y-4">
            <div className="space-y-2">
              <Label>Target User ID *</Label>
              <Input
                value={executeUserId}
                onChange={(e) => setExecuteUserId(e.target.value)}
                placeholder="Enter user ID"
                required
              />
            </div>
            {selectedWorkflow && (
              <div className="p-3 bg-muted rounded-lg text-sm">
                <p className="font-medium mb-2">Actions to execute:</p>
                <ol className="list-decimal ml-4 space-y-1">
                  {(selectedWorkflow.actions || []).map((a, i) => (
                    <li key={i}>{actionTypeLabels[(a as Record<string, string>).type] || (a as Record<string, string>).type}</li>
                  ))}
                </ol>
              </div>
            )}
            <div className="flex justify-end gap-2 pt-4">
              <Button type="button" variant="outline" onClick={() => setExecuteModal(false)}>Cancel</Button>
              <Button type="submit" disabled={executeMutation.isPending}>
                {executeMutation.isPending ? 'Executing...' : 'Execute'}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* Execution History Modal */}
      <Dialog open={executionsModal} onOpenChange={setExecutionsModal}>
        <DialogContent className="sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>Execution History — {selectedWorkflow?.name}</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            {!executions || executions.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">
                <Clock className="h-10 w-10 mx-auto mb-2 opacity-40" />
                <p>No executions yet.</p>
              </div>
            ) : (
              <div className="rounded-md border">
                <Table>
                  <TableHeader>
                    <TableRow className="border-b bg-muted">
                      <TableHead className="p-3 text-left text-sm font-medium">Started</TableHead>
                      <TableHead className="p-3 text-left text-sm font-medium">User ID</TableHead>
                      <TableHead className="p-3 text-left text-sm font-medium">Status</TableHead>
                      <TableHead className="p-3 text-left text-sm font-medium">Completed/Failed</TableHead>
                      <TableHead className="p-3 text-left text-sm font-medium">Completed At</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {executions.map((exec) => (
                      <TableRow key={exec.id} className="border-b">
                        <TableCell className="p-3 text-sm">{formatDate(exec.started_at)}</TableCell>
                        <TableCell className="p-3 text-sm font-mono">{exec.user_id.slice(0, 8)}...</TableCell>
                        <TableCell className="p-3">
                          <span className={`inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium ${executionStatusColors[exec.status] || 'bg-muted text-foreground'}`}>
                            {exec.status === 'completed' ? <CheckCircle className="h-3 w-3" /> : exec.status === 'failed' ? <XCircle className="h-3 w-3" /> : <Clock className="h-3 w-3" />}
                            {exec.status}
                          </span>
                        </TableCell>
                        <TableCell className="p-3 text-sm">
                          <span className="text-green-600">{exec.actions_completed?.length || 0}</span>
                          {' / '}
                          <span className="text-red-600">{exec.actions_failed?.length || 0}</span>
                        </TableCell>
                        <TableCell className="p-3 text-sm">{formatDate(exec.completed_at)}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </div>
        </DialogContent>
      </Dialog>
    </div>
  )
}
