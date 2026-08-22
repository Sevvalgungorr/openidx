import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { api } from '../lib/api'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'
import { Trash2, Plus, Play, Eye, Clock, UserMinus, CheckCircle, AlertTriangle } from 'lucide-react'
import { ConfirmAction } from '../components/confirm-action'

interface LifecyclePolicy {
  id: string
  name: string
  description: string
  policy_type: string
  conditions: Record<string, number>
  actions: Record<string, unknown>
  enabled: boolean
  schedule: string
  grace_period_days: number
  notify_before_days: number
  last_run_at: string | null
  next_run_at: string | null
  created_at: string
}

interface LifecycleExecution {
  id: string
  policy_id: string
  status: string
  users_scanned: number
  users_affected: number
  actions_taken: Array<{ user_id: string; username: string; action: string; status: string; reason: string }>
  started_at: string
  completed_at: string | null
  error_message: string
}

interface AffectedUser {
  id: string
  username: string
  email: string
  enabled: boolean
  last_login_at: string | null
  reason: string
}

const policyTypeLabels: Record<string, { label: string; description: string }> = {
  stale_account_disable: { label: 'Stale Account Disable', description: 'Disable accounts that have not logged in recently' },
  disabled_account_cleanup: { label: 'Disabled Account Cleanup', description: 'Delete accounts that have been disabled for a long time' },
  orphan_detection: { label: 'Orphan Detection', description: 'Flag accounts with no group memberships and no recent activity' },
  password_expiry_enforcement: { label: 'Password Expiry', description: 'Disable accounts with passwords older than threshold' },
  scheduled_offboarding: { label: 'Scheduled Offboarding', description: 'Deactivate users at a specified future date' },
}

export function LifecyclePoliciesPage() {
  const queryClient = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [selectedPolicy, setSelectedPolicy] = useState<string | null>(null)
  const [previewData, setPreviewData] = useState<AffectedUser[] | null>(null)

  // Create form state
  const [formName, setFormName] = useState('')
  const [formDesc, setFormDesc] = useState('')
  const [formType, setFormType] = useState('stale_account_disable')
  const [formDays, setFormDays] = useState(90)
  const [formSchedule, setFormSchedule] = useState('daily')
  const [formGrace, setFormGrace] = useState(7)

  const { data: policiesData, isLoading, isError, error } = useQuery({
    queryKey: ['lifecycle-policies'],
    queryFn: () => api.get<{ data: LifecyclePolicy[] }>('/api/v1/lifecycle-policies'),
  })

  const { data: executionsData } = useQuery({
    queryKey: ['lifecycle-executions', selectedPolicy],
    queryFn: () => api.get<{ data: LifecycleExecution[] }>(`/api/v1/lifecycle-policies/${selectedPolicy}/executions`),
    enabled: !!selectedPolicy,
  })

  const createMutation = useMutation({
    mutationFn: (data: Record<string, unknown>) => api.post('/api/v1/lifecycle-policies', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['lifecycle-policies'] })
      setShowCreate(false)
      setFormName('')
      setFormDesc('')
    },
  })

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      api.put(`/api/v1/lifecycle-policies/${id}`, { enabled }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['lifecycle-policies'] }),
  })

  const executeMutation = useMutation({
    mutationFn: ({ id, dry_run }: { id: string; dry_run: boolean }) =>
      api.post<{ affected_users?: AffectedUser[]; execution_id?: string; affected_count?: number }>(
        `/api/v1/lifecycle-policies/${id}/execute`, { dry_run }),
    onSuccess: (data, vars) => {
      if (vars.dry_run && data.affected_users) {
        setPreviewData(data.affected_users)
      } else {
        queryClient.invalidateQueries({ queryKey: ['lifecycle-executions'] })
        setPreviewData(null)
      }
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/lifecycle-policies/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['lifecycle-policies'] })
      setSelectedPolicy(null)
    },
  })

  const handleCreate = () => {
    const condKey = formType === 'disabled_account_cleanup' ? 'disabled_days' :
                    formType === 'password_expiry_enforcement' ? 'max_age_days' : 'inactive_days'
    createMutation.mutate({
      name: formName, description: formDesc, policy_type: formType,
      conditions: { [condKey]: formDays },
      actions: { action: formType === 'disabled_account_cleanup' ? 'delete' : 'disable', notify_user: true },
      schedule: formSchedule, grace_period_days: formGrace,
    })
  }

  if (isLoading) return <div className="flex justify-center py-12"><LoadingSpinner size="lg" /></div>

  if (isError) return <QueryError error={error} resource="lifecycle policies" />

  const policies = policiesData?.data || []
  const executions = executionsData?.data || []

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Lifecycle Policies</h1>
          <p className="text-muted-foreground">Automated de-provisioning and account lifecycle management</p>
        </div>
        <Button onClick={() => setShowCreate(!showCreate)}>
          <Plus className="h-4 w-4 mr-2" />{showCreate ? 'Cancel' : 'Create Policy'}
        </Button>
      </div>

      {/* Create Form */}
      {showCreate && (
        <Card>
          <CardHeader><CardTitle>New Lifecycle Policy</CardTitle></CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-sm font-medium">Name</label>
                <input className="w-full border rounded px-3 py-2 mt-1 text-sm" value={formName} onChange={e => setFormName(e.target.value)} />
              </div>
              <div>
                <label className="text-sm font-medium">Policy Type</label>
                <select className="w-full border rounded px-3 py-2 mt-1 text-sm" value={formType} onChange={e => setFormType(e.target.value)}>
                  {Object.entries(policyTypeLabels).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
                </select>
              </div>
              <div>
                <label className="text-sm font-medium">Threshold (days)</label>
                <input type="number" className="w-full border rounded px-3 py-2 mt-1 text-sm" value={formDays} onChange={e => setFormDays(Number(e.target.value))} />
              </div>
              <div>
                <label className="text-sm font-medium">Schedule</label>
                <select className="w-full border rounded px-3 py-2 mt-1 text-sm" value={formSchedule} onChange={e => setFormSchedule(e.target.value)}>
                  <option value="daily">Daily</option>
                  <option value="weekly">Weekly</option>
                  <option value="monthly">Monthly</option>
                </select>
              </div>
              <div>
                <label className="text-sm font-medium">Grace Period (days)</label>
                <input type="number" className="w-full border rounded px-3 py-2 mt-1 text-sm" value={formGrace} onChange={e => setFormGrace(Number(e.target.value))} />
              </div>
            </div>
            <div>
              <label className="text-sm font-medium">Description</label>
              <textarea className="w-full border rounded px-3 py-2 mt-1 text-sm h-16" value={formDesc} onChange={e => setFormDesc(e.target.value)} />
            </div>
            <Button onClick={handleCreate} disabled={!formName || createMutation.isPending}>
              {createMutation.isPending ? 'Creating...' : 'Create Policy'}
            </Button>
          </CardContent>
        </Card>
      )}

      {/* Policy List */}
      <Card>
        <CardHeader><CardTitle className="flex items-center gap-2"><UserMinus className="h-5 w-5" />Policies ({policies.length})</CardTitle></CardHeader>
        <CardContent>
          <div className="divide-y">
            {policies.map(p => (
              <div key={p.id} className="py-3">
                <div className="flex items-center justify-between">
                  <div className="flex-1 cursor-pointer" onClick={() => setSelectedPolicy(selectedPolicy === p.id ? null : p.id)}>
                    <div className="flex items-center gap-2">
                      <p className="font-medium text-sm">{p.name}</p>
                      <Badge variant="outline">{policyTypeLabels[p.policy_type]?.label || p.policy_type}</Badge>
                      <Badge variant={p.enabled ? 'default' : 'secondary'}>{p.enabled ? 'Enabled' : 'Disabled'}</Badge>
                    </div>
                    <p className="text-xs text-muted-foreground mt-0.5">{p.description}</p>
                    <div className="flex gap-4 text-xs text-muted-foreground mt-1">
                      <span>Schedule: {p.schedule}</span>
                      <span>Grace: {p.grace_period_days}d</span>
                      {p.last_run_at && <span>Last run: {new Date(p.last_run_at).toLocaleString()}</span>}
                    </div>
                  </div>
                  <div className="flex gap-2 ml-4">
                    <Button size="sm" variant="outline" onClick={() => toggleMutation.mutate({ id: p.id, enabled: !p.enabled })}>
                      {p.enabled ? 'Disable' : 'Enable'}
                    </Button>
                    <Button size="sm" variant="outline" onClick={() => { setSelectedPolicy(p.id); executeMutation.mutate({ id: p.id, dry_run: true }); }}>
                      <Eye className="h-3 w-3 mr-1" />Preview
                    </Button>
                    <ConfirmAction
                      title="Run this lifecycle policy for real?"
                      description={`This executes "${p.name}" against live accounts (not a preview). Matching users will be ${p.policy_type === 'disabled_account_cleanup' ? 'permanently deleted' : 'disabled'} according to the policy actions. This affects real users and cannot be undone — use Preview first to review who is affected.`}
                      destructive
                      requireReason
                      confirmLabel="Run Now"
                      onConfirm={() => executeMutation.mutateAsync({ id: p.id, dry_run: false })}
                    >
                      {(open) => (
                        <Button size="sm" onClick={open}>
                          <Play className="h-3 w-3 mr-1" />Run
                        </Button>
                      )}
                    </ConfirmAction>
                    <ConfirmAction
                      title="Delete this lifecycle policy?"
                      description={`This permanently removes the "${p.name}" lifecycle policy and its schedule. Existing execution history is retained, but the policy will no longer run.`}
                      destructive
                      confirmLabel="Delete"
                      onConfirm={() => deleteMutation.mutateAsync(p.id)}
                    >
                      {(open) => (
                        <Button size="sm" variant="ghost" onClick={open}>
                          <Trash2 className="h-3 w-3" />
                        </Button>
                      )}
                    </ConfirmAction>
                  </div>
                </div>
              </div>
            ))}
            {policies.length === 0 && <p className="py-8 text-center text-muted-foreground">No lifecycle policies configured</p>}
          </div>
        </CardContent>
      </Card>

      {/* Preview Results */}
      {previewData && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center justify-between">
              <span>Preview: {previewData.length} Users Affected</span>
              <Button variant="ghost" size="sm" onClick={() => setPreviewData(null)}>Close</Button>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="divide-y max-h-64 overflow-y-auto">
              {previewData.map(u => (
                <div key={u.id} className="py-2 flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium">{u.username}</p>
                    <p className="text-xs text-muted-foreground">{u.email}</p>
                  </div>
                  <div className="text-right">
                    <Badge variant={u.enabled ? 'default' : 'secondary'}>{u.enabled ? 'Active' : 'Disabled'}</Badge>
                    <p className="text-xs text-muted-foreground mt-0.5">{u.reason}</p>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Execution History */}
      {selectedPolicy && executions.length > 0 && (
        <Card>
          <CardHeader><CardTitle className="flex items-center gap-2"><Clock className="h-5 w-5" />Execution History</CardTitle></CardHeader>
          <CardContent>
            <div className="divide-y">
              {executions.map(e => (
                <div key={e.id} className="py-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      {e.status === 'completed' ? <CheckCircle className="h-4 w-4 text-green-600" /> : <AlertTriangle className="h-4 w-4 text-yellow-600" />}
                      <span className="text-sm">{new Date(e.started_at).toLocaleString()}</span>
                      <Badge className={e.status === 'completed' ? 'bg-green-100 text-green-800' : 'bg-yellow-100 text-yellow-800'}>{e.status}</Badge>
                    </div>
                    <div className="text-sm text-right">
                      <span>{e.users_affected} affected</span>
                      <span className="text-muted-foreground ml-2">/ {e.users_scanned} scanned</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
