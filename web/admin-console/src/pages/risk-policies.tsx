import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Shield, Plus, Edit2, Trash2, AlertTriangle, Activity, Info } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Switch } from '../components/ui/switch'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
  DialogDescription,
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
import { Checkbox } from '../components/ui/checkbox'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { ConfirmAction } from '../components/confirm-action'
import { QueryError } from '../components/query-error'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

interface PolicyCondition {
  risk_score_min?: number
  risk_score_max?: number
  new_device?: boolean
  new_location?: boolean
  impossible_travel?: boolean
  off_hours?: boolean
  failed_attempts?: number
  untrusted_device?: boolean
  countries?: string[]
  exclude_countries?: string[]
}

interface PolicyAction {
  require_mfa: boolean
  mfa_methods?: string[]
  step_up?: boolean
  deny?: boolean
  notify_user?: boolean
  notify_admin?: boolean
  log_level?: string
  session_duration?: number
  require_reason?: boolean
}

interface RiskPolicy {
  id: string
  name: string
  description: string
  enabled: boolean
  priority: number
  conditions: PolicyCondition
  actions: PolicyAction
  created_at: string
  updated_at: string
}

interface RiskStats {
  high_risk_logins_today: number
  new_devices_today: number
  total_devices: number
  trusted_devices: number
  failed_logins_today: number
  avg_risk_score_today: number
}

const emptyPolicy: Partial<RiskPolicy> = {
  name: '',
  description: '',
  enabled: true,
  priority: 100,
  conditions: {},
  actions: { require_mfa: true }
}

export function RiskPoliciesPage() {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [editDialog, setEditDialog] = useState(false)
  const [testDialog, setTestDialog] = useState(false)
  const [selectedPolicy, setSelectedPolicy] = useState<RiskPolicy | null>(null)
  const [formData, setFormData] = useState<Partial<RiskPolicy>>(emptyPolicy)

  // Test form state
  const [testForm, setTestForm] = useState({
    user_id: '',
    ip_address: '',
    user_agent: navigator.userAgent
  })

  // Fetch policies
  const { data: policiesData, isLoading, isError, error } = useQuery({
    queryKey: ['risk-policies'],
    queryFn: async () => {
      return api.get<{ policies: RiskPolicy[] }>('/api/v1/identity/risk/policies')
    }
  })

  const policies: RiskPolicy[] = policiesData?.policies || []

  // Fetch stats
  const { data: statsData } = useQuery({
    queryKey: ['risk-stats'],
    queryFn: async () => {
      return api.get<{ stats: RiskStats }>('/api/v1/identity/risk/stats')
    }
  })

  const stats: RiskStats = statsData?.stats || {
    high_risk_logins_today: 0,
    new_devices_today: 0,
    total_devices: 0,
    trusted_devices: 0,
    failed_logins_today: 0,
    avg_risk_score_today: 0
  }

  // Mutations
  const createMutation = useMutation({
    mutationFn: (data: Partial<RiskPolicy>) =>
      api.post('/api/v1/identity/risk/policies', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['risk-policies'] })
      toast({ title: 'Policy Created', description: 'Risk policy has been created.' })
      setEditDialog(false)
      setFormData(emptyPolicy)
    },
    onError: (error: Error) => {
      toast({ title: 'Error', description: error.message, variant: 'destructive' })
    }
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<RiskPolicy> }) =>
      api.put(`/api/v1/identity/risk/policies/${id}`, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['risk-policies'] })
      toast({ title: 'Policy Updated', description: 'Risk policy has been updated.' })
      setEditDialog(false)
    },
    onError: (error: Error) => {
      toast({ title: 'Error', description: error.message, variant: 'destructive' })
    }
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/identity/risk/policies/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['risk-policies'] })
      toast({ title: 'Policy Deleted', description: 'Risk policy has been deleted.' })
    }
  })

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      api.patch(`/api/v1/identity/risk/policies/${id}/toggle`, { enabled }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['risk-policies'] })
    }
  })

  // Test evaluation
  const [testResult, setTestResult] = useState<Record<string, unknown> | null>(null)
  const testMutation = useMutation({
    mutationFn: (data: typeof testForm) =>
      api.post<Record<string, unknown>>('/api/v1/identity/risk/evaluate', data),
    onSuccess: (response) => {
      setTestResult(response)
    },
    onError: (error: Error) => {
      toast({ title: 'Error', description: error.message, variant: 'destructive' })
    }
  })

  const openCreate = () => {
    setSelectedPolicy(null)
    setFormData(emptyPolicy)
    setEditDialog(true)
  }

  const openEdit = (policy: RiskPolicy) => {
    setSelectedPolicy(policy)
    setFormData(policy)
    setEditDialog(true)
  }


  const handleSave = () => {
    if (selectedPolicy) {
      updateMutation.mutate({ id: selectedPolicy.id, data: formData })
    } else {
      createMutation.mutate(formData)
    }
  }

  const getDecisionBadge = (action: PolicyAction) => {
    if (action.deny) {
      return <Badge className="bg-red-100 text-red-800">Deny Access</Badge>
    }
    if (action.step_up) {
      return <Badge className="bg-amber-100 text-amber-800">Step-Up MFA</Badge>
    }
    if (action.require_mfa) {
      return <Badge className="bg-blue-100 text-blue-800">Require MFA</Badge>
    }
    return <Badge className="bg-green-100 text-green-800">Allow</Badge>
  }

  const formatConditions = (cond: PolicyCondition): string[] => {
    const parts: string[] = []
    if (cond.risk_score_min !== undefined) parts.push(`Risk >= ${cond.risk_score_min}`)
    if (cond.risk_score_max !== undefined) parts.push(`Risk <= ${cond.risk_score_max}`)
    if (cond.new_device) parts.push('New Device')
    if (cond.new_location) parts.push('New Location')
    if (cond.impossible_travel) parts.push('Impossible Travel')
    if (cond.off_hours) parts.push('Off Hours')
    if (cond.untrusted_device) parts.push('Untrusted Device')
    if (cond.failed_attempts) parts.push(`${cond.failed_attempts}+ Failed Attempts`)
    if (cond.countries?.length) parts.push(`Countries: ${cond.countries.join(', ')}`)
    return parts.length ? parts : ['Any']
  }

  if (isLoading) {
    return (
      <div className="flex justify-center py-12">
        <LoadingSpinner size="lg" />
      </div>
    )
  }

  if (isError) {
    return <QueryError error={error} resource="risk policies" />
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Risk-Based MFA Policies</h1>
          <p className="text-muted-foreground">Configure adaptive authentication based on risk factors</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => setTestDialog(true)}>
            <Activity className="h-4 w-4 mr-2" />
            Test Evaluation
          </Button>
          <Button onClick={openCreate}>
            <Plus className="h-4 w-4 mr-2" />
            Create Policy
          </Button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid gap-4 md:grid-cols-6">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">High Risk Today</CardTitle>
            <AlertTriangle className="h-4 w-4 text-red-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-600">{stats.high_risk_logins_today}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Avg Risk Score</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.avg_risk_score_today}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">New Devices</CardTitle>
            <Shield className="h-4 w-4 text-blue-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.new_devices_today}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Failed Logins</CardTitle>
            <AlertTriangle className="h-4 w-4 text-amber-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-amber-600">{stats.failed_logins_today}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Devices</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.total_devices}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Trusted</CardTitle>
            <Shield className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600">{stats.trusted_devices}</div>
          </CardContent>
        </Card>
      </div>

      {/* Info Banner */}
      <Card className="border-blue-200 bg-blue-50">
        <CardContent className="pt-4">
          <div className="flex items-start gap-3">
            <Info className="h-5 w-5 text-primary mt-0.5" />
            <div>
              <p className="font-medium text-blue-900">How Risk-Based MFA Works</p>
              <p className="text-sm text-blue-800">
                Policies are evaluated in priority order (lowest first). When conditions match, the most restrictive action is applied.
                Risk factors include: new device (+30), unusual location (+25), impossible travel (+50), failed attempts (+10 each), and off-hours login (+10).
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Policies List */}
      <Card>
        <CardHeader>
          <CardTitle>Active Policies</CardTitle>
          <CardDescription>Policies are evaluated in priority order</CardDescription>
        </CardHeader>
        <CardContent>
          {policies.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <Shield className="h-12 w-12 mx-auto mb-3 opacity-40" />
              <p>No risk policies configured</p>
              <Button variant="link" onClick={openCreate}>Create your first policy</Button>
            </div>
          ) : (
            <div className="space-y-4">
              {policies.map((policy) => (
                <div
                  key={policy.id}
                  className={`flex items-center justify-between p-4 border rounded-lg ${
                    policy.enabled ? 'bg-background' : 'bg-muted opacity-60'
                  }`}
                >
                  <div className="flex-1">
                    <div className="flex items-center gap-3">
                      <span className="text-xs font-mono bg-muted px-2 py-1 rounded">
                        #{policy.priority}
                      </span>
                      <h3 className="font-medium">{policy.name}</h3>
                      {getDecisionBadge(policy.actions)}
                      {!policy.enabled && (
                        <Badge variant="secondary">Disabled</Badge>
                      )}
                    </div>
                    {policy.description && (
                      <p className="text-sm text-muted-foreground mt-1">{policy.description}</p>
                    )}
                    <div className="flex flex-wrap gap-1 mt-2">
                      {formatConditions(policy.conditions).map((cond, i) => (
                        <Badge key={i} variant="outline" className="text-xs">{cond}</Badge>
                      ))}
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Switch
                      checked={policy.enabled}
                      onCheckedChange={(checked) =>
                        toggleMutation.mutate({ id: policy.id, enabled: checked })
                      }
                    />
                    <Button variant="ghost" size="icon" onClick={() => openEdit(policy)}>
                      <Edit2 className="h-4 w-4" />
                    </Button>
                    <ConfirmAction
                      title="Delete Policy"
                      description={`Are you sure you want to delete the risk policy ${policy.name}? This action cannot be undone.`}
                      destructive
                      confirmLabel="Delete"
                      onConfirm={() => deleteMutation.mutateAsync(policy.id)}
                    >
                      {(open) => (
                        <Button variant="ghost" size="icon" onClick={open}>
                          <Trash2 className="h-4 w-4 text-red-500" />
                        </Button>
                      )}
                    </ConfirmAction>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Create/Edit Dialog */}
      <Dialog open={editDialog} onOpenChange={setEditDialog}>
        <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>{selectedPolicy ? 'Edit Policy' : 'Create Policy'}</DialogTitle>
            <DialogDescription>Configure conditions and actions for this risk policy</DialogDescription>
          </DialogHeader>

          <div className="space-y-6">
            {/* Basic Info */}
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>Policy Name *</Label>
                  <Input
                    value={formData.name || ''}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                    placeholder="e.g., High Risk Block"
                  />
                </div>
                <div className="space-y-2">
                  <Label>Priority (lower = first)</Label>
                  <Input
                    type="number"
                    value={formData.priority || 100}
                    onChange={(e) => setFormData({ ...formData, priority: parseInt(e.target.value) })}
                  />
                </div>
              </div>
              <div className="space-y-2">
                <Label>Description</Label>
                <Textarea
                  value={formData.description || ''}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                  placeholder="What does this policy do?"
                  rows={2}
                />
              </div>
            </div>

            {/* Conditions */}
            <div className="space-y-4">
              <h4 className="font-medium">Conditions (when to trigger)</h4>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>Min Risk Score</Label>
                  <Input
                    type="number"
                    value={formData.conditions?.risk_score_min ?? ''}
                    onChange={(e) => setFormData({
                      ...formData,
                      conditions: {
                        ...formData.conditions,
                        risk_score_min: e.target.value ? parseInt(e.target.value) : undefined
                      }
                    })}
                    placeholder="0"
                  />
                </div>
                <div className="space-y-2">
                  <Label>Max Risk Score</Label>
                  <Input
                    type="number"
                    value={formData.conditions?.risk_score_max ?? ''}
                    onChange={(e) => setFormData({
                      ...formData,
                      conditions: {
                        ...formData.conditions,
                        risk_score_max: e.target.value ? parseInt(e.target.value) : undefined
                      }
                    })}
                    placeholder="100"
                  />
                </div>
              </div>

              <div className="grid grid-cols-3 gap-4">
                <div className="flex items-center space-x-2">
                  <Checkbox
                    id="new_device"
                    checked={formData.conditions?.new_device || false}
                    onCheckedChange={(checked) => setFormData({
                      ...formData,
                      conditions: { ...formData.conditions, new_device: checked === true }
                    })}
                  />
                  <label htmlFor="new_device" className="text-sm">New Device</label>
                </div>
                <div className="flex items-center space-x-2">
                  <Checkbox
                    id="new_location"
                    checked={formData.conditions?.new_location || false}
                    onCheckedChange={(checked) => setFormData({
                      ...formData,
                      conditions: { ...formData.conditions, new_location: checked === true }
                    })}
                  />
                  <label htmlFor="new_location" className="text-sm">New Location</label>
                </div>
                <div className="flex items-center space-x-2">
                  <Checkbox
                    id="impossible_travel"
                    checked={formData.conditions?.impossible_travel || false}
                    onCheckedChange={(checked) => setFormData({
                      ...formData,
                      conditions: { ...formData.conditions, impossible_travel: checked === true }
                    })}
                  />
                  <label htmlFor="impossible_travel" className="text-sm">Impossible Travel</label>
                </div>
                <div className="flex items-center space-x-2">
                  <Checkbox
                    id="off_hours"
                    checked={formData.conditions?.off_hours || false}
                    onCheckedChange={(checked) => setFormData({
                      ...formData,
                      conditions: { ...formData.conditions, off_hours: checked === true }
                    })}
                  />
                  <label htmlFor="off_hours" className="text-sm">Off Hours</label>
                </div>
                <div className="flex items-center space-x-2">
                  <Checkbox
                    id="untrusted_device"
                    checked={formData.conditions?.untrusted_device || false}
                    onCheckedChange={(checked) => setFormData({
                      ...formData,
                      conditions: { ...formData.conditions, untrusted_device: checked === true }
                    })}
                  />
                  <label htmlFor="untrusted_device" className="text-sm">Untrusted Device</label>
                </div>
              </div>

              <div className="space-y-2">
                <Label>Failed Attempts Threshold</Label>
                <Input
                  type="number"
                  value={formData.conditions?.failed_attempts ?? ''}
                  onChange={(e) => setFormData({
                    ...formData,
                    conditions: {
                      ...formData.conditions,
                      failed_attempts: e.target.value ? parseInt(e.target.value) : undefined
                    }
                  })}
                  placeholder="e.g., 3"
                />
              </div>
            </div>

            {/* Actions */}
            <div className="space-y-4">
              <h4 className="font-medium">Actions (what to do)</h4>
              <div className="grid grid-cols-2 gap-4">
                <div className="flex items-center space-x-2">
                  <Checkbox
                    id="require_mfa"
                    checked={formData.actions?.require_mfa || false}
                    onCheckedChange={(checked) => setFormData({
                      ...formData,
                      actions: { ...formData.actions!, require_mfa: checked === true }
                    })}
                  />
                  <label htmlFor="require_mfa" className="text-sm">Require MFA</label>
                </div>
                <div className="flex items-center space-x-2">
                  <Checkbox
                    id="step_up"
                    checked={formData.actions?.step_up || false}
                    onCheckedChange={(checked) => setFormData({
                      ...formData,
                      actions: { ...formData.actions!, step_up: checked === true }
                    })}
                  />
                  <label htmlFor="step_up" className="text-sm">Step-Up Auth</label>
                </div>
                <div className="flex items-center space-x-2">
                  <Checkbox
                    id="deny"
                    checked={formData.actions?.deny || false}
                    onCheckedChange={(checked) => setFormData({
                      ...formData,
                      actions: { ...formData.actions!, deny: checked === true }
                    })}
                  />
                  <label htmlFor="deny" className="text-sm font-medium text-red-600">Deny Access</label>
                </div>
                <div className="flex items-center space-x-2">
                  <Checkbox
                    id="notify_admin"
                    checked={formData.actions?.notify_admin || false}
                    onCheckedChange={(checked) => setFormData({
                      ...formData,
                      actions: { ...formData.actions!, notify_admin: checked === true }
                    })}
                  />
                  <label htmlFor="notify_admin" className="text-sm">Notify Admin</label>
                </div>
                <div className="flex items-center space-x-2">
                  <Checkbox
                    id="notify_user"
                    checked={formData.actions?.notify_user || false}
                    onCheckedChange={(checked) => setFormData({
                      ...formData,
                      actions: { ...formData.actions!, notify_user: checked === true }
                    })}
                  />
                  <label htmlFor="notify_user" className="text-sm">Notify User</label>
                </div>
              </div>

              <div className="space-y-2">
                <Label>Log Level</Label>
                <Select
                  value={formData.actions?.log_level || 'info'}
                  onValueChange={(value) => setFormData({
                    ...formData,
                    actions: { ...formData.actions!, log_level: value }
                  })}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="info">Info</SelectItem>
                    <SelectItem value="warning">Warning</SelectItem>
                    <SelectItem value="critical">Critical</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setEditDialog(false)}>Cancel</Button>
            <Button onClick={handleSave} disabled={!formData.name}>
              {selectedPolicy ? 'Update Policy' : 'Create Policy'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Test Evaluation Dialog */}
      <Dialog open={testDialog} onOpenChange={setTestDialog}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Test Risk Evaluation</DialogTitle>
            <DialogDescription>Test how policies would evaluate for a specific login context</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>User ID *</Label>
                <Input
                  value={testForm.user_id}
                  onChange={(e) => setTestForm({ ...testForm, user_id: e.target.value })}
                  placeholder="Enter user UUID"
                />
              </div>
              <div className="space-y-2">
                <Label>IP Address *</Label>
                <Input
                  value={testForm.ip_address}
                  onChange={(e) => setTestForm({ ...testForm, ip_address: e.target.value })}
                  placeholder="e.g., 8.8.8.8"
                />
              </div>
            </div>
            <div className="space-y-2">
              <Label>User Agent</Label>
              <Input
                value={testForm.user_agent}
                onChange={(e) => setTestForm({ ...testForm, user_agent: e.target.value })}
              />
            </div>
            <Button
              onClick={() => testMutation.mutate(testForm)}
              disabled={!testForm.user_id || !testForm.ip_address}
            >
              <Activity className="h-4 w-4 mr-2" />
              Evaluate
            </Button>

            {testResult && (
              <div className="mt-4 p-4 bg-muted rounded-lg">
                <h4 className="font-medium mb-2">Evaluation Result</h4>
                <pre className="text-xs overflow-auto max-h-60">
                  {JSON.stringify(testResult, null, 2)}
                </pre>
              </div>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => { setTestDialog(false); setTestResult(null); }}>
              Close
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
