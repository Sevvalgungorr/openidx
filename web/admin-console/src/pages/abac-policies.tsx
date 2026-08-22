import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Plus, Search, Edit, Trash2, X, ChevronLeft, ChevronRight,
  MoreHorizontal, Shield, ShieldOff, FlaskConical, Filter,
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
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '../components/ui/alert-dialog'
import { Label } from '../components/ui/label'
import { Textarea } from '../components/ui/textarea'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/select'
import { Switch } from '../components/ui/switch'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '../components/ui/dropdown-menu'
import { QueryError } from '../components/query-error'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

interface ABACCondition {
  attribute: string
  operator: string
  value: unknown
}

interface ABACPolicy {
  id: string
  name: string
  description: string
  resource_type: string
  resource_id?: string
  conditions: ABACCondition[]
  effect: string
  priority: number
  enabled: boolean
  created_at: string
  updated_at: string
}

interface ABACEvaluationResult {
  allowed: boolean
  reason?: string
  policy_id?: string
}

const resourceTypes = [
  { value: 'application', label: 'Application' },
  { value: 'route', label: 'Route' },
  { value: 'service', label: 'Service' },
  { value: '*', label: 'All Resources (*)' },
]

const attributeOptions = [
  { value: 'department', label: 'Department' },
  { value: 'location', label: 'Location' },
  { value: 'device_trust_level', label: 'Device Trust Level' },
  { value: 'time_of_day', label: 'Time of Day' },
  { value: 'risk_score', label: 'Risk Score' },
  { value: 'group_membership', label: 'Group Membership' },
  { value: 'ip_range', label: 'IP Range' },
]

const operatorOptions = [
  { value: 'eq', label: 'Equals (eq)' },
  { value: 'neq', label: 'Not Equals (neq)' },
  { value: 'in', label: 'In (in)' },
  { value: 'not_in', label: 'Not In (not_in)' },
  { value: 'gt', label: 'Greater Than (gt)' },
  { value: 'gte', label: 'Greater or Equal (gte)' },
  { value: 'lt', label: 'Less Than (lt)' },
  { value: 'lte', label: 'Less or Equal (lte)' },
  { value: 'between', label: 'Between (between)' },
  { value: 'contains', label: 'Contains (contains)' },
]

const emptyCondition: ABACCondition = { attribute: 'department', operator: 'eq', value: '' }

function parseConditionValue(raw: string, operator: string): unknown {
  if (operator === 'in' || operator === 'not_in') {
    return raw.split(',').map(s => s.trim()).filter(Boolean)
  }
  if (operator === 'between') {
    const parts = raw.split(',').map(s => s.trim()).filter(Boolean)
    if (parts.length === 2) return [parseFloat(parts[0]) || parts[0], parseFloat(parts[1]) || parts[1]]
    return parts
  }
  const num = parseFloat(raw)
  if (!isNaN(num) && raw.trim() === String(num)) return num
  return raw
}

function conditionValueToString(val: unknown): string {
  if (Array.isArray(val)) return val.join(', ')
  return String(val ?? '')
}

export function ABACPoliciesPage() {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [search, setSearch] = useState('')
  const [resourceTypeFilter, setResourceTypeFilter] = useState('')
  const [offset, setOffset] = useState(0)
  const [editDialogOpen, setEditDialogOpen] = useState(false)
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false)
  const [testDialogOpen, setTestDialogOpen] = useState(false)
  const [selectedPolicy, setSelectedPolicy] = useState<ABACPolicy | null>(null)
  const [isCreating, setIsCreating] = useState(false)
  const limit = 20

  // Form state
  const [formName, setFormName] = useState('')
  const [formDescription, setFormDescription] = useState('')
  const [formResourceType, setFormResourceType] = useState('application')
  const [formResourceId, setFormResourceId] = useState('')
  const [formEffect, setFormEffect] = useState('allow')
  const [formPriority, setFormPriority] = useState(0)
  const [formEnabled, setFormEnabled] = useState(true)
  const [formConditions, setFormConditions] = useState<ABACCondition[]>([{ ...emptyCondition }])
  const [conditionInputs, setConditionInputs] = useState<string[]>([''])

  // Test state
  const [testResourceType, setTestResourceType] = useState('application')
  const [testResourceId, setTestResourceId] = useState('')
  const [testAttributes, setTestAttributes] = useState('{\n  "department": "engineering",\n  "risk_score": 25\n}')
  const [testResult, setTestResult] = useState<ABACEvaluationResult | null>(null)

  const { data: policies, isLoading, isError, error } = useQuery({
    queryKey: ['abac-policies', offset, limit, resourceTypeFilter],
    queryFn: async () => {
      const params = new URLSearchParams({ offset: String(offset), limit: String(limit) })
      if (resourceTypeFilter) params.set('resource_type', resourceTypeFilter)
      const result = await api.getWithHeaders<ABACPolicy[]>(`/api/v1/governance/abac-policies?${params}`)
      return {
        items: result.data,
        total: parseInt(result.headers['x-total-count'] || '0', 10),
      }
    },
  })

  const createMutation = useMutation({
    mutationFn: (data: Partial<ABACPolicy>) =>
      api.post<ABACPolicy>('/api/v1/governance/abac-policies', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['abac-policies'] })
      setEditDialogOpen(false)
      toast({ title: 'ABAC policy created successfully' })
    },
    onError: (err: Error) => {
      toast({ title: 'Failed to create policy', description: err.message, variant: 'destructive' })
    },
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<ABACPolicy> }) =>
      api.put<ABACPolicy>(`/api/v1/governance/abac-policies/${id}`, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['abac-policies'] })
      setEditDialogOpen(false)
      toast({ title: 'ABAC policy updated successfully' })
    },
    onError: (err: Error) => {
      toast({ title: 'Failed to update policy', description: err.message, variant: 'destructive' })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/governance/abac-policies/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['abac-policies'] })
      setDeleteDialogOpen(false)
      toast({ title: 'ABAC policy deleted' })
    },
    onError: (err: Error) => {
      toast({ title: 'Failed to delete policy', description: err.message, variant: 'destructive' })
    },
  })

  const toggleMutation = useMutation({
    mutationFn: (policy: ABACPolicy) =>
      api.put<ABACPolicy>(`/api/v1/governance/abac-policies/${policy.id}`, {
        ...policy,
        enabled: !policy.enabled,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['abac-policies'] })
    },
  })

  const evaluateMutation = useMutation({
    mutationFn: (data: { user_attributes: Record<string, unknown>; resource_type: string; resource_id: string }) =>
      api.post<ABACEvaluationResult>('/api/v1/governance/abac-policies/evaluate', data),
    onSuccess: (result) => {
      setTestResult(result)
    },
    onError: (err: Error) => {
      toast({ title: 'Evaluation failed', description: err.message, variant: 'destructive' })
    },
  })

  const resetForm = () => {
    setFormName('')
    setFormDescription('')
    setFormResourceType('application')
    setFormResourceId('')
    setFormEffect('allow')
    setFormPriority(0)
    setFormEnabled(true)
    setFormConditions([{ ...emptyCondition }])
    setConditionInputs([''])
  }

  const openCreate = () => {
    setIsCreating(true)
    setSelectedPolicy(null)
    resetForm()
    setEditDialogOpen(true)
  }

  const openEdit = (policy: ABACPolicy) => {
    setIsCreating(false)
    setSelectedPolicy(policy)
    setFormName(policy.name)
    setFormDescription(policy.description)
    setFormResourceType(policy.resource_type)
    setFormResourceId(policy.resource_id || '')
    setFormEffect(policy.effect)
    setFormPriority(policy.priority)
    setFormEnabled(policy.enabled)
    const conds = policy.conditions.length > 0 ? policy.conditions : [{ ...emptyCondition }]
    setFormConditions(conds)
    setConditionInputs(conds.map(c => conditionValueToString(c.value)))
    setEditDialogOpen(true)
  }

  const openDelete = (policy: ABACPolicy) => {
    setSelectedPolicy(policy)
    setDeleteDialogOpen(true)
  }

  const handleSave = () => {
    const conditions = formConditions.map((c, i) => ({
      ...c,
      value: parseConditionValue(conditionInputs[i] || '', c.operator),
    }))
    const payload: Partial<ABACPolicy> = {
      name: formName,
      description: formDescription,
      resource_type: formResourceType,
      resource_id: formResourceId || undefined,
      conditions,
      effect: formEffect,
      priority: formPriority,
      enabled: formEnabled,
    }

    if (isCreating) {
      createMutation.mutate(payload)
    } else if (selectedPolicy) {
      updateMutation.mutate({ id: selectedPolicy.id, data: payload })
    }
  }

  const addCondition = () => {
    setFormConditions([...formConditions, { ...emptyCondition }])
    setConditionInputs([...conditionInputs, ''])
  }

  const removeCondition = (index: number) => {
    setFormConditions(formConditions.filter((_, i) => i !== index))
    setConditionInputs(conditionInputs.filter((_, i) => i !== index))
  }

  const updateCondition = (index: number, field: keyof ABACCondition, value: string) => {
    const updated = [...formConditions]
    updated[index] = { ...updated[index], [field]: value }
    setFormConditions(updated)
  }

  const updateConditionInput = (index: number, value: string) => {
    const updated = [...conditionInputs]
    updated[index] = value
    setConditionInputs(updated)
  }

  const handleTest = () => {
    setTestResult(null)
    try {
      const attrs = JSON.parse(testAttributes)
      evaluateMutation.mutate({
        user_attributes: attrs,
        resource_type: testResourceType,
        resource_id: testResourceId,
      })
    } catch {
      toast({ title: 'Invalid JSON', description: 'Please enter valid JSON for user attributes', variant: 'destructive' })
    }
  }

  const filtered = (policies?.items || []).filter(p =>
    !search || p.name.toLowerCase().includes(search.toLowerCase()) ||
    p.description.toLowerCase().includes(search.toLowerCase())
  )

  const totalPages = Math.ceil((policies?.total || 0) / limit)
  const currentPage = Math.floor(offset / limit) + 1

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">ABAC Policies</h1>
          <p className="text-muted-foreground">
            Attribute-Based Access Control policies for fine-grained resource authorization
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => setTestDialogOpen(true)}>
            <FlaskConical className="mr-2 h-4 w-4" />
            Test Policy
          </Button>
          <Button onClick={openCreate}>
            <Plus className="mr-2 h-4 w-4" />
            Create Policy
          </Button>
        </div>
      </div>

      {/* Filters */}
      <Card>
        <CardContent className="pt-6">
          <div className="flex gap-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder="Search policies..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-10"
              />
            </div>
            <Select value={resourceTypeFilter} onValueChange={(val) => { setResourceTypeFilter(val === 'all' ? '' : val); setOffset(0) }}>
              <SelectTrigger className="w-[200px]">
                <SelectValue placeholder="All Resource Types" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Resource Types</SelectItem>
                {resourceTypes.map(rt => (
                  <SelectItem key={rt.value} value={rt.value}>{rt.label}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Table */}
      {isLoading ? (
        <div className="flex justify-center py-12">
          <LoadingSpinner size="lg" />
        </div>
      ) : isError ? (
        <QueryError error={error} resource="ABAC policies" />
      ) : (
        <Card>
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <p className="text-sm text-muted-foreground">
                {policies?.total || 0} {(policies?.total || 0) === 1 ? 'policy' : 'policies'}
              </p>
            </div>
          </CardHeader>
          <CardContent>
            <div className="rounded-md border">
              <table className="w-full">
                <thead>
                  <tr className="border-b bg-muted/50">
                    <th className="p-3 text-left text-sm font-medium">Name</th>
                    <th className="p-3 text-left text-sm font-medium">Resource Type</th>
                    <th className="p-3 text-left text-sm font-medium">Conditions</th>
                    <th className="p-3 text-left text-sm font-medium">Effect</th>
                    <th className="p-3 text-left text-sm font-medium">Priority</th>
                    <th className="p-3 text-left text-sm font-medium">Enabled</th>
                    <th className="p-3 text-right text-sm font-medium">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="p-8 text-center text-muted-foreground">
                        <Filter className="mx-auto mb-2 h-8 w-8 opacity-50" />
                        <p>No ABAC policies found</p>
                      </td>
                    </tr>
                  ) : (
                    filtered.map(policy => (
                      <tr key={policy.id} className="border-b last:border-b-0 hover:bg-muted/25">
                        <td className="p-3">
                          <div>
                            <p className="font-medium">{policy.name}</p>
                            {policy.description && (
                              <p className="text-sm text-muted-foreground truncate max-w-[250px]">{policy.description}</p>
                            )}
                          </div>
                        </td>
                        <td className="p-3">
                          <Badge variant="outline">{policy.resource_type}</Badge>
                          {policy.resource_id && (
                            <span className="ml-1 text-xs text-muted-foreground">({policy.resource_id})</span>
                          )}
                        </td>
                        <td className="p-3">
                          <Badge variant="secondary">{policy.conditions?.length || 0} condition{(policy.conditions?.length || 0) !== 1 ? 's' : ''}</Badge>
                        </td>
                        <td className="p-3">
                          <Badge className={policy.effect === 'allow' ? 'bg-green-100 text-green-800 hover:bg-green-100' : 'bg-red-100 text-red-800 hover:bg-red-100'}>
                            {policy.effect === 'allow' ? <Shield className="mr-1 h-3 w-3" /> : <ShieldOff className="mr-1 h-3 w-3" />}
                            {policy.effect}
                          </Badge>
                        </td>
                        <td className="p-3 text-sm">{policy.priority}</td>
                        <td className="p-3">
                          <Switch
                            checked={policy.enabled}
                            onCheckedChange={() => toggleMutation.mutate(policy)}
                          />
                        </td>
                        <td className="p-3 text-right">
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <Button variant="ghost" size="sm">
                                <MoreHorizontal className="h-4 w-4" />
                              </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end">
                              <DropdownMenuItem onClick={() => openEdit(policy)}>
                                <Edit className="mr-2 h-4 w-4" /> Edit
                              </DropdownMenuItem>
                              <DropdownMenuSeparator />
                              <DropdownMenuItem onClick={() => openDelete(policy)} className="text-red-600">
                                <Trash2 className="mr-2 h-4 w-4" /> Delete
                              </DropdownMenuItem>
                            </DropdownMenuContent>
                          </DropdownMenu>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="flex items-center justify-between pt-4">
                <p className="text-sm text-muted-foreground">
                  Page {currentPage} of {totalPages}
                </p>
                <div className="flex gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setOffset(Math.max(0, offset - limit))}
                    disabled={offset === 0}
                  >
                    <ChevronLeft className="h-4 w-4" />
                    Previous
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setOffset(offset + limit)}
                    disabled={currentPage >= totalPages}
                  >
                    Next
                    <ChevronRight className="h-4 w-4" />
                  </Button>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Create/Edit Dialog */}
      <Dialog open={editDialogOpen} onOpenChange={setEditDialogOpen}>
        <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>{isCreating ? 'Create ABAC Policy' : 'Edit ABAC Policy'}</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>Name</Label>
                <Input
                  placeholder="Policy name"
                  value={formName}
                  onChange={(e) => setFormName(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label>Priority</Label>
                <Input
                  type="number"
                  placeholder="0"
                  value={formPriority}
                  onChange={(e) => setFormPriority(parseInt(e.target.value) || 0)}
                />
              </div>
            </div>
            <div className="space-y-2">
              <Label>Description</Label>
              <Textarea
                placeholder="Policy description..."
                value={formDescription}
                onChange={(e) => setFormDescription(e.target.value)}
              />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>Resource Type</Label>
                <Select value={formResourceType} onValueChange={setFormResourceType}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {resourceTypes.map(rt => (
                      <SelectItem key={rt.value} value={rt.value}>{rt.label}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>Resource ID (optional)</Label>
                <Input
                  placeholder="Specific resource ID"
                  value={formResourceId}
                  onChange={(e) => setFormResourceId(e.target.value)}
                />
              </div>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>Effect</Label>
                <Select value={formEffect} onValueChange={setFormEffect}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="allow">Allow</SelectItem>
                    <SelectItem value="deny">Deny</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="flex items-center gap-3 pt-6">
                <Switch checked={formEnabled} onCheckedChange={setFormEnabled} />
                <Label>Enabled</Label>
              </div>
            </div>

            {/* Conditions Builder */}
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <Label className="text-base font-semibold">Conditions</Label>
                <Button type="button" variant="outline" size="sm" onClick={addCondition}>
                  <Plus className="mr-1 h-3 w-3" /> Add Condition
                </Button>
              </div>
              <p className="text-sm text-muted-foreground">All conditions must match for the policy to apply.</p>
              {formConditions.map((cond, i) => (
                <div key={i} className="flex gap-2 items-start rounded-md border p-3 bg-muted/30">
                  <div className="flex-1 space-y-2">
                    <div className="grid grid-cols-3 gap-2">
                      <Select value={cond.attribute} onValueChange={(val) => updateCondition(i, 'attribute', val)}>
                        <SelectTrigger className="text-xs">
                          <SelectValue placeholder="Attribute" />
                        </SelectTrigger>
                        <SelectContent>
                          {attributeOptions.map(a => (
                            <SelectItem key={a.value} value={a.value}>{a.label}</SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                      <Select value={cond.operator} onValueChange={(val) => updateCondition(i, 'operator', val)}>
                        <SelectTrigger className="text-xs">
                          <SelectValue placeholder="Operator" />
                        </SelectTrigger>
                        <SelectContent>
                          {operatorOptions.map(o => (
                            <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                      <Input
                        placeholder={cond.operator === 'in' || cond.operator === 'not_in' ? 'val1, val2, ...' : cond.operator === 'between' ? 'min, max' : 'value'}
                        value={conditionInputs[i] || ''}
                        onChange={(e) => updateConditionInput(i, e.target.value)}
                        className="text-xs"
                      />
                    </div>
                  </div>
                  {formConditions.length > 1 && (
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      onClick={() => removeCondition(i)}
                      className="text-muted-foreground hover:text-red-600 mt-0.5"
                    >
                      <X className="h-4 w-4" />
                    </Button>
                  )}
                </div>
              ))}
            </div>

            <div className="flex justify-end gap-2 pt-4">
              <Button variant="outline" onClick={() => setEditDialogOpen(false)}>Cancel</Button>
              <Button
                onClick={handleSave}
                disabled={!formName || !formResourceType || createMutation.isPending || updateMutation.isPending}
              >
                {(createMutation.isPending || updateMutation.isPending) && <LoadingSpinner className="mr-2 h-4 w-4" />}
                {isCreating ? 'Create' : 'Save Changes'}
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <AlertDialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete ABAC Policy</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete the policy &quot;{selectedPolicy?.name}&quot;? This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => selectedPolicy && deleteMutation.mutate(selectedPolicy.id)}
              className="bg-red-600 hover:bg-red-700"
            >
              {deleteMutation.isPending ? <LoadingSpinner className="mr-2 h-4 w-4" /> : null}
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Test Policy Dialog */}
      <Dialog open={testDialogOpen} onOpenChange={(open) => { setTestDialogOpen(open); if (!open) setTestResult(null) }}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Test ABAC Policy Evaluation</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>Resource Type</Label>
                <Select value={testResourceType} onValueChange={setTestResourceType}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {resourceTypes.filter(rt => rt.value !== '*').map(rt => (
                      <SelectItem key={rt.value} value={rt.value}>{rt.label}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>Resource ID</Label>
                <Input
                  placeholder="Resource ID"
                  value={testResourceId}
                  onChange={(e) => setTestResourceId(e.target.value)}
                />
              </div>
            </div>
            <div className="space-y-2">
              <Label>User Attributes (JSON)</Label>
              <Textarea
                className="font-mono text-sm"
                rows={6}
                value={testAttributes}
                onChange={(e) => setTestAttributes(e.target.value)}
              />
            </div>
            <Button onClick={handleTest} disabled={evaluateMutation.isPending} className="w-full">
              {evaluateMutation.isPending && <LoadingSpinner className="mr-2 h-4 w-4" />}
              Evaluate
            </Button>

            {testResult && (
              <div className={`rounded-md border p-4 ${testResult.allowed ? 'border-green-200 bg-green-50' : 'border-red-200 bg-red-50'}`}>
                <div className="flex items-center gap-2">
                  {testResult.allowed
                    ? <Shield className="h-5 w-5 text-green-600" />
                    : <ShieldOff className="h-5 w-5 text-red-600" />
                  }
                  <span className={`font-semibold ${testResult.allowed ? 'text-green-800' : 'text-red-800'}`}>
                    {testResult.allowed ? 'ALLOWED' : 'DENIED'}
                  </span>
                </div>
                {testResult.reason && (
                  <p className={`mt-1 text-sm ${testResult.allowed ? 'text-green-700' : 'text-red-700'}`}>
                    {testResult.reason}
                  </p>
                )}
                {testResult.policy_id && (
                  <p className="mt-1 text-xs text-muted-foreground">
                    Matched Policy: {testResult.policy_id}
                  </p>
                )}
              </div>
            )}
          </div>
        </DialogContent>
      </Dialog>
    </div>
  )
}
