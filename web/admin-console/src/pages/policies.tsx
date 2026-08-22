import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Search, Scale, Shield, Clock, MapPin, AlertTriangle, Edit, Trash2, ToggleLeft, ToggleRight, X, ChevronLeft, ChevronRight, Fingerprint, MoreHorizontal } from 'lucide-react'
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
import { TableSkeleton } from '../components/ui/skeleton'
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '../components/ui/table'
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

interface Policy {
  id: string
  name: string
  description: string
  type: string
  enabled: boolean
  priority: number
  rules: PolicyRule[]
  created_at: string
  updated_at: string
}

interface PolicyRule {
  id: string
  condition: Record<string, unknown>
  effect: string
  priority: number
}

const policyTypeIcons: Record<string, React.ReactNode> = {
  separation_of_duty: <Shield className="h-4 w-4" />,
  risk_based: <AlertTriangle className="h-4 w-4" />,
  timebound: <Clock className="h-4 w-4" />,
  location: <MapPin className="h-4 w-4" />,
  conditional_access: <Fingerprint className="h-4 w-4" />,
}

const policyTypeColors: Record<string, string> = {
  separation_of_duty: 'bg-purple-100 text-purple-800',
  risk_based: 'bg-red-100 text-red-800',
  timebound: 'bg-blue-100 text-blue-800',
  location: 'bg-green-100 text-green-800',
  conditional_access: 'bg-orange-100 text-orange-800',
}

const policyTypeLabels: Record<string, string> = {
  separation_of_duty: 'Separation of Duty',
  risk_based: 'Risk-based',
  timebound: 'Timebound',
  location: 'Location-based',
  conditional_access: 'Conditional Access',
}

const conditionTemplates: Record<string, { key: string; label: string; placeholder: string }[]> = {
  separation_of_duty: [
    { key: 'conflicting_roles', label: 'Conflicting Roles', placeholder: 'e.g., finance_approver, finance_requester' },
  ],
  risk_based: [
    { key: 'min_risk_score', label: 'Min Risk Score', placeholder: 'e.g., 0' },
    { key: 'max_risk_score', label: 'Max Risk Score', placeholder: 'e.g., 100' },
  ],
  timebound: [
    { key: 'start_hour', label: 'Start Hour (0-23)', placeholder: 'e.g., 9' },
    { key: 'end_hour', label: 'End Hour (0-23)', placeholder: 'e.g., 17' },
    { key: 'days', label: 'Days', placeholder: 'e.g., mon,tue,wed,thu,fri' },
  ],
  location: [
    { key: 'allowed_ips', label: 'Allowed IPs', placeholder: 'e.g., 10.0.0.0/8, 192.168.1.0/24' },
    { key: 'blocked_ips', label: 'Blocked IPs', placeholder: 'e.g., 0.0.0.0/0' },
  ],
  conditional_access: [
    { key: 'require_mfa', label: 'Require MFA', placeholder: 'true or false' },
    { key: 'device_trust_required', label: 'Require Trusted Device', placeholder: 'true or false' },
    { key: 'allowed_locations', label: 'Allowed Countries', placeholder: 'e.g., US,CA,GB' },
    { key: 'blocked_locations', label: 'Blocked Countries', placeholder: 'e.g., CN,RU' },
    { key: 'max_risk_score', label: 'Max Risk Score', placeholder: 'e.g., 70' },
  ],
}

const effectOptions = ['allow', 'deny', 'require_approval', 'step_up_mfa']

interface FormRule {
  condition: Record<string, string>
  effect: string
  priority: number
}

export function PoliciesPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [search, setSearch] = useState('')
  const [createModal, setCreateModal] = useState(false)
  const [editModal, setEditModal] = useState(false)
  const [deleteDialog, setDeleteDialog] = useState(false)
  const [selectedPolicy, setSelectedPolicy] = useState<Policy | null>(null)
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    type: 'separation_of_duty',
    enabled: true,
    priority: 0,
  })
  const [rules, setRules] = useState<FormRule[]>([])
  const [page, setPage] = useState(0)
  const [totalCount, setTotalCount] = useState(0)
  const PAGE_SIZE = 20

  const { data: policies, isLoading, isError, error } = useQuery({
    queryKey: ['policies', search, page],
    queryFn: async () => {
      const params = new URLSearchParams()
      params.set('offset', String(page * PAGE_SIZE))
      params.set('limit', String(PAGE_SIZE))
      if (search) params.set('search', search)
      const result = await api.getWithHeaders<Policy[]>(`/api/v1/governance/policies?${params.toString()}`)
      const total = parseInt(result.headers['x-total-count'] || '0', 10)
      if (!isNaN(total)) setTotalCount(total)
      return result.data
    },
  })

  const createPolicyMutation = useMutation({
    mutationFn: (policyData: Partial<Policy>) => api.post('/api/v1/governance/policies', policyData),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['policies'] })
      toast({
        title: 'Success',
        description: 'Policy created successfully!',
        variant: 'success',
      })
      setCreateModal(false)
      resetForm()
    },
    onError: (error: Error) => {
      toast({
        title: 'Error',
        description: `Failed to create policy: ${error.message}`,
        variant: 'destructive',
      })
    },
  })

  const updatePolicyMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<Policy> }) =>
      api.put(`/api/v1/governance/policies/${id}`, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['policies'] })
      toast({
        title: 'Success',
        description: 'Policy updated successfully!',
        variant: 'success',
      })
      setEditModal(false)
      setSelectedPolicy(null)
    },
    onError: (error: Error) => {
      toast({
        title: 'Error',
        description: `Failed to update policy: ${error.message}`,
        variant: 'destructive',
      })
    },
  })

  const deletePolicyMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/governance/policies/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['policies'] })
      toast({
        title: 'Success',
        description: 'Policy deleted successfully!',
        variant: 'success',
      })
      setDeleteDialog(false)
      setSelectedPolicy(null)
    },
    onError: (error: Error) => {
      toast({
        title: 'Error',
        description: `Failed to delete policy: ${error.message}`,
        variant: 'destructive',
      })
    },
  })

  const togglePolicyMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      api.put(`/api/v1/governance/policies/${id}`, { enabled }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['policies'] })
      toast({
        title: 'Success',
        description: 'Policy status updated!',
        variant: 'success',
      })
    },
    onError: (error: Error) => {
      toast({
        title: 'Error',
        description: `Failed to update policy: ${error.message}`,
        variant: 'destructive',
      })
    },
  })

  // Policies are filtered server-side via search param
  const filteredPolicies = policies

  const resetForm = () => {
    setFormData({
      name: '',
      description: '',
      type: 'separation_of_duty',
      enabled: true,
      priority: 0,
    })
    setRules([])
  }

  const handleFormChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => {
    const { name, value, type } = e.target
    setFormData(prev => ({
      ...prev,
      [name]: type === 'number' ? parseInt(value) || 0 : value,
    }))
  }

  const handleCreateSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    createPolicyMutation.mutate({
      id: crypto.randomUUID(),
      ...formData,
      rules: rules.map((r, i) => ({ id: crypto.randomUUID(), condition: r.condition, effect: r.effect, priority: r.priority || i })),
    })
  }

  const handleEditClick = (policy: Policy) => {
    setSelectedPolicy(policy)
    setFormData({
      name: policy.name,
      description: policy.description || '',
      type: policy.type,
      enabled: policy.enabled,
      priority: policy.priority,
    })
    setRules(
      (policy.rules || []).map(r => ({
        condition: Object.fromEntries(Object.entries(r.condition).map(([k, v]) => [k, String(v)])),
        effect: r.effect,
        priority: r.priority,
      }))
    )
    setEditModal(true)
  }

  const handleEditSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!selectedPolicy) return
    updatePolicyMutation.mutate({
      id: selectedPolicy.id,
      data: {
        ...formData,
        rules: rules.map((r, i) => ({ id: crypto.randomUUID(), condition: r.condition, effect: r.effect, priority: r.priority || i })),
      },
    })
  }

  const addRule = () => {
    const templates = conditionTemplates[formData.type] || []
    const emptyCondition: Record<string, string> = {}
    templates.forEach(t => { emptyCondition[t.key] = '' })
    setRules(prev => [...prev, { condition: emptyCondition, effect: 'deny', priority: prev.length }])
  }

  const removeRule = (index: number) => {
    setRules(prev => prev.filter((_, i) => i !== index))
  }

  const updateRuleCondition = (ruleIndex: number, key: string, value: string) => {
    setRules(prev => prev.map((r, i) => i === ruleIndex ? { ...r, condition: { ...r.condition, [key]: value } } : r))
  }

  const updateRuleEffect = (ruleIndex: number, effect: string) => {
    setRules(prev => prev.map((r, i) => i === ruleIndex ? { ...r, effect } : r))
  }

  const updateRulePriority = (ruleIndex: number, priority: number) => {
    setRules(prev => prev.map((r, i) => i === ruleIndex ? { ...r, priority } : r))
  }

  const renderRuleBuilder = () => {
    const templates = conditionTemplates[formData.type] || []
    return (
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <Label className="text-base font-semibold">Rules</Label>
          <Button type="button" variant="outline" size="sm" onClick={addRule}>
            <Plus className="h-3 w-3 mr-1" /> Add Rule
          </Button>
        </div>
        {rules.length === 0 && (
          <p className="text-sm text-muted-foreground">No rules defined. Add rules to specify conditions and effects.</p>
        )}
        {rules.map((rule, ruleIndex) => (
          <div key={ruleIndex} className="border rounded-lg p-3 space-y-3 relative">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium">Rule {ruleIndex + 1}</span>
              <Button type="button" variant="ghost" size="sm" onClick={() => removeRule(ruleIndex)}>
                <X className="h-4 w-4" />
              </Button>
            </div>
            <div className="grid gap-2">
              {templates.map(template => (
                <div key={template.key} className="grid grid-cols-3 gap-2 items-center">
                  <Label className="text-xs">{template.label}</Label>
                  <Input
                    className="col-span-2 h-8 text-sm"
                    placeholder={template.placeholder}
                    value={rule.condition[template.key] || ''}
                    onChange={(e) => updateRuleCondition(ruleIndex, template.key, e.target.value)}
                  />
                </div>
              ))}
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div className="space-y-1">
                <Label className="text-xs">Effect</Label>
                <Select value={rule.effect} onValueChange={(value) => updateRuleEffect(ruleIndex, value)}>
                  <SelectTrigger className="h-8 text-sm">
                    <SelectValue placeholder="Select effect" />
                  </SelectTrigger>
                  <SelectContent>
                    {effectOptions.map(opt => (
                      <SelectItem key={opt} value={opt}>{opt.replace(/_/g, ' ')}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1">
                <Label className="text-xs">Priority</Label>
                <Input
                  type="number"
                  className="h-8 text-sm"
                  value={rule.priority}
                  onChange={(e) => updateRulePriority(ruleIndex, parseInt(e.target.value) || 0)}
                  min={0}
                />
              </div>
            </div>
          </div>
        ))}
      </div>
    )
  }

  const handleDeleteClick = (policy: Policy) => {
    setSelectedPolicy(policy)
    setDeleteDialog(true)
  }

  const handleToggleEnabled = (policy: Policy) => {
    togglePolicyMutation.mutate({
      id: policy.id,
      enabled: !policy.enabled,
    })
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Policies</h1>
          <p className="text-muted-foreground">Manage access control policies</p>
        </div>
        <Button onClick={() => setCreateModal(true)}>
          <Plus className="mr-2 h-4 w-4" /> Create Policy
        </Button>
      </div>

      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className="h-12 w-12 rounded-lg bg-purple-100 flex items-center justify-center">
                <Shield className="h-6 w-6 text-purple-700" />
              </div>
              <div>
                <p className="text-2xl font-bold">
                  {policies?.filter(p => p.type === 'separation_of_duty').length || 0}
                </p>
                <p className="text-sm text-muted-foreground">SoD Policies</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className="h-12 w-12 rounded-lg bg-red-100 flex items-center justify-center">
                <AlertTriangle className="h-6 w-6 text-red-700" />
              </div>
              <div>
                <p className="text-2xl font-bold">
                  {policies?.filter(p => p.type === 'risk_based').length || 0}
                </p>
                <p className="text-sm text-muted-foreground">Risk-based</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className="h-12 w-12 rounded-lg bg-green-100 flex items-center justify-center">
                <ToggleRight className="h-6 w-6 text-green-700" />
              </div>
              <div>
                <p className="text-2xl font-bold">
                  {policies?.filter(p => p.enabled).length || 0}
                </p>
                <p className="text-sm text-muted-foreground">Active</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-4">
              <div className="h-12 w-12 rounded-lg bg-muted flex items-center justify-center">
                <Scale className="h-6 w-6 text-foreground" />
              </div>
              <div>
                <p className="text-2xl font-bold">{policies?.length || 0}</p>
                <p className="text-sm text-muted-foreground">Total Policies</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder="Search policies..."
                value={search}
                onChange={(e) => { setSearch(e.target.value); setPage(0) }}
                className="pl-9"
              />
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <TableSkeleton rows={8} cols={5} />
          ) : isError ? (
            <QueryError error={error} resource="policies" />
          ) : !filteredPolicies || filteredPolicies.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <Shield className="h-12 w-12 text-muted-foreground/40 mb-3" />
              <p className="font-medium">No policies found</p>
              <p className="text-sm">Create a policy to get started with access control</p>
            </div>
          ) : (
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow className="border-b bg-muted">
                  <TableHead className="p-3 text-left text-sm font-medium">Policy</TableHead>
                  <TableHead className="p-3 text-left text-sm font-medium">Type</TableHead>
                  <TableHead className="p-3 text-left text-sm font-medium">Status</TableHead>
                  <TableHead className="p-3 text-left text-sm font-medium">Priority</TableHead>
                  <TableHead className="p-3 text-right text-sm font-medium">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredPolicies?.map((policy) => (
                    <TableRow key={policy.id} className="border-b hover:bg-muted">
                      <TableCell className="p-3">
                        <div className="flex items-center gap-3">
                          <div className={`h-10 w-10 rounded-lg ${policyTypeColors[policy.type]?.split(' ')[0] || 'bg-muted'} flex items-center justify-center`}>
                            {policyTypeIcons[policy.type] || <Scale className="h-5 w-5" />}
                          </div>
                          <div>
                            <p className="font-medium">{policy.name}</p>
                            <p className="text-sm text-muted-foreground max-w-xs truncate">{policy.description || '-'}</p>
                          </div>
                        </div>
                      </TableCell>
                      <TableCell className="p-3">
                        <span className={`inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium ${policyTypeColors[policy.type] || 'bg-muted text-foreground'}`}>
                          {policyTypeIcons[policy.type]}
                          {policyTypeLabels[policy.type] || policy.type}
                        </span>
                      </TableCell>
                      <TableCell className="p-3">
                        <button
                          onClick={() => handleToggleEnabled(policy)}
                          className={`inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium cursor-pointer ${
                            policy.enabled
                              ? 'bg-green-100 text-green-800'
                              : 'bg-muted text-muted-foreground'
                          }`}
                        >
                          {policy.enabled ? (
                            <>
                              <ToggleRight className="h-4 w-4" />
                              Enabled
                            </>
                          ) : (
                            <>
                              <ToggleLeft className="h-4 w-4" />
                              Disabled
                            </>
                          )}
                        </button>
                      </TableCell>
                      <TableCell className="p-3">
                        <Badge variant="outline">{policy.priority}</Badge>
                      </TableCell>
                      <TableCell className="p-3 text-right">
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="sm">
                              <MoreHorizontal className="h-4 w-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuItem onClick={() => handleEditClick(policy)}>
                              <Edit className="h-4 w-4 mr-2" />
                              Edit
                            </DropdownMenuItem>
                            <DropdownMenuItem onClick={() => handleToggleEnabled(policy)}>
                              {policy.enabled ? (
                                <>
                                  <ToggleLeft className="h-4 w-4 mr-2" />
                                  Disable
                                </>
                              ) : (
                                <>
                                  <ToggleRight className="h-4 w-4 mr-2" />
                                  Enable
                                </>
                              )}
                            </DropdownMenuItem>
                            <DropdownMenuSeparator />
                            <DropdownMenuItem
                              onClick={() => handleDeleteClick(policy)}
                              className="text-red-600 focus:text-red-600"
                            >
                              <Trash2 className="h-4 w-4 mr-2" />
                              Delete
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </TableCell>
                    </TableRow>
                  ))}
              </TableBody>
            </Table>
          </div>
          )}

          {/* Pagination Controls */}
          {totalCount > PAGE_SIZE && (
            <div className="flex items-center justify-between pt-4 px-1">
              <p className="text-sm text-muted-foreground">
                Showing {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, totalCount)} of {totalCount} policies
              </p>
              <div className="flex items-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setPage(p => Math.max(0, p - 1))}
                  disabled={page === 0}
                >
                  <ChevronLeft className="h-4 w-4 mr-1" />
                  Previous
                </Button>
                <span className="text-sm text-muted-foreground">
                  Page {page + 1} of {Math.ceil(totalCount / PAGE_SIZE)}
                </span>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setPage(p => p + 1)}
                  disabled={(page + 1) * PAGE_SIZE >= totalCount}
                >
                  Next
                  <ChevronRight className="h-4 w-4 ml-1" />
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Create Policy Modal */}
      <Dialog open={createModal} onOpenChange={setCreateModal}>
        <DialogContent className="sm:max-w-2xl max-h-[85vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Create Policy</DialogTitle>
          </DialogHeader>
          <form onSubmit={handleCreateSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="name">Policy Name *</Label>
              <Input
                id="name"
                name="name"
                value={formData.name}
                onChange={handleFormChange}
                placeholder="e.g., SoD - Finance/Approver"
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="description">Description</Label>
              <Textarea
                id="description"
                name="description"
                value={formData.description}
                onChange={handleFormChange}
                placeholder="Describe what this policy enforces..."
                rows={3}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="type">Policy Type *</Label>
              <Select value={formData.type} onValueChange={(value) => { setFormData(prev => ({ ...prev, type: value })); setRules([]) }}>
                <SelectTrigger>
                  <SelectValue placeholder="Select policy type" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="separation_of_duty">Separation of Duty (SoD)</SelectItem>
                  <SelectItem value="risk_based">Risk-based</SelectItem>
                  <SelectItem value="timebound">Timebound</SelectItem>
                  <SelectItem value="location">Location-based</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="priority">Priority</Label>
              <Input
                id="priority"
                name="priority"
                type="number"
                value={formData.priority}
                onChange={handleFormChange}
                min={0}
                max={100}
              />
              <p className="text-xs text-muted-foreground">Higher priority policies are evaluated first</p>
            </div>
            <div className="flex items-center gap-2">
              <input
                type="checkbox"
                id="enabled"
                name="enabled"
                checked={formData.enabled}
                onChange={(e) => setFormData(prev => ({ ...prev, enabled: e.target.checked }))}
                className="h-4 w-4"
              />
              <Label htmlFor="enabled">Enable policy immediately</Label>
            </div>
            {renderRuleBuilder()}
            <div className="flex justify-end gap-2 pt-4">
              <Button
                type="button"
                variant="outline"
                onClick={() => { setCreateModal(false); resetForm(); }}
                disabled={createPolicyMutation.isPending}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={createPolicyMutation.isPending}>
                {createPolicyMutation.isPending ? 'Creating...' : 'Create Policy'}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* Edit Policy Modal */}
      <Dialog open={editModal} onOpenChange={setEditModal}>
        <DialogContent className="sm:max-w-2xl max-h-[85vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Edit Policy</DialogTitle>
          </DialogHeader>
          <form onSubmit={handleEditSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="edit-name">Policy Name *</Label>
              <Input
                id="edit-name"
                name="name"
                value={formData.name}
                onChange={handleFormChange}
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="edit-description">Description</Label>
              <Textarea
                id="edit-description"
                name="description"
                value={formData.description}
                onChange={handleFormChange}
                rows={3}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="edit-type">Policy Type *</Label>
              <Select value={formData.type} onValueChange={(value) => { setFormData(prev => ({ ...prev, type: value })); setRules([]) }}>
                <SelectTrigger>
                  <SelectValue placeholder="Select policy type" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="separation_of_duty">Separation of Duty (SoD)</SelectItem>
                  <SelectItem value="risk_based">Risk-based</SelectItem>
                  <SelectItem value="timebound">Timebound</SelectItem>
                  <SelectItem value="location">Location-based</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="edit-priority">Priority</Label>
              <Input
                id="edit-priority"
                name="priority"
                type="number"
                value={formData.priority}
                onChange={handleFormChange}
                min={0}
                max={100}
              />
            </div>
            <div className="flex items-center gap-2">
              <input
                type="checkbox"
                id="edit-enabled"
                name="enabled"
                checked={formData.enabled}
                onChange={(e) => setFormData(prev => ({ ...prev, enabled: e.target.checked }))}
                className="h-4 w-4"
              />
              <Label htmlFor="edit-enabled">Policy enabled</Label>
            </div>
            {renderRuleBuilder()}
            <div className="flex justify-end gap-2 pt-4">
              <Button
                type="button"
                variant="outline"
                onClick={() => { setEditModal(false); setSelectedPolicy(null); }}
                disabled={updatePolicyMutation.isPending}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={updatePolicyMutation.isPending}>
                {updatePolicyMutation.isPending ? 'Saving...' : 'Save Changes'}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <AlertDialog open={deleteDialog} onOpenChange={setDeleteDialog}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Policy</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete "{selectedPolicy?.name}"? This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deletePolicyMutation.isPending}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => selectedPolicy && deletePolicyMutation.mutate(selectedPolicy.id)}
              disabled={deletePolicyMutation.isPending}
              className="bg-red-600 hover:bg-red-700"
            >
              {deletePolicyMutation.isPending ? 'Deleting...' : 'Delete'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
