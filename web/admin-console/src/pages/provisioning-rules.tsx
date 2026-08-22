import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Search, MoreHorizontal, Edit, Trash2, ChevronLeft, ChevronRight } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '../components/ui/dropdown-menu'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '../components/ui/dialog'
import { Label } from '../components/ui/label'
import { Textarea } from '../components/ui/textarea'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '../components/ui/select'
import { Switch } from '../components/ui/switch'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '../components/ui/table'
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
import { api, ProvisioningRule, RuleCondition, RuleAction } from '../lib/api'
import { useToast } from '../hooks/use-toast'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'

const TRIGGER_OPTIONS = [
  { value: 'user_created', label: 'User Created' },
  { value: 'user_updated', label: 'User Updated' },
  { value: 'user_deleted', label: 'User Deleted' },
  { value: 'group_membership', label: 'Group Membership' },
  { value: 'attribute_change', label: 'Attribute Change' },
  { value: 'scheduled', label: 'Scheduled' },
]

const OPERATOR_OPTIONS = [
  { value: 'equals', label: 'Equals' },
  { value: 'not_equals', label: 'Not Equals' },
  { value: 'contains', label: 'Contains' },
  { value: 'not_contains', label: 'Not Contains' },
  { value: 'starts_with', label: 'Starts With' },
  { value: 'ends_with', label: 'Ends With' },
  { value: 'regex', label: 'Regex' },
  { value: 'greater_than', label: 'Greater Than' },
  { value: 'less_than', label: 'Less Than' },
]

const ACTION_TYPE_OPTIONS = [
  { value: 'add_to_group', label: 'Add to Group' },
  { value: 'remove_from_group', label: 'Remove from Group' },
  { value: 'assign_role', label: 'Assign Role' },
  { value: 'remove_role', label: 'Remove Role' },
  { value: 'set_attribute', label: 'Set Attribute' },
  { value: 'send_email', label: 'Send Email' },
  { value: 'notify_admin', label: 'Notify Admin' },
  { value: 'disable_account', label: 'Disable Account' },
  { value: 'enable_account', label: 'Enable Account' },
]

interface RuleFormData {
  name: string
  description: string
  trigger: string
  enabled: boolean
  priority: number
  conditions: RuleCondition[]
  actions: RuleAction[]
}

const emptyForm: RuleFormData = {
  name: '',
  description: '',
  trigger: 'user_created',
  enabled: true,
  priority: 0,
  conditions: [],
  actions: [],
}

export function ProvisioningRulesPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [search, setSearch] = useState('')
  const [addModal, setAddModal] = useState(false)
  const [editModal, setEditModal] = useState(false)
  const [selectedRule, setSelectedRule] = useState<ProvisioningRule | null>(null)
  const [formData, setFormData] = useState<RuleFormData>(emptyForm)
  const [deleteTarget, setDeleteTarget] = useState<{id: string, name: string} | null>(null)
  const [page, setPage] = useState(0)
  const [totalCount, setTotalCount] = useState(0)
  const PAGE_SIZE = 20

  const { data: rules, isLoading, isError, error } = useQuery({
    queryKey: ['provisioning-rules', page, search],
    queryFn: async () => {
      const params = new URLSearchParams()
      params.set('offset', String(page * PAGE_SIZE))
      params.set('limit', String(PAGE_SIZE))
      if (search) params.set('search', search)
      const result = await api.getWithHeaders<ProvisioningRule[]>(`/api/v1/provisioning/rules?${params.toString()}`)
      const total = parseInt(result.headers['x-total-count'] || '0', 10)
      if (!isNaN(total)) setTotalCount(total)
      return result.data
    },
  })

  const createMutation = useMutation({
    mutationFn: (data: RuleFormData) => api.createProvisioningRule(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['provisioning-rules'] })
      setAddModal(false)
      setFormData(emptyForm)
      toast({ title: 'Rule created successfully' })
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to create rule.', variant: 'destructive' })
    },
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: RuleFormData }) => api.updateProvisioningRule(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['provisioning-rules'] })
      setEditModal(false)
      setSelectedRule(null)
      toast({ title: 'Rule updated successfully' })
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to update rule.', variant: 'destructive' })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.deleteProvisioningRule(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['provisioning-rules'] })
      toast({ title: 'Rule deleted successfully' })
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to delete rule.', variant: 'destructive' })
    },
  })

  const handleAdd = () => {
    setFormData(emptyForm)
    setAddModal(true)
  }

  const handleEdit = (rule: ProvisioningRule) => {
    setSelectedRule(rule)
    setFormData({
      name: rule.name,
      description: rule.description,
      trigger: rule.trigger,
      enabled: rule.enabled,
      priority: rule.priority,
      conditions: rule.conditions || [],
      actions: rule.actions || [],
    })
    setEditModal(true)
  }

  const handleDelete = (rule: ProvisioningRule) => {
    setDeleteTarget({ id: rule.id, name: rule.name })
  }

  const handleFormSubmit = () => {
    if (editModal && selectedRule) {
      updateMutation.mutate({ id: selectedRule.id, data: formData })
    } else {
      createMutation.mutate(formData)
    }
  }

  const addCondition = () => {
    setFormData({
      ...formData,
      conditions: [...formData.conditions, { field: '', operator: 'equals', value: '' }],
    })
  }

  const removeCondition = (index: number) => {
    setFormData({
      ...formData,
      conditions: formData.conditions.filter((_, i) => i !== index),
    })
  }

  const updateCondition = (index: number, field: keyof RuleCondition, value: string) => {
    const updated = [...formData.conditions]
    updated[index] = { ...updated[index], [field]: value }
    setFormData({ ...formData, conditions: updated })
  }

  const addAction = () => {
    setFormData({
      ...formData,
      actions: [...formData.actions, { type: '', target: '' }],
    })
  }

  const removeAction = (index: number) => {
    setFormData({
      ...formData,
      actions: formData.actions.filter((_, i) => i !== index),
    })
  }

  const updateAction = (index: number, field: keyof RuleAction, value: string) => {
    const updated = [...formData.actions]
    updated[index] = { ...updated[index], [field]: value }
    setFormData({ ...formData, actions: updated })
  }

  // Rules are filtered server-side via search param
  const filteredRules = rules || []

  const triggerLabel = (trigger: string) =>
    TRIGGER_OPTIONS.find((t) => t.value === trigger)?.label || trigger

  if (isLoading) {
    return (
      <div className="flex justify-center items-center h-64">
        <LoadingSpinner />
      </div>
    )
  }

  if (isError) {
    return <QueryError error={error} resource="provisioning rules" />
  }

  const formContent = (
    <div className="space-y-4">
      <div>
        <Label htmlFor="name">Name</Label>
        <Input
          id="name"
          value={formData.name}
          onChange={(e) => setFormData({ ...formData, name: e.target.value })}
          placeholder="Rule name"
        />
      </div>
      <div>
        <Label htmlFor="description">Description</Label>
        <Textarea
          id="description"
          value={formData.description}
          onChange={(e) => setFormData({ ...formData, description: e.target.value })}
          placeholder="Rule description"
        />
      </div>
      <div>
        <Label>Trigger</Label>
        <Select value={formData.trigger} onValueChange={(v) => setFormData({ ...formData, trigger: v })}>
          <SelectTrigger>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {TRIGGER_OPTIONS.map((opt) => (
              <SelectItem key={opt.value} value={opt.value}>{opt.label}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <div>
        <Label htmlFor="priority">Priority</Label>
        <Input
          id="priority"
          type="number"
          value={formData.priority}
          onChange={(e) => setFormData({ ...formData, priority: parseInt(e.target.value) || 0 })}
        />
      </div>
      <div className="flex items-center gap-2">
        <Switch
          checked={formData.enabled}
          onCheckedChange={(checked) => setFormData({ ...formData, enabled: checked })}
        />
        <Label>Enabled</Label>
      </div>

      {/* Conditions */}
      <div>
        <div className="flex items-center justify-between mb-2">
          <Label>Conditions</Label>
          <Button type="button" variant="outline" size="sm" onClick={addCondition}>Add</Button>
        </div>
        {formData.conditions.map((cond, i) => (
          <div key={i} className="flex gap-2 mb-2">
            <Input
              placeholder="Field"
              value={cond.field}
              onChange={(e) => updateCondition(i, 'field', e.target.value)}
              className="flex-1"
            />
            <Select value={cond.operator} onValueChange={(v) => updateCondition(i, 'operator', v)}>
              <SelectTrigger className="w-36">
                <SelectValue placeholder="Operator" />
              </SelectTrigger>
              <SelectContent>
                {OPERATOR_OPTIONS.map((opt) => (
                  <SelectItem key={opt.value} value={opt.value}>{opt.label}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Input
              placeholder="Value"
              value={cond.value}
              onChange={(e) => updateCondition(i, 'value', e.target.value)}
              className="flex-1"
            />
            <Button type="button" variant="ghost" size="sm" onClick={() => removeCondition(i)}>
              <Trash2 className="h-4 w-4" />
            </Button>
          </div>
        ))}
      </div>

      {/* Actions */}
      <div>
        <div className="flex items-center justify-between mb-2">
          <Label>Actions</Label>
          <Button type="button" variant="outline" size="sm" onClick={addAction}>Add</Button>
        </div>
        {formData.actions.map((action, i) => (
          <div key={i} className="flex gap-2 mb-2">
            <Select value={action.type} onValueChange={(v) => updateAction(i, 'type', v)}>
              <SelectTrigger className="flex-1">
                <SelectValue placeholder="Action type" />
              </SelectTrigger>
              <SelectContent>
                {ACTION_TYPE_OPTIONS.map((opt) => (
                  <SelectItem key={opt.value} value={opt.value}>{opt.label}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Input
              placeholder="Target"
              value={action.target}
              onChange={(e) => updateAction(i, 'target', e.target.value)}
              className="flex-1"
            />
            <Button type="button" variant="ghost" size="sm" onClick={() => removeAction(i)}>
              <Trash2 className="h-4 w-4" />
            </Button>
          </div>
        ))}
      </div>

      <div className="flex justify-end gap-2 pt-4">
        <Button variant="outline" onClick={() => { setAddModal(false); setEditModal(false) }}>
          Cancel
        </Button>
        <Button onClick={handleFormSubmit} disabled={createMutation.isPending || updateMutation.isPending}>
          {editModal ? 'Update' : 'Create'}
        </Button>
      </div>
    </div>
  )

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Provisioning Rules</h1>
        <Button onClick={handleAdd}>
          <Plus className="h-4 w-4 mr-2" />
          Add Rule
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Automated Provisioning Rules</CardTitle>
          <CardDescription>
            Define rules to automate user provisioning based on triggers and conditions.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="mb-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
              <Input
                placeholder="Search rules..."
                value={search}
                onChange={(e) => { setSearch(e.target.value); setPage(0) }}
                className="pl-10"
              />
            </div>
          </div>

          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Trigger</TableHead>
                <TableHead>Priority</TableHead>
                <TableHead>Enabled</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredRules.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} className="text-center">
                    No provisioning rules found.
                  </TableCell>
                </TableRow>
              ) : (
                filteredRules.map((rule) => (
                  <TableRow key={rule.id}>
                    <TableCell className="font-medium">{rule.name}</TableCell>
                    <TableCell>
                      <Badge variant="outline">{triggerLabel(rule.trigger)}</Badge>
                    </TableCell>
                    <TableCell>{rule.priority}</TableCell>
                    <TableCell>
                      <Badge variant={rule.enabled ? 'default' : 'secondary'}>
                        {rule.enabled ? 'Enabled' : 'Disabled'}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" size="sm">
                            <MoreHorizontal className="h-4 w-4" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuItem onClick={() => handleEdit(rule)}>
                            <Edit className="mr-2 h-4 w-4" />
                            Edit
                          </DropdownMenuItem>
                          <DropdownMenuItem onClick={() => handleDelete(rule)} className="text-red-600">
                            <Trash2 className="mr-2 h-4 w-4" />
                            Delete
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
          {totalCount > PAGE_SIZE && (
            <div className="flex items-center justify-between pt-4">
              <span className="text-sm text-muted-foreground">
                Page {page + 1} of {Math.ceil(totalCount / PAGE_SIZE)}
              </span>
              <div className="flex gap-2">
                <Button variant="outline" size="sm" onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0}>
                  <ChevronLeft className="h-4 w-4 mr-1" /> Previous
                </Button>
                <Button variant="outline" size="sm" onClick={() => setPage(p => p + 1)} disabled={(page + 1) * PAGE_SIZE >= totalCount}>
                  Next <ChevronRight className="h-4 w-4 ml-1" />
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Add Rule Dialog */}
      <Dialog open={addModal} onOpenChange={setAddModal}>
        <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Add Provisioning Rule</DialogTitle>
          </DialogHeader>
          {formContent}
        </DialogContent>
      </Dialog>

      {/* Edit Rule Dialog */}
      <Dialog open={editModal} onOpenChange={setEditModal}>
        <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Edit Provisioning Rule</DialogTitle>
          </DialogHeader>
          {formContent}
        </DialogContent>
      </Dialog>

      {/* Delete Rule Confirmation */}
      <AlertDialog open={!!deleteTarget} onOpenChange={(open) => !open && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Are you sure?</AlertDialogTitle>
            <AlertDialogDescription>
              {deleteTarget ? `Are you sure you want to delete rule "${deleteTarget.name}"? This action cannot be undone.` : ''}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={() => { if (deleteTarget) { deleteMutation.mutate(deleteTarget.id); setDeleteTarget(null) } }}>
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
