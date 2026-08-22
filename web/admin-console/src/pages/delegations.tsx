import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Plus,
  MoreHorizontal,
  Edit,
  Trash2,
  UserCheck,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '../components/ui/dropdown-menu'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '../components/ui/dialog'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '../components/ui/select'
import { Label } from '../components/ui/label'
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
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'
import { QueryError } from '../components/query-error'

interface AdminDelegation {
  id: string
  delegate_id: string
  delegate_name?: string
  delegated_by: string
  delegated_by_name?: string
  scope_type: string
  scope_id: string
  scope_name?: string
  permissions: string[]
  enabled: boolean
  expires_at?: string
  created_at: string
  updated_at: string
}

const SCOPE_TYPES = ['group', 'role', 'application', 'organization']

// delegate_id and scope_id are uuid columns server-side; a non-UUID value is
// rejected with a 400 (previously a confusing 500). Validate on the client so
// the operator gets an inline hint instead of a failed submit.
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
function isUuid(value: string): boolean {
  return UUID_RE.test(value.trim())
}

// Where to find the UUID for each scope type, so the "Scope ID" field is not a
// mystery box.
const SCOPE_ID_HINT: Record<string, string> = {
  group: 'Group UUID — copy it from the Groups page.',
  role: 'Role UUID — copy it from the Roles page.',
  application: 'Application UUID — copy it from the Applications page.',
  organization: 'Organization UUID — copy it from the Organizations page.',
}

export function DelegationsPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [scopeFilter, setScopeFilter] = useState('')
  const [addModal, setAddModal] = useState(false)
  const [editModal, setEditModal] = useState(false)
  const [selectedDelegation, setSelectedDelegation] = useState<AdminDelegation | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<{ id: string; name: string } | null>(null)
  const [page, setPage] = useState(0)
  const [totalCount, setTotalCount] = useState(0)
  const PAGE_SIZE = 20

  const [formData, setFormData] = useState({
    delegate_id: '',
    delegated_by: '',
    scope_type: 'group',
    scope_id: '',
    permissions_text: '',
    enabled: true,
    expires_at: '',
  })

  // Fetch delegations
  const { data: delegations, isLoading, isError, error } = useQuery({
    queryKey: ['delegations', page, scopeFilter],
    queryFn: async () => {
      const params = new URLSearchParams()
      params.set('offset', String(page * PAGE_SIZE))
      params.set('limit', String(PAGE_SIZE))
      if (scopeFilter) params.set('scope_type', scopeFilter)
      const result = await api.getWithHeaders<AdminDelegation[]>(`/api/v1/delegations?${params.toString()}`)
      const total = parseInt(result.headers['x-total-count'] || '0', 10)
      if (!isNaN(total)) setTotalCount(total)
      return result.data
    },
  })

  // Create delegation
  const createMutation = useMutation({
    mutationFn: (data: Partial<AdminDelegation>) =>
      api.post<AdminDelegation>('/api/v1/delegations', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['delegations'] })
      toast({ title: 'Success', description: 'Delegation created successfully!', variant: 'success' })
      setAddModal(false)
      resetForm()
    },
    onError: (error: Error) => {
      toast({ title: 'Error', description: `Failed to create delegation: ${error.message}`, variant: 'destructive' })
    },
  })

  // Update delegation
  const updateMutation = useMutation({
    mutationFn: ({ id, ...data }: { id: string } & Record<string, unknown>) =>
      api.put<unknown>(`/api/v1/delegations/${id}`, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['delegations'] })
      toast({ title: 'Success', description: 'Delegation updated successfully!', variant: 'success' })
      setEditModal(false)
      setSelectedDelegation(null)
    },
    onError: (error: Error) => {
      toast({ title: 'Error', description: `Failed to update delegation: ${error.message}`, variant: 'destructive' })
    },
  })

  // Delete delegation
  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/delegations/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['delegations'] })
      toast({ title: 'Success', description: 'Delegation deleted successfully!', variant: 'success' })
    },
    onError: (error: Error) => {
      toast({ title: 'Error', description: `Failed to delete delegation: ${error.message}`, variant: 'destructive' })
    },
  })

  const resetForm = () => {
    setFormData({
      delegate_id: '',
      delegated_by: '',
      scope_type: 'group',
      scope_id: '',
      permissions_text: '',
      enabled: true,
      expires_at: '',
    })
  }

  const handleAdd = () => {
    resetForm()
    setAddModal(true)
  }

  const handleEdit = (d: AdminDelegation) => {
    setSelectedDelegation(d)
    setFormData({
      delegate_id: d.delegate_id,
      delegated_by: d.delegated_by,
      scope_type: d.scope_type,
      scope_id: d.scope_id,
      permissions_text: d.permissions.join(', '),
      enabled: d.enabled,
      expires_at: d.expires_at ? d.expires_at.slice(0, 16) : '',
    })
    setEditModal(true)
  }

  const parsePermissions = (text: string): string[] => {
    return text.split(',').map(s => s.trim()).filter(Boolean)
  }

  const handleFormSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    const permissions = parsePermissions(formData.permissions_text)
    const payload: Record<string, unknown> = {
      delegate_id: formData.delegate_id,
      delegated_by: formData.delegated_by,
      scope_type: formData.scope_type,
      scope_id: formData.scope_id,
      permissions,
      enabled: formData.enabled,
    }
    if (formData.expires_at) {
      payload.expires_at = new Date(formData.expires_at).toISOString()
    }

    if (addModal) {
      createMutation.mutate(payload as Partial<AdminDelegation>)
    } else if (editModal && selectedDelegation) {
      updateMutation.mutate({ id: selectedDelegation.id, ...payload })
    }
  }

  const items = delegations || []

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Delegated Administration</h1>
          <p className="text-muted-foreground">Manage delegated admin permissions for users</p>
        </div>
        <Button onClick={handleAdd}>
          <Plus className="mr-2 h-4 w-4" /> Add Delegation
        </Button>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-4">
            <div className="w-48">
              <Select value={scopeFilter} onValueChange={(v) => { setScopeFilter(v === 'all' ? '' : v); setPage(0) }}>
                <SelectTrigger>
                  <SelectValue placeholder="All scope types" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All scope types</SelectItem>
                  {SCOPE_TYPES.map(t => (
                    <SelectItem key={t} value={t}>{t.charAt(0).toUpperCase() + t.slice(1)}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {isError ? (
            <QueryError error={error} resource="delegations" />
          ) : isLoading ? (
            <div className="flex flex-col items-center justify-center py-12">
              <LoadingSpinner size="lg" />
              <p className="mt-4 text-sm text-muted-foreground">Loading delegations...</p>
            </div>
          ) : items.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <UserCheck className="h-12 w-12 text-muted-foreground/40 mb-3" />
              <p className="font-medium">No delegations found</p>
              <p className="text-sm">Create a delegation to grant scoped admin permissions</p>
            </div>
          ) : (
            <div className="rounded-md border">
              <table className="w-full">
                <thead>
                  <tr className="border-b bg-gray-50">
                    <th className="p-3 text-left text-sm font-medium">Delegate</th>
                    <th className="p-3 text-left text-sm font-medium">Scope Type</th>
                    <th className="p-3 text-left text-sm font-medium">Scope</th>
                    <th className="p-3 text-left text-sm font-medium">Permissions</th>
                    <th className="p-3 text-left text-sm font-medium">Expires</th>
                    <th className="p-3 text-left text-sm font-medium">Enabled</th>
                    <th className="p-3 text-right text-sm font-medium">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((d) => (
                    <tr key={d.id} className="border-b hover:bg-gray-50">
                      <td className="p-3">
                        <div className="flex items-center gap-3">
                          <div className="h-10 w-10 rounded-full bg-blue-100 flex items-center justify-center">
                            <UserCheck className="h-5 w-5 text-blue-700" />
                          </div>
                          <div>
                            <p className="font-medium">{d.delegate_name || d.delegate_id}</p>
                            {d.delegated_by_name && (
                              <p className="text-xs text-gray-500">by {d.delegated_by_name}</p>
                            )}
                          </div>
                        </div>
                      </td>
                      <td className="p-3">
                        <Badge variant="secondary">{d.scope_type}</Badge>
                      </td>
                      <td className="p-3 text-gray-600">
                        {d.scope_name || d.scope_id}
                      </td>
                      <td className="p-3">
                        <div className="flex flex-wrap gap-1">
                          {d.permissions.slice(0, 3).map((p, i) => (
                            <Badge key={i} variant="outline" className="text-xs">{p}</Badge>
                          ))}
                          {d.permissions.length > 3 && (
                            <Badge variant="outline" className="text-xs">+{d.permissions.length - 3} more</Badge>
                          )}
                        </div>
                      </td>
                      <td className="p-3 text-gray-500 text-sm">
                        {d.expires_at ? new Date(d.expires_at).toLocaleDateString() : 'Never'}
                      </td>
                      <td className="p-3">
                        <Badge variant={d.enabled ? 'default' : 'secondary'}>
                          {d.enabled ? 'Yes' : 'No'}
                        </Badge>
                      </td>
                      <td className="p-3 text-right">
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="icon">
                              <MoreHorizontal className="h-4 w-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuItem onClick={() => handleEdit(d)}>
                              <Edit className="mr-2 h-4 w-4" />
                              Edit Delegation
                            </DropdownMenuItem>
                            <DropdownMenuSeparator />
                            <DropdownMenuItem
                              className="text-red-600"
                              onClick={() => setDeleteTarget({ id: d.id, name: d.delegate_name || d.delegate_id })}
                              disabled={deleteMutation.isPending}
                            >
                              <Trash2 className="mr-2 h-4 w-4" />
                              {deleteMutation.isPending ? 'Deleting...' : 'Delete Delegation'}
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Pagination */}
          {totalCount > PAGE_SIZE && (
            <div className="flex items-center justify-between pt-4 px-1">
              <p className="text-sm text-gray-500">
                Showing {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, totalCount)} of {totalCount} delegations
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
                <span className="text-sm text-gray-600">
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

      {/* Add Delegation Modal */}
      <Dialog open={addModal} onOpenChange={setAddModal}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>Add Delegation</DialogTitle>
          </DialogHeader>
          <form onSubmit={handleFormSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="delegate_id">Delegate User ID *</Label>
              <Input
                id="delegate_id"
                value={formData.delegate_id}
                onChange={(e) => setFormData(prev => ({ ...prev, delegate_id: e.target.value }))}
                required
                placeholder="e.g. 00000000-0000-0000-0000-000000000000"
              />
              <p className="text-xs text-gray-500">User UUID of the delegate — copy it from the Users page.</p>
              {formData.delegate_id.trim() !== '' && !isUuid(formData.delegate_id) && (
                <p className="text-xs text-destructive">Must be a user UUID, not a username or email.</p>
              )}
            </div>
            <div className="space-y-2">
              <Label htmlFor="delegated_by">Delegated By (User ID)</Label>
              <Input
                id="delegated_by"
                value={formData.delegated_by}
                onChange={(e) => setFormData(prev => ({ ...prev, delegated_by: e.target.value }))}
                placeholder="Leave empty to use current user"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="scope_type">Scope Type *</Label>
              <Select value={formData.scope_type} onValueChange={(v) => setFormData(prev => ({ ...prev, scope_type: v }))}>
                <SelectTrigger id="scope_type">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {SCOPE_TYPES.map(t => (
                    <SelectItem key={t} value={t}>{t.charAt(0).toUpperCase() + t.slice(1)}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="scope_id">Scope ID *</Label>
              <Input
                id="scope_id"
                value={formData.scope_id}
                onChange={(e) => setFormData(prev => ({ ...prev, scope_id: e.target.value }))}
                required
                placeholder="e.g. 00000000-0000-0000-0000-000000000000"
              />
              <p className="text-xs text-gray-500">
                {SCOPE_ID_HINT[formData.scope_type] ?? 'UUID of the scoped resource.'}
              </p>
              {formData.scope_id.trim() !== '' && !isUuid(formData.scope_id) && (
                <p className="text-xs text-destructive">Must be a {formData.scope_type} UUID, not a name.</p>
              )}
            </div>
            <div className="space-y-2">
              <Label htmlFor="permissions">Permissions (comma-separated)</Label>
              <Input
                id="permissions"
                value={formData.permissions_text}
                onChange={(e) => setFormData(prev => ({ ...prev, permissions_text: e.target.value }))}
                placeholder="users:read, users:write, groups:manage"
              />
              <p className="text-xs text-gray-500">Format: resource:action, separated by commas</p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="expires_at">Expires At (optional)</Label>
              <Input
                id="expires_at"
                type="datetime-local"
                value={formData.expires_at}
                onChange={(e) => setFormData(prev => ({ ...prev, expires_at: e.target.value }))}
              />
            </div>
            <div className="flex items-center space-x-2">
              <input
                type="checkbox"
                id="enabled"
                checked={formData.enabled}
                onChange={(e) => setFormData(prev => ({ ...prev, enabled: e.target.checked }))}
                className="rounded"
              />
              <Label htmlFor="enabled">Enabled</Label>
            </div>
            <div className="flex justify-end gap-2 pt-4">
              <Button type="button" variant="outline" onClick={() => setAddModal(false)} disabled={createMutation.isPending}>
                Cancel
              </Button>
              <Button type="submit" disabled={createMutation.isPending || !isUuid(formData.delegate_id) || !isUuid(formData.scope_id)}>
                {createMutation.isPending ? 'Creating...' : 'Create Delegation'}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* Edit Delegation Modal */}
      <Dialog open={editModal} onOpenChange={setEditModal}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>Edit Delegation</DialogTitle>
          </DialogHeader>
          <form onSubmit={handleFormSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="edit-scope_type">Scope Type</Label>
              <Select value={formData.scope_type} onValueChange={(v) => setFormData(prev => ({ ...prev, scope_type: v }))}>
                <SelectTrigger id="edit-scope_type">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {SCOPE_TYPES.map(t => (
                    <SelectItem key={t} value={t}>{t.charAt(0).toUpperCase() + t.slice(1)}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="edit-scope_id">Scope ID</Label>
              <Input
                id="edit-scope_id"
                value={formData.scope_id}
                onChange={(e) => setFormData(prev => ({ ...prev, scope_id: e.target.value }))}
                placeholder="UUID of the scoped resource"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="edit-permissions">Permissions (comma-separated)</Label>
              <Input
                id="edit-permissions"
                value={formData.permissions_text}
                onChange={(e) => setFormData(prev => ({ ...prev, permissions_text: e.target.value }))}
                placeholder="users:read, users:write, groups:manage"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="edit-expires_at">Expires At</Label>
              <Input
                id="edit-expires_at"
                type="datetime-local"
                value={formData.expires_at}
                onChange={(e) => setFormData(prev => ({ ...prev, expires_at: e.target.value }))}
              />
            </div>
            <div className="flex items-center space-x-2">
              <input
                type="checkbox"
                id="edit-enabled"
                checked={formData.enabled}
                onChange={(e) => setFormData(prev => ({ ...prev, enabled: e.target.checked }))}
                className="rounded"
              />
              <Label htmlFor="edit-enabled">Enabled</Label>
            </div>
            <div className="flex justify-end gap-2 pt-4">
              <Button type="button" variant="outline" onClick={() => setEditModal(false)} disabled={updateMutation.isPending}>
                Cancel
              </Button>
              <Button type="submit" disabled={updateMutation.isPending}>
                {updateMutation.isPending ? 'Updating...' : 'Update Delegation'}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <AlertDialog open={!!deleteTarget} onOpenChange={(open) => !open && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Are you sure?</AlertDialogTitle>
            <AlertDialogDescription>
              {deleteTarget ? `Are you sure you want to delete the delegation for "${deleteTarget.name}"? This will revoke the delegated permissions immediately.` : ''}
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
