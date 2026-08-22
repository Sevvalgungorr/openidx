import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Search, MoreHorizontal, Edit, Trash2, Shield, ShieldCheck, Key, ChevronLeft, ChevronRight } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '../components/ui/table'
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
import { TableSkeleton } from '../components/ui/skeleton'
import { QueryError } from '../components/query-error'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

interface Role {
  id: string
  name: string
  description: string
  is_composite: boolean
  created_at: string
}

interface Permission {
  id: string
  name: string
  description: string
  resource: string
  action: string
}

export function RolesPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [search, setSearch] = useState('')
  const [addRoleModal, setAddRoleModal] = useState(false)
  const [editRoleModal, setEditRoleModal] = useState(false)
  const [selectedRole, setSelectedRole] = useState<Role | null>(null)
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    is_composite: false,
  })
  const [deleteTarget, setDeleteTarget] = useState<{id: string, name: string} | null>(null)
  const [permissionsModal, setPermissionsModal] = useState(false)
  const [permissionsRole, setPermissionsRole] = useState<Role | null>(null)
  const [selectedPermissions, setSelectedPermissions] = useState<string[]>([])
  const [page, setPage] = useState(0)
  const [totalCount, setTotalCount] = useState(0)
  const PAGE_SIZE = 20

  // Fetch roles
  const { data: roles, isLoading, isError, error } = useQuery({
    queryKey: ['roles', page, search],
    queryFn: async () => {
      const params = new URLSearchParams()
      params.set('offset', String(page * PAGE_SIZE))
      params.set('limit', String(PAGE_SIZE))
      if (search) params.set('search', search)
      const result = await api.getWithHeaders<Role[]>(`/api/v1/identity/roles?${params.toString()}`)
      const total = parseInt(result.headers['x-total-count'] || '0', 10)
      if (!isNaN(total)) setTotalCount(total)
      return result.data
    },
  })

  const { data: allPermissions } = useQuery({
    queryKey: ['permissions'],
    queryFn: () => api.get<Permission[]>('/api/v1/identity/permissions'),
  })

  const { data: rolePermissions, isLoading: rolePermsLoading } = useQuery({
    queryKey: ['role-permissions', permissionsRole?.id],
    queryFn: () => permissionsRole ? api.get<Permission[]>(`/api/v1/identity/roles/${permissionsRole.id}/permissions`) : [],
    enabled: !!permissionsRole && permissionsModal,
  })

  const updatePermissionsMutation = useMutation({
    mutationFn: ({ roleId, permissionIds }: { roleId: string; permissionIds: string[] }) =>
      api.put(`/api/v1/identity/roles/${roleId}/permissions`, { permission_ids: permissionIds }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['role-permissions'] })
      toast({
        title: 'Success',
        description: 'Permissions updated successfully!',
        variant: 'success',
      })
      setPermissionsModal(false)
      setPermissionsRole(null)
    },
    onError: (error: Error) => {
      toast({
        title: 'Error',
        description: `Failed to update permissions: ${error.message}`,
        variant: 'destructive',
      })
    },
  })

  useEffect(() => {
    if (rolePermissions && permissionsModal) {
      setSelectedPermissions(rolePermissions.map(p => p.id))
    }
  }, [rolePermissions, permissionsModal])

  const handlePermissionToggle = (permId: string) => {
    setSelectedPermissions(prev =>
      prev.includes(permId) ? prev.filter(id => id !== permId) : [...prev, permId]
    )
  }

  // Create role mutation
  const createRoleMutation = useMutation({
    mutationFn: (roleData: Partial<Role>) =>
      api.post<Role>('/api/v1/identity/roles', roleData),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['roles'] })
      toast({
        title: 'Success',
        description: `Role "${data.name}" created successfully!`,
        variant: 'success',
      })
      setAddRoleModal(false)
      setFormData({ name: '', description: '', is_composite: false })
    },
    onError: (error: Error) => {
      toast({
        title: 'Error',
        description: `Failed to create role: ${error.message}`,
        variant: 'destructive',
      })
    },
  })

  // Update role mutation
  const updateRoleMutation = useMutation({
    mutationFn: ({ id, ...roleData }: Partial<Role> & { id: string }) =>
      api.put<Role>(`/api/v1/identity/roles/${id}`, roleData),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['roles'] })
      toast({
        title: 'Success',
        description: `Role "${data.name}" updated successfully!`,
        variant: 'success',
      })
      setEditRoleModal(false)
      setSelectedRole(null)
    },
    onError: (error: Error) => {
      toast({
        title: 'Error',
        description: `Failed to update role: ${error.message}`,
        variant: 'destructive',
      })
    },
  })

  // Delete role mutation
  const deleteRoleMutation = useMutation({
    mutationFn: (roleId: string) =>
      api.delete(`/api/v1/identity/roles/${roleId}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['roles'] })
      queryClient.invalidateQueries({ queryKey: ['users'] })
      toast({
        title: 'Success',
        description: 'Role deleted successfully!',
        variant: 'success',
      })
    },
    onError: (error: Error) => {
      toast({
        title: 'Error',
        description: `Failed to delete role: ${error.message}`,
        variant: 'destructive',
      })
    },
  })

  const handleAddRole = () => {
    setFormData({ name: '', description: '', is_composite: false })
    setAddRoleModal(true)
  }

  const handleEditRole = (role: Role) => {
    setSelectedRole(role)
    setFormData({
      name: role.name,
      description: role.description || '',
      is_composite: role.is_composite,
    })
    setEditRoleModal(true)
  }

  const handleDeleteRole = (roleId: string, roleName: string) => {
    setDeleteTarget({ id: roleId, name: roleName })
  }

  const handleFormSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    if (addRoleModal) {
      createRoleMutation.mutate({
        name: formData.name,
        description: formData.description,
        is_composite: formData.is_composite,
      })
    } else if (editRoleModal && selectedRole) {
      updateRoleMutation.mutate({
        id: selectedRole.id,
        name: formData.name,
        description: formData.description,
        is_composite: formData.is_composite,
      })
    }
  }

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    const { name, value, type } = e.target
    setFormData(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? (e.target as HTMLInputElement).checked : value
    }))
  }

  // Roles are filtered server-side via search param
  const filteredRoles = roles || []

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Roles</h1>
          <p className="text-muted-foreground">Manage roles and permissions</p>
        </div>
        <Button onClick={handleAddRole}>
          <Plus className="mr-2 h-4 w-4" /> Add Role
        </Button>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder="Search roles..."
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
            <QueryError error={error} resource="roles" />
          ) : filteredRoles.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <ShieldCheck className="h-12 w-12 text-muted-foreground/40 mb-3" />
              <p className="font-medium">No roles found</p>
              <p className="text-sm">{search ? 'No roles found matching your search' : 'Create a role to define access permissions'}</p>
            </div>
          ) : (
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow className="border-b bg-muted">
                  <TableHead className="p-3 text-left text-sm font-medium">Role</TableHead>
                  <TableHead className="p-3 text-left text-sm font-medium">Description</TableHead>
                  <TableHead className="p-3 text-left text-sm font-medium">Type</TableHead>
                  <TableHead className="p-3 text-left text-sm font-medium">Created</TableHead>
                  <TableHead className="p-3 text-right text-sm font-medium">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredRoles.map((role) => (
                    <TableRow key={role.id} className="border-b hover:bg-muted">
                      <TableCell className="p-3">
                        <div className="flex items-center gap-3">
                          <div className="h-10 w-10 rounded-full bg-purple-100 flex items-center justify-center">
                            <Shield className="h-5 w-5 text-purple-700" />
                          </div>
                          <div>
                            <p className="font-medium capitalize">{role.name}</p>
                          </div>
                        </div>
                      </TableCell>
                      <TableCell className="p-3 text-muted-foreground">
                        {role.description || '-'}
                      </TableCell>
                      <TableCell className="p-3">
                        <Badge variant={role.is_composite ? 'default' : 'secondary'}>
                          {role.is_composite ? 'Composite' : 'Simple'}
                        </Badge>
                      </TableCell>
                      <TableCell className="p-3 text-muted-foreground">
                        {new Date(role.created_at).toLocaleDateString()}
                      </TableCell>
                      <TableCell className="p-3 text-right">
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="icon">
                              <MoreHorizontal className="h-4 w-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuItem onClick={() => handleEditRole(role)}>
                              <Edit className="mr-2 h-4 w-4" />
                              Edit Role
                            </DropdownMenuItem>
                            <DropdownMenuItem onClick={() => {
                              setPermissionsRole(role)
                              setSelectedPermissions([])
                              setPermissionsModal(true)
                            }}>
                              <Key className="mr-2 h-4 w-4" />
                              Manage Permissions
                            </DropdownMenuItem>
                            <DropdownMenuSeparator />
                            <DropdownMenuItem
                              className="text-red-600"
                              onClick={() => handleDeleteRole(role.id, role.name)}
                              disabled={deleteRoleMutation.isPending}
                            >
                              <Trash2 className="mr-2 h-4 w-4" />
                              {deleteRoleMutation.isPending ? 'Deleting...' : 'Delete Role'}
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </TableCell>
                    </TableRow>
                  ))
                }
              </TableBody>
            </Table>
          </div>
          )}

          {/* Pagination Controls */}
          {totalCount > PAGE_SIZE && (
            <div className="flex items-center justify-between pt-4 px-1">
              <p className="text-sm text-muted-foreground">
                Showing {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, totalCount)} of {totalCount} roles
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

      {/* Add Role Modal */}
      <Dialog open={addRoleModal} onOpenChange={setAddRoleModal}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Add New Role</DialogTitle>
          </DialogHeader>
          <form onSubmit={handleFormSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="name">Role Name *</Label>
              <Input
                id="name"
                name="name"
                value={formData.name}
                onChange={handleInputChange}
                required
                placeholder="e.g., manager, viewer"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="description">Description</Label>
              <Input
                id="description"
                name="description"
                value={formData.description}
                onChange={handleInputChange}
                placeholder="Role description..."
              />
            </div>
            <div className="flex items-center space-x-2">
              <input
                type="checkbox"
                id="is_composite"
                name="is_composite"
                checked={formData.is_composite}
                onChange={handleInputChange}
                className="rounded"
              />
              <Label htmlFor="is_composite">Composite Role (contains other roles)</Label>
            </div>
            <div className="flex justify-end gap-2 pt-4">
              <Button
                type="button"
                variant="outline"
                onClick={() => setAddRoleModal(false)}
                disabled={createRoleMutation.isPending}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={createRoleMutation.isPending}>
                {createRoleMutation.isPending ? 'Creating...' : 'Create Role'}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* Edit Role Modal */}
      <Dialog open={editRoleModal} onOpenChange={setEditRoleModal}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Edit Role</DialogTitle>
          </DialogHeader>
          <form onSubmit={handleFormSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="edit-name">Role Name *</Label>
              <Input
                id="edit-name"
                name="name"
                value={formData.name}
                onChange={handleInputChange}
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="edit-description">Description</Label>
              <Input
                id="edit-description"
                name="description"
                value={formData.description}
                onChange={handleInputChange}
              />
            </div>
            <div className="flex items-center space-x-2">
              <input
                type="checkbox"
                id="edit-is_composite"
                name="is_composite"
                checked={formData.is_composite}
                onChange={handleInputChange}
                className="rounded"
              />
              <Label htmlFor="edit-is_composite">Composite Role</Label>
            </div>
            <div className="flex justify-end gap-2 pt-4">
              <Button
                type="button"
                variant="outline"
                onClick={() => setEditRoleModal(false)}
                disabled={updateRoleMutation.isPending}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={updateRoleMutation.isPending}>
                {updateRoleMutation.isPending ? 'Updating...' : 'Update Role'}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* Manage Permissions Modal */}
      <Dialog open={permissionsModal} onOpenChange={setPermissionsModal}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Manage Permissions - {permissionsRole?.name}</DialogTitle>
          </DialogHeader>
          {rolePermsLoading ? (
            <div className="py-4 text-center">Loading permissions...</div>
          ) : (
            <form onSubmit={(e) => {
              e.preventDefault()
              if (permissionsRole) {
                updatePermissionsMutation.mutate({ roleId: permissionsRole.id, permissionIds: selectedPermissions })
              }
            }} className="space-y-4">
              <div className="space-y-4 max-h-80 overflow-y-auto">
                {Object.entries(
                  (allPermissions || []).reduce<Record<string, Permission[]>>((acc, perm) => {
                    if (!acc[perm.resource]) acc[perm.resource] = []
                    acc[perm.resource].push(perm)
                    return acc
                  }, {})
                ).map(([resource, perms]) => (
                  <div key={resource} className="space-y-2">
                    <Label className="text-sm font-semibold capitalize">{resource}</Label>
                    <div className="space-y-1 pl-2">
                      {perms.map((perm) => (
                        <div key={perm.id} className="flex items-center space-x-2">
                          <input
                            type="checkbox"
                            id={`perm-${perm.id}`}
                            checked={selectedPermissions.includes(perm.id)}
                            onChange={() => handlePermissionToggle(perm.id)}
                            className="rounded"
                          />
                          <Label htmlFor={`perm-${perm.id}`} className="text-sm font-normal">
                            {perm.name}
                            {perm.description && (
                              <span className="text-muted-foreground ml-1">- {perm.description}</span>
                            )}
                          </Label>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
              <div className="flex justify-end gap-2 pt-4">
                <Button type="button" variant="outline" onClick={() => setPermissionsModal(false)}>
                  Cancel
                </Button>
                <Button type="submit" disabled={updatePermissionsMutation.isPending}>
                  {updatePermissionsMutation.isPending ? 'Saving...' : 'Save Permissions'}
                </Button>
              </div>
            </form>
          )}
        </DialogContent>
      </Dialog>

      {/* Delete Role Confirmation */}
      <AlertDialog open={!!deleteTarget} onOpenChange={(open) => !open && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Are you sure?</AlertDialogTitle>
            <AlertDialogDescription>
              {deleteTarget ? `Are you sure you want to delete role "${deleteTarget.name}"? This will remove the role from all users.` : ''}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={() => { if (deleteTarget) { deleteRoleMutation.mutate(deleteTarget.id); setDeleteTarget(null) } }}>
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
