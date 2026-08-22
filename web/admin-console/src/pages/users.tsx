import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { isAxiosError } from 'axios'
import { Plus, Search, MoreHorizontal, Mail, Edit, Trash2, Key, Shield, Download, Upload, ChevronLeft, ChevronRight, Users, Network, LayoutGrid } from 'lucide-react'
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
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { TableSkeleton } from '../components/ui/skeleton'
import { QueryError } from '../components/query-error'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

interface User {
  id: string
  username: string
  email: string
  first_name: string
  last_name: string
  enabled: boolean
  email_verified: boolean
  created_at: string
}

// The /api/v1/identity/users endpoint speaks SCIM (userName, name.givenName,
// emails[].value, active, createdAt) — see internal/identity models + the SCIM
// integration tests — while this console is flat snake_case throughout. These
// adapters bridge the two so the rest of the page stays flat. They also accept
// the flat shape defensively, so they keep working if the API is ever flattened.
type RawUser = Record<string, unknown>
function toFlatUser(u: RawUser): User {
  const name = (u.name ?? {}) as Record<string, unknown>
  const emails = (u.emails ?? []) as Array<{ value?: string; primary?: boolean }>
  return {
    id: String(u.id ?? ''),
    username: String(u.userName ?? u.username ?? ''),
    email: String(emails[0]?.value ?? u.email ?? ''),
    first_name: String(name.givenName ?? u.first_name ?? ''),
    last_name: String(name.familyName ?? u.last_name ?? ''),
    enabled: Boolean(u.enabled ?? u.active ?? false),
    email_verified: Boolean(u.emailVerified ?? u.email_verified ?? false),
    created_at: String(u.createdAt ?? u.created_at ?? ''),
  }
}
function toApiUser(d: Partial<User> & { password?: string }): Record<string, unknown> {
  const body: Record<string, unknown> = {}
  if (d.username !== undefined) body.userName = d.username
  if (d.email !== undefined) body.emails = [{ value: d.email, primary: true }]
  if (d.first_name !== undefined || d.last_name !== undefined) {
    body.name = { givenName: d.first_name ?? '', familyName: d.last_name ?? '' }
  }
  if (d.enabled !== undefined) { body.enabled = d.enabled; body.active = d.enabled }
  if (d.password) body.password = d.password
  return body
}

interface Role {
  id: string
  name: string
  description: string
  is_composite: boolean
  created_at: string
}

interface ZitiInfo {
  ziti_id: string
  name: string
  enrolled: boolean
  attributes: string[]
}

export function UsersPage() {
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const { toast } = useToast()
  const [search, setSearch] = useState('')
  const [addUserModal, setAddUserModal] = useState(false)
  const [editUserModal, setEditUserModal] = useState(false)
  const [manageRolesModal, setManageRolesModal] = useState(false)
  const [selectedUser, setSelectedUser] = useState<User | null>(null)
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    first_name: '',
    last_name: '',
    password: '',
  })
  const [selectedRoles, setSelectedRoles] = useState<string[]>([])
  const [resetPasswordTarget, setResetPasswordTarget] = useState<{id: string, username: string} | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<{id: string, username: string} | null>(null)
  const [importModal, setImportModal] = useState(false)
  const [importFile, setImportFile] = useState<File | null>(null)
  const [page, setPage] = useState(0)
  const [totalCount, setTotalCount] = useState(0)
  const PAGE_SIZE = 20

  // Fetch available roles
  const { data: availableRoles, isLoading: rolesLoading } = useQuery({
    queryKey: ['roles'],
    queryFn: () => api.get<Role[]>('/api/v1/identity/roles'),
  })

  // Fetch user roles when managing roles
  const { data: userRoles, isLoading: userRolesLoading } = useQuery({
    queryKey: ['user-roles', selectedUser?.id],
    queryFn: () => selectedUser ? api.get<Role[]>(`/api/v1/identity/users/${selectedUser.id}/roles`) : [],
    enabled: !!selectedUser && manageRolesModal,
  })

  // Populate selectedRoles when userRoles data loads
  useEffect(() => {
    if (userRoles && manageRolesModal) {
      const roleIds = userRoles.map(role => role.id)
      setSelectedRoles(roleIds)
    }
  }, [userRoles, manageRolesModal])

  // Fetch users
  const { data: users, isLoading, isError, error } = useQuery({
    queryKey: ['users', page, search],
    queryFn: async () => {
      const params = new URLSearchParams()
      params.set('offset', String(page * PAGE_SIZE))
      params.set('limit', String(PAGE_SIZE))
      if (search) params.set('search', search)
      const result = await api.getWithHeaders<RawUser[]>(`/api/v1/identity/users?${params.toString()}`)
      const total = parseInt(result.headers['x-total-count'] || '0', 10)
      if (!isNaN(total)) setTotalCount(total)
      return (result.data || []).map(toFlatUser)
    },
  })

  // Fetch Ziti identity mapping for all users
  const { data: zitiMap } = useQuery({
    queryKey: ['ziti-user-map'],
    queryFn: () => api.get<Record<string, ZitiInfo>>('/api/v1/access/ziti/sync/user-map'),
  })

  // Create user mutation
  const createUserMutation = useMutation({
    mutationFn: (userData: Partial<User> & { password?: string }) =>
      api.post<RawUser>('/api/v1/identity/users', toApiUser(userData)),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
      toast({
        title: 'Success',
        description: `User ${toFlatUser(data).username} created successfully!`,
        variant: 'success',
      })
      setAddUserModal(false)
      setFormData({ username: '', email: '', first_name: '', last_name: '', password: '' })
    },
    onError: (error: Error) => {
      toast({
        title: 'Error',
        description: `Failed to create user: ${error.message}`,
        variant: 'destructive',
      })
    },
  })

  // Update user mutation
  const updateUserMutation = useMutation({
    mutationFn: ({ id, ...userData }: Partial<User> & { id: string; password?: string }) =>
      api.put<RawUser>(`/api/v1/identity/users/${id}`, toApiUser(userData)),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
      toast({
        title: 'Success',
        description: `User ${toFlatUser(data).username} updated successfully!`,
        variant: 'success',
      })
      setEditUserModal(false)
      setSelectedUser(null)
    },
    onError: (error: Error) => {
      toast({
        title: 'Error',
        description: `Failed to update user: ${error.message}`,
        variant: 'destructive',
      })
    },
  })

  // Delete user mutation
  const deleteUserMutation = useMutation({
    mutationFn: (userId: string) =>
      api.delete(`/api/v1/identity/users/${userId}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
      toast({
        title: 'Success',
        description: 'User deleted successfully!',
        variant: 'success',
      })
    },
    onError: (error: Error) => {
      toast({
        title: 'Error',
        description: `Failed to delete user: ${error.message}`,
        variant: 'destructive',
      })
    },
  })

  const importUsersMutation = useMutation({
    mutationFn: (file: File) => {
      const formData = new FormData()
      formData.append('file', file)
      return api.postFormData<{ total: number; created: number; errors: number; details: string[] }>('/api/v1/identity/users/import', formData)
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
      toast({
        title: 'Import Complete',
        description: `${data.created} of ${data.total} users imported. ${data.errors} errors.`,
        variant: data.errors > 0 ? 'destructive' : 'success',
      })
      setImportModal(false)
      setImportFile(null)
    },
    onError: (error: Error) => {
      toast({
        title: 'Error',
        description: `Failed to import users: ${error.message}`,
        variant: 'destructive',
      })
    },
  })

  const handleExportCSV = async () => {
    try {
      const data = await api.get<string>('/api/v1/identity/users/export')
      const blob = new Blob([typeof data === 'string' ? data : JSON.stringify(data)], { type: 'text/csv' })
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = 'users.csv'
      a.click()
      window.URL.revokeObjectURL(url)
    } catch {
      toast({ title: 'Error', description: 'Failed to export users', variant: 'destructive' })
    }
  }

  const handleAddUser = () => {
    setFormData({ username: '', email: '', first_name: '', last_name: '', password: '' })
    setAddUserModal(true)
  }

  const handleEditUser = (user: User) => {
    setSelectedUser(user)
    setFormData({
      username: user.username,
      email: user.email,
      first_name: user.first_name || '',
      last_name: user.last_name || '',
      password: '',
    })
    setEditUserModal(true)
  }

  const handleResetPassword = (userId: string, username: string) => {
    setResetPasswordTarget({ id: userId, username })
  }

  const executeResetPassword = async (userId: string) => {
    try {
      await api.post(`/api/v1/identity/users/${userId}/reset-password`)
      toast({
        title: 'Success',
        description: 'Password reset email sent successfully.',
        variant: 'success',
      })
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : 'Unknown error'
      toast({
        title: 'Error',
        description: `Failed to reset password: ${message}`,
        variant: 'destructive',
      })
    }
  }

  const handleManageRoles = (userId: string) => {
    const user = users?.find(u => u.id === userId)
    if (user) {
      setSelectedUser(user)
      // Reset selected roles - will be populated when userRoles query loads
      setSelectedRoles([])
      setManageRolesModal(true)
    }
  }

  const handleRoleToggle = (roleId: string) => {
    setSelectedRoles(prev =>
      prev.includes(roleId)
        ? prev.filter(id => id !== roleId)
        : [...prev, roleId]
    )
  }

  const handleRolesSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (selectedUser) {
      updateUserRolesMutation.mutate({
        userId: selectedUser.id,
        roleIds: selectedRoles,
      })
    }
  }

  // Update user roles mutation
  const updateUserRolesMutation = useMutation({
    mutationFn: ({ userId, roleIds }: { userId: string; roleIds: string[] }) =>
      api.put(`/api/v1/identity/users/${userId}/roles`, { role_ids: roleIds }),
    onSuccess: (_data, variables) => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
      queryClient.invalidateQueries({ queryKey: ['roles'] })
      queryClient.invalidateQueries({ queryKey: ['user-roles', variables.userId] })
      toast({
        title: 'Success',
        description: `Roles updated for user ${selectedUser?.username}`,
        variant: 'success',
      })
      setManageRolesModal(false)
      setSelectedUser(null)
      setSelectedRoles([])
    },
    onError: (error: Error) => {
      if (isAxiosError(error) && error.response?.status === 403 && error.response?.data?.violations) {
        const violations = error.response.data.violations as Array<{ policy_name: string; reason: string }>
        const details = violations.map((v: { policy_name: string; reason: string }) => `${v.policy_name}: ${v.reason}`).join('\n')
        toast({
          title: 'Policy Violation',
          description: details,
          variant: 'destructive',
        })
      } else {
        toast({
          title: 'Error',
          description: `Failed to update roles: ${error.message}`,
          variant: 'destructive',
        })
      }
    },
  })

  const handleDeleteUser = (userId: string, username: string) => {
    setDeleteTarget({ id: userId, username })
  }

  const handleFormSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    if (addUserModal) {
      createUserMutation.mutate({
        username: formData.username,
        email: formData.email,
        first_name: formData.first_name,
        last_name: formData.last_name,
        password: formData.password,
        enabled: true,
        email_verified: false,
      } as Partial<User> & { password?: string })
    } else if (editUserModal && selectedUser) {
      updateUserMutation.mutate({
        id: selectedUser.id,
        username: formData.username,
        email: formData.email,
        first_name: formData.first_name,
        last_name: formData.last_name,
        enabled: selectedUser.enabled,
        email_verified: selectedUser.email_verified,
      })
    }
  }

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFormData(prev => ({ ...prev, [e.target.name]: e.target.value }))
  }

  // Users are already filtered server-side via search param
  const filteredUsers = users || []

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Users</h1>
          <p className="text-muted-foreground">Manage user accounts and access</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={handleExportCSV}>
            <Download className="mr-2 h-4 w-4" /> Export CSV
          </Button>
          <Button variant="outline" onClick={() => setImportModal(true)}>
            <Upload className="mr-2 h-4 w-4" /> Import CSV
          </Button>
          <Button onClick={handleAddUser}>
            <Plus className="mr-2 h-4 w-4" /> Add User
          </Button>
        </div>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder="Search users..."
                value={search}
                onChange={(e) => { setSearch(e.target.value); setPage(0) }}
                className="pl-9"
              />
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <TableSkeleton rows={8} cols={6} />
          ) : isError ? (
            <QueryError error={error} resource="users" />
          ) : filteredUsers.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <Users className="h-12 w-12 text-muted-foreground/40 mb-3" />
              <p className="font-medium">No users found</p>
              <p className="text-sm">{search ? 'No users match your search criteria' : 'Users will appear here when accounts are created'}</p>
            </div>
          ) : (
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow className="border-b bg-muted">
                  <TableHead className="p-3 text-left text-sm font-medium">User</TableHead>
                  <TableHead className="p-3 text-left text-sm font-medium">Email</TableHead>
                  <TableHead className="p-3 text-left text-sm font-medium">Status</TableHead>
                  <TableHead className="p-3 text-left text-sm font-medium">Ziti</TableHead>
                  <TableHead className="p-3 text-left text-sm font-medium">Created</TableHead>
                  <TableHead className="p-3 text-right text-sm font-medium">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredUsers.map((user) => (
                    <TableRow key={user.id} className="border-b hover:bg-muted">
                      <TableCell className="p-3">
                        <div className="flex items-center gap-3">
                          <div className="h-10 w-10 rounded-full bg-blue-100 flex items-center justify-center">
                            <span className="text-blue-700 font-medium">
                              {user.first_name?.[0] || user.username?.[0]?.toUpperCase() || '?'}
                              {user.last_name?.[0] || ''}
                            </span>
                          </div>
                          <div>
                            <p className="font-medium">
                              {user.first_name && user.last_name
                                ? `${user.first_name} ${user.last_name}`
                                : user.username}
                            </p>
                            <p className="text-sm text-muted-foreground">@{user.username}</p>
                          </div>
                        </div>
                      </TableCell>
                      <TableCell className="p-3">
                        <div className="flex items-center gap-2">
                          <Mail className="h-4 w-4 text-muted-foreground" />
                          {user.email}
                          {user.email_verified && (
                            <Badge variant="outline" className="ml-2">Verified</Badge>
                          )}
                        </div>
                      </TableCell>
                      <TableCell className="p-3">
                        <Badge className={user.enabled ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}>
                          {user.enabled ? 'Active' : 'Disabled'}
                        </Badge>
                      </TableCell>
                      <TableCell className="p-3">
                        {zitiMap && zitiMap[user.id] ? (
                          <div className="flex items-center gap-1.5" title={`Ziti: ${zitiMap[user.id].name}\nRoles: ${zitiMap[user.id].attributes.join(', ') || 'none'}`}>
                            <Network className="h-3.5 w-3.5 text-green-600" />
                            <Badge variant="outline" className="text-xs bg-green-50 text-green-700 border-green-200">
                              {zitiMap[user.id].enrolled ? 'Enrolled' : 'Linked'}
                            </Badge>
                          </div>
                        ) : (
                          <span className="text-xs text-muted-foreground">—</span>
                        )}
                      </TableCell>
                      <TableCell className="p-3 text-muted-foreground">
                        {new Date(user.created_at).toLocaleDateString()}
                      </TableCell>
                      <TableCell className="p-3 text-right">
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="icon">
                              <MoreHorizontal className="h-4 w-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuItem onClick={() => navigate(`/users/${user.id}/access-360`)}>
                              <LayoutGrid className="mr-2 h-4 w-4" />
                              Access 360
                            </DropdownMenuItem>
                            <DropdownMenuSeparator />
                            <DropdownMenuItem onClick={() => handleEditUser(user)}>
                              <Edit className="mr-2 h-4 w-4" />
                              Edit User
                            </DropdownMenuItem>
                            <DropdownMenuItem onClick={() => handleResetPassword(user.id, user.username)}>
                              <Key className="mr-2 h-4 w-4" />
                              Reset Password
                            </DropdownMenuItem>
                            <DropdownMenuItem onClick={() => handleManageRoles(user.id)}>
                              <Shield className="mr-2 h-4 w-4" />
                              Manage Roles
                            </DropdownMenuItem>
                            <DropdownMenuSeparator />
                            <DropdownMenuItem
                              className="text-red-600"
                              onClick={() => handleDeleteUser(user.id, user.username)}
                              disabled={deleteUserMutation.isPending}
                            >
                              <Trash2 className="mr-2 h-4 w-4" />
                              {deleteUserMutation.isPending ? 'Deleting...' : 'Delete User'}
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
                Showing {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, totalCount)} of {totalCount} users
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

      {/* Add User Modal */}
      <Dialog open={addUserModal} onOpenChange={setAddUserModal}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Add New User</DialogTitle>
          </DialogHeader>
          <form onSubmit={handleFormSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="username">Username *</Label>
              <Input
                id="username"
                name="username"
                value={formData.username}
                onChange={handleInputChange}
                required
                placeholder="john.doe"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="email">Email *</Label>
              <Input
                id="email"
                name="email"
                type="email"
                value={formData.email}
                onChange={handleInputChange}
                required
                placeholder="john.doe@example.com"
              />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="first_name">First Name</Label>
                <Input
                  id="first_name"
                  name="first_name"
                  value={formData.first_name}
                  onChange={handleInputChange}
                  placeholder="John"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="last_name">Last Name</Label>
                <Input
                  id="last_name"
                  name="last_name"
                  value={formData.last_name}
                  onChange={handleInputChange}
                  placeholder="Doe"
                />
              </div>
            </div>
            <div className="flex justify-end gap-2 pt-4">
              <Button
                type="button"
                variant="outline"
                onClick={() => setAddUserModal(false)}
                disabled={createUserMutation.isPending}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={createUserMutation.isPending}>
                {createUserMutation.isPending ? 'Creating...' : 'Create User'}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* Edit User Modal */}
      <Dialog open={editUserModal} onOpenChange={setEditUserModal}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Edit User</DialogTitle>
          </DialogHeader>
          <form onSubmit={handleFormSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="edit-username">Username *</Label>
              <Input
                id="edit-username"
                name="username"
                value={formData.username}
                onChange={handleInputChange}
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="edit-email">Email *</Label>
              <Input
                id="edit-email"
                name="email"
                type="email"
                value={formData.email}
                onChange={handleInputChange}
                required
              />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="edit-first_name">First Name</Label>
                <Input
                  id="edit-first_name"
                  name="first_name"
                  value={formData.first_name}
                  onChange={handleInputChange}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="edit-last_name">Last Name</Label>
                <Input
                  id="edit-last_name"
                  name="last_name"
                  value={formData.last_name}
                  onChange={handleInputChange}
                />
              </div>
            </div>
            <div className="flex justify-end gap-2 pt-4">
              <Button
                type="button"
                variant="outline"
                onClick={() => setEditUserModal(false)}
                disabled={updateUserMutation.isPending}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={updateUserMutation.isPending}>
                {updateUserMutation.isPending ? 'Updating...' : 'Update User'}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* Import Users Modal */}
      <Dialog open={importModal} onOpenChange={setImportModal}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Import Users from CSV</DialogTitle>
          </DialogHeader>
          <form onSubmit={(e) => {
            e.preventDefault()
            if (importFile) importUsersMutation.mutate(importFile)
          }} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="csv-file">CSV File</Label>
              <Input
                id="csv-file"
                type="file"
                accept=".csv"
                onChange={(e) => setImportFile(e.target.files?.[0] || null)}
                required
              />
              <p className="text-xs text-muted-foreground">
                CSV file with headers: username, email, first_name, last_name, enabled
              </p>
            </div>
            <div className="flex justify-end gap-2 pt-4">
              <Button type="button" variant="outline" onClick={() => { setImportModal(false); setImportFile(null) }}>
                Cancel
              </Button>
              <Button type="submit" disabled={importUsersMutation.isPending || !importFile}>
                {importUsersMutation.isPending ? 'Importing...' : 'Import'}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* Manage Roles Modal */}
      <Dialog open={manageRolesModal} onOpenChange={setManageRolesModal}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Manage Roles - {selectedUser?.username}</DialogTitle>
          </DialogHeader>
          {rolesLoading || userRolesLoading ? (
            <div className="flex flex-col items-center justify-center py-8">
              <LoadingSpinner size="md" />
              <p className="mt-3 text-sm text-muted-foreground">Loading roles...</p>
            </div>
          ) : (
            <form onSubmit={handleRolesSubmit} className="space-y-4">
              <div className="space-y-3">
                <Label>Available Roles</Label>
                <div className="space-y-2 max-h-64 overflow-y-auto">
                  {availableRoles?.map((role) => (
                    <div key={role.id} className="flex items-center space-x-2">
                      <input
                        type="checkbox"
                        id={`role-${role.id}`}
                        checked={selectedRoles.includes(role.id)}
                        onChange={() => handleRoleToggle(role.id)}
                        className="rounded"
                      />
                      <Label htmlFor={`role-${role.id}`} className="capitalize">
                        {role.name}
                        {role.description && (
                          <span className="text-sm text-muted-foreground ml-2">
                            - {role.description}
                          </span>
                        )}
                      </Label>
                    </div>
                  ))}
                </div>
              </div>
              <div className="flex justify-end gap-2 pt-4">
                <Button type="button" variant="outline" onClick={() => setManageRolesModal(false)}>
                  Cancel
                </Button>
                <Button type="submit" disabled={updateUserRolesMutation.isPending}>
                  {updateUserRolesMutation.isPending ? 'Updating...' : 'Update Roles'}
                </Button>
              </div>
            </form>
          )}
        </DialogContent>
      </Dialog>

      {/* Reset Password Confirmation */}
      <AlertDialog open={!!resetPasswordTarget} onOpenChange={(open) => !open && setResetPasswordTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Are you sure?</AlertDialogTitle>
            <AlertDialogDescription>
              {resetPasswordTarget ? `Are you sure you want to reset the password for "${resetPasswordTarget.username}"?` : ''}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={() => { if (resetPasswordTarget) { executeResetPassword(resetPasswordTarget.id); setResetPasswordTarget(null) } }}>
              Reset Password
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Delete User Confirmation */}
      <AlertDialog open={!!deleteTarget} onOpenChange={(open) => !open && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Are you sure?</AlertDialogTitle>
            <AlertDialogDescription>
              {deleteTarget ? `Are you sure you want to delete user "${deleteTarget.username}"? This action cannot be undone.` : ''}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={() => { if (deleteTarget) { deleteUserMutation.mutate(deleteTarget.id); setDeleteTarget(null) } }}>
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
