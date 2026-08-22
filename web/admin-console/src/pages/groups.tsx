import React, { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { isAxiosError } from 'axios'
import { Plus, Search, Users, MoreHorizontal, FolderTree, Edit, Trash2, UserPlus, Settings, X, ChevronRight, ChevronLeft, Network } from 'lucide-react'
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
import { TableSkeleton } from '../components/ui/skeleton'
import { QueryError } from '../components/query-error'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

interface Group {
  id: string
  name: string
  description: string
  parent_id: string | null
  allow_self_join: boolean
  require_approval: boolean
  max_members: number | null
  member_count: number
  created_at: string
  updated_at: string
}

// The /api/v1/identity/groups endpoint speaks SCIM (displayName, members[],
// attributes.{description,parentId}, createdAt) while this console is flat
// snake_case. These adapters bridge read/write so the page stays flat; they also
// accept the flat shape defensively in case the API is ever flattened.
type RawGroup = Record<string, unknown>
function toFlatGroup(g: RawGroup): Group {
  const attrs = (g.attributes ?? {}) as Record<string, unknown>
  const members = (g.members ?? []) as unknown[]
  return {
    id: String(g.id ?? ''),
    name: String(g.displayName ?? g.name ?? ''),
    description: String(attrs.description ?? g.description ?? ''),
    parent_id: (attrs.parentId ?? g.parent_id ?? null) as string | null,
    allow_self_join: Boolean(g.allow_self_join ?? false),
    require_approval: Boolean(g.require_approval ?? false),
    max_members: (g.max_members ?? null) as number | null,
    member_count: Number(g.member_count ?? members.length ?? 0),
    created_at: String(g.createdAt ?? g.created_at ?? ''),
    updated_at: String(g.updatedAt ?? g.updated_at ?? ''),
  }
}
function toApiGroup(d: Partial<Group>): Record<string, unknown> {
  const attributes: Record<string, string> = {}
  if (d.description !== undefined) attributes.description = d.description ?? ''
  if (d.parent_id) attributes.parentId = d.parent_id
  const body: Record<string, unknown> = {}
  if (d.name !== undefined) body.displayName = d.name
  if (Object.keys(attributes).length) body.attributes = attributes
  return body
}

interface GroupMember {
  user_id: string
  username: string
  email: string
  first_name: string
  last_name: string
  joined_at: string
}

interface User {
  id: string
  username: string
  email: string
  first_name: string
  last_name: string
}

// /api/v1/identity/users/search returns the SCIM user shape (userName,
// name.givenName, emails[].value); flatten it for the add-member dropdown.
function searchUserToFlat(u: RawGroup): User {
  const name = (u.name ?? {}) as Record<string, unknown>
  const emails = (u.emails ?? []) as Array<{ value?: string }>
  return {
    id: String(u.id ?? ''),
    username: String(u.userName ?? u.username ?? ''),
    email: String(emails[0]?.value ?? u.email ?? ''),
    first_name: String(name.givenName ?? u.first_name ?? ''),
    last_name: String(name.familyName ?? u.last_name ?? ''),
  }
}

export function GroupsPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [search, setSearch] = useState('')
  const [createGroupModal, setCreateGroupModal] = useState(false)
  const [editGroupModal, setEditGroupModal] = useState(false)
  const [manageMembersModal, setManageMembersModal] = useState(false)
  const [groupSettingsModal, setGroupSettingsModal] = useState(false)
  const [selectedGroup, setSelectedGroup] = useState<Group | null>(null)
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    parent_id: '',
  })
  const [groupSettings, setGroupSettings] = useState({
    allowSelfJoin: false,
    requireApproval: false,
    maxMembers: '',
  })
  const [deleteTarget, setDeleteTarget] = useState<{id: string, name: string} | null>(null)
  const [removeMemberTarget, setRemoveMemberTarget] = useState<{userId: string, username: string} | null>(null)
  const [memberSearch, setMemberSearch] = useState('')
  const [userSearchQuery, setUserSearchQuery] = useState('')
  const [debouncedUserSearch, setDebouncedUserSearch] = useState('')
  const [page, setPage] = useState(0)
  const [totalCount, setTotalCount] = useState(0)
  const PAGE_SIZE = 20

  // Debounce user search
  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedUserSearch(userSearchQuery)
    }, 300)
    return () => clearTimeout(timer)
  }, [userSearchQuery])

  const { data: groups, isLoading, isError, error } = useQuery({
    queryKey: ['groups', page, search],
    queryFn: async () => {
      const params = new URLSearchParams()
      params.set('offset', String(page * PAGE_SIZE))
      params.set('limit', String(PAGE_SIZE))
      if (search) params.set('search', search)
      const result = await api.getWithHeaders<RawGroup[]>(`/api/v1/identity/groups?${params.toString()}`)
      const total = parseInt(result.headers['x-total-count'] || '0', 10)
      if (!isNaN(total)) setTotalCount(total)
      return (result.data || []).map(toFlatGroup)
    },
  })

  // Fetch group members when managing members
  const { data: groupMembers, isLoading: membersLoading } = useQuery({
    queryKey: ['groupMembers', selectedGroup?.id],
    queryFn: () => api.get<GroupMember[]>(`/api/v1/identity/groups/${selectedGroup?.id}/members`),
    enabled: !!selectedGroup?.id && manageMembersModal,
  })

  // Search users for adding to group
  const { data: searchedUsers, isLoading: searchingUsers } = useQuery({
    queryKey: ['userSearch', debouncedUserSearch],
    queryFn: async () => {
      const raw = await api.get<RawGroup[]>(`/api/v1/identity/users/search?q=${encodeURIComponent(debouncedUserSearch)}&limit=10`)
      return (raw || []).map(searchUserToFlat)
    },
    enabled: debouncedUserSearch.length >= 2,
  })

  // Create group mutation
  const createGroupMutation = useMutation({
    mutationFn: (groupData: Partial<Group>) =>
      api.post<RawGroup>('/api/v1/identity/groups', toApiGroup(groupData)),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['groups'] })
      toast({
        title: 'Success',
        description: `Group ${toFlatGroup(data).name} created successfully!`,
        variant: 'success',
      })
      setCreateGroupModal(false)
      setFormData({ name: '', description: '', parent_id: '' })
    },
    onError: (error: Error) => {
      toast({
        title: 'Error',
        description: `Failed to create group: ${error.message}`,
        variant: 'destructive',
      })
    },
  })

  // Update group mutation
  const updateGroupMutation = useMutation({
    mutationFn: ({ id, ...groupData }: Partial<Group> & { id: string }) =>
      api.put<RawGroup>(`/api/v1/identity/groups/${id}`, toApiGroup(groupData)),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['groups'] })
      toast({
        title: 'Success',
        description: `Group ${toFlatGroup(data).name} updated successfully!`,
        variant: 'success',
      })
      setEditGroupModal(false)
      setGroupSettingsModal(false)
      setSelectedGroup(null)
    },
    onError: (error: Error) => {
      toast({
        title: 'Error',
        description: `Failed to update group: ${error.message}`,
        variant: 'destructive',
      })
    },
  })

  // Delete group mutation
  const deleteGroupMutation = useMutation({
    mutationFn: (groupId: string) =>
      api.delete(`/api/v1/identity/groups/${groupId}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['groups'] })
      toast({
        title: 'Success',
        description: 'Group deleted successfully!',
        variant: 'success',
      })
    },
    onError: (error: Error) => {
      toast({
        title: 'Error',
        description: `Failed to delete group: ${error.message}`,
        variant: 'destructive',
      })
    },
  })

  // Add member mutation
  const addMemberMutation = useMutation({
    mutationFn: ({ groupId, userId }: { groupId: string; userId: string }) =>
      api.post(`/api/v1/identity/groups/${groupId}/members`, { user_id: userId }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['groupMembers', selectedGroup?.id] })
      queryClient.invalidateQueries({ queryKey: ['groups'] })
      toast({
        title: 'Success',
        description: 'Member added successfully!',
        variant: 'success',
      })
      setUserSearchQuery('')
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
          description: `Failed to add member: ${error.message}`,
          variant: 'destructive',
        })
      }
    },
  })

  // Remove member mutation
  const removeMemberMutation = useMutation({
    mutationFn: ({ groupId, userId }: { groupId: string; userId: string }) =>
      api.delete(`/api/v1/identity/groups/${groupId}/members/${userId}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['groupMembers', selectedGroup?.id] })
      queryClient.invalidateQueries({ queryKey: ['groups'] })
      toast({
        title: 'Success',
        description: 'Member removed successfully!',
        variant: 'success',
      })
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
          description: `Failed to remove member: ${error.message}`,
          variant: 'destructive',
        })
      }
    },
  })

  // Get root groups for parent selection
  const rootGroups = groups?.filter(g => !g.parent_id) || []

  // Build hierarchy map for display
  const getGroupHierarchy = (group: Group): string => {
    if (!group.parent_id) return ''
    const parent = groups?.find(g => g.id === group.parent_id)
    if (!parent) return ''
    const parentHierarchy = getGroupHierarchy(parent)
    return parentHierarchy ? `${parentHierarchy} > ${parent.name}` : parent.name
  }

  // Groups are already filtered server-side via search param
  const filteredGroups = groups

  // Filter members based on search
  const filteredMembers = groupMembers?.filter(member =>
    memberSearch === '' ||
    member.username.toLowerCase().includes(memberSearch.toLowerCase()) ||
    member.email.toLowerCase().includes(memberSearch.toLowerCase()) ||
    member.first_name?.toLowerCase().includes(memberSearch.toLowerCase()) ||
    member.last_name?.toLowerCase().includes(memberSearch.toLowerCase())
  )

  // Filter out users who are already members
  const availableUsers = searchedUsers?.filter(
    user => !groupMembers?.some(member => member.user_id === user.id)
  )

  const handleCreateGroup = () => {
    setFormData({ name: '', description: '', parent_id: '' })
    setCreateGroupModal(true)
  }

  const handleEditGroup = (group: Group) => {
    setSelectedGroup(group)
    setFormData({
      name: group.name,
      description: group.description || '',
      parent_id: group.parent_id || '',
    })
    setEditGroupModal(true)
  }

  const handleManageMembers = (groupId: string) => {
    const group = groups?.find(g => g.id === groupId)
    if (group) {
      setSelectedGroup(group)
      setMemberSearch('')
      setUserSearchQuery('')
      setManageMembersModal(true)
    }
  }

  const handleGroupSettings = (groupId: string) => {
    const group = groups?.find(g => g.id === groupId)
    if (group) {
      setSelectedGroup(group)
      setGroupSettings({
        allowSelfJoin: group.allow_self_join,
        requireApproval: group.require_approval,
        maxMembers: group.max_members?.toString() || '',
      })
      setGroupSettingsModal(true)
    }
  }

  const handleSettingsChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value, type, checked } = e.target
    setGroupSettings(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value
    }))
  }

  const handleSettingsSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (selectedGroup) {
      const maxMembers = groupSettings.maxMembers ? parseInt(groupSettings.maxMembers) : null
      updateGroupMutation.mutate({
        id: selectedGroup.id,
        name: selectedGroup.name,
        description: selectedGroup.description,
        parent_id: selectedGroup.parent_id,
        allow_self_join: groupSettings.allowSelfJoin,
        require_approval: groupSettings.requireApproval,
        max_members: maxMembers,
      })
    }
  }

  const handleDeleteGroup = (groupId: string, groupName: string) => {
    setDeleteTarget({ id: groupId, name: groupName })
  }

  const handleFormSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    if (createGroupModal) {
      createGroupMutation.mutate({
        name: formData.name,
        description: formData.description,
        parent_id: formData.parent_id || null,
      })
    } else if (editGroupModal && selectedGroup) {
      updateGroupMutation.mutate({
        id: selectedGroup.id,
        name: formData.name,
        description: formData.description,
        parent_id: formData.parent_id || null,
      })
    }
  }

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    setFormData(prev => ({ ...prev, [e.target.name]: e.target.value }))
  }

  const handleAddMember = (userId: string) => {
    if (selectedGroup) {
      addMemberMutation.mutate({ groupId: selectedGroup.id, userId })
    }
  }

  const handleRemoveMember = (userId: string, username: string) => {
    setRemoveMemberTarget({ userId, username })
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Groups</h1>
          <p className="text-muted-foreground">Manage user groups and memberships</p>
        </div>
        <Button onClick={handleCreateGroup}>
          <Plus className="mr-2 h-4 w-4" /> Create Group
        </Button>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder="Search groups..."
                value={search}
                onChange={(e) => { setSearch(e.target.value); setPage(0) }}
                className="pl-9"
              />
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <TableSkeleton rows={8} cols={7} />
          ) : isError ? (
            <QueryError error={error} resource="groups" />
          ) : !filteredGroups || filteredGroups.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <FolderTree className="h-12 w-12 text-muted-foreground/40 mb-3" />
              <p className="font-medium">No groups found</p>
              <p className="text-sm">Create a group to organize your users</p>
            </div>
          ) : (
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow className="border-b bg-muted">
                  <TableHead className="p-3 text-left text-sm font-medium">Group</TableHead>
                  <TableHead className="p-3 text-left text-sm font-medium">Description</TableHead>
                  <TableHead className="p-3 text-left text-sm font-medium">Members</TableHead>
                  <TableHead className="p-3 text-left text-sm font-medium">Type</TableHead>
                  <TableHead className="p-3 text-left text-sm font-medium">Ziti Role</TableHead>
                  <TableHead className="p-3 text-left text-sm font-medium">Created</TableHead>
                  <TableHead className="p-3 text-right text-sm font-medium">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredGroups.map((group) => (
                    <TableRow key={group.id} className="border-b hover:bg-muted">
                      <TableCell className="p-3">
                        <div className="flex items-center gap-3">
                          <div className="h-10 w-10 rounded-lg bg-purple-100 flex items-center justify-center">
                            {group.parent_id ? (
                              <FolderTree className="h-5 w-5 text-purple-700" />
                            ) : (
                              <Users className="h-5 w-5 text-purple-700" />
                            )}
                          </div>
                          <div>
                            <p className="font-medium">{group.name}</p>
                            {group.parent_id && (
                              <p className="text-xs text-muted-foreground flex items-center gap-1">
                                <ChevronRight className="h-3 w-3" />
                                {getGroupHierarchy(group)}
                              </p>
                            )}
                          </div>
                        </div>
                      </TableCell>
                      <TableCell className="p-3 text-muted-foreground max-w-xs truncate">
                        {group.description || '-'}
                      </TableCell>
                      <TableCell className="p-3">
                        <div className="flex items-center gap-2">
                          <Users className="h-4 w-4 text-muted-foreground" />
                          <span>{group.member_count}</span>
                          {group.max_members && (
                            <span className="text-muted-foreground">/ {group.max_members}</span>
                          )}
                        </div>
                      </TableCell>
                      <TableCell className="p-3">
                        <div className="flex flex-col gap-1">
                          <Badge variant={group.parent_id ? 'secondary' : 'default'}>
                            {group.parent_id ? 'Subgroup' : 'Root'}
                          </Badge>
                          {group.allow_self_join && (
                            <Badge variant="outline" className="text-xs">Self-join</Badge>
                          )}
                        </div>
                      </TableCell>
                      <TableCell className="p-3">
                        <div className="flex items-center gap-1.5" title={`Members of "${group.name}" get Ziti role attribute "#${group.name}" on their identity`}>
                          <Network className="h-3.5 w-3.5 text-purple-500" />
                          <Badge variant="outline" className="text-xs bg-purple-50 text-purple-700 border-purple-200">
                            #{group.name}
                          </Badge>
                        </div>
                      </TableCell>
                      <TableCell className="p-3 text-muted-foreground">
                        {new Date(group.created_at).toLocaleDateString()}
                      </TableCell>
                      <TableCell className="p-3 text-right">
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="icon">
                              <MoreHorizontal className="h-4 w-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuItem onClick={() => handleEditGroup(group)}>
                              <Edit className="mr-2 h-4 w-4" />
                              Edit Group
                            </DropdownMenuItem>
                            <DropdownMenuItem onClick={() => handleManageMembers(group.id)}>
                              <UserPlus className="mr-2 h-4 w-4" />
                              Manage Members
                            </DropdownMenuItem>
                            <DropdownMenuItem onClick={() => handleGroupSettings(group.id)}>
                              <Settings className="mr-2 h-4 w-4" />
                              Group Settings
                            </DropdownMenuItem>
                            <DropdownMenuSeparator />
                            <DropdownMenuItem
                              className="text-red-600"
                              onClick={() => handleDeleteGroup(group.id, group.name)}
                              disabled={deleteGroupMutation.isPending}
                            >
                              <Trash2 className="mr-2 h-4 w-4" />
                              {deleteGroupMutation.isPending ? 'Deleting...' : 'Delete Group'}
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
                Showing {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, totalCount)} of {totalCount} groups
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

      {/* Create Group Modal */}
      <Dialog open={createGroupModal} onOpenChange={setCreateGroupModal}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Create New Group</DialogTitle>
          </DialogHeader>
          <form onSubmit={handleFormSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="name">Group Name</Label>
              <Input
                id="name"
                name="name"
                value={formData.name}
                onChange={handleInputChange}
                required
                placeholder="Enter group name"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="description">Description</Label>
              <Input
                id="description"
                name="description"
                value={formData.description}
                onChange={handleInputChange}
                placeholder="Enter group description (optional)"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="parent_id">Parent Group (optional)</Label>
              <Select
                value={formData.parent_id}
                onValueChange={(value) => setFormData(prev => ({ ...prev, parent_id: value === 'none' ? '' : value }))}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select parent group (creates subgroup)" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="none">No parent (root group)</SelectItem>
                  {rootGroups.map((group) => (
                    <SelectItem key={group.id} value={group.id}>
                      {group.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="flex justify-end gap-2 pt-4">
              <Button
                type="button"
                variant="outline"
                onClick={() => setCreateGroupModal(false)}
                disabled={createGroupMutation.isPending}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={createGroupMutation.isPending}>
                {createGroupMutation.isPending ? 'Creating...' : 'Create Group'}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* Edit Group Modal */}
      <Dialog open={editGroupModal} onOpenChange={setEditGroupModal}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Edit Group</DialogTitle>
          </DialogHeader>
          <form onSubmit={handleFormSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="edit-name">Group Name</Label>
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
                placeholder="Enter group description (optional)"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="edit-parent">Parent Group</Label>
              <Select
                value={formData.parent_id}
                onValueChange={(value) => setFormData(prev => ({ ...prev, parent_id: value === 'none' ? '' : value }))}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select parent group" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="none">No parent (root group)</SelectItem>
                  {rootGroups
                    .filter(g => g.id !== selectedGroup?.id)
                    .map((group) => (
                      <SelectItem key={group.id} value={group.id}>
                        {group.name}
                      </SelectItem>
                    ))}
                </SelectContent>
              </Select>
            </div>
            <div className="flex justify-end gap-2 pt-4">
              <Button
                type="button"
                variant="outline"
                onClick={() => setEditGroupModal(false)}
                disabled={updateGroupMutation.isPending}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={updateGroupMutation.isPending}>
                {updateGroupMutation.isPending ? 'Updating...' : 'Update Group'}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* Manage Members Modal */}
      <Dialog open={manageMembersModal} onOpenChange={setManageMembersModal}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>Manage Members - {selectedGroup?.name}</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            {/* Add Member Section */}
            <div className="space-y-2">
              <Label>Add Member</Label>
              <div className="relative">
                <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  placeholder="Search users by name or email..."
                  value={userSearchQuery}
                  onChange={(e) => setUserSearchQuery(e.target.value)}
                  className="pl-9"
                />
              </div>
              {searchingUsers && <p className="text-sm text-muted-foreground">Searching...</p>}
              {availableUsers && availableUsers.length > 0 && (
                <div className="border rounded-md max-h-40 overflow-y-auto">
                  {availableUsers.map((user) => (
                    <div
                      key={user.id}
                      className="flex items-center justify-between p-2 hover:bg-muted border-b last:border-b-0"
                    >
                      <div>
                        <p className="text-sm font-medium">
                          {user.first_name} {user.last_name}
                        </p>
                        <p className="text-xs text-muted-foreground">{user.email}</p>
                      </div>
                      <Button
                        size="sm"
                        onClick={() => handleAddMember(user.id)}
                        disabled={addMemberMutation.isPending}
                      >
                        Add
                      </Button>
                    </div>
                  ))}
                </div>
              )}
              {debouncedUserSearch.length >= 2 && availableUsers?.length === 0 && !searchingUsers && (
                <p className="text-sm text-muted-foreground">No users found</p>
              )}
            </div>

            {/* Current Members Section */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <Label>Current Members ({groupMembers?.length || 0})</Label>
                {(groupMembers?.length || 0) > 5 && (
                  <div className="relative w-48">
                    <Search className="absolute left-2 top-1/2 h-3 w-3 -translate-y-1/2 text-muted-foreground" />
                    <Input
                      placeholder="Filter members..."
                      value={memberSearch}
                      onChange={(e) => setMemberSearch(e.target.value)}
                      className="pl-7 h-8 text-sm"
                    />
                  </div>
                )}
              </div>
              <div className="border rounded-md max-h-60 overflow-y-auto">
                {membersLoading ? (
                  <p className="p-4 text-center text-sm text-muted-foreground">Loading members...</p>
                ) : filteredMembers?.length === 0 ? (
                  <p className="p-4 text-center text-sm text-muted-foreground">
                    {memberSearch ? 'No members match your search' : 'No members in this group'}
                  </p>
                ) : (
                  filteredMembers?.map((member) => (
                    <div
                      key={member.user_id}
                      className="flex items-center justify-between p-2 hover:bg-muted border-b last:border-b-0"
                    >
                      <div className="flex items-center gap-3">
                        <div className="h-8 w-8 rounded-full bg-muted flex items-center justify-center">
                          <span className="text-sm font-medium text-muted-foreground">
                            {member.first_name?.[0] || member.username[0].toUpperCase()}
                          </span>
                        </div>
                        <div>
                          <p className="text-sm font-medium">
                            {member.first_name} {member.last_name}
                          </p>
                          <p className="text-xs text-muted-foreground">{member.email}</p>
                        </div>
                      </div>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => handleRemoveMember(member.user_id, member.username)}
                        disabled={removeMemberMutation.isPending}
                        className="text-red-600 hover:text-red-700 hover:bg-red-50"
                      >
                        <X className="h-4 w-4" />
                      </Button>
                    </div>
                  ))
                )}
              </div>
            </div>

            <div className="flex justify-end pt-2">
              <Button variant="outline" onClick={() => setManageMembersModal(false)}>
                Close
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {/* Group Settings Modal */}
      <Dialog open={groupSettingsModal} onOpenChange={setGroupSettingsModal}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Group Settings - {selectedGroup?.name}</DialogTitle>
          </DialogHeader>
          <form onSubmit={handleSettingsSubmit} className="space-y-4">
            <div className="space-y-3">
              <div className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  id="allowSelfJoin"
                  name="allowSelfJoin"
                  checked={groupSettings.allowSelfJoin}
                  onChange={handleSettingsChange}
                  className="rounded"
                />
                <Label htmlFor="allowSelfJoin">Allow users to join without approval</Label>
              </div>
              <div className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  id="requireApproval"
                  name="requireApproval"
                  checked={groupSettings.requireApproval}
                  onChange={handleSettingsChange}
                  className="rounded"
                />
                <Label htmlFor="requireApproval">Require admin approval for new members</Label>
              </div>
            </div>
            <div className="space-y-2">
              <Label htmlFor="maxMembers">Maximum Members (optional)</Label>
              <Input
                id="maxMembers"
                name="maxMembers"
                type="number"
                min="1"
                value={groupSettings.maxMembers}
                onChange={handleSettingsChange}
                placeholder="Leave empty for unlimited"
              />
            </div>
            <div className="flex justify-end gap-2 pt-4">
              <Button
                type="button"
                variant="outline"
                onClick={() => setGroupSettingsModal(false)}
                disabled={updateGroupMutation.isPending}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={updateGroupMutation.isPending}>
                {updateGroupMutation.isPending ? 'Saving...' : 'Save Settings'}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* Delete Group Confirmation */}
      <AlertDialog open={!!deleteTarget} onOpenChange={(open) => !open && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Are you sure?</AlertDialogTitle>
            <AlertDialogDescription>
              {deleteTarget ? `Are you sure you want to delete group "${deleteTarget.name}"? This action cannot be undone.` : ''}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={() => { if (deleteTarget) { deleteGroupMutation.mutate(deleteTarget.id); setDeleteTarget(null) } }}>
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Remove Member Confirmation */}
      <AlertDialog open={!!removeMemberTarget} onOpenChange={(open) => !open && setRemoveMemberTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Are you sure?</AlertDialogTitle>
            <AlertDialogDescription>
              {removeMemberTarget && selectedGroup ? `Remove ${removeMemberTarget.username} from ${selectedGroup.name}?` : ''}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={() => { if (removeMemberTarget && selectedGroup) { removeMemberMutation.mutate({ groupId: selectedGroup.id, userId: removeMemberTarget.userId }); setRemoveMemberTarget(null) } }}>
              Remove
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
