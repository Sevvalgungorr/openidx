import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Building2, Plus, Users, Pencil, Trash2 } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Badge } from '../components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table'
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '../components/ui/dialog'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/select'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '../components/ui/alert-dialog'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'

interface Organization {
  id: string
  name: string
  slug: string
  domain?: string
  plan: string
  status: string
  max_users: number
  max_applications: number
  member_count: number
  created_at: string
  updated_at: string
}

interface OrgMember {
  id: string
  organization_id: string
  user_id: string
  role: string
  joined_at: string
  user_email: string
  user_name: string
}

export function OrganizationsPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [createOpen, setCreateOpen] = useState(false)
  const [editOrg, setEditOrg] = useState<Organization | null>(null)
  const [membersOrg, setMembersOrg] = useState<Organization | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<Organization | null>(null)
  const [addMemberOpen, setAddMemberOpen] = useState(false)

  const [form, setForm] = useState({ name: '', slug: '', plan: 'free', max_users: 10, max_applications: 5 })
  const [memberForm, setMemberForm] = useState({ user_id: '', role: 'member' })

  // The backend returns a bare JSON array with an X-Total-Count header (the
  // convention across list endpoints), not a wrapped { organizations, total }
  // object — reading a wrapper key left the org list permanently empty.
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['organizations'],
    queryFn: () => api.get<Organization[]>('/api/v1/organizations'),
  })
  const orgs = data || []

  const { data: membersData } = useQuery({
    queryKey: ['org-members', membersOrg?.id],
    queryFn: () => api.get<OrgMember[]>(`/api/v1/organizations/${membersOrg!.id}/members`),
    enabled: !!membersOrg,
  })
  const members = membersData || []

  const createMutation = useMutation({
    mutationFn: (body: Record<string, unknown>) => api.post('/api/v1/organizations', body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['organizations'] })
      toast({ title: 'Organization created' })
      setCreateOpen(false)
    },
    onError: () => toast({ title: 'Failed to create organization', variant: 'destructive' }),
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, body }: { id: string; body: Record<string, unknown> }) =>
      api.put(`/api/v1/organizations/${id}`, body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['organizations'] })
      toast({ title: 'Organization updated' })
      setEditOrg(null)
    },
    onError: () => toast({ title: 'Failed to update organization', variant: 'destructive' }),
  })

  const addMemberMutation = useMutation({
    mutationFn: ({ orgId, body }: { orgId: string; body: Record<string, unknown> }) =>
      api.post(`/api/v1/organizations/${orgId}/members`, body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['org-members', membersOrg?.id] })
      queryClient.invalidateQueries({ queryKey: ['organizations'] })
      toast({ title: 'Member added' })
      setAddMemberOpen(false)
    },
    onError: () => toast({ title: 'Failed to add member', variant: 'destructive' }),
  })

  const removeMemberMutation = useMutation({
    mutationFn: ({ orgId, userId }: { orgId: string; userId: string }) =>
      api.delete(`/api/v1/organizations/${orgId}/members/${userId}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['org-members', membersOrg?.id] })
      queryClient.invalidateQueries({ queryKey: ['organizations'] })
      toast({ title: 'Member removed' })
    },
  })

  const openCreate = () => {
    setEditOrg(null)
    setForm({ name: '', slug: '', plan: 'free', max_users: 10, max_applications: 5 })
    setCreateOpen(true)
  }

  const openEdit = (org: Organization) => {
    setEditOrg(org)
    setForm({ name: org.name, slug: org.slug, plan: org.plan, max_users: org.max_users, max_applications: org.max_applications })
    setCreateOpen(true)
  }

  const handleSave = () => {
    if (editOrg) {
      updateMutation.mutate({ id: editOrg.id, body: { name: form.name, plan: form.plan, status: editOrg.status } })
    } else {
      createMutation.mutate(form)
    }
  }

  const planColor = (plan: string) => {
    switch (plan) {
      case 'enterprise': return 'default'
      case 'team': return 'secondary'
      default: return 'outline'
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Organizations</h1>
          <p className="text-muted-foreground">Manage multi-tenant organizations</p>
        </div>
        <Button onClick={openCreate}><Plus className="mr-2 h-4 w-4" />Create Organization</Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><Building2 className="h-5 w-5" />All Organizations</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex flex-col items-center justify-center py-12">
              <LoadingSpinner size="lg" />
              <p className="mt-4 text-sm text-muted-foreground">Loading organizations...</p>
            </div>
          ) : isError ? (
            <QueryError error={error} resource="organizations" />
          ) : orgs.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <Building2 className="h-12 w-12 text-muted-foreground/40 mb-3" />
              <p className="font-medium">No organizations found</p>
              <p className="text-sm">Create an organization to enable multi-tenancy</p>
            </div>
          ) : (
            <Table>
              <TableHeader><TableRow>
                <TableHead>Name</TableHead><TableHead>Slug</TableHead><TableHead>Plan</TableHead>
                <TableHead>Status</TableHead><TableHead>Members</TableHead><TableHead>Created</TableHead><TableHead>Actions</TableHead>
              </TableRow></TableHeader>
              <TableBody>
                {orgs.map(org => (
                  <TableRow key={org.id}>
                    <TableCell className="font-medium">{org.name}</TableCell>
                    <TableCell className="text-muted-foreground">/{org.slug}</TableCell>
                    <TableCell><Badge variant={planColor(org.plan) as 'default' | 'secondary' | 'outline'}>{org.plan}</Badge></TableCell>
                    <TableCell>
                      <Badge variant={org.status === 'active' ? 'default' : 'secondary'}>{org.status}</Badge>
                    </TableCell>
                    <TableCell>
                      <button className="flex items-center gap-1 text-blue-600 hover:underline" onClick={() => setMembersOrg(org)}>
                        <Users className="h-3 w-3" />{org.member_count}
                      </button>
                    </TableCell>
                    <TableCell>{new Date(org.created_at).toLocaleDateString()}</TableCell>
                    <TableCell>
                      <div className="flex gap-1">
                        <Button variant="ghost" size="sm" onClick={() => openEdit(org)}>
                          <Pencil className="h-4 w-4" />
                        </Button>
                        <Button variant="ghost" size="sm" onClick={() => setDeleteTarget(org)}>
                          <Trash2 className="h-4 w-4 text-red-500" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Create/Edit Dialog */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent className="max-w-lg">
          <DialogHeader><DialogTitle>{editOrg ? 'Edit Organization' : 'Create Organization'}</DialogTitle></DialogHeader>
          <div className="space-y-4">
            <div>
              <label className="text-sm font-medium">Name</label>
              <Input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} placeholder="Organization name" />
            </div>
            {!editOrg && (
              <div>
                <label className="text-sm font-medium">Slug</label>
                <Input value={form.slug} onChange={e => setForm(f => ({ ...f, slug: e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, '') }))} placeholder="org-slug" />
              </div>
            )}
            <div>
              <label className="text-sm font-medium">Plan</label>
              <Select value={form.plan} onValueChange={v => setForm(f => ({ ...f, plan: v }))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="free">Free</SelectItem>
                  <SelectItem value="team">Team</SelectItem>
                  <SelectItem value="enterprise">Enterprise</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-sm font-medium">Max Users</label>
                <Input type="number" value={form.max_users} onChange={e => setForm(f => ({ ...f, max_users: parseInt(e.target.value) || 10 }))} />
              </div>
              <div>
                <label className="text-sm font-medium">Max Applications</label>
                <Input type="number" value={form.max_applications} onChange={e => setForm(f => ({ ...f, max_applications: parseInt(e.target.value) || 5 }))} />
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>Cancel</Button>
            <Button disabled={!form.name || createMutation.isPending || updateMutation.isPending} onClick={handleSave}>
              {editOrg ? 'Update' : 'Create'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Members Dialog */}
      <Dialog open={!!membersOrg} onOpenChange={open => { if (!open) setMembersOrg(null) }}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Members — {membersOrg?.name}</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div className="flex justify-end">
              <Button size="sm" onClick={() => { setMemberForm({ user_id: '', role: 'member' }); setAddMemberOpen(true) }}>
                <Plus className="mr-2 h-4 w-4" />Add Member
              </Button>
            </div>
            <Table>
              <TableHeader><TableRow>
                <TableHead>Name</TableHead><TableHead>Email</TableHead><TableHead>Role</TableHead><TableHead>Joined</TableHead><TableHead>Actions</TableHead>
              </TableRow></TableHeader>
              <TableBody>
                {members.map(m => (
                  <TableRow key={m.id}>
                    <TableCell>{m.user_name}</TableCell>
                    <TableCell>{m.user_email}</TableCell>
                    <TableCell><Badge variant={m.role === 'owner' ? 'default' : 'outline'}>{m.role}</Badge></TableCell>
                    <TableCell>{new Date(m.joined_at).toLocaleDateString()}</TableCell>
                    <TableCell>
                      {m.role !== 'owner' && (
                        <Button variant="ghost" size="sm" onClick={() => membersOrg && removeMemberMutation.mutate({ orgId: membersOrg.id, userId: m.user_id })}>
                          <Trash2 className="h-4 w-4 text-red-500" />
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </DialogContent>
      </Dialog>

      {/* Add Member Dialog */}
      <Dialog open={addMemberOpen} onOpenChange={setAddMemberOpen}>
        <DialogContent>
          <DialogHeader><DialogTitle>Add Member</DialogTitle></DialogHeader>
          <div className="space-y-4">
            <div>
              <label className="text-sm font-medium">User ID</label>
              <Input value={memberForm.user_id} onChange={e => setMemberForm(f => ({ ...f, user_id: e.target.value }))} placeholder="User UUID" />
            </div>
            <div>
              <label className="text-sm font-medium">Role</label>
              <Select value={memberForm.role} onValueChange={v => setMemberForm(f => ({ ...f, role: v }))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="member">Member</SelectItem>
                  <SelectItem value="admin">Admin</SelectItem>
                  <SelectItem value="owner">Owner</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setAddMemberOpen(false)}>Cancel</Button>
            <Button disabled={!memberForm.user_id} onClick={() => membersOrg && addMemberMutation.mutate({ orgId: membersOrg.id, body: memberForm })}>
              Add
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <AlertDialog open={!!deleteTarget} onOpenChange={open => !open && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Organization</AlertDialogTitle>
            <AlertDialogDescription>
              Delete &quot;{deleteTarget?.name}&quot;? This will remove all members and cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={() => deleteTarget && api.delete(`/api/v1/organizations/${deleteTarget.id}`).then(() => {
              queryClient.invalidateQueries({ queryKey: ['organizations'] })
              toast({ title: 'Organization deleted' })
              setDeleteTarget(null)
            })}>Delete</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
