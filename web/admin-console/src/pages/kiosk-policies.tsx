import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Plus, Edit, Trash2, Lock, LockOpen, MonitorSmartphone, Tag,
  Smartphone, Users, X,
} from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '../components/ui/table'
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
  DialogDescription,
} from '../components/ui/dialog'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '../components/ui/alert-dialog'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

/**
 * Kiosk policy admin page. Lists policies and lets admins create, edit,
 * delete, and assign them to agents or tags. Mirrors the server-side
 * /api/v1/access/kiosk/policies endpoint surface from Phase 3.
 */

interface KioskPolicy {
  id: string
  name: string
  description: string
  mode: 'single_app' | 'multi_app' | 'off'
  allowed_packages: string[]
  primary_activity?: string
  lock_task_features: string[]
  branding: Record<string, unknown>
  has_exit_pin: boolean
  enabled: boolean
  created_at: string
  updated_at: string
}

interface KioskAssignment {
  id: string
  policy_id: string
  target_kind: 'agent' | 'group' | 'tag'
  target_id: string
  priority: number
  created_at: string
}

const ALL_FEATURES = [
  'home', 'notifications', 'global_actions', 'system_info',
  'keyguard', 'overview', 'blocked_activity',
] as const

export function KioskPoliciesPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [editing, setEditing] = useState<KioskPolicy | null>(null)
  const [editorOpen, setEditorOpen] = useState(false)
  const [assignmentsFor, setAssignmentsFor] = useState<KioskPolicy | null>(null)
  const [confirmDelete, setConfirmDelete] = useState<KioskPolicy | null>(null)

  const { data: policies = [], isLoading, isError, error } = useQuery({
    queryKey: ['kiosk-policies'],
    queryFn: () => api.get<KioskPolicy[]>('/api/v1/access/kiosk/policies'),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/access/kiosk/policies/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['kiosk-policies'] })
      setConfirmDelete(null)
      toast({ title: 'Policy deleted' })
    },
    onError: () => toast({ title: 'Failed to delete policy', variant: 'destructive' }),
  })

  function openCreate() {
    setEditing(null)
    setEditorOpen(true)
  }
  function openEdit(p: KioskPolicy) {
    setEditing(p)
    setEditorOpen(true)
  }

  return (
    <div className="space-y-6 p-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Kiosk policies</h1>
          <p className="text-muted-foreground">
            Lockdown configurations distributed to Android agents via /agent/config.
          </p>
        </div>
        <Button onClick={openCreate}>
          <Plus className="mr-2 h-4 w-4" /> New policy
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Policies</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="py-12 flex justify-center"><LoadingSpinner /></div>
          ) : isError ? (
            <QueryError error={error} resource="kiosk policies" />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Mode</TableHead>
                  <TableHead>Apps</TableHead>
                  <TableHead>Lock features</TableHead>
                  <TableHead>Enabled</TableHead>
                  <TableHead>Updated</TableHead>
                  <TableHead className="w-32" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {policies.map((p) => (
                  <TableRow key={p.id}>
                    <TableCell>
                      <div className="font-medium">{p.name}</div>
                      {p.description && (
                        <div className="text-xs text-muted-foreground">{p.description}</div>
                      )}
                    </TableCell>
                    <TableCell><ModeBadge mode={p.mode} /></TableCell>
                    <TableCell>{p.allowed_packages?.length || 0}</TableCell>
                    <TableCell>
                      <span className="text-sm text-muted-foreground">
                        {p.lock_task_features?.length || 0} feature{(p.lock_task_features?.length || 0) === 1 ? '' : 's'}
                      </span>
                    </TableCell>
                    <TableCell>
                      {p.enabled ? <Badge variant="success">on</Badge> : <Badge variant="secondary">off</Badge>}
                    </TableCell>
                    <TableCell className="text-muted-foreground text-sm">
                      {new Date(p.updated_at).toLocaleDateString()}
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-1">
                        <Button variant="ghost" size="icon" onClick={() => setAssignmentsFor(p)}>
                          <Users className="h-4 w-4" />
                        </Button>
                        <Button variant="ghost" size="icon" onClick={() => openEdit(p)}>
                          <Edit className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="text-destructive"
                          onClick={() => setConfirmDelete(p)}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
                {policies.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center py-8 text-muted-foreground">
                      No policies yet. Click "New policy" to create one.
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {editorOpen && (
        <PolicyEditor
          policy={editing}
          onClose={() => setEditorOpen(false)}
          onSaved={() => {
            setEditorOpen(false)
            queryClient.invalidateQueries({ queryKey: ['kiosk-policies'] })
          }}
        />
      )}

      {assignmentsFor && (
        <AssignmentsDialog
          policy={assignmentsFor}
          onClose={() => setAssignmentsFor(null)}
        />
      )}

      <AlertDialog open={!!confirmDelete} onOpenChange={(o) => !o && setConfirmDelete(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete "{confirmDelete?.name}"?</AlertDialogTitle>
            <AlertDialogDescription>
              All assignments to this policy are also removed. Devices currently in
              kiosk under this policy will exit lock-task at the next config fetch.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => confirmDelete && deleteMutation.mutate(confirmDelete.id)}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}

function ModeBadge({ mode }: { mode: KioskPolicy['mode'] }) {
  if (mode === 'single_app') return <Badge><Lock className="mr-1 h-3 w-3" /> single-app</Badge>
  if (mode === 'multi_app') return <Badge><MonitorSmartphone className="mr-1 h-3 w-3" /> multi-app</Badge>
  return <Badge variant="secondary"><LockOpen className="mr-1 h-3 w-3" /> off</Badge>
}

interface PolicyEditorProps {
  policy: KioskPolicy | null
  onClose: () => void
  onSaved: () => void
}

function PolicyEditor({ policy, onClose, onSaved }: PolicyEditorProps) {
  const { toast } = useToast()
  const isCreate = !policy
  const [name, setName] = useState(policy?.name ?? '')
  const [description, setDescription] = useState(policy?.description ?? '')
  const [mode, setMode] = useState<KioskPolicy['mode']>(policy?.mode ?? 'multi_app')
  const [allowedPackages, setAllowedPackages] = useState<string[]>(policy?.allowed_packages ?? [])
  const [packageInput, setPackageInput] = useState('')
  const [primaryActivity, setPrimaryActivity] = useState(policy?.primary_activity ?? '')
  const [features, setFeatures] = useState<string[]>(policy?.lock_task_features ?? [])
  const [exitPin, setExitPin] = useState('')
  const [enabled, setEnabled] = useState(policy?.enabled ?? true)

  const saveMutation = useMutation({
    mutationFn: async () => {
      const body: any = {
        name,
        description,
        mode,
        allowed_packages: allowedPackages,
        primary_activity: primaryActivity,
        lock_task_features: features,
        enabled,
      }
      if (exitPin) body.exit_pin = exitPin
      if (isCreate) {
        return api.post('/api/v1/access/kiosk/policies', body)
      }
      return api.put(`/api/v1/access/kiosk/policies/${policy!.id}`, body)
    },
    onSuccess: () => {
      toast({ title: isCreate ? 'Policy created' : 'Policy updated' })
      onSaved()
    },
    onError: () => toast({ title: 'Save failed', variant: 'destructive' }),
  })

  function addPackage() {
    const p = packageInput.trim()
    if (!p) return
    if (allowedPackages.includes(p)) return
    setAllowedPackages([...allowedPackages, p])
    setPackageInput('')
  }
  function removePackage(p: string) {
    setAllowedPackages(allowedPackages.filter((x) => x !== p))
  }
  function toggleFeature(f: string) {
    setFeatures((cur) => cur.includes(f) ? cur.filter((x) => x !== f) : [...cur, f])
  }

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{isCreate ? 'New kiosk policy' : `Edit ${policy?.name}`}</DialogTitle>
          <DialogDescription>
            Distributed to Android agents on their next /agent/config cycle.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-sm font-medium">Name</label>
              <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Front desk kiosk" />
            </div>
            <div>
              <label className="text-sm font-medium">Mode</label>
              <select
                value={mode}
                onChange={(e) => setMode(e.target.value as KioskPolicy['mode'])}
                className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm"
              >
                <option value="multi_app">multi-app — curated app grid</option>
                <option value="single_app">single-app — pin one activity</option>
                <option value="off">off — disable kiosk for this target</option>
              </select>
            </div>
          </div>

          <div>
            <label className="text-sm font-medium">Description</label>
            <Input
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Optional"
            />
          </div>

          {mode === 'single_app' && (
            <div>
              <label className="text-sm font-medium">Primary activity</label>
              <Input
                value={primaryActivity}
                onChange={(e) => setPrimaryActivity(e.target.value)}
                placeholder="com.example.app/.MainActivity"
              />
              <p className="text-xs text-muted-foreground mt-1">
                Component name (package/.Activity) that gets pinned full-screen.
              </p>
            </div>
          )}

          {mode !== 'off' && (
            <div>
              <label className="text-sm font-medium">Allowed packages</label>
              <div className="flex gap-2 mt-1">
                <Input
                  value={packageInput}
                  onChange={(e) => setPackageInput(e.target.value)}
                  onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); addPackage() } }}
                  placeholder="com.example.app"
                />
                <Button onClick={addPackage} variant="outline">Add</Button>
              </div>
              {allowedPackages.length > 0 && (
                <div className="flex flex-wrap gap-1 mt-2">
                  {allowedPackages.map((p) => (
                    <Badge key={p} variant="secondary" className="gap-1">
                      <Smartphone className="h-3 w-3" />
                      {p}
                      <button
                        type="button"
                        onClick={() => removePackage(p)}
                        className="ml-1 hover:text-destructive"
                      >
                        <X className="h-3 w-3" />
                      </button>
                    </Badge>
                  ))}
                </div>
              )}
            </div>
          )}

          {mode !== 'off' && (
            <div>
              <label className="text-sm font-medium">Lock-task features</label>
              <div className="grid grid-cols-2 gap-2 mt-2">
                {ALL_FEATURES.map((f) => (
                  <label key={f} className="flex items-center gap-2 text-sm">
                    <input
                      type="checkbox"
                      checked={features.includes(f)}
                      onChange={() => toggleFeature(f)}
                    />
                    {f}
                  </label>
                ))}
              </div>
              <p className="text-xs text-muted-foreground mt-1">
                Features the user can interact with (status bar, notifications, etc.).
                Unchecked = blocked.
              </p>
            </div>
          )}

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-sm font-medium">
                {policy?.has_exit_pin ? 'Rotate exit PIN' : 'Exit PIN'}
              </label>
              <Input
                type="password"
                value={exitPin}
                onChange={(e) => setExitPin(e.target.value)}
                placeholder={policy?.has_exit_pin ? '(leave blank to keep)' : 'optional'}
              />
            </div>
            <div className="flex items-end">
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={enabled}
                  onChange={(e) => setEnabled(e.target.checked)}
                />
                Policy enabled
              </label>
            </div>
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button
            onClick={() => saveMutation.mutate()}
            disabled={!name || saveMutation.isPending}
          >
            {saveMutation.isPending ? 'Saving…' : 'Save'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

interface AssignmentsDialogProps {
  policy: KioskPolicy
  onClose: () => void
}

function AssignmentsDialog({ policy, onClose }: AssignmentsDialogProps) {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [targetKind, setTargetKind] = useState<'agent' | 'tag'>('agent')
  const [targetId, setTargetId] = useState('')
  const [priority, setPriority] = useState('')

  const { data: assignments = [], isLoading } = useQuery({
    queryKey: ['kiosk-policy-assignments', policy.id],
    queryFn: () => api.get<KioskAssignment[]>(`/api/v1/access/kiosk/policies/${policy.id}/assignments`),
  })

  const assignMutation = useMutation({
    mutationFn: () => api.post(`/api/v1/access/kiosk/policies/${policy.id}/assignments`, {
      target_kind: targetKind,
      target_id: targetId,
      priority: priority ? parseInt(priority, 10) : undefined,
    }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['kiosk-policy-assignments', policy.id] })
      setTargetId('')
      setPriority('')
      toast({ title: 'Assigned' })
    },
    onError: () => toast({ title: 'Failed to assign', variant: 'destructive' }),
  })

  const unassignMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/access/kiosk/assignments/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['kiosk-policy-assignments', policy.id] })
      toast({ title: 'Unassigned' })
    },
    onError: () => toast({ title: 'Failed to unassign', variant: 'destructive' }),
  })

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-w-xl">
        <DialogHeader>
          <DialogTitle>Assignments — {policy.name}</DialogTitle>
          <DialogDescription>
            Agent assignments beat tag assignments. Higher priority wins within a kind.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-3">
          <div className="flex gap-2">
            <select
              value={targetKind}
              onChange={(e) => setTargetKind(e.target.value as 'agent' | 'tag')}
              className="h-9 rounded-md border border-input bg-background px-3 text-sm"
            >
              <option value="agent">agent</option>
              <option value="tag">tag</option>
            </select>
            <Input
              value={targetId}
              onChange={(e) => setTargetId(e.target.value)}
              placeholder={targetKind === 'agent' ? 'agent-xxxxxxxx' : 'tag (e.g. front-desk)'}
            />
            <Input
              type="number"
              value={priority}
              onChange={(e) => setPriority(e.target.value)}
              placeholder="priority"
              className="w-24"
            />
            <Button
              onClick={() => assignMutation.mutate()}
              disabled={!targetId || assignMutation.isPending}
            >
              Assign
            </Button>
          </div>

          {isLoading ? (
            <LoadingSpinner />
          ) : (
            <div className="border rounded-md divide-y">
              {assignments.map((a) => (
                <div key={a.id} className="flex items-center justify-between p-2 text-sm">
                  <div className="flex items-center gap-2">
                    {a.target_kind === 'agent'
                      ? <Smartphone className="h-4 w-4 text-muted-foreground" />
                      : <Tag className="h-4 w-4 text-muted-foreground" />}
                    <span className="font-mono">{a.target_id}</span>
                    <Badge variant="outline">priority {a.priority}</Badge>
                  </div>
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={() => unassignMutation.mutate(a.id)}
                  >
                    <X className="h-4 w-4" />
                  </Button>
                </div>
              ))}
              {assignments.length === 0 && (
                <div className="p-4 text-center text-muted-foreground text-sm">
                  No assignments yet.
                </div>
              )}
            </div>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Close</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
