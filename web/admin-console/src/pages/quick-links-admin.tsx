import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Pencil, Trash2, Link2 } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Textarea } from '../components/ui/textarea'
import { Badge } from '../components/ui/badge'
import { Checkbox } from '../components/ui/checkbox'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from '../components/ui/dialog'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/select'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '../components/ui/alert-dialog'
import { api, QuickLink, QuickLinkInput } from '../lib/api'
import { QueryError } from '../components/query-error'
import { useToast } from '../hooks/use-toast'

const CATEGORIES = ['Support', 'Collaboration', 'Monitoring', 'IT', 'Other']
const ROLES = ['user', 'operator', 'admin', 'super_admin']
const ICONS = ['Link2', 'Video', 'MessageSquare', 'Headphones', 'LifeBuoy', 'Monitor', 'Server', 'Ticket', 'Globe', 'Mail', 'Phone', 'Terminal']

const emptyForm: QuickLinkInput = {
  title: '', description: '', category: 'Support', icon: 'Link2',
  type: 'external', url: '', pam_entry_id: '', min_role: 'user',
  sort_order: 0, enabled: true, open_in_new: true,
}

export function QuickLinksAdminPage() {
  const qc = useQueryClient()
  const { toast } = useToast()
  const [showDialog, setShowDialog] = useState(false)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [form, setForm] = useState<QuickLinkInput>(emptyForm)
  const [deleteLink, setDeleteLink] = useState<QuickLink | null>(null)

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['quick-links-admin'],
    queryFn: () => api.quickLinks.list(),
  })
  // PAM entries to reference for type='pam' links (session entries only).
  const { data: pamData } = useQuery({
    queryKey: ['pam-entries-for-quicklinks'],
    queryFn: () => api.pam.listEntries(),
  })
  const sessionEntries = (pamData?.entries || []).filter((e) => e.kind === 'session')

  const invalidate = () => qc.invalidateQueries({ queryKey: ['quick-links-admin'] })

  const save = useMutation({
    mutationFn: async () => {
      if (editingId) return api.quickLinks.update(editingId, form)
      await api.quickLinks.create(form)
      return { status: 'created' }
    },
    onSuccess: () => {
      invalidate()
      setShowDialog(false)
      toast({ title: editingId ? 'Quick link updated' : 'Quick link created' })
    },
    onError: (e: Error) => toast({ title: 'Save failed', description: e.message, variant: 'destructive' }),
  })

  const del = useMutation({
    mutationFn: (id: string) => api.quickLinks.remove(id),
    onSuccess: () => { invalidate(); setDeleteLink(null); toast({ title: 'Quick link deleted' }) },
    onError: (e: Error) => toast({ title: 'Delete failed', description: e.message, variant: 'destructive' }),
  })

  const openCreate = () => { setEditingId(null); setForm(emptyForm); setShowDialog(true) }
  const openEdit = (l: QuickLink) => {
    setEditingId(l.id)
    setForm({
      title: l.title, description: l.description, category: l.category, icon: l.icon,
      type: l.type, url: l.url, pam_entry_id: l.pam_entry_id, min_role: l.min_role,
      sort_order: l.sort_order, enabled: l.enabled, open_in_new: l.open_in_new,
    })
    setShowDialog(true)
  }

  const links = data?.quick_links || []

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Quick Links</h1>
          <p className="text-muted-foreground">Curate the support/collaboration launcher your users see.</p>
        </div>
        <Button onClick={openCreate}><Plus className="h-4 w-4 mr-1" /> Add link</Button>
      </div>

      <Card>
        <CardHeader><CardTitle className="text-base">All quick links</CardTitle></CardHeader>
        <CardContent>
          {isLoading ? (
            <p className="text-center py-8 text-muted-foreground">Loading…</p>
          ) : isError ? (
            <QueryError error={error} resource="quick links" />
          ) : links.length === 0 ? (
            <div className="text-center py-8">
              <Link2 className="h-10 w-10 mx-auto text-muted-foreground mb-3" />
              <p className="font-medium">No quick links yet</p>
              <p className="text-sm text-muted-foreground">Add Teams, Zoom, a status page, or a PAM connection.</p>
            </div>
          ) : (
            <div className="divide-y">
              {links.map((l) => (
                <div key={l.id} className="flex items-center gap-3 py-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-medium truncate">{l.title}</span>
                      <Badge variant={l.type === 'pam' ? 'secondary' : 'outline'} className="text-xs">{l.type}</Badge>
                      <Badge variant="outline" className="text-xs">{l.category}</Badge>
                      {!l.enabled && <Badge variant="destructive" className="text-xs">disabled</Badge>}
                      <Badge variant="outline" className="text-xs">≥ {l.min_role}</Badge>
                    </div>
                    <p className="text-sm text-muted-foreground truncate">{l.type === 'external' ? l.url : `PAM: ${l.pam_entry_id || ''}`}</p>
                  </div>
                  <Button size="sm" variant="ghost" onClick={() => openEdit(l)}><Pencil className="h-4 w-4" /></Button>
                  <Button size="sm" variant="ghost" onClick={() => setDeleteLink(l)}><Trash2 className="h-4 w-4 text-red-500" /></Button>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Create / edit dialog */}
      <Dialog open={showDialog} onOpenChange={setShowDialog}>
        <DialogContent className="max-w-lg">
          <DialogHeader><DialogTitle>{editingId ? 'Edit quick link' : 'Add quick link'}</DialogTitle></DialogHeader>
          <div className="space-y-3">
            <div>
              <label className="text-sm font-medium">Title</label>
              <Input value={form.title} onChange={(e) => setForm((f) => ({ ...f, title: e.target.value }))} placeholder="Microsoft Teams" />
            </div>
            <div>
              <label className="text-sm font-medium">Description</label>
              <Textarea value={form.description} onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))} rows={2} />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-sm font-medium">Type</label>
                <Select value={form.type} onValueChange={(v) => setForm((f) => ({ ...f, type: v as 'external' | 'pam' }))}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="external">External URL</SelectItem>
                    <SelectItem value="pam">PAM connection</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div>
                <label className="text-sm font-medium">Category</label>
                <Select value={form.category} onValueChange={(v) => setForm((f) => ({ ...f, category: v }))}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>{CATEGORIES.map((c) => <SelectItem key={c} value={c}>{c}</SelectItem>)}</SelectContent>
                </Select>
              </div>
            </div>

            {form.type === 'external' ? (
              <div>
                <label className="text-sm font-medium">URL</label>
                <Input value={form.url} onChange={(e) => setForm((f) => ({ ...f, url: e.target.value }))} placeholder="https://teams.microsoft.com" />
              </div>
            ) : (
              <div>
                <label className="text-sm font-medium">PAM connection</label>
                <Select value={form.pam_entry_id || ''} onValueChange={(v) => setForm((f) => ({ ...f, pam_entry_id: v }))}>
                  <SelectTrigger><SelectValue placeholder="Select a connection…" /></SelectTrigger>
                  <SelectContent>
                    {sessionEntries.map((e) => (
                      <SelectItem key={e.id} value={e.id}>{e.name} ({e.entry_type})</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            )}

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-sm font-medium">Icon</label>
                <Select value={form.icon} onValueChange={(v) => setForm((f) => ({ ...f, icon: v }))}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>{ICONS.map((i) => <SelectItem key={i} value={i}>{i}</SelectItem>)}</SelectContent>
                </Select>
              </div>
              <div>
                <label className="text-sm font-medium">Minimum role</label>
                <Select value={form.min_role} onValueChange={(v) => setForm((f) => ({ ...f, min_role: v }))}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>{ROLES.map((r) => <SelectItem key={r} value={r}>{r}</SelectItem>)}</SelectContent>
                </Select>
              </div>
            </div>

            <div className="flex flex-wrap gap-4 pt-1">
              <label className="flex items-center gap-2 text-sm">
                <Checkbox checked={form.enabled} onCheckedChange={(v) => setForm((f) => ({ ...f, enabled: !!v }))} />
                Enabled
              </label>
              {form.type === 'external' && (
                <label className="flex items-center gap-2 text-sm">
                  <Checkbox checked={form.open_in_new} onCheckedChange={(v) => setForm((f) => ({ ...f, open_in_new: !!v }))} />
                  Open in new tab
                </label>
              )}
              <div className="flex items-center gap-2 text-sm">
                <span>Sort</span>
                <Input type="number" className="w-20 h-8" value={form.sort_order} onChange={(e) => setForm((f) => ({ ...f, sort_order: Number(e.target.value) }))} />
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowDialog(false)}>Cancel</Button>
            <Button onClick={() => save.mutate()} disabled={save.isPending || !form.title}>{editingId ? 'Save' : 'Create'}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <AlertDialog open={!!deleteLink} onOpenChange={(o) => { if (!o) setDeleteLink(null) }}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete quick link?</AlertDialogTitle>
            <AlertDialogDescription>“{deleteLink?.title}” will be removed for all users.</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={() => deleteLink && del.mutate(deleteLink.id)}>Delete</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
