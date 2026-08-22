import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Globe, Plus, Settings, Trash2, Check, X } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'
import { Input } from '../components/ui/input'
import { Label } from '../components/ui/label'
import { Switch } from '../components/ui/switch'
import { Textarea } from '../components/ui/textarea'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '../components/ui/select'
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
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

interface SocialProvider {
  id: string
  provider_id: string
  provider_key: string
  display_name: string
  icon_url: string
  button_color: string
  button_text: string
  auto_create_users: boolean
  auto_link_by_email: boolean
  default_role: string
  allowed_domains: string[]
  attribute_mapping: Record<string, string>
  enabled: boolean
  sort_order: number
}

interface SocialProviderFormData {
  provider_key: string
  display_name: string
  button_color: string
  button_text: string
  auto_create_users: boolean
  auto_link_by_email: boolean
  default_role: string
  allowed_domains: string
  sort_order: number
  enabled: boolean
}

const PROVIDER_KEY_OPTIONS = [
  { value: 'google', label: 'Google' },
  { value: 'github', label: 'GitHub' },
  { value: 'microsoft', label: 'Microsoft' },
  { value: 'apple', label: 'Apple' },
]

const DEFAULT_BUTTON_COLORS: Record<string, string> = {
  google: '#4285F4',
  github: '#24292e',
  microsoft: '#00a4ef',
  apple: '#000000',
}

const emptyForm: SocialProviderFormData = {
  provider_key: 'google',
  display_name: '',
  button_color: '#4285F4',
  button_text: '',
  auto_create_users: true,
  auto_link_by_email: true,
  default_role: 'user',
  allowed_domains: '',
  sort_order: 0,
  enabled: true,
}

export function SocialProvidersPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [formOpen, setFormOpen] = useState(false)
  const [editTarget, setEditTarget] = useState<SocialProvider | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<SocialProvider | null>(null)
  const [form, setForm] = useState<SocialProviderFormData>(emptyForm)

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['social-providers'],
    queryFn: () =>
      api.get<{ data: SocialProvider[] }>('/api/v1/social-providers'),
  })

  const providers = data?.data || []

  const createMutation = useMutation({
    mutationFn: (body: SocialProviderFormData) => {
      const payload = {
        ...body,
        allowed_domains: body.allowed_domains
          .split(',')
          .map((d) => d.trim())
          .filter(Boolean),
      }
      return api.post('/api/v1/social-providers', payload)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['social-providers'] })
      setFormOpen(false)
      setForm(emptyForm)
      toast({ title: 'Social provider created successfully' })
    },
    onError: () => {
      toast({ title: 'Failed to create social provider', variant: 'destructive' })
    },
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, body }: { id: string; body: SocialProviderFormData }) => {
      const payload = {
        ...body,
        allowed_domains: body.allowed_domains
          .split(',')
          .map((d) => d.trim())
          .filter(Boolean),
      }
      return api.put(`/api/v1/social-providers/${id}`, payload)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['social-providers'] })
      setEditTarget(null)
      setFormOpen(false)
      setForm(emptyForm)
      toast({ title: 'Social provider updated successfully' })
    },
    onError: () => {
      toast({ title: 'Failed to update social provider', variant: 'destructive' })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      api.delete(`/api/v1/social-providers/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['social-providers'] })
      setDeleteTarget(null)
      toast({ title: 'Social provider deleted successfully' })
    },
    onError: () => {
      toast({ title: 'Failed to delete social provider', variant: 'destructive' })
    },
  })

  function openCreate() {
    setEditTarget(null)
    setForm(emptyForm)
    setFormOpen(true)
  }

  function openEdit(provider: SocialProvider) {
    setEditTarget(provider)
    setForm({
      provider_key: provider.provider_key,
      display_name: provider.display_name,
      button_color: provider.button_color,
      button_text: provider.button_text,
      auto_create_users: provider.auto_create_users,
      auto_link_by_email: provider.auto_link_by_email,
      default_role: provider.default_role,
      allowed_domains: (provider.allowed_domains || []).join(', '),
      sort_order: provider.sort_order,
      enabled: provider.enabled,
    })
    setFormOpen(true)
  }

  function handleSubmit() {
    if (editTarget) {
      updateMutation.mutate({ id: editTarget.id, body: form })
    } else {
      createMutation.mutate(form)
    }
  }

  function handleProviderKeyChange(key: string) {
    const label = PROVIDER_KEY_OPTIONS.find((o) => o.value === key)?.label || key
    setForm((f) => ({
      ...f,
      provider_key: key,
      display_name: f.display_name || label,
      button_color: DEFAULT_BUTTON_COLORS[key] || f.button_color,
      button_text: f.button_text || `Sign in with ${label}`,
    }))
  }

  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center py-12">
        <LoadingSpinner size="lg" />
        <p className="mt-4 text-sm text-muted-foreground">Loading social providers...</p>
      </div>
    )
  }

  if (isError) {
    return <QueryError error={error} resource="social providers" />
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Social Login Providers</h1>
          <p className="text-muted-foreground">
            Configure social identity providers for SSO
          </p>
        </div>
        <Button onClick={openCreate}>
          <Plus className="mr-2 h-4 w-4" />
          Add Provider
        </Button>
      </div>

      {providers.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
          <Globe className="h-12 w-12 text-muted-foreground/40 mb-3" />
          <p className="font-medium">No social providers configured</p>
          <p className="text-sm">Add a social login provider to enable SSO</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {providers.map((provider) => (
            <Card key={provider.id}>
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-lg">{provider.display_name}</CardTitle>
                  <Badge variant={provider.enabled ? 'default' : 'secondary'}>
                    {provider.enabled ? (
                      <span className="flex items-center gap-1">
                        <Check className="h-3 w-3" /> Enabled
                      </span>
                    ) : (
                      <span className="flex items-center gap-1">
                        <X className="h-3 w-3" /> Disabled
                      </span>
                    )}
                  </Badge>
                </div>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  <div className="flex items-center gap-2 text-sm">
                    <span className="text-muted-foreground">Provider:</span>
                    <Badge variant="outline">{provider.provider_key}</Badge>
                  </div>
                  <div className="flex items-center gap-2 text-sm">
                    <span className="text-muted-foreground">Sort Order:</span>
                    <span>{provider.sort_order}</span>
                  </div>
                  {provider.button_color && (
                    <div className="flex items-center gap-2 text-sm">
                      <span className="text-muted-foreground">Button Color:</span>
                      <div
                        className="h-4 w-4 rounded border"
                        style={{ backgroundColor: provider.button_color }}
                      />
                      <span className="font-mono text-xs">{provider.button_color}</span>
                    </div>
                  )}
                  {provider.allowed_domains && provider.allowed_domains.length > 0 && (
                    <div className="text-sm">
                      <span className="text-muted-foreground">Allowed Domains:</span>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {provider.allowed_domains.map((domain) => (
                          <Badge key={domain} variant="outline" className="text-xs">
                            {domain}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                  <div className="flex items-center gap-2 text-sm">
                    <span className="text-muted-foreground">Auto-create users:</span>
                    <Badge variant={provider.auto_create_users ? 'default' : 'secondary'} className="text-xs">
                      {provider.auto_create_users ? 'Yes' : 'No'}
                    </Badge>
                  </div>
                  <div className="flex items-center gap-2 text-sm">
                    <span className="text-muted-foreground">Auto-link by email:</span>
                    <Badge variant={provider.auto_link_by_email ? 'default' : 'secondary'} className="text-xs">
                      {provider.auto_link_by_email ? 'Yes' : 'No'}
                    </Badge>
                  </div>
                  <div className="flex justify-end gap-2 pt-2 border-t">
                    <Button variant="ghost" size="sm" onClick={() => openEdit(provider)}>
                      <Settings className="h-4 w-4 mr-1" />
                      Edit
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setDeleteTarget(provider)}
                    >
                      <Trash2 className="h-4 w-4 mr-1 text-red-500" />
                      <span className="text-red-500">Delete</span>
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Create / Edit Dialog */}
      <Dialog open={formOpen} onOpenChange={(open) => { if (!open) { setFormOpen(false); setEditTarget(null) } }}>
        <DialogContent className="max-w-lg max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>
              {editTarget ? 'Edit Social Provider' : 'Add Social Provider'}
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label>Provider Key</Label>
              <Select
                value={form.provider_key}
                onValueChange={handleProviderKeyChange}
                disabled={!!editTarget}
              >
                <SelectTrigger className="mt-1">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {PROVIDER_KEY_OPTIONS.map((opt) => (
                    <SelectItem key={opt.value} value={opt.value}>
                      {opt.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label htmlFor="display_name">Display Name</Label>
              <Input
                id="display_name"
                value={form.display_name}
                onChange={(e) => setForm((f) => ({ ...f, display_name: e.target.value }))}
                placeholder="e.g. Google"
              />
            </div>
            <div>
              <Label htmlFor="button_color">Button Color</Label>
              <div className="flex items-center gap-2 mt-1">
                <input
                  type="color"
                  value={form.button_color}
                  onChange={(e) => setForm((f) => ({ ...f, button_color: e.target.value }))}
                  className="h-9 w-12 rounded border cursor-pointer"
                />
                <Input
                  id="button_color"
                  value={form.button_color}
                  onChange={(e) => setForm((f) => ({ ...f, button_color: e.target.value }))}
                  placeholder="#4285F4"
                  className="flex-1"
                />
              </div>
            </div>
            <div>
              <Label htmlFor="button_text">Button Text</Label>
              <Input
                id="button_text"
                value={form.button_text}
                onChange={(e) => setForm((f) => ({ ...f, button_text: e.target.value }))}
                placeholder="Sign in with Google"
              />
            </div>
            <div className="flex items-center justify-between">
              <Label>Auto-Create Users</Label>
              <Switch
                checked={form.auto_create_users}
                onCheckedChange={(checked) => setForm((f) => ({ ...f, auto_create_users: checked }))}
              />
            </div>
            <div className="flex items-center justify-between">
              <Label>Auto-Link by Email</Label>
              <Switch
                checked={form.auto_link_by_email}
                onCheckedChange={(checked) => setForm((f) => ({ ...f, auto_link_by_email: checked }))}
              />
            </div>
            <div>
              <Label htmlFor="default_role">Default Role</Label>
              <Input
                id="default_role"
                value={form.default_role}
                onChange={(e) => setForm((f) => ({ ...f, default_role: e.target.value }))}
                placeholder="user"
              />
            </div>
            <div>
              <Label htmlFor="allowed_domains">Allowed Domains (comma-separated)</Label>
              <Textarea
                id="allowed_domains"
                value={form.allowed_domains}
                onChange={(e) => setForm((f) => ({ ...f, allowed_domains: e.target.value }))}
                placeholder="example.com, company.org"
                rows={2}
              />
              <p className="text-xs text-muted-foreground mt-1">
                Leave empty to allow all domains.
              </p>
            </div>
            <div>
              <Label htmlFor="sort_order">Sort Order</Label>
              <Input
                id="sort_order"
                type="number"
                value={form.sort_order}
                onChange={(e) => setForm((f) => ({ ...f, sort_order: parseInt(e.target.value, 10) || 0 }))}
                placeholder="0"
              />
            </div>
            <div className="flex items-center justify-between">
              <Label>Enabled</Label>
              <Switch
                checked={form.enabled}
                onCheckedChange={(checked) => setForm((f) => ({ ...f, enabled: checked }))}
              />
            </div>
            <div className="flex justify-end gap-2 pt-4 border-t">
              <Button variant="outline" onClick={() => { setFormOpen(false); setEditTarget(null) }}>
                Cancel
              </Button>
              <Button
                onClick={handleSubmit}
                disabled={!form.display_name.trim() || createMutation.isPending || updateMutation.isPending}
              >
                {createMutation.isPending || updateMutation.isPending
                  ? 'Saving...'
                  : editTarget
                    ? 'Update Provider'
                    : 'Create Provider'}
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <AlertDialog open={!!deleteTarget} onOpenChange={(open) => !open && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Social Provider</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete &quot;{deleteTarget?.display_name}&quot;?
              Users will no longer be able to sign in using this social provider.
              This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => deleteTarget && deleteMutation.mutate(deleteTarget.id)}
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
