import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Search, Plus, Pencil, Trash2, Download, ShieldCheck, ToggleLeft, ToggleRight,
} from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '../components/ui/table'
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from '../components/ui/dialog'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '../components/ui/alert-dialog'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '../components/ui/select'
import { Textarea } from '../components/ui/textarea'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

interface SAMLServiceProvider {
  id: string
  name: string
  entity_id: string
  acs_url: string
  slo_url?: string
  name_id_format: string
  certificate: string
  enabled: boolean
  created_at: string
  updated_at: string
}

const NAME_ID_FORMATS = [
  { value: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress', label: 'Email Address' },
  { value: 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified', label: 'Unspecified' },
  { value: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent', label: 'Persistent' },
  { value: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient', label: 'Transient' },
]

interface SPFormState {
  name: string
  entity_id: string
  acs_url: string
  slo_url: string
  name_id_format: string
  certificate: string
}

const emptyForm: SPFormState = {
  name: '',
  entity_id: '',
  acs_url: '',
  slo_url: '',
  name_id_format: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  certificate: '',
}

export function SAMLServiceProvidersPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [search, setSearch] = useState('')

  const [createOpen, setCreateOpen] = useState(false)
  const [editTarget, setEditTarget] = useState<SAMLServiceProvider | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<SAMLServiceProvider | null>(null)
  const [form, setForm] = useState<SPFormState>(emptyForm)

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['saml-service-providers', search],
    queryFn: () =>
      api.get<{ service_providers: SAMLServiceProvider[] }>(
        `/api/v1/saml/service-providers?search=${encodeURIComponent(search)}`
      ),
  })

  const providers = data?.service_providers || []

  const filteredProviders = providers.filter((sp) => {
    if (!search) return true
    const q = search.toLowerCase()
    return (
      sp.name.toLowerCase().includes(q) ||
      sp.entity_id.toLowerCase().includes(q) ||
      sp.acs_url.toLowerCase().includes(q)
    )
  })

  const createMutation = useMutation({
    mutationFn: (body: SPFormState) =>
      api.post('/api/v1/saml/service-providers', body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['saml-service-providers'] })
      setCreateOpen(false)
      setForm(emptyForm)
      toast({ title: 'SAML service provider created' })
    },
    onError: () => {
      toast({ title: 'Failed to create service provider', variant: 'destructive' })
    },
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, body }: { id: string; body: SPFormState }) =>
      api.put(`/api/v1/saml/service-providers/${id}`, body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['saml-service-providers'] })
      setEditTarget(null)
      setForm(emptyForm)
      toast({ title: 'Service provider updated' })
    },
    onError: () => {
      toast({ title: 'Failed to update service provider', variant: 'destructive' })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      api.delete(`/api/v1/saml/service-providers/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['saml-service-providers'] })
      setDeleteTarget(null)
      toast({ title: 'Service provider deleted' })
    },
    onError: () => {
      toast({ title: 'Failed to delete service provider', variant: 'destructive' })
    },
  })

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      api.put(`/api/v1/saml/service-providers/${id}`, { enabled }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['saml-service-providers'] })
      toast({ title: 'Service provider status updated' })
    },
    onError: () => {
      toast({ title: 'Failed to update status', variant: 'destructive' })
    },
  })

  function openCreate() {
    setForm(emptyForm)
    setCreateOpen(true)
  }

  function openEdit(sp: SAMLServiceProvider) {
    setForm({
      name: sp.name,
      entity_id: sp.entity_id,
      acs_url: sp.acs_url,
      slo_url: sp.slo_url || '',
      name_id_format: sp.name_id_format,
      certificate: sp.certificate,
    })
    setEditTarget(sp)
  }

  async function downloadIdPMetadata() {
    try {
      const metadata = await api.get<string>('/saml/idp/metadata', {
        responseType: 'text',
        headers: { Accept: 'application/xml' },
      })
      const blob = new Blob([metadata as unknown as string], { type: 'application/xml' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = 'idp-metadata.xml'
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
      toast({ title: 'IdP metadata downloaded' })
    } catch {
      toast({ title: 'Failed to download IdP metadata', variant: 'destructive' })
    }
  }

  function formatNameIdLabel(format: string): string {
    const found = NAME_ID_FORMATS.find((f) => f.value === format)
    return found ? found.label : format.split(':').pop() || format
  }

  const isFormValid = form.name.trim() && form.entity_id.trim() && form.acs_url.trim()

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">SAML Service Providers</h1>
          <p className="text-muted-foreground">
            Manage SAML 2.0 service provider registrations for SSO
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" onClick={downloadIdPMetadata}>
            <Download className="mr-2 h-4 w-4" />
            Download IdP Metadata
          </Button>
          <Button onClick={openCreate}>
            <Plus className="mr-2 h-4 w-4" />
            Add Service Provider
          </Button>
        </div>
      </div>

      <div className="flex items-center gap-4">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search by name, entity ID, or ACS URL..."
            className="pl-9"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
      </div>

      {isLoading ? (
        <div className="flex flex-col items-center justify-center py-12">
          <LoadingSpinner size="lg" />
          <p className="mt-4 text-sm text-muted-foreground">Loading service providers...</p>
        </div>
      ) : isError ? (
        <QueryError error={error} resource="SAML service providers" />
      ) : filteredProviders.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
          <ShieldCheck className="h-12 w-12 text-muted-foreground/40 mb-3" />
          <p className="font-medium">No SAML service providers found</p>
          <p className="text-sm">Register a service provider to enable SAML SSO</p>
        </div>
      ) : (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">
              Registered Service Providers ({filteredProviders.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Entity ID</TableHead>
                  <TableHead>ACS URL</TableHead>
                  <TableHead>Name ID Format</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredProviders.map((sp) => (
                  <TableRow key={sp.id}>
                    <TableCell className="font-medium">{sp.name}</TableCell>
                    <TableCell>
                      <span className="font-mono text-xs max-w-[200px] truncate block" title={sp.entity_id}>
                        {sp.entity_id}
                      </span>
                    </TableCell>
                    <TableCell>
                      <span className="text-xs max-w-[200px] truncate block" title={sp.acs_url}>
                        {sp.acs_url}
                      </span>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className="text-xs">
                        {formatNameIdLabel(sp.name_id_format)}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <Badge
                        className={
                          sp.enabled
                            ? 'bg-green-100 text-green-800 hover:bg-green-100'
                            : 'bg-gray-100 text-gray-800 hover:bg-gray-100'
                        }
                      >
                        {sp.enabled ? 'Enabled' : 'Disabled'}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {new Date(sp.created_at).toLocaleDateString()}
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex items-center justify-end gap-1">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() =>
                            toggleMutation.mutate({ id: sp.id, enabled: !sp.enabled })
                          }
                          title={sp.enabled ? 'Disable' : 'Enable'}
                        >
                          {sp.enabled ? (
                            <ToggleRight className="h-4 w-4 text-green-600" />
                          ) : (
                            <ToggleLeft className="h-4 w-4 text-muted-foreground" />
                          )}
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => openEdit(sp)}
                        >
                          <Pencil className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setDeleteTarget(sp)}
                        >
                          <Trash2 className="h-4 w-4 text-red-500" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      {/* Create Dialog */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Add SAML Service Provider</DialogTitle>
            <DialogDescription>
              Register a new SAML 2.0 service provider for single sign-on.
            </DialogDescription>
          </DialogHeader>
          <SPForm form={form} setForm={setForm} />
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>
              Cancel
            </Button>
            <Button
              disabled={!isFormValid || createMutation.isPending}
              onClick={() => createMutation.mutate(form)}
            >
              {createMutation.isPending ? 'Creating...' : 'Create'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Edit Dialog */}
      <Dialog open={!!editTarget} onOpenChange={(open) => !open && setEditTarget(null)}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Edit Service Provider</DialogTitle>
            <DialogDescription>
              Update the SAML service provider configuration.
            </DialogDescription>
          </DialogHeader>
          <SPForm form={form} setForm={setForm} />
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditTarget(null)}>
              Cancel
            </Button>
            <Button
              disabled={!isFormValid || updateMutation.isPending}
              onClick={() =>
                editTarget && updateMutation.mutate({ id: editTarget.id, body: form })
              }
            >
              {updateMutation.isPending ? 'Saving...' : 'Save Changes'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <AlertDialog open={!!deleteTarget} onOpenChange={(open) => !open && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Service Provider</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete &quot;{deleteTarget?.name}&quot;? Users will no
              longer be able to use SAML SSO with this service provider. This action cannot be
              undone.
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

function SPForm({
  form,
  setForm,
}: {
  form: SPFormState
  setForm: React.Dispatch<React.SetStateAction<SPFormState>>
}) {
  return (
    <div className="space-y-4">
      <div>
        <label className="text-sm font-medium">Name *</label>
        <Input
          placeholder="My Application"
          value={form.name}
          onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
        />
      </div>
      <div>
        <label className="text-sm font-medium">Entity ID *</label>
        <Input
          placeholder="https://app.example.com/saml/metadata"
          value={form.entity_id}
          onChange={(e) => setForm((f) => ({ ...f, entity_id: e.target.value }))}
        />
      </div>
      <div>
        <label className="text-sm font-medium">ACS URL (Assertion Consumer Service) *</label>
        <Input
          placeholder="https://app.example.com/saml/acs"
          value={form.acs_url}
          onChange={(e) => setForm((f) => ({ ...f, acs_url: e.target.value }))}
        />
      </div>
      <div>
        <label className="text-sm font-medium">SLO URL (Single Logout, optional)</label>
        <Input
          placeholder="https://app.example.com/saml/slo"
          value={form.slo_url}
          onChange={(e) => setForm((f) => ({ ...f, slo_url: e.target.value }))}
        />
      </div>
      <div>
        <label className="text-sm font-medium">Name ID Format</label>
        <Select
          value={form.name_id_format}
          onValueChange={(value) => setForm((f) => ({ ...f, name_id_format: value }))}
        >
          <SelectTrigger className="mt-1">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {NAME_ID_FORMATS.map((fmt) => (
              <SelectItem key={fmt.value} value={fmt.value}>
                {fmt.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <div>
        <label className="text-sm font-medium">SP Certificate (PEM, optional)</label>
        <Textarea
          placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
          className="font-mono text-xs"
          rows={5}
          value={form.certificate}
          onChange={(e) => setForm((f) => ({ ...f, certificate: e.target.value }))}
        />
        <p className="text-xs text-muted-foreground mt-1">
          The SP&apos;s X.509 certificate for validating signed requests.
        </p>
      </div>
    </div>
  )
}
