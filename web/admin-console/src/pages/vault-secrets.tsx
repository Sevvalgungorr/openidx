import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { api, VaultSecretMeta, VaultSecretDetail, VaultGrant, VaultCheckout, VaultRotationRun } from '../lib/api'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'
import { Input } from '../components/ui/input'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '../components/ui/dialog'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from '../components/ui/alert-dialog'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '../components/ui/select'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '../components/ui/table'
import { KeyRound, Plus, Copy, Eye, Trash2, RefreshCw, Shield, X } from 'lucide-react'
import { useToast } from '../hooks/use-toast'
import { ConfirmAction } from '../components/confirm-action'
import { useRevealedSecret, copyWithWarning } from '../lib/secret-reveal'

const typeColors: Record<string, string> = {
  password: 'bg-blue-100 text-blue-800',
  api_key: 'bg-purple-100 text-purple-800',
  ssh_key: 'bg-green-100 text-green-800',
  generic: 'bg-gray-100 text-gray-800',
}

const typeLabels: Record<string, string> = {
  password: 'Password',
  api_key: 'API Key',
  ssh_key: 'SSH Key',
  generic: 'Generic',
}

export function VaultSecretsPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()

  // UI state
  const [showCreate, setShowCreate] = useState(false)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [showReveal, setShowReveal] = useState(false)
  const [revealReason, setRevealReason] = useState('')
  // Revealed plaintext lives in useRevealedSecret so it auto-clears after the TTL
  // and on unmount — it is never held in plain component state indefinitely.
  const { value: revealedValue, reveal: revealSecret, clear: clearRevealed } = useRevealedSecret()
  const [showNewVersion, setShowNewVersion] = useState(false)
  const [newVersionValue, setNewVersionValue] = useState('')
  const [showAddGrant, setShowAddGrant] = useState(false)

  // Grant form state
  const [grantPrincipalType, setGrantPrincipalType] = useState('user')
  const [grantPrincipalId, setGrantPrincipalId] = useState('')
  const [grantActions, setGrantActions] = useState<string[]>(['use'])
  const [grantExpiresAt, setGrantExpiresAt] = useState('')

  // Create form state
  const [formName, setFormName] = useState('')
  const [formType, setFormType] = useState('generic')
  const [formDesc, setFormDesc] = useState('')
  const [formValue, setFormValue] = useState('')
  const [formMetaKey, setFormMetaKey] = useState('')
  const [formMetaVal, setFormMetaVal] = useState('')
  const [formMetaPairs, setFormMetaPairs] = useState<Array<{ key: string; val: string }>>([])

  // Queries
  const { data: listData, isLoading, error: listError } = useQuery({
    queryKey: ['vault-secrets'],
    queryFn: () => api.vault.listSecrets(),
  })

  const { data: detailData, isLoading: detailLoading } = useQuery({
    queryKey: ['vault-secret', selectedId],
    queryFn: () => api.vault.getSecret(selectedId!),
    enabled: !!selectedId,
  })

  const { data: grantsData } = useQuery({
    queryKey: ['vault-grants', selectedId],
    queryFn: () => api.vault.listGrants(selectedId!),
    enabled: !!selectedId,
  })

  const { data: checkoutsData } = useQuery({
    queryKey: ['vault-checkouts', selectedId],
    queryFn: () => api.vault.listCheckouts(selectedId!),
    enabled: !!selectedId,
  })

  const { data: rotationsData } = useQuery({
    queryKey: ['vault-rotations', selectedId],
    queryFn: () => api.vault.listRotations(selectedId!),
    enabled: !!selectedId,
  })

  const rotations: VaultRotationRun[] = rotationsData?.rotations || []

  const secrets: VaultSecretMeta[] = listData?.secrets || []
  const detail: VaultSecretDetail | undefined = detailData
  const grants: VaultGrant[] = grantsData?.grants || []
  const checkouts: VaultCheckout[] = checkoutsData?.checkouts || []

  // Mutations
  const createMutation = useMutation({
    mutationFn: () =>
      api.vault.createSecret({
        name: formName,
        type: formType,
        description: formDesc || undefined,
        value: formValue,
        metadata:
          formMetaPairs.length > 0
            ? Object.fromEntries(formMetaPairs.map((p) => [p.key, p.val]))
            : undefined,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vault-secrets'] })
      setFormName('')
      setFormType('generic')
      setFormDesc('')
      setFormValue('')
      setFormMetaKey('')
      setFormMetaVal('')
      setFormMetaPairs([])
      setShowCreate(false)
      toast({ title: 'Secret created' })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.vault.deleteSecret(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vault-secrets'] })
      setSelectedId(null)
      toast({ title: 'Secret deleted' })
    },
  })

  const revealMutation = useMutation({
    mutationFn: () => {
      if (!selectedId) throw new Error('No secret selected')
      return api.vault.reveal(selectedId, revealReason)
    },
    onSuccess: (data) => {
      revealSecret(data.value)
    },
  })

  const newVersionMutation = useMutation({
    mutationFn: () => {
      if (!selectedId) throw new Error('No secret selected')
      return api.vault.newVersion(selectedId, newVersionValue)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vault-secret', selectedId] })
      queryClient.invalidateQueries({ queryKey: ['vault-grants', selectedId] })
      queryClient.invalidateQueries({ queryKey: ['vault-checkouts', selectedId] })
      queryClient.invalidateQueries({ queryKey: ['vault-secrets'] })
      setShowNewVersion(false)
      setNewVersionValue('')
      toast({ title: 'New version saved' })
    },
  })

  const addGrantMutation = useMutation({
    mutationFn: () => {
      if (!selectedId) throw new Error('No secret selected')
      return api.vault.addGrant(selectedId, {
        principal_type: grantPrincipalType,
        principal_id: grantPrincipalId,
        actions: grantActions,
        expires_at: grantExpiresAt || undefined,
      })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vault-grants', selectedId] })
      setGrantPrincipalType('user')
      setGrantPrincipalId('')
      setGrantActions(['use'])
      setGrantExpiresAt('')
      setShowAddGrant(false)
      toast({ title: 'Grant added' })
    },
  })

  const removeGrantMutation = useMutation({
    mutationFn: ({ secretId, grantId }: { secretId: string; grantId: string }) =>
      api.vault.removeGrant(secretId, grantId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vault-grants', selectedId] })
      toast({ title: 'Grant removed' })
    },
  })

  const rotateNowMutation = useMutation({
    mutationFn: () => {
      if (!selectedId) throw new Error('No secret selected')
      return api.vault.rotateNow(selectedId)
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['vault-rotations', selectedId] })
      const status = (data as { status?: string }).status ?? 'completed'
      toast({ title: `Rotation ${status}` })
    },
    onError: (err: { response?: { status?: number } }) => {
      if (err?.response?.status === 404) {
        toast({ title: 'No rotation policy configured for this secret', variant: 'destructive' })
      } else {
        toast({ title: 'Rotation failed', variant: 'destructive' })
      }
    },
  })

  function handleCreate() {
    createMutation.mutate()
  }

  function handleAddMetaPair() {
    if (formMetaKey.trim()) {
      setFormMetaPairs((prev) => [...prev, { key: formMetaKey.trim(), val: formMetaVal }])
      setFormMetaKey('')
      setFormMetaVal('')
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Vault Secrets</h1>
          <p className="text-muted-foreground">Manage encrypted credentials — admin guarded</p>
        </div>
        <Button onClick={() => setShowCreate(!showCreate)}>
          <Plus className="h-4 w-4 mr-2" />
          {showCreate ? 'Cancel' : 'New Secret'}
        </Button>
      </div>

      {/* Create form */}
      {showCreate && (
        <Card>
          <CardHeader>
            <CardTitle>Create New Secret</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-sm font-medium">Name *</label>
                <Input
                  className="mt-1"
                  placeholder="my-api-key"
                  value={formName}
                  onChange={(e) => setFormName(e.target.value)}
                />
              </div>
              <div>
                <label className="text-sm font-medium">Type</label>
                <Select value={formType} onValueChange={setFormType}>
                  <SelectTrigger className="mt-1">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="generic">Generic</SelectItem>
                    <SelectItem value="password">Password</SelectItem>
                    <SelectItem value="api_key">API Key</SelectItem>
                    <SelectItem value="ssh_key">SSH Key</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div>
              <label className="text-sm font-medium">Description</label>
              <Input
                className="mt-1"
                placeholder="Optional description"
                value={formDesc}
                onChange={(e) => setFormDesc(e.target.value)}
              />
            </div>
            <div>
              <label className="text-sm font-medium">Value *</label>
              <Input
                type="password"
                className="mt-1"
                placeholder="Enter secret value (write-only)"
                value={formValue}
                onChange={(e) => setFormValue(e.target.value)}
              />
            </div>

            {/* Metadata key/value builder */}
            <div>
              <label className="text-sm font-medium">Metadata (optional)</label>
              <div className="flex gap-2 mt-1">
                <Input
                  placeholder="Key"
                  value={formMetaKey}
                  onChange={(e) => setFormMetaKey(e.target.value)}
                  className="flex-1"
                />
                <Input
                  placeholder="Value"
                  value={formMetaVal}
                  onChange={(e) => setFormMetaVal(e.target.value)}
                  className="flex-1"
                />
                <Button type="button" variant="outline" size="sm" onClick={handleAddMetaPair}>
                  Add
                </Button>
              </div>
              {formMetaPairs.length > 0 && (
                <div className="mt-2 space-y-1">
                  {formMetaPairs.map((p, i) => (
                    <div key={i} className="flex items-center gap-2 text-sm">
                      <Badge variant="outline" className="font-mono">
                        {p.key}: {p.val}
                      </Badge>
                      <Button
                        type="button"
                        variant="ghost"
                        size="sm"
                        className="h-5 w-5 p-0"
                        onClick={() => setFormMetaPairs((prev) => prev.filter((_, idx) => idx !== i))}
                      >
                        <X className="h-3 w-3" />
                      </Button>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <Button
              onClick={handleCreate}
              disabled={!formName || !formValue || createMutation.isPending}
            >
              {createMutation.isPending ? 'Creating...' : 'Create Secret'}
            </Button>
          </CardContent>
        </Card>
      )}

      {/* List */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <KeyRound className="h-5 w-5" />
            Secrets ({secrets.length})
          </CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex justify-center py-12">
              <LoadingSpinner size="lg" />
            </div>
          ) : listError ? (
            <QueryError error={listError} resource="vault secrets" />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Version</TableHead>
                  <TableHead>Updated</TableHead>
                  <TableHead></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {secrets.map((s) => (
                  <TableRow
                    key={s.id}
                    className="cursor-pointer"
                    onClick={() => setSelectedId(selectedId === s.id ? null : s.id)}
                  >
                    <TableCell className="font-medium">{s.name}</TableCell>
                    <TableCell>
                      <Badge className={typeColors[s.type] || 'bg-gray-100 text-gray-800'}>
                        {typeLabels[s.type] || s.type}
                      </Badge>
                    </TableCell>
                    <TableCell>v{s.current_version}</TableCell>
                    <TableCell className="text-muted-foreground text-sm">
                      {new Date(s.updated_at).toLocaleDateString()}
                    </TableCell>
                    <TableCell onClick={(e) => e.stopPropagation()}>
                      {selectedId === s.id && (
                        <span className="text-xs text-blue-600">▶ selected</span>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
                {secrets.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={5} className="text-center text-muted-foreground py-8">
                      No secrets yet
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Detail panel */}
      {selectedId && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center justify-between">
              <span className="flex items-center gap-2">
                <Shield className="h-5 w-5" />
                {detail?.name || 'Loading...'}
              </span>
              <div className="flex gap-2">
                <ConfirmAction
                  title="Rotate this secret now?"
                  description="The current value is replaced immediately. Any dependents must be updated to use the new value or they will start failing."
                  destructive
                  confirmLabel="Rotate"
                  onConfirm={() => rotateNowMutation.mutate()}
                >
                  {(open) => (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={open}
                      disabled={rotateNowMutation.isPending}
                      data-testid="rotate-now-btn"
                    >
                      <RefreshCw className="h-3 w-3 mr-1" />
                      {rotateNowMutation.isPending ? 'Rotating...' : 'Rotate now'}
                    </Button>
                  )}
                </ConfirmAction>
                <Button variant="outline" size="sm" onClick={() => setShowReveal(true)}>
                  <Eye className="h-3 w-3 mr-1" />
                  Reveal
                </Button>
                <AlertDialog>
                  <AlertDialogTrigger asChild>
                    <Button
                      variant="outline"
                      size="sm"
                      className="text-red-600 border-red-200 hover:bg-red-50"
                    >
                      <Trash2 className="h-3 w-3 mr-1" />
                      Delete
                    </Button>
                  </AlertDialogTrigger>
                  <AlertDialogContent>
                    <AlertDialogHeader>
                      <AlertDialogTitle>Crypto-erase secret?</AlertDialogTitle>
                      <AlertDialogDescription>
                        This permanently deletes all versions and ciphertext. The secret is
                        cryptographically unrecoverable.
                      </AlertDialogDescription>
                    </AlertDialogHeader>
                    <AlertDialogFooter>
                      <AlertDialogCancel>Cancel</AlertDialogCancel>
                      <AlertDialogAction
                        onClick={() => deleteMutation.mutate(selectedId)}
                        className="bg-red-600 hover:bg-red-700"
                      >
                        Delete forever
                      </AlertDialogAction>
                    </AlertDialogFooter>
                  </AlertDialogContent>
                </AlertDialog>
                <Button variant="ghost" size="sm" onClick={() => setSelectedId(null)}>
                  <X className="h-4 w-4" />
                </Button>
              </div>
            </CardTitle>
          </CardHeader>
          <CardContent>
            {detailLoading ? (
              <div className="flex justify-center py-8">
                <LoadingSpinner />
              </div>
            ) : (
              <Tabs defaultValue="versions">
                <TabsList>
                  <TabsTrigger value="versions">
                    Versions ({detail?.versions?.length || 0})
                  </TabsTrigger>
                  <TabsTrigger value="grants">Grants ({grants.length})</TabsTrigger>
                  <TabsTrigger value="checkouts">Checkouts ({checkouts.length})</TabsTrigger>
                  <TabsTrigger value="rotations">Rotations ({rotations.length})</TabsTrigger>
                </TabsList>

                {/* Versions tab */}
                <TabsContent value="versions" className="space-y-3">
                  <div className="flex justify-end pt-2">
                    <Button size="sm" onClick={() => setShowNewVersion(true)}>
                      <RefreshCw className="h-3 w-3 mr-1" />
                      New Version
                    </Button>
                  </div>
                  <div className="divide-y">
                    {(detail?.versions || []).map((v) => (
                      <div key={v.version} className="py-2 flex items-center justify-between">
                        <div>
                          <span className="font-medium text-sm">v{v.version}</span>
                          {detail?.current_version === v.version && (
                            <Badge className="ml-2 bg-green-100 text-green-800">current</Badge>
                          )}
                        </div>
                        <div className="text-xs text-muted-foreground">
                          {v.created_by && <span className="mr-3">by {v.created_by}</span>}
                          {new Date(v.created_at).toLocaleString()}
                        </div>
                      </div>
                    ))}
                  </div>
                </TabsContent>

                {/* Grants tab */}
                <TabsContent value="grants" className="space-y-3">
                  <div className="flex justify-end pt-2">
                    <Button size="sm" onClick={() => setShowAddGrant(true)}>
                      <Plus className="h-3 w-3 mr-1" />
                      Add Grant
                    </Button>
                  </div>
                  <div className="divide-y">
                    {grants.map((g) => (
                      <div key={g.id} className="py-2 flex items-center justify-between">
                        <div>
                          <span className="text-sm font-medium">
                            {g.principal_type}: {g.principal_id}
                          </span>
                          <div className="flex gap-1 mt-0.5">
                            {g.actions.map((a) => (
                              <Badge key={a} variant="outline" className="text-xs">
                                {a}
                              </Badge>
                            ))}
                          </div>
                          {g.expires_at && (
                            <p className="text-xs text-muted-foreground">
                              Expires {new Date(g.expires_at).toLocaleDateString()}
                            </p>
                          )}
                        </div>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() =>
                            removeGrantMutation.mutate({ secretId: selectedId, grantId: g.id })
                          }
                        >
                          <X className="h-3 w-3" />
                        </Button>
                      </div>
                    ))}
                    {grants.length === 0 && (
                      <p className="py-4 text-center text-sm text-muted-foreground">No grants</p>
                    )}
                  </div>
                </TabsContent>

                {/* Checkouts tab */}
                <TabsContent value="checkouts">
                  <div className="divide-y mt-2">
                    {checkouts.map((c) => (
                      <div key={c.id} className="py-2 flex items-center justify-between">
                        <div>
                          <span className="text-sm">
                            {c.mode === 'reveal' ? 'Reveal' : 'Use'}
                          </span>
                          {c.principal_id && (
                            <span className="text-xs text-muted-foreground ml-2">
                              {c.principal_id}
                            </span>
                          )}
                          {c.reason && (
                            <p className="text-xs text-muted-foreground">{c.reason}</p>
                          )}
                        </div>
                        <div className="text-right">
                          <Badge
                            className={
                              c.status === 'active'
                                ? 'bg-green-100 text-green-800'
                                : 'bg-gray-100 text-gray-800'
                            }
                          >
                            {c.status}
                          </Badge>
                          <p className="text-xs text-muted-foreground mt-0.5">
                            {new Date(c.leased_at).toLocaleString()}
                          </p>
                        </div>
                      </div>
                    ))}
                    {checkouts.length === 0 && (
                      <p className="py-4 text-center text-sm text-muted-foreground">
                        No checkouts yet
                      </p>
                    )}
                  </div>
                </TabsContent>

                {/* Rotations tab */}
                <TabsContent value="rotations">
                  <div className="divide-y mt-2">
                    {rotations.map((r) => (
                      <div key={r.id} className="py-2 flex items-center justify-between">
                        <div>
                          <div className="flex items-center gap-2">
                            <Badge
                              className={
                                r.status === 'success'
                                  ? 'bg-green-100 text-green-800'
                                  : r.status === 'failed'
                                  ? 'bg-red-100 text-red-800'
                                  : 'bg-yellow-100 text-yellow-800'
                              }
                            >
                              {r.status}
                            </Badge>
                            <span className="text-xs text-muted-foreground">{r.trigger}</span>
                            <span className="text-xs text-muted-foreground">{r.connector_type}</span>
                          </div>
                          {(r.version_from !== undefined || r.version_to !== undefined) && (
                            <p className="text-xs text-muted-foreground mt-0.5">
                              v{r.version_from} → v{r.version_to}
                            </p>
                          )}
                          {r.error_message && (
                            <p className="text-xs text-red-600 mt-0.5">{r.error_message}</p>
                          )}
                        </div>
                        <div className="text-right text-xs text-muted-foreground">
                          {r.started_at && new Date(r.started_at).toLocaleString()}
                        </div>
                      </div>
                    ))}
                    {rotations.length === 0 && (
                      <p className="py-4 text-center text-sm text-muted-foreground">
                        No rotations yet
                      </p>
                    )}
                  </div>
                </TabsContent>
              </Tabs>
            )}
          </CardContent>
        </Card>
      )}

      {/* Reveal modal */}
      <Dialog
        open={showReveal}
        onOpenChange={(open) => {
          if (!open) {
            clearRevealed()
            setRevealReason('')
          }
          setShowReveal(open)
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Reveal Secret Value</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            {!revealedValue ? (
              <>
                <p className="text-sm text-muted-foreground">
                  Provide a reason for accessing this secret. This action is audited.
                </p>
                <div>
                  <label className="text-sm font-medium">Reason (required)</label>
                  <Input
                    className="mt-1"
                    placeholder="e.g. emergency credential rotation"
                    value={revealReason}
                    onChange={(e) => setRevealReason(e.target.value)}
                  />
                </div>
                <Button
                  onClick={() => revealMutation.mutate()}
                  disabled={!revealReason.trim() || revealMutation.isPending}
                  className="w-full"
                >
                  {revealMutation.isPending ? 'Revealing...' : 'Reveal Value'}
                </Button>
              </>
            ) : (
              <div className="space-y-3">
                <div className="flex items-center gap-2 p-3 bg-amber-50 border border-amber-200 rounded-md">
                  <p className="text-xs text-amber-800 font-medium">
                    Value shown once and auto-hidden shortly — not stored or logged after this dialog closes.
                  </p>
                </div>
                <div className="flex gap-2">
                  <Input
                    value={revealedValue}
                    readOnly
                    className="font-mono text-sm"
                    type="text"
                    data-testid="revealed-value"
                  />
                  <Button
                    variant="outline"
                    size="icon"
                    onClick={async () => {
                      const ok = await copyWithWarning(revealedValue)
                      if (ok) {
                        toast({ title: 'Copied', description: 'The clipboard may retain this value — clear it when done.' })
                      } else {
                        toast({ title: 'Copy failed', description: 'Clipboard unavailable — copy the value manually.', variant: 'destructive' })
                      }
                    }}
                  >
                    <Copy className="h-4 w-4" />
                  </Button>
                </div>
              </div>
            )}
          </div>
        </DialogContent>
      </Dialog>

      {/* New Version dialog */}
      <Dialog open={showNewVersion} onOpenChange={setShowNewVersion}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>New Secret Version</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <p className="text-sm text-muted-foreground">
              Enter the new value. Previous versions are retained in the audit history.
            </p>
            <div>
              <label className="text-sm font-medium">New Value</label>
              <Input
                type="password"
                className="mt-1"
                placeholder="Enter new secret value"
                value={newVersionValue}
                onChange={(e) => setNewVersionValue(e.target.value)}
              />
            </div>
            <Button
              onClick={() => newVersionMutation.mutate()}
              disabled={!newVersionValue || newVersionMutation.isPending}
              className="w-full"
            >
              {newVersionMutation.isPending ? 'Saving...' : 'Save New Version'}
            </Button>
          </div>
        </DialogContent>
      </Dialog>

      {/* Add Grant dialog */}
      <Dialog open={showAddGrant} onOpenChange={setShowAddGrant}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add Grant</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <label className="text-sm font-medium">Principal Type</label>
              <Select value={grantPrincipalType} onValueChange={setGrantPrincipalType}>
                <SelectTrigger className="mt-1">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="user">User</SelectItem>
                  <SelectItem value="role">Role</SelectItem>
                  <SelectItem value="service_account">Service Account</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <label className="text-sm font-medium">Principal ID</label>
              <Input
                className="mt-1"
                value={grantPrincipalId}
                onChange={(e) => setGrantPrincipalId(e.target.value)}
              />
            </div>
            <div>
              <label className="text-sm font-medium">Actions</label>
              <div className="flex gap-3 mt-1">
                {['use', 'reveal'].map((action) => (
                  <label key={action} className="flex items-center gap-1 text-sm">
                    <input
                      type="checkbox"
                      checked={grantActions.includes(action)}
                      onChange={(e) =>
                        setGrantActions((prev) =>
                          e.target.checked ? [...prev, action] : prev.filter((a) => a !== action)
                        )
                      }
                    />
                    {action}
                  </label>
                ))}
              </div>
            </div>
            <div>
              <label className="text-sm font-medium">Expires At (optional)</label>
              <Input
                type="datetime-local"
                className="mt-1"
                value={grantExpiresAt}
                onChange={(e) => setGrantExpiresAt(e.target.value)}
              />
            </div>
            <Button
              onClick={() => addGrantMutation.mutate()}
              disabled={
                !grantPrincipalId || grantActions.length === 0 || addGrantMutation.isPending
              }
              className="w-full"
            >
              {addGrantMutation.isPending ? 'Adding...' : 'Add Grant'}
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  )
}
