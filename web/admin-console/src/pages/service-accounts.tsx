import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Search, Plus, Key, Trash2, Copy, ChevronLeft, ChevronRight, Eye, EyeOff, Bot } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from '../components/ui/dialog'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '../components/ui/alert-dialog'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

interface ServiceAccount {
  id: string
  name: string
  description: string
  owner_id: string
  status: string
  created_at: string
  updated_at: string
}

interface APIKey {
  id: string
  name: string
  key_prefix: string
  scopes: string[]
  expires_at?: string
  last_used_at?: string
  status: string
  created_at: string
}

export function ServiceAccountsPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)
  const pageSize = 10

  const [createOpen, setCreateOpen] = useState(false)
  const [newName, setNewName] = useState('')
  const [newDescription, setNewDescription] = useState('')

  const [deleteTarget, setDeleteTarget] = useState<ServiceAccount | null>(null)

  const [expandedAccount, setExpandedAccount] = useState<string | null>(null)

  const [createKeyOpen, setCreateKeyOpen] = useState(false)
  const [createKeyAccountId, setCreateKeyAccountId] = useState<string | null>(null)
  const [keyName, setKeyName] = useState('')
  const [keyScopes, setKeyScopes] = useState('')

  const [revealedKey, setRevealedKey] = useState<string | null>(null)
  const [showKeyDialog, setShowKeyDialog] = useState(false)
  const [generatedKey, setGeneratedKey] = useState('')

  const [revokeKeyTarget, setRevokeKeyTarget] = useState<APIKey | null>(null)

  const { data: accountsData, isLoading, isError, error } = useQuery({
    queryKey: ['service-accounts', page, search],
    queryFn: () =>
      api.get<{ service_accounts: ServiceAccount[]; total: number }>(
        `/api/v1/service-accounts?page=${page}&page_size=${pageSize}&search=${encodeURIComponent(search)}`
      ),
  })

  const accounts = accountsData?.service_accounts || []
  const total = accountsData?.total || 0
  const totalPages = Math.ceil(total / pageSize)

  const createMutation = useMutation({
    mutationFn: (body: { name: string; description: string }) =>
      api.post('/api/v1/service-accounts', body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['service-accounts'] })
      setCreateOpen(false)
      setNewName('')
      setNewDescription('')
      toast({ title: 'Service account created' })
    },
    onError: () => {
      toast({ title: 'Failed to create service account', variant: 'destructive' })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/service-accounts/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['service-accounts'] })
      setDeleteTarget(null)
      toast({ title: 'Service account deleted' })
    },
    onError: () => {
      toast({ title: 'Failed to delete service account', variant: 'destructive' })
    },
  })

  const createKeyMutation = useMutation({
    mutationFn: (body: { accountId: string; name: string; scopes: string[] }) =>
      api.post<{ key: string; api_key: APIKey }>(
        `/api/v1/service-accounts/${body.accountId}/api-keys`,
        { name: body.name, scopes: body.scopes }
      ),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['api-keys'] })
      setCreateKeyOpen(false)
      setKeyName('')
      setKeyScopes('')
      setGeneratedKey(data.key)
      setShowKeyDialog(true)
    },
    onError: () => {
      toast({ title: 'Failed to create API key', variant: 'destructive' })
    },
  })

  const revokeKeyMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/api-keys/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['api-keys'] })
      setRevokeKeyTarget(null)
      toast({ title: 'API key revoked' })
    },
    onError: () => {
      toast({ title: 'Failed to revoke API key', variant: 'destructive' })
    },
  })

  function copyToClipboard(text: string) {
    navigator.clipboard.writeText(text)
    toast({ title: 'Copied to clipboard' })
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Service Accounts</h1>
          <p className="text-muted-foreground">Manage service accounts and their API keys</p>
        </div>
        <Button onClick={() => setCreateOpen(true)}>
          <Plus className="mr-2 h-4 w-4" />
          Create Service Account
        </Button>
      </div>

      <div className="flex items-center gap-4">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search service accounts..."
            className="pl-9"
            value={search}
            onChange={(e) => {
              setSearch(e.target.value)
              setPage(1)
            }}
          />
        </div>
      </div>

      {isLoading ? (
        <div className="flex flex-col items-center justify-center py-12">
          <LoadingSpinner size="lg" />
          <p className="mt-4 text-sm text-muted-foreground">Loading service accounts...</p>
        </div>
      ) : isError ? (
        <QueryError error={error} resource="service accounts" />
      ) : accounts.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
          <Bot className="h-12 w-12 text-muted-foreground/40 mb-3" />
          <p className="font-medium">No service accounts found</p>
          <p className="text-sm">Create a service account for programmatic access</p>
        </div>
      ) : (
        <div className="space-y-4">
          {accounts.map((account) => (
            <Card key={account.id}>
              <CardHeader className="flex flex-row items-center justify-between pb-2">
                <div className="flex items-center gap-3">
                  <Key className="h-5 w-5 text-muted-foreground" />
                  <div>
                    <CardTitle className="text-base">{account.name}</CardTitle>
                    <p className="text-sm text-muted-foreground">{account.description}</p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Badge variant={account.status === 'active' ? 'default' : 'secondary'}>
                    {account.status}
                  </Badge>
                  <span className="text-xs text-muted-foreground">
                    Created {new Date(account.created_at).toLocaleDateString()}
                  </span>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() =>
                      setExpandedAccount(expandedAccount === account.id ? null : account.id)
                    }
                  >
                    <Key className="mr-1 h-3 w-3" />
                    API Keys
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => setDeleteTarget(account)}
                  >
                    <Trash2 className="h-4 w-4 text-red-500" />
                  </Button>
                </div>
              </CardHeader>

              {expandedAccount === account.id && (
                <CardContent>
                  <APIKeysSection
                    accountId={account.id}
                    onCreateKey={() => {
                      setCreateKeyAccountId(account.id)
                      setCreateKeyOpen(true)
                    }}
                    onRevokeKey={setRevokeKeyTarget}
                    revealedKey={revealedKey}
                    setRevealedKey={setRevealedKey}
                  />
                </CardContent>
              )}
            </Card>
          ))}
        </div>
      )}

      {totalPages > 1 && (
        <div className="flex items-center justify-between">
          <p className="text-sm text-muted-foreground">
            Showing {(page - 1) * pageSize + 1}-{Math.min(page * pageSize, total)} of {total}
          </p>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => setPage(page - 1)}>
              <ChevronLeft className="h-4 w-4" />
            </Button>
            <Button variant="outline" size="sm" disabled={page >= totalPages} onClick={() => setPage(page + 1)}>
              <ChevronRight className="h-4 w-4" />
            </Button>
          </div>
        </div>
      )}

      {/* Create Service Account Dialog */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create Service Account</DialogTitle>
            <DialogDescription>Add a new service account for programmatic access.</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <label className="text-sm font-medium">Name</label>
              <Input
                placeholder="my-service-account"
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
              />
            </div>
            <div>
              <label className="text-sm font-medium">Description</label>
              <Input
                placeholder="Description of the service account"
                value={newDescription}
                onChange={(e) => setNewDescription(e.target.value)}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>Cancel</Button>
            <Button
              disabled={!newName.trim() || createMutation.isPending}
              onClick={() => createMutation.mutate({ name: newName, description: newDescription })}
            >
              {createMutation.isPending ? 'Creating...' : 'Create'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <AlertDialog open={!!deleteTarget} onOpenChange={(open) => !open && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Service Account</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete &quot;{deleteTarget?.name}&quot;? This will revoke all associated API keys. This action cannot be undone.
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

      {/* Create API Key Dialog */}
      <Dialog open={createKeyOpen} onOpenChange={setCreateKeyOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create API Key</DialogTitle>
            <DialogDescription>Generate a new API key for this service account.</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <label className="text-sm font-medium">Key Name</label>
              <Input
                placeholder="production-key"
                value={keyName}
                onChange={(e) => setKeyName(e.target.value)}
              />
            </div>
            <div>
              <label className="text-sm font-medium">Scopes (comma-separated)</label>
              <Input
                placeholder="read:users, write:users, read:groups"
                value={keyScopes}
                onChange={(e) => setKeyScopes(e.target.value)}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateKeyOpen(false)}>Cancel</Button>
            <Button
              disabled={!keyName.trim() || createKeyMutation.isPending}
              onClick={() =>
                createKeyAccountId &&
                createKeyMutation.mutate({
                  accountId: createKeyAccountId,
                  name: keyName,
                  scopes: keyScopes.split(',').map((s) => s.trim()).filter(Boolean),
                })
              }
            >
              {createKeyMutation.isPending ? 'Creating...' : 'Create Key'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Show Generated Key Dialog */}
      <Dialog open={showKeyDialog} onOpenChange={setShowKeyDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>API Key Created</DialogTitle>
            <DialogDescription>
              Copy this key now. You will not be able to see it again.
            </DialogDescription>
          </DialogHeader>
          <div className="flex items-center gap-2 p-3 bg-muted rounded-md font-mono text-sm break-all">
            <span className="flex-1">{generatedKey}</span>
            <Button variant="ghost" size="sm" onClick={() => copyToClipboard(generatedKey)}>
              <Copy className="h-4 w-4" />
            </Button>
          </div>
          <DialogFooter>
            <Button onClick={() => setShowKeyDialog(false)}>Done</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Revoke API Key Confirmation */}
      <AlertDialog open={!!revokeKeyTarget} onOpenChange={(open) => !open && setRevokeKeyTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Revoke API Key</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to revoke &quot;{revokeKeyTarget?.name}&quot;? Applications using this key will lose access immediately.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => revokeKeyTarget && revokeKeyMutation.mutate(revokeKeyTarget.id)}
            >
              Revoke
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}

function APIKeysSection({
  accountId,
  onCreateKey,
  onRevokeKey,
  revealedKey,
  setRevealedKey,
}: {
  accountId: string
  onCreateKey: () => void
  onRevokeKey: (key: APIKey) => void
  revealedKey: string | null
  setRevealedKey: (id: string | null) => void
}) {
  const { data: keysData, isLoading } = useQuery({
    queryKey: ['api-keys', accountId],
    queryFn: () =>
      api.get<{ api_keys: APIKey[] }>(`/api/v1/service-accounts/${accountId}/api-keys`),
  })

  const keys = keysData?.api_keys || []

  return (
    <div className="space-y-3 border-t pt-4">
      <div className="flex items-center justify-between">
        <h4 className="text-sm font-medium">API Keys</h4>
        <Button variant="outline" size="sm" onClick={onCreateKey}>
          <Plus className="mr-1 h-3 w-3" />
          Create Key
        </Button>
      </div>

      {isLoading ? (
        <p className="text-sm text-muted-foreground">Loading keys...</p>
      ) : keys.length === 0 ? (
        <p className="text-sm text-muted-foreground">No API keys yet</p>
      ) : (
        <div className="space-y-2">
          {keys.map((key) => (
            <div
              key={key.id}
              className="flex items-center justify-between p-3 border rounded-md"
            >
              <div className="flex items-center gap-3">
                <div className="flex items-center gap-1">
                  <code className="text-sm bg-muted px-2 py-0.5 rounded">
                    {revealedKey === key.id ? key.key_prefix + '...' : '****...'}
                  </code>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => setRevealedKey(revealedKey === key.id ? null : key.id)}
                  >
                    {revealedKey === key.id ? (
                      <EyeOff className="h-3 w-3" />
                    ) : (
                      <Eye className="h-3 w-3" />
                    )}
                  </Button>
                </div>
                <span className="text-sm font-medium">{key.name}</span>
                <div className="flex gap-1">
                  {key.scopes.map((scope) => (
                    <Badge key={scope} variant="outline" className="text-xs">
                      {scope}
                    </Badge>
                  ))}
                </div>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-xs text-muted-foreground">
                  {key.last_used_at
                    ? `Last used ${new Date(key.last_used_at).toLocaleDateString()}`
                    : 'Never used'}
                </span>
                <Button variant="ghost" size="sm" onClick={() => onRevokeKey(key)}>
                  <Trash2 className="h-4 w-4 text-red-500" />
                </Button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
