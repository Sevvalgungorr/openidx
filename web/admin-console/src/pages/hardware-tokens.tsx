import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Key, Plus, UserPlus, UserMinus, Ban, AlertTriangle, MoreHorizontal, Search } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '../components/ui/dialog'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '../components/ui/dropdown-menu'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '../components/ui/select'
import { Label } from '../components/ui/label'
import { Textarea } from '../components/ui/textarea'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'
import { ConfirmAction } from '../components/confirm-action'

interface HardwareToken {
  id: string
  serial_number: string
  name: string
  token_type: string
  manufacturer?: string
  model?: string
  status: string
  assigned_to?: string
  assigned_at?: string
  last_used_at?: string
  use_count: number
  created_at: string
  notes?: string
}

export function HardwareTokensPage() {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [statusFilter, setStatusFilter] = useState('')
  const [searchTerm, setSearchTerm] = useState('')
  const [createDialog, setCreateDialog] = useState(false)
  const [assignDialog, setAssignDialog] = useState(false)
  const [selectedToken, setSelectedToken] = useState<HardwareToken | null>(null)

  // Form state
  const [newToken, setNewToken] = useState({
    serial_number: '',
    name: '',
    token_type: 'yubikey',
    manufacturer: '',
    model: '',
    notes: ''
  })
  const [assignUserId, setAssignUserId] = useState('')

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['hardware-tokens', statusFilter],
    queryFn: async () => {
      const params = new URLSearchParams()
      if (statusFilter) params.append('status', statusFilter)
      return api.get<{ tokens: HardwareToken[] }>(`/api/v1/identity/hardware-tokens?${params}`)
    }
  })

  const tokens: HardwareToken[] = data?.tokens || []

  const createMutation = useMutation({
    mutationFn: (data: typeof newToken) => api.post('/api/v1/identity/hardware-tokens', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['hardware-tokens'] })
      toast({ title: 'Token Created', description: 'Hardware token has been registered.' })
      setCreateDialog(false)
      setNewToken({ serial_number: '', name: '', token_type: 'yubikey', manufacturer: '', model: '', notes: '' })
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to create token.', variant: 'destructive' })
    }
  })

  const assignMutation = useMutation({
    mutationFn: ({ tokenId, userId }: { tokenId: string; userId: string }) =>
      api.post(`/api/v1/identity/hardware-tokens/${tokenId}/assign`, { user_id: userId }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['hardware-tokens'] })
      toast({ title: 'Token Assigned', description: 'Token has been assigned to user.' })
      setAssignDialog(false)
      setAssignUserId('')
    },
    onError: () => {
      toast({ title: 'Error', description: 'Failed to assign token.', variant: 'destructive' })
    }
  })

  const unassignMutation = useMutation({
    mutationFn: (tokenId: string) =>
      api.post(`/api/v1/identity/hardware-tokens/${tokenId}/unassign`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['hardware-tokens'] })
      toast({ title: 'Token Unassigned', description: 'Token has been unassigned.' })
    }
  })

  const revokeMutation = useMutation({
    mutationFn: ({ tokenId, reason }: { tokenId: string; reason: string }) =>
      api.post(`/api/v1/identity/hardware-tokens/${tokenId}/revoke`, { reason }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['hardware-tokens'] })
      toast({ title: 'Token Revoked', description: 'Token has been revoked.' })
    }
  })

  const reportLostMutation = useMutation({
    mutationFn: (tokenId: string) =>
      api.post(`/api/v1/identity/hardware-tokens/${tokenId}/report-lost`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['hardware-tokens'] })
      toast({ title: 'Token Reported Lost', description: 'Token has been marked as lost.' })
    }
  })

  const getStatusBadge = (status: string) => {
    const styles: Record<string, string> = {
      available: 'bg-green-100 text-green-800',
      assigned: 'bg-blue-100 text-blue-800',
      revoked: 'bg-red-100 text-red-800',
      lost: 'bg-amber-100 text-amber-800'
    }
    return <Badge className={styles[status] || 'bg-gray-100'}>{status}</Badge>
  }

  const filteredTokens = tokens.filter(t =>
    t.serial_number.toLowerCase().includes(searchTerm.toLowerCase()) ||
    t.name?.toLowerCase().includes(searchTerm.toLowerCase())
  )

  // Stats
  const available = tokens.filter(t => t.status === 'available').length
  const assigned = tokens.filter(t => t.status === 'assigned').length
  const revoked = tokens.filter(t => t.status === 'revoked' || t.status === 'lost').length

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Hardware Tokens</h1>
          <p className="text-muted-foreground">Manage YubiKey and OATH hardware tokens</p>
        </div>
        <Button onClick={() => setCreateDialog(true)}>
          <Plus className="h-4 w-4 mr-2" />
          Add Token
        </Button>
      </div>

      {/* Stats */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Tokens</CardTitle>
            <Key className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{tokens.length}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Available</CardTitle>
            <Key className="h-4 w-4 text-green-600" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600">{available}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Assigned</CardTitle>
            <Key className="h-4 w-4 text-blue-600" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-blue-600">{assigned}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Revoked/Lost</CardTitle>
            <Key className="h-4 w-4 text-red-600" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-600">{revoked}</div>
          </CardContent>
        </Card>
      </div>

      {/* Filters */}
      <div className="flex gap-4">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search tokens..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="pl-10"
          />
        </div>
        <Select value={statusFilter || 'all'} onValueChange={(v) => setStatusFilter(v === 'all' ? '' : v)}>
          <SelectTrigger className="w-[180px]">
            <SelectValue placeholder="All statuses" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All statuses</SelectItem>
            <SelectItem value="available">Available</SelectItem>
            <SelectItem value="assigned">Assigned</SelectItem>
            <SelectItem value="revoked">Revoked</SelectItem>
            <SelectItem value="lost">Lost</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Tokens List */}
      <Card>
        <CardHeader>
          <CardTitle>Token Inventory</CardTitle>
          <CardDescription>All registered hardware security tokens</CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex justify-center py-8">
              <LoadingSpinner size="lg" />
            </div>
          ) : isError ? (
            <QueryError error={error} resource="hardware tokens" />
          ) : filteredTokens.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <Key className="h-12 w-12 mx-auto mb-3 opacity-40" />
              <p>No hardware tokens found</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b">
                    <th className="text-left py-3 px-2 font-medium">Serial Number</th>
                    <th className="text-left py-3 px-2 font-medium">Name</th>
                    <th className="text-left py-3 px-2 font-medium">Type</th>
                    <th className="text-left py-3 px-2 font-medium">Status</th>
                    <th className="text-left py-3 px-2 font-medium">Use Count</th>
                    <th className="text-left py-3 px-2 font-medium">Last Used</th>
                    <th className="text-left py-3 px-2 font-medium">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredTokens.map((token) => (
                    <tr key={token.id} className="border-b hover:bg-muted/50">
                      <td className="py-3 px-2 font-mono">{token.serial_number}</td>
                      <td className="py-3 px-2">{token.name || '-'}</td>
                      <td className="py-3 px-2">{token.token_type}</td>
                      <td className="py-3 px-2">{getStatusBadge(token.status)}</td>
                      <td className="py-3 px-2">{token.use_count}</td>
                      <td className="py-3 px-2">
                        {token.last_used_at ? new Date(token.last_used_at).toLocaleDateString() : 'Never'}
                      </td>
                      <td className="py-3 px-2">
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="sm">
                              <MoreHorizontal className="h-4 w-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            {token.status === 'available' && (
                              <DropdownMenuItem onClick={() => {
                                setSelectedToken(token)
                                setAssignDialog(true)
                              }}>
                                <UserPlus className="h-4 w-4 mr-2" />
                                Assign to User
                              </DropdownMenuItem>
                            )}
                            {token.status === 'assigned' && (
                              <DropdownMenuItem onClick={() => unassignMutation.mutate(token.id)}>
                                <UserMinus className="h-4 w-4 mr-2" />
                                Unassign
                              </DropdownMenuItem>
                            )}
                            <DropdownMenuSeparator />
                            {token.status !== 'revoked' && (
                              <ConfirmAction
                                title="Revoke this hardware token?"
                                description={`This permanently revokes token ${token.serial_number}. It can no longer be used for authentication, and any user it is assigned to loses this factor. This cannot be undone. Provide the reason; it is recorded in the audit log.`}
                                destructive
                                requireReason
                                confirmLabel="Revoke"
                                onConfirm={(reason) => revokeMutation.mutateAsync({ tokenId: token.id, reason: reason! })}
                              >
                                {(open) => (
                                  <DropdownMenuItem
                                    onSelect={(e) => { e.preventDefault(); open() }}
                                    className="text-red-600"
                                  >
                                    <Ban className="h-4 w-4 mr-2" />
                                    Revoke
                                  </DropdownMenuItem>
                                )}
                              </ConfirmAction>
                            )}
                            {token.status !== 'lost' && (
                              <ConfirmAction
                                title="Report this token as lost?"
                                description={`This marks token ${token.serial_number} as lost. It is disabled for authentication and the assigned user loses this factor until a replacement is issued. Provide the reason; it is recorded in the audit log.`}
                                destructive
                                requireReason
                                confirmLabel="Report Lost"
                                onConfirm={() => reportLostMutation.mutateAsync(token.id)}
                              >
                                {(open) => (
                                  <DropdownMenuItem
                                    onSelect={(e) => { e.preventDefault(); open() }}
                                    className="text-amber-600"
                                  >
                                    <AlertTriangle className="h-4 w-4 mr-2" />
                                    Report Lost
                                  </DropdownMenuItem>
                                )}
                              </ConfirmAction>
                            )}
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Create Token Dialog */}
      <Dialog open={createDialog} onOpenChange={setCreateDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add Hardware Token</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>Serial Number *</Label>
              <Input
                value={newToken.serial_number}
                onChange={(e) => setNewToken({ ...newToken, serial_number: e.target.value })}
                placeholder="e.g., 12345678"
              />
            </div>
            <div className="space-y-2">
              <Label>Name</Label>
              <Input
                value={newToken.name}
                onChange={(e) => setNewToken({ ...newToken, name: e.target.value })}
                placeholder="e.g., YubiKey 5 NFC #1"
              />
            </div>
            <div className="space-y-2">
              <Label>Token Type</Label>
              <Select
                value={newToken.token_type}
                onValueChange={(v) => setNewToken({ ...newToken, token_type: v })}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="yubikey">YubiKey</SelectItem>
                  <SelectItem value="oath-hotp">OATH HOTP</SelectItem>
                  <SelectItem value="oath-totp">OATH TOTP</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>Manufacturer</Label>
                <Input
                  value={newToken.manufacturer}
                  onChange={(e) => setNewToken({ ...newToken, manufacturer: e.target.value })}
                  placeholder="Yubico"
                />
              </div>
              <div className="space-y-2">
                <Label>Model</Label>
                <Input
                  value={newToken.model}
                  onChange={(e) => setNewToken({ ...newToken, model: e.target.value })}
                  placeholder="YubiKey 5 NFC"
                />
              </div>
            </div>
            <div className="space-y-2">
              <Label>Notes</Label>
              <Textarea
                value={newToken.notes}
                onChange={(e) => setNewToken({ ...newToken, notes: e.target.value })}
                placeholder="Optional notes..."
                rows={2}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateDialog(false)}>Cancel</Button>
            <Button onClick={() => createMutation.mutate(newToken)} disabled={!newToken.serial_number}>
              Add Token
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Assign Token Dialog */}
      <Dialog open={assignDialog} onOpenChange={setAssignDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Assign Token to User</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <p className="text-sm text-muted-foreground">
              Assigning token: <strong>{selectedToken?.serial_number}</strong>
            </p>
            <div className="space-y-2">
              <Label>User ID</Label>
              <Input
                value={assignUserId}
                onChange={(e) => setAssignUserId(e.target.value)}
                placeholder="Enter user ID"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setAssignDialog(false)}>Cancel</Button>
            <Button
              onClick={() => selectedToken && assignMutation.mutate({ tokenId: selectedToken.id, userId: assignUserId })}
              disabled={!assignUserId}
            >
              Assign Token
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
