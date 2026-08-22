import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Key, Plus, Ban, Copy, Clock, CheckCircle2, XCircle, AlertTriangle, FileText } from 'lucide-react'
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
  DialogDescription,
} from '../components/ui/dialog'
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

interface BypassCode {
  id: string
  user_id: string
  user_email: string
  code?: string
  reason: string
  generated_by: string
  generator_email: string
  valid_from: string
  valid_until: string
  max_uses: number
  use_count: number
  status: string
  used_at?: string
  used_from_ip?: string
  created_at: string
}

interface AuditEntry {
  id: string
  bypass_code_id?: string
  user_id?: string
  action: string
  performed_by?: string
  ip_address?: string
  details?: Record<string, unknown>
  created_at: string
}

export function MFABypassCodesPage() {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [statusFilter, setStatusFilter] = useState('')
  const [userFilter, setUserFilter] = useState('')
  const [createDialog, setCreateDialog] = useState(false)
  const [codeDialog, setCodeDialog] = useState(false)
  const [auditDialog, setAuditDialog] = useState(false)
  const [generatedCode, setGeneratedCode] = useState<BypassCode | null>(null)

  // Form state
  const [newCode, setNewCode] = useState({
    user_id: '',
    reason: '',
    valid_hours: 24,
    max_uses: 1
  })

  // Fetch codes
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['bypass-codes', statusFilter, userFilter],
    queryFn: async () => {
      const params = new URLSearchParams()
      if (statusFilter) params.append('status', statusFilter)
      if (userFilter) params.append('user_id', userFilter)
      return api.get<{ codes: BypassCode[] }>(`/api/v1/identity/mfa/bypass-codes?${params}`)
    }
  })

  const codes: BypassCode[] = data?.codes || []

  // Fetch audit log
  const { data: auditData } = useQuery({
    queryKey: ['bypass-codes-audit'],
    queryFn: async () => {
      return api.get<{ entries: AuditEntry[] }>('/api/v1/identity/mfa/bypass-codes/audit')
    },
    enabled: auditDialog
  })

  const auditEntries: AuditEntry[] = auditData?.entries || []

  // Mutations
  const generateMutation = useMutation({
    mutationFn: (data: typeof newCode) =>
      api.post<BypassCode>('/api/v1/identity/mfa/bypass-codes', data),
    onSuccess: (response) => {
      queryClient.invalidateQueries({ queryKey: ['bypass-codes'] })
      setGeneratedCode(response)
      setCreateDialog(false)
      setCodeDialog(true)
      setNewCode({ user_id: '', reason: '', valid_hours: 24, max_uses: 1 })
    },
    onError: (error: Error) => {
      toast({ title: 'Error', description: error.message, variant: 'destructive' })
    }
  })

  const revokeMutation = useMutation({
    mutationFn: (codeId: string) =>
      api.delete(`/api/v1/identity/mfa/bypass-codes/${codeId}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['bypass-codes'] })
      toast({ title: 'Code Revoked', description: 'Bypass code has been revoked.' })
    }
  })

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'active':
        return <Badge className="bg-green-100 text-green-800"><CheckCircle2 className="h-3 w-3 mr-1" />Active</Badge>
      case 'used':
        return <Badge className="bg-blue-100 text-blue-800"><CheckCircle2 className="h-3 w-3 mr-1" />Used</Badge>
      case 'expired':
        return <Badge className="bg-gray-100 text-gray-800"><Clock className="h-3 w-3 mr-1" />Expired</Badge>
      case 'revoked':
        return <Badge className="bg-red-100 text-red-800"><XCircle className="h-3 w-3 mr-1" />Revoked</Badge>
      default:
        return <Badge>{status}</Badge>
    }
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
    toast({ title: 'Copied', description: 'Code copied to clipboard.' })
  }

  // Stats
  const active = codes.filter(c => c.status === 'active').length
  const used = codes.filter(c => c.status === 'used').length
  const expired = codes.filter(c => c.status === 'expired' || c.status === 'revoked').length

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">MFA Bypass Codes</h1>
          <p className="text-muted-foreground">Generate temporary bypass codes for users</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => setAuditDialog(true)}>
            <FileText className="h-4 w-4 mr-2" />
            Audit Log
          </Button>
          <Button onClick={() => setCreateDialog(true)}>
            <Plus className="h-4 w-4 mr-2" />
            Generate Code
          </Button>
        </div>
      </div>

      {/* Warning Banner */}
      <Card className="border-amber-200 bg-amber-50">
        <CardContent className="pt-4">
          <div className="flex items-start gap-3">
            <AlertTriangle className="h-5 w-5 text-amber-600 mt-0.5" />
            <div>
              <p className="font-medium text-amber-900">Security Notice</p>
              <p className="text-sm text-amber-800">
                Bypass codes allow users to skip MFA verification. Use sparingly and always document the reason.
                All bypass code usage is logged for audit purposes.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Stats */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Codes</CardTitle>
            <Key className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{codes.length}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active</CardTitle>
            <Key className="h-4 w-4 text-green-600" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600">{active}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Used</CardTitle>
            <Key className="h-4 w-4 text-blue-600" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-blue-600">{used}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Expired/Revoked</CardTitle>
            <Key className="h-4 w-4 text-gray-600" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-gray-600">{expired}</div>
          </CardContent>
        </Card>
      </div>

      {/* Filters */}
      <div className="flex gap-4">
        <Input
          placeholder="Filter by user ID..."
          value={userFilter}
          onChange={(e) => setUserFilter(e.target.value)}
          className="max-w-sm"
        />
        <Select value={statusFilter || 'all'} onValueChange={(v) => setStatusFilter(v === 'all' ? '' : v)}>
          <SelectTrigger className="w-[180px]">
            <SelectValue placeholder="All statuses" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All statuses</SelectItem>
            <SelectItem value="active">Active</SelectItem>
            <SelectItem value="used">Used</SelectItem>
            <SelectItem value="expired">Expired</SelectItem>
            <SelectItem value="revoked">Revoked</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Codes List */}
      <Card>
        <CardHeader>
          <CardTitle>Bypass Codes</CardTitle>
          <CardDescription>All generated MFA bypass codes</CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex justify-center py-8">
              <LoadingSpinner size="lg" />
            </div>
          ) : isError ? (
            <QueryError error={error} resource="MFA bypass codes" />
          ) : codes.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <Key className="h-12 w-12 mx-auto mb-3 opacity-40" />
              <p>No bypass codes found</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b">
                    <th className="text-left py-3 px-2 font-medium">User</th>
                    <th className="text-left py-3 px-2 font-medium">Reason</th>
                    <th className="text-left py-3 px-2 font-medium">Generated By</th>
                    <th className="text-left py-3 px-2 font-medium">Status</th>
                    <th className="text-left py-3 px-2 font-medium">Uses</th>
                    <th className="text-left py-3 px-2 font-medium">Valid Until</th>
                    <th className="text-left py-3 px-2 font-medium">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {codes.map((code) => (
                    <tr key={code.id} className="border-b hover:bg-muted/50">
                      <td className="py-3 px-2">{code.user_email}</td>
                      <td className="py-3 px-2 max-w-[200px] truncate" title={code.reason}>
                        {code.reason}
                      </td>
                      <td className="py-3 px-2">{code.generator_email}</td>
                      <td className="py-3 px-2">{getStatusBadge(code.status)}</td>
                      <td className="py-3 px-2">{code.use_count} / {code.max_uses}</td>
                      <td className="py-3 px-2 whitespace-nowrap">
                        {new Date(code.valid_until).toLocaleString()}
                      </td>
                      <td className="py-3 px-2">
                        {code.status === 'active' && (
                          <ConfirmAction
                            title="Revoke this MFA bypass code?"
                            description={`This immediately revokes the active MFA bypass code for ${code.user_email}. The code can no longer be used to skip MFA. This cannot be undone.`}
                            destructive
                            confirmLabel="Revoke"
                            onConfirm={() => revokeMutation.mutateAsync(code.id)}
                          >
                            {(open) => (
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={open}
                                className="text-red-600"
                              >
                                <Ban className="h-4 w-4" />
                              </Button>
                            )}
                          </ConfirmAction>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Create Dialog */}
      <Dialog open={createDialog} onOpenChange={setCreateDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Generate Bypass Code</DialogTitle>
            <DialogDescription>
              Create a temporary code to allow a user to bypass MFA verification.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>User ID *</Label>
              <Input
                value={newCode.user_id}
                onChange={(e) => setNewCode({ ...newCode, user_id: e.target.value })}
                placeholder="Enter user ID"
              />
            </div>
            <div className="space-y-2">
              <Label>Reason *</Label>
              <Textarea
                value={newCode.reason}
                onChange={(e) => setNewCode({ ...newCode, reason: e.target.value })}
                placeholder="Why is this bypass code needed?"
                rows={2}
              />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>Valid Hours</Label>
                <Input
                  type="number"
                  value={newCode.valid_hours}
                  onChange={(e) => setNewCode({ ...newCode, valid_hours: parseInt(e.target.value) })}
                  min={1}
                  max={168}
                />
              </div>
              <div className="space-y-2">
                <Label>Max Uses</Label>
                <Input
                  type="number"
                  value={newCode.max_uses}
                  onChange={(e) => setNewCode({ ...newCode, max_uses: parseInt(e.target.value) })}
                  min={1}
                  max={10}
                />
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateDialog(false)}>Cancel</Button>
            <Button
              onClick={() => generateMutation.mutate(newCode)}
              disabled={!newCode.user_id || !newCode.reason}
            >
              Generate Code
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Generated Code Dialog */}
      <Dialog open={codeDialog} onOpenChange={setCodeDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Bypass Code Generated</DialogTitle>
            <DialogDescription>
              Share this code securely with the user. It will not be shown again.
            </DialogDescription>
          </DialogHeader>
          {generatedCode && (
            <div className="space-y-4">
              <div className="bg-muted p-6 rounded-lg text-center">
                <p className="text-3xl font-mono tracking-widest">{generatedCode.code}</p>
              </div>
              <Button
                variant="outline"
                className="w-full"
                onClick={() => copyToClipboard(generatedCode.code || '')}
              >
                <Copy className="h-4 w-4 mr-2" />
                Copy to Clipboard
              </Button>
              <div className="text-sm text-muted-foreground space-y-1">
                <p><strong>User:</strong> {generatedCode.user_email}</p>
                <p><strong>Valid until:</strong> {new Date(generatedCode.valid_until).toLocaleString()}</p>
                <p><strong>Max uses:</strong> {generatedCode.max_uses}</p>
              </div>
            </div>
          )}
          <DialogFooter>
            <Button onClick={() => setCodeDialog(false)}>Close</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Audit Log Dialog */}
      <Dialog open={auditDialog} onOpenChange={setAuditDialog}>
        <DialogContent className="max-w-3xl max-h-[80vh] overflow-auto">
          <DialogHeader>
            <DialogTitle>Bypass Code Audit Log</DialogTitle>
          </DialogHeader>
          <div className="space-y-2">
            {auditEntries.map((entry) => (
              <div key={entry.id} className="flex items-start gap-3 p-3 bg-muted rounded-lg text-sm">
                <div className={`p-1 rounded ${
                  entry.action === 'generated' ? 'bg-green-100' :
                  entry.action === 'used' ? 'bg-blue-100' :
                  entry.action === 'revoked' ? 'bg-red-100' : 'bg-gray-100'
                }`}>
                  {entry.action === 'generated' && <Plus className="h-4 w-4 text-green-600" />}
                  {entry.action === 'used' && <CheckCircle2 className="h-4 w-4 text-blue-600" />}
                  {entry.action === 'revoked' && <Ban className="h-4 w-4 text-red-600" />}
                </div>
                <div className="flex-1">
                  <p className="font-medium capitalize">{entry.action}</p>
                  <p className="text-xs text-muted-foreground">
                    {new Date(entry.created_at).toLocaleString()}
                    {entry.ip_address && ` • ${entry.ip_address}`}
                  </p>
                </div>
              </div>
            ))}
            {auditEntries.length === 0 && (
              <p className="text-center text-muted-foreground py-4">No audit entries found</p>
            )}
          </div>
        </DialogContent>
      </Dialog>
    </div>
  )
}
