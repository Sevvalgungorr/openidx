import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { api } from '../lib/api'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'
import { Layers, Play, Download, X, CheckCircle, AlertTriangle, Clock } from 'lucide-react'

interface BulkOperation {
  id: string
  type: string
  status: string
  total_items: number
  processed_items: number
  success_count: number
  error_count: number
  errors: Array<{ user_id: string; error: string }>
  parameters: Record<string, string>
  created_by: string | null
  created_at: string
  completed_at: string | null
}

interface BulkOperationItem {
  id: string
  operation_id: string
  entity_id: string | null
  entity_name: string
  status: string
  error_message: string
  processed_at: string | null
}

const operationTypes: Record<string, { label: string; description: string; needsParam: string }> = {
  enable_users: { label: 'Enable Users', description: 'Enable multiple disabled user accounts', needsParam: '' },
  disable_users: { label: 'Disable Users', description: 'Disable multiple user accounts', needsParam: '' },
  delete_users: { label: 'Delete Users', description: 'Permanently delete multiple user accounts', needsParam: '' },
  assign_role: { label: 'Assign Role', description: 'Assign a role to multiple users', needsParam: 'role_id' },
  remove_role: { label: 'Remove Role', description: 'Remove a role from multiple users', needsParam: 'role_id' },
  add_to_group: { label: 'Add to Group', description: 'Add multiple users to a group', needsParam: 'group_id' },
  remove_from_group: { label: 'Remove from Group', description: 'Remove multiple users from a group', needsParam: 'group_id' },
  reset_passwords: { label: 'Force Password Reset', description: 'Force password reset for multiple users', needsParam: '' },
}

const statusIcons: Record<string, React.ReactNode> = {
  completed: <CheckCircle className="h-4 w-4 text-green-600" />,
  running: <Clock className="h-4 w-4 text-primary animate-spin" />,
  failed: <AlertTriangle className="h-4 w-4 text-red-600" />,
  pending: <Clock className="h-4 w-4 text-muted-foreground" />,
  cancelled: <X className="h-4 w-4 text-muted-foreground" />,
}

const statusColors: Record<string, string> = {
  completed: 'bg-green-100 text-green-800',
  running: 'bg-blue-100 text-blue-800',
  failed: 'bg-red-100 text-red-800',
  pending: 'bg-muted text-foreground',
  cancelled: 'bg-muted text-muted-foreground',
}

export function BulkOperationsPage() {
  const queryClient = useQueryClient()
  const [selectedType, setSelectedType] = useState('')
  const [userIdsText, setUserIdsText] = useState('')
  const [paramValue, setParamValue] = useState('')
  const [selectedOpId, setSelectedOpId] = useState<string | null>(null)

  const { data: opsData, isLoading, isError, error } = useQuery({
    queryKey: ['bulk-operations'],
    queryFn: () => api.get<{ data: BulkOperation[] }>('/api/v1/bulk-operations'),
    refetchInterval: 5000,
  })

  const { data: detailData } = useQuery({
    queryKey: ['bulk-operation-detail', selectedOpId],
    queryFn: () => api.get<{ operation: BulkOperation; items: BulkOperationItem[] }>(`/api/v1/bulk-operations/${selectedOpId}`),
    enabled: !!selectedOpId,
    refetchInterval: 3000,
  })

  const { data: rolesData } = useQuery({
    queryKey: ['roles-for-bulk'],
    queryFn: () => api.get<{ data: Array<{ id: string; name: string }> }>('/api/v1/identity/roles'),
  })

  const { data: groupsData } = useQuery({
    queryKey: ['groups-for-bulk'],
    // /api/v1/identity/groups returns a bare SCIM array (displayName), not
    // { data: [{id,name}] } — flatten it for the group selector.
    queryFn: async () => {
      const raw = await api.get<Array<Record<string, unknown>>>('/api/v1/identity/groups')
      return (raw || []).map(g => ({ id: String(g.id ?? ''), name: String(g.displayName ?? g.name ?? '') }))
    },
  })

  const createMutation = useMutation({
    mutationFn: (data: { type: string; user_ids: string[]; parameters: Record<string, string> }) =>
      api.post('/api/v1/bulk-operations', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['bulk-operations'] })
      setSelectedType('')
      setUserIdsText('')
      setParamValue('')
    },
  })

  const handleSubmit = () => {
    const userIds = userIdsText.split(/[\n,]+/).map(s => s.trim()).filter(Boolean)
    if (userIds.length === 0) return
    const params: Record<string, string> = {}
    const opConfig = operationTypes[selectedType]
    if (opConfig?.needsParam && paramValue) {
      params[opConfig.needsParam] = paramValue
    }
    createMutation.mutate({ type: selectedType, user_ids: userIds, parameters: params })
  }

  const handleExportCSV = async () => {
    const data = await api.get<string>('/api/v1/bulk-operations/export/users')
    const blob = new Blob([data], { type: 'text/csv' })
    const url = window.URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `users_export_${new Date().toISOString().split('T')[0]}.csv`
    a.click()
    window.URL.revokeObjectURL(url)
  }

  if (isLoading) return <div className="flex justify-center py-12"><LoadingSpinner size="lg" /></div>
  if (isError) return <QueryError error={error} resource="bulk operations" />

  const ops = opsData?.data || []
  const detail = detailData?.operation
  const items = detailData?.items || []
  const roles = rolesData?.data || []
  const groups = groupsData || []

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Bulk Operations</h1>
          <p className="text-muted-foreground">Perform operations on multiple users at once</p>
        </div>
        <Button variant="outline" onClick={handleExportCSV}>
          <Download className="h-4 w-4 mr-2" />Export Users CSV
        </Button>
      </div>

      {/* New Operation */}
      <Card>
        <CardHeader><CardTitle className="flex items-center gap-2"><Layers className="h-5 w-5" />New Bulk Operation</CardTitle></CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-sm font-medium">Operation Type</label>
              <select className="w-full border rounded px-3 py-2 mt-1 text-sm" value={selectedType} onChange={e => setSelectedType(e.target.value)}>
                <option value="">Select an operation...</option>
                {Object.entries(operationTypes).map(([key, val]) => (
                  <option key={key} value={key}>{val.label}</option>
                ))}
              </select>
              {selectedType && <p className="text-xs text-muted-foreground mt-1">{operationTypes[selectedType]?.description}</p>}
            </div>
            <div>
              {selectedType && operationTypes[selectedType]?.needsParam === 'role_id' && (
                <>
                  <label className="text-sm font-medium">Role</label>
                  <select className="w-full border rounded px-3 py-2 mt-1 text-sm" value={paramValue} onChange={e => setParamValue(e.target.value)}>
                    <option value="">Select role...</option>
                    {roles.map(r => <option key={r.id} value={r.id}>{r.name}</option>)}
                  </select>
                </>
              )}
              {selectedType && operationTypes[selectedType]?.needsParam === 'group_id' && (
                <>
                  <label className="text-sm font-medium">Group</label>
                  <select className="w-full border rounded px-3 py-2 mt-1 text-sm" value={paramValue} onChange={e => setParamValue(e.target.value)}>
                    <option value="">Select group...</option>
                    {groups.map(g => <option key={g.id} value={g.id}>{g.name}</option>)}
                  </select>
                </>
              )}
            </div>
          </div>
          <div>
            <label className="text-sm font-medium">User IDs (one per line or comma-separated)</label>
            <textarea className="w-full border rounded px-3 py-2 mt-1 text-sm font-mono h-24"
              placeholder="Paste user IDs here..."
              value={userIdsText} onChange={e => setUserIdsText(e.target.value)} />
          </div>
          <Button onClick={handleSubmit} disabled={!selectedType || !userIdsText.trim() || createMutation.isPending}>
            <Play className="h-4 w-4 mr-2" />{createMutation.isPending ? 'Running...' : 'Execute Operation'}
          </Button>
        </CardContent>
      </Card>

      {/* Operation History */}
      <Card>
        <CardHeader><CardTitle>Operation History</CardTitle></CardHeader>
        <CardContent>
          <div className="divide-y">
            {ops.map(op => (
              <div key={op.id} className="py-3 flex items-center justify-between cursor-pointer hover:bg-muted px-2 rounded"
                onClick={() => setSelectedOpId(op.id)}>
                <div className="flex items-center gap-3">
                  {statusIcons[op.status]}
                  <div>
                    <p className="font-medium text-sm">{operationTypes[op.type]?.label || op.type}</p>
                    <p className="text-xs text-muted-foreground">{new Date(op.created_at).toLocaleString()}</p>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <Badge className={statusColors[op.status] || ''}>{op.status}</Badge>
                  <div className="text-right text-sm">
                    <p>{op.processed_items}/{op.total_items} processed</p>
                    <div className="flex gap-2 text-xs">
                      <span className="text-green-600">{op.success_count} ok</span>
                      {op.error_count > 0 && <span className="text-red-600">{op.error_count} errors</span>}
                    </div>
                  </div>
                  {op.total_items > 0 && (
                    <div className="w-20 h-2 bg-muted rounded-full">
                      <div className="h-2 bg-blue-500 rounded-full" style={{ width: `${(op.processed_items / op.total_items) * 100}%` }} />
                    </div>
                  )}
                </div>
              </div>
            ))}
            {ops.length === 0 && (
              <p className="py-8 text-center text-muted-foreground">No bulk operations yet</p>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Operation Detail */}
      {selectedOpId && detail && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center justify-between">
              <span>Operation Detail: {operationTypes[detail.type]?.label || detail.type}</span>
              <Button variant="ghost" size="sm" onClick={() => setSelectedOpId(null)}><X className="h-4 w-4" /></Button>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="divide-y">
              {items.map(item => (
                <div key={item.id} className="py-2 flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium">{item.entity_name}</p>
                    <p className="text-xs text-muted-foreground">{item.entity_id}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge className={item.status === 'success' ? 'bg-green-100 text-green-800' : item.status === 'error' ? 'bg-red-100 text-red-800' : 'bg-muted text-foreground'}>
                      {item.status}
                    </Badge>
                    {item.error_message && <span className="text-xs text-red-600">{item.error_message}</span>}
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
