import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { api } from '../lib/api'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'
import { ConfirmAction } from '../components/confirm-action'
import { Archive, Plus, Trash2, RotateCcw, Database, Shield } from 'lucide-react'

interface RetentionPolicy {
  id: string
  name: string
  event_category: string
  retention_days: number
  archive_enabled: boolean
  archive_format: string
  enabled: boolean
  created_at: string
  updated_at: string
}

interface AuditArchive {
  id: string
  name: string
  date_range_start: string | null
  date_range_end: string | null
  event_count: number
  file_size: number
  file_path: string
  format: string
  status: string
  created_by: string | null
  created_at: string
}

const statusColors: Record<string, string> = {
  completed: 'bg-green-100 text-green-800',
  creating: 'bg-blue-100 text-blue-800',
  failed: 'bg-red-100 text-red-800',
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`
}

export function AuditArchivalPage() {
  const queryClient = useQueryClient()
  const [activeTab, setActiveTab] = useState<'retention' | 'archives'>('retention')

  // Retention form state
  const [showCreateRetention, setShowCreateRetention] = useState(false)
  const [retName, setRetName] = useState('')
  const [retCategory, setRetCategory] = useState('all')
  const [retDays, setRetDays] = useState(365)
  const [retArchive, setRetArchive] = useState(true)

  // Archive form state
  const [showCreateArchive, setShowCreateArchive] = useState(false)
  const [arcName, setArcName] = useState('')
  const [arcStart, setArcStart] = useState('')
  const [arcEnd, setArcEnd] = useState('')

  const { data: retentionData, isLoading: retLoading } = useQuery({
    queryKey: ['audit-retention'],
    queryFn: () => api.get<{ data: RetentionPolicy[] }>('/api/v1/audit-retention'),
  })

  const { data: archivesData, isLoading: arcLoading, isError: arcError, error: arcErrorObj } = useQuery({
    queryKey: ['audit-archives'],
    queryFn: () => api.get<{ data: AuditArchive[] }>('/api/v1/audit-archives'),
    refetchInterval: 5000,
  })

  // Retention mutations
  const createRetentionMutation = useMutation({
    mutationFn: (data: Record<string, unknown>) => api.post('/api/v1/audit-retention', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['audit-retention'] })
      setShowCreateRetention(false)
      setRetName('')
    },
  })

  const toggleRetentionMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      api.put(`/api/v1/audit-retention/${id}`, { enabled }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['audit-retention'] }),
  })

  const deleteRetentionMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/audit-retention/${id}`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['audit-retention'] }),
  })

  // Archive mutations
  const createArchiveMutation = useMutation({
    mutationFn: (data: Record<string, unknown>) => api.post('/api/v1/audit-archives', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['audit-archives'] })
      setShowCreateArchive(false)
      setArcName('')
    },
  })

  const restoreMutation = useMutation({
    mutationFn: (id: string) => api.post(`/api/v1/audit-archives/${id}/restore`, {}),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['audit-archives'] }),
  })

  const isLoading = retLoading || arcLoading
  if (isLoading) return <div className="flex justify-center py-12"><LoadingSpinner size="lg" /></div>
  if (arcError) return <QueryError error={arcErrorObj} resource="audit archives" />

  const retentionPolicies = retentionData?.data || []
  const archives = archivesData?.data || []

  const totalArchiveSize = archives.reduce((sum, a) => sum + (a.file_size || 0), 0)
  const totalArchivedEvents = archives.filter(a => a.status === 'completed').reduce((sum, a) => sum + a.event_count, 0)

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Audit Archival & Retention</h1>
        <p className="text-muted-foreground">Manage audit event lifecycle, retention policies, and archives</p>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-3 gap-4">
        <Card><CardContent className="pt-4 text-center">
          <Database className="h-5 w-5 mx-auto mb-1 text-blue-600" />
          <p className="text-2xl font-bold">{retentionPolicies.length}</p>
          <p className="text-xs text-muted-foreground">Retention Policies</p>
        </CardContent></Card>
        <Card><CardContent className="pt-4 text-center">
          <Archive className="h-5 w-5 mx-auto mb-1 text-green-600" />
          <p className="text-2xl font-bold">{totalArchivedEvents.toLocaleString()}</p>
          <p className="text-xs text-muted-foreground">Archived Events</p>
        </CardContent></Card>
        <Card><CardContent className="pt-4 text-center">
          <Shield className="h-5 w-5 mx-auto mb-1 text-purple-600" />
          <p className="text-2xl font-bold">{formatBytes(totalArchiveSize)}</p>
          <p className="text-xs text-muted-foreground">Archive Storage</p>
        </CardContent></Card>
      </div>

      {/* Tab Navigation */}
      <div className="flex gap-2 border-b">
        <button className={`px-4 py-2 text-sm font-medium border-b-2 ${activeTab === 'retention' ? 'border-blue-500 text-blue-600' : 'border-transparent text-muted-foreground'}`}
          onClick={() => setActiveTab('retention')}>Retention Policies</button>
        <button className={`px-4 py-2 text-sm font-medium border-b-2 ${activeTab === 'archives' ? 'border-blue-500 text-blue-600' : 'border-transparent text-muted-foreground'}`}
          onClick={() => setActiveTab('archives')}>Archives</button>
      </div>

      {/* Retention Policies Tab */}
      {activeTab === 'retention' && (
        <>
          <div className="flex justify-end">
            <Button onClick={() => setShowCreateRetention(!showCreateRetention)}>
              <Plus className="h-4 w-4 mr-2" />{showCreateRetention ? 'Cancel' : 'New Policy'}
            </Button>
          </div>

          {showCreateRetention && (
            <Card>
              <CardHeader><CardTitle>New Retention Policy</CardTitle></CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-3 gap-4">
                  <div>
                    <label className="text-sm font-medium">Name</label>
                    <input className="w-full border rounded px-3 py-2 mt-1 text-sm" value={retName} onChange={e => setRetName(e.target.value)} />
                  </div>
                  <div>
                    <label className="text-sm font-medium">Event Category</label>
                    <select className="w-full border rounded px-3 py-2 mt-1 text-sm" value={retCategory} onChange={e => setRetCategory(e.target.value)}>
                      <option value="all">All Categories</option>
                      <option value="authentication">Authentication</option>
                      <option value="authorization">Authorization</option>
                      <option value="user_management">User Management</option>
                      <option value="configuration">Configuration</option>
                      <option value="data_access">Data Access</option>
                    </select>
                  </div>
                  <div>
                    <label className="text-sm font-medium">Retention Days</label>
                    <input type="number" className="w-full border rounded px-3 py-2 mt-1 text-sm" value={retDays} onChange={e => setRetDays(Number(e.target.value))} />
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <input type="checkbox" id="archiveEnabled" checked={retArchive} onChange={e => setRetArchive(e.target.checked)} />
                  <label htmlFor="archiveEnabled" className="text-sm">Archive events before deletion</label>
                </div>
                <Button onClick={() => createRetentionMutation.mutate({ name: retName, event_category: retCategory, retention_days: retDays, archive_enabled: retArchive })}
                  disabled={!retName || createRetentionMutation.isPending}>
                  {createRetentionMutation.isPending ? 'Creating...' : 'Create Policy'}
                </Button>
              </CardContent>
            </Card>
          )}

          <Card>
            <CardContent className="pt-4">
              <div className="divide-y">
                {retentionPolicies.map(p => (
                  <div key={p.id} className="py-3 flex items-center justify-between">
                    <div>
                      <div className="flex items-center gap-2">
                        <p className="font-medium text-sm">{p.name}</p>
                        <Badge variant="outline">{p.event_category}</Badge>
                        <Badge variant={p.enabled ? 'default' : 'secondary'}>{p.enabled ? 'Enabled' : 'Disabled'}</Badge>
                      </div>
                      <p className="text-xs text-muted-foreground mt-0.5">
                        Retain for {p.retention_days} days {p.archive_enabled ? '(archive before delete)' : '(no archive)'}
                      </p>
                    </div>
                    <div className="flex gap-2">
                      <Button size="sm" variant="outline" onClick={() => toggleRetentionMutation.mutate({ id: p.id, enabled: !p.enabled })}>
                        {p.enabled ? 'Disable' : 'Enable'}
                      </Button>
                      <ConfirmAction
                        title="Delete this retention policy?"
                        description={`This removes the retention policy ${p.name}. Audit events in the ${p.event_category} category will no longer be governed by it.`}
                        destructive
                        confirmLabel="Delete"
                        onConfirm={() => deleteRetentionMutation.mutateAsync(p.id)}
                      >
                        {(open) => (
                          <Button size="sm" variant="ghost" onClick={open}>
                            <Trash2 className="h-3 w-3" />
                          </Button>
                        )}
                      </ConfirmAction>
                    </div>
                  </div>
                ))}
                {retentionPolicies.length === 0 && <p className="py-8 text-center text-muted-foreground">No retention policies configured</p>}
              </div>
            </CardContent>
          </Card>
        </>
      )}

      {/* Archives Tab */}
      {activeTab === 'archives' && (
        <>
          <div className="flex justify-end">
            <Button onClick={() => setShowCreateArchive(!showCreateArchive)}>
              <Plus className="h-4 w-4 mr-2" />{showCreateArchive ? 'Cancel' : 'Create Archive'}
            </Button>
          </div>

          {showCreateArchive && (
            <Card>
              <CardHeader><CardTitle>Create Archive</CardTitle></CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-3 gap-4">
                  <div>
                    <label className="text-sm font-medium">Archive Name</label>
                    <input className="w-full border rounded px-3 py-2 mt-1 text-sm" value={arcName} onChange={e => setArcName(e.target.value)} />
                  </div>
                  <div>
                    <label className="text-sm font-medium">Start Date</label>
                    <input type="datetime-local" className="w-full border rounded px-3 py-2 mt-1 text-sm" value={arcStart} onChange={e => setArcStart(e.target.value)} />
                  </div>
                  <div>
                    <label className="text-sm font-medium">End Date</label>
                    <input type="datetime-local" className="w-full border rounded px-3 py-2 mt-1 text-sm" value={arcEnd} onChange={e => setArcEnd(e.target.value)} />
                  </div>
                </div>
                <Button onClick={() => createArchiveMutation.mutate({
                  name: arcName,
                  date_range_start: new Date(arcStart).toISOString(),
                  date_range_end: new Date(arcEnd).toISOString(),
                })} disabled={!arcName || !arcStart || !arcEnd || createArchiveMutation.isPending}>
                  {createArchiveMutation.isPending ? 'Creating...' : 'Create Archive'}
                </Button>
              </CardContent>
            </Card>
          )}

          <Card>
            <CardContent className="pt-4">
              <div className="divide-y">
                {archives.map(a => (
                  <div key={a.id} className="py-3 flex items-center justify-between">
                    <div>
                      <div className="flex items-center gap-2">
                        <p className="font-medium text-sm">{a.name}</p>
                        <Badge className={statusColors[a.status] || ''}>{a.status}</Badge>
                      </div>
                      <div className="flex gap-3 text-xs text-muted-foreground mt-0.5">
                        {a.date_range_start && <span>{new Date(a.date_range_start).toLocaleDateString()} - {a.date_range_end ? new Date(a.date_range_end).toLocaleDateString() : ''}</span>}
                        <span>{a.event_count.toLocaleString()} events</span>
                        <span>{formatBytes(a.file_size)}</span>
                      </div>
                    </div>
                    <div className="flex gap-2">
                      {a.status === 'completed' && (
                        <ConfirmAction
                          title="Restore this archive?"
                          description="This re-ingests the archived audit events back into the live audit store. Depending on the archive size this can take a while and add load to the system."
                          confirmLabel="Restore"
                          onConfirm={() => restoreMutation.mutateAsync(a.id)}
                        >
                          {(open) => (
                            <Button size="sm" variant="outline" onClick={open} disabled={restoreMutation.isPending}>
                              <RotateCcw className="h-3 w-3 mr-1" />Restore
                            </Button>
                          )}
                        </ConfirmAction>
                      )}
                    </div>
                  </div>
                ))}
                {archives.length === 0 && <p className="py-8 text-center text-muted-foreground">No archives created yet</p>}
              </div>
            </CardContent>
          </Card>
        </>
      )}
    </div>
  )
}
