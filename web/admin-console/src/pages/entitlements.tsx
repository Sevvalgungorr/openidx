import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Search,
  Shield,
  Users2,
  AppWindow,
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
  Package,
  Edit,
  MoreHorizontal,
} from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '../components/ui/dialog'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '../components/ui/dropdown-menu'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/select'
import { Label } from '../components/ui/label'
import { Textarea } from '../components/ui/textarea'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

interface EntitlementEntry {
  id: string
  name: string
  type: string
  description: string
  member_count: number
  risk_level: string
  owner_id?: string
  tags: string[]
  review_required: boolean
  last_reviewed_at?: string
  created_at: string
}

interface EntitlementStats {
  total_entitlements: number
  by_type: Record<string, number>
  by_risk_level: Record<string, number>
  orphan_count: number
}

const typeIcons: Record<string, React.ReactNode> = {
  role: <Shield className="h-4 w-4" />,
  group: <Users2 className="h-4 w-4" />,
  application: <AppWindow className="h-4 w-4" />,
}

const typeLabels: Record<string, string> = {
  role: 'Role',
  group: 'Group',
  application: 'Application',
}

const riskColors: Record<string, string> = {
  low: 'bg-green-100 text-green-800',
  medium: 'bg-yellow-100 text-yellow-800',
  high: 'bg-orange-100 text-orange-800',
  critical: 'bg-red-100 text-red-800',
}

export function EntitlementsPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState('')
  const [riskFilter, setRiskFilter] = useState('')
  const [page, setPage] = useState(0)
  const [totalCount, setTotalCount] = useState(0)
  const [editModal, setEditModal] = useState(false)
  const [selectedEntry, setSelectedEntry] = useState<EntitlementEntry | null>(null)
  const [metadata, setMetadata] = useState({
    risk_level: 'low',
    description: '',
    review_required: false,
    tags: '',
  })
  const PAGE_SIZE = 25

  const { data: stats } = useQuery({
    queryKey: ['entitlement-stats'],
    queryFn: () => api.get<EntitlementStats>('/api/v1/entitlements/stats'),
  })

  const { data: entitlements, isLoading, isError, error } = useQuery({
    queryKey: ['entitlements', search, typeFilter, riskFilter, page],
    queryFn: async () => {
      const params = new URLSearchParams()
      if (search) params.set('search', search)
      if (typeFilter) params.set('type', typeFilter)
      if (riskFilter) params.set('risk_level', riskFilter)
      params.set('offset', String(page * PAGE_SIZE))
      params.set('limit', String(PAGE_SIZE))
      const result = await api.getWithHeaders<EntitlementEntry[]>(`/api/v1/entitlements?${params.toString()}`)
      const total = parseInt(result.headers['x-total-count'] || '0', 10)
      if (!isNaN(total)) setTotalCount(total)
      return result.data
    },
  })

  const updateMetadataMutation = useMutation({
    mutationFn: ({ type, id, data }: { type: string; id: string; data: Record<string, unknown> }) =>
      api.put(`/api/v1/entitlements/${type}/${id}/metadata`, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['entitlements'] })
      queryClient.invalidateQueries({ queryKey: ['entitlement-stats'] })
      toast({ title: 'Success', description: 'Entitlement metadata updated', variant: 'success' })
      setEditModal(false)
    },
    onError: (error: Error) => {
      toast({ title: 'Error', description: error.message, variant: 'destructive' })
    },
  })

  const handleEditMetadata = (entry: EntitlementEntry) => {
    setSelectedEntry(entry)
    setMetadata({
      risk_level: entry.risk_level || 'low',
      description: entry.description || '',
      review_required: entry.review_required,
      tags: (entry.tags || []).join(', '),
    })
    setEditModal(true)
  }

  const handleSaveMetadata = (e: React.FormEvent) => {
    e.preventDefault()
    if (!selectedEntry) return
    updateMetadataMutation.mutate({
      type: selectedEntry.type,
      id: selectedEntry.id,
      data: {
        risk_level: metadata.risk_level,
        description: metadata.description,
        review_required: metadata.review_required,
        tags: metadata.tags.split(',').map(t => t.trim()).filter(Boolean),
      },
    })
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Entitlement Catalog</h1>
        <p className="text-muted-foreground">Unified view of roles, groups, and application entitlements</p>
      </div>

      {/* Stats Cards */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="h-10 w-10 rounded-lg bg-blue-100 flex items-center justify-center">
                <Package className="h-5 w-5 text-blue-700" />
              </div>
              <div>
                <p className="text-2xl font-bold">{stats?.total_entitlements || 0}</p>
                <p className="text-sm text-gray-500">Total Entitlements</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="h-10 w-10 rounded-lg bg-purple-100 flex items-center justify-center">
                <Shield className="h-5 w-5 text-purple-700" />
              </div>
              <div>
                <p className="text-2xl font-bold">
                  {stats?.by_type?.role || 0} / {stats?.by_type?.group || 0} / {stats?.by_type?.application || 0}
                </p>
                <p className="text-sm text-gray-500">Roles / Groups / Apps</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="h-10 w-10 rounded-lg bg-red-100 flex items-center justify-center">
                <AlertTriangle className="h-5 w-5 text-red-700" />
              </div>
              <div>
                <p className="text-2xl font-bold">
                  {(stats?.by_risk_level?.high || 0) + (stats?.by_risk_level?.critical || 0)}
                </p>
                <p className="text-sm text-gray-500">High/Critical Risk</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="h-10 w-10 rounded-lg bg-yellow-100 flex items-center justify-center">
                <Users2 className="h-5 w-5 text-yellow-700" />
              </div>
              <div>
                <p className="text-2xl font-bold">{stats?.orphan_count || 0}</p>
                <p className="text-sm text-gray-500">Orphan Entitlements</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Catalog Table */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-500" />
              <Input
                placeholder="Search entitlements..."
                value={search}
                onChange={(e) => { setSearch(e.target.value); setPage(0) }}
                className="pl-9"
              />
            </div>
            <Select value={typeFilter || 'all'} onValueChange={(val) => { setTypeFilter(val === 'all' ? '' : val); setPage(0) }}>
              <SelectTrigger className="w-[160px]">
                <SelectValue placeholder="All Types" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Types</SelectItem>
                <SelectItem value="role">Roles</SelectItem>
                <SelectItem value="group">Groups</SelectItem>
                <SelectItem value="application">Applications</SelectItem>
              </SelectContent>
            </Select>
            <Select value={riskFilter || 'all'} onValueChange={(val) => { setRiskFilter(val === 'all' ? '' : val); setPage(0) }}>
              <SelectTrigger className="w-[160px]">
                <SelectValue placeholder="All Risk Levels" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Risk Levels</SelectItem>
                <SelectItem value="low">Low</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="critical">Critical</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex flex-col items-center justify-center py-12">
              <LoadingSpinner size="lg" />
              <p className="mt-4 text-sm text-muted-foreground">Loading entitlements...</p>
            </div>
          ) : isError ? (
            <QueryError error={error} resource="entitlements" />
          ) : !entitlements || entitlements.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <Package className="h-12 w-12 text-muted-foreground/40 mb-3" />
              <p className="font-medium">No entitlements found</p>
              <p className="text-sm">Try adjusting your filters</p>
            </div>
          ) : (
            <>
              <div className="rounded-md border">
                <table className="w-full">
                  <thead>
                    <tr className="border-b bg-gray-50">
                      <th className="p-3 text-left text-sm font-medium">Entitlement</th>
                      <th className="p-3 text-left text-sm font-medium">Type</th>
                      <th className="p-3 text-left text-sm font-medium">Risk</th>
                      <th className="p-3 text-left text-sm font-medium">Members</th>
                      <th className="p-3 text-left text-sm font-medium">Tags</th>
                      <th className="p-3 text-right text-sm font-medium">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {entitlements.map((entry) => (
                      <tr key={`${entry.type}-${entry.id}`} className="border-b hover:bg-gray-50">
                        <td className="p-3">
                          <div className="flex items-center gap-3">
                            <div className="h-8 w-8 rounded-lg bg-gray-100 flex items-center justify-center">
                              {typeIcons[entry.type] || <Package className="h-4 w-4" />}
                            </div>
                            <div>
                              <p className="font-medium">{entry.name}</p>
                              <p className="text-sm text-gray-500 max-w-xs truncate">{entry.description || '-'}</p>
                            </div>
                          </div>
                        </td>
                        <td className="p-3">
                          <Badge variant="outline">{typeLabels[entry.type] || entry.type}</Badge>
                        </td>
                        <td className="p-3">
                          <span className={`inline-flex px-2 py-1 rounded-full text-xs font-medium ${riskColors[entry.risk_level] || riskColors.low}`}>
                            {entry.risk_level}
                          </span>
                        </td>
                        <td className="p-3">
                          <span className="text-sm">{entry.member_count}</span>
                        </td>
                        <td className="p-3">
                          <div className="flex gap-1 flex-wrap">
                            {entry.tags?.length > 0 ? entry.tags.slice(0, 3).map((tag) => (
                              <Badge key={tag} variant="secondary" className="text-xs">{tag}</Badge>
                            )) : (
                              <span className="text-sm text-gray-400">-</span>
                            )}
                            {entry.tags?.length > 3 && (
                              <Badge variant="secondary" className="text-xs">+{entry.tags.length - 3}</Badge>
                            )}
                          </div>
                        </td>
                        <td className="p-3 text-right">
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <Button variant="ghost" size="sm" className="h-8 w-8 p-0">
                                <MoreHorizontal className="h-4 w-4" />
                              </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end">
                              <DropdownMenuItem onClick={() => handleEditMetadata(entry)}>
                                <Edit className="h-4 w-4 mr-2" />
                                Edit Metadata
                              </DropdownMenuItem>
                            </DropdownMenuContent>
                          </DropdownMenu>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {totalCount > PAGE_SIZE && (
                <div className="flex items-center justify-between pt-4 px-1">
                  <p className="text-sm text-gray-500">
                    Showing {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, totalCount)} of {totalCount}
                  </p>
                  <div className="flex items-center gap-2">
                    <Button variant="outline" size="sm" onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0}>
                      <ChevronLeft className="h-4 w-4 mr-1" /> Previous
                    </Button>
                    <span className="text-sm text-gray-600">Page {page + 1} of {Math.ceil(totalCount / PAGE_SIZE)}</span>
                    <Button variant="outline" size="sm" onClick={() => setPage(p => p + 1)} disabled={(page + 1) * PAGE_SIZE >= totalCount}>
                      Next <ChevronRight className="h-4 w-4 ml-1" />
                    </Button>
                  </div>
                </div>
              )}
            </>
          )}
        </CardContent>
      </Card>

      {/* Edit Metadata Modal */}
      <Dialog open={editModal} onOpenChange={setEditModal}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Edit Entitlement Metadata</DialogTitle>
          </DialogHeader>
          {selectedEntry && (
            <form onSubmit={handleSaveMetadata} className="space-y-4">
              <div className="flex items-center gap-2 p-3 bg-gray-50 rounded-lg">
                {typeIcons[selectedEntry.type]}
                <span className="font-medium">{selectedEntry.name}</span>
                <Badge variant="outline" className="ml-auto">{typeLabels[selectedEntry.type]}</Badge>
              </div>
              <div className="space-y-2">
                <Label>Risk Level</Label>
                <Select value={metadata.risk_level} onValueChange={(val) => setMetadata(prev => ({ ...prev, risk_level: val }))}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="low">Low</SelectItem>
                    <SelectItem value="medium">Medium</SelectItem>
                    <SelectItem value="high">High</SelectItem>
                    <SelectItem value="critical">Critical</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>Description</Label>
                <Textarea
                  value={metadata.description}
                  onChange={(e) => setMetadata(prev => ({ ...prev, description: e.target.value }))}
                  rows={2}
                />
              </div>
              <div className="space-y-2">
                <Label>Tags (comma-separated)</Label>
                <Input
                  value={metadata.tags}
                  onChange={(e) => setMetadata(prev => ({ ...prev, tags: e.target.value }))}
                  placeholder="sensitive, finance, pii"
                />
              </div>
              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  id="review_required"
                  checked={metadata.review_required}
                  onChange={(e) => setMetadata(prev => ({ ...prev, review_required: e.target.checked }))}
                  className="rounded border-gray-300"
                />
                <Label htmlFor="review_required">Require periodic review</Label>
              </div>
              <div className="flex justify-end gap-2 pt-4">
                <Button type="button" variant="outline" onClick={() => setEditModal(false)}>Cancel</Button>
                <Button type="submit" disabled={updateMetadataMutation.isPending}>
                  {updateMetadataMutation.isPending ? 'Saving...' : 'Save'}
                </Button>
              </div>
            </form>
          )}
        </DialogContent>
      </Dialog>
    </div>
  )
}
