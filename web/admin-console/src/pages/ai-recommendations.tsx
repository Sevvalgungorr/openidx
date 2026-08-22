import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { api } from '../lib/api'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'
import { Lightbulb, Sparkles, Check, X, Zap, BarChart3, Shield, Scale, Settings, Bot } from 'lucide-react'

interface Recommendation {
  id: string
  recommendation_type: string
  category: string
  title: string
  description: string
  impact: string
  effort: string
  affected_entities: Array<{ type: string; id?: string; name?: string; count?: number }>
  suggested_action: Record<string, unknown>
  status: string
  dismissed_reason: string
  applied_at: string | null
  created_at: string
}

interface RecommendationStats {
  by_status: Record<string, number>
  pending_by_category: Record<string, number>
  acceptance_rate: number
  total_resolved: number
  total_accepted: number
}

const impactColors: Record<string, string> = {
  high: 'bg-red-100 text-red-800',
  medium: 'bg-yellow-100 text-yellow-800',
  low: 'bg-blue-100 text-blue-800',
}

const effortColors: Record<string, string> = {
  high: 'bg-orange-100 text-orange-800',
  medium: 'bg-yellow-100 text-yellow-800',
  low: 'bg-green-100 text-green-800',
}

const categoryIcons: Record<string, React.ReactNode> = {
  security: <Shield className="h-4 w-4 text-red-600" />,
  compliance: <Scale className="h-4 w-4 text-primary" />,
  governance: <Settings className="h-4 w-4 text-purple-600" />,
  optimization: <Zap className="h-4 w-4 text-yellow-600" />,
}

export function AIRecommendationsPage() {
  const queryClient = useQueryClient()
  const [categoryFilter, setCategoryFilter] = useState<string>('')
  const [statusFilter, setStatusFilter] = useState<string>('pending')

  const { data: recsData, isLoading, isError, error } = useQuery({
    queryKey: ['ai-recommendations', categoryFilter, statusFilter],
    queryFn: () => {
      const params = new URLSearchParams()
      if (categoryFilter) params.set('category', categoryFilter)
      if (statusFilter) params.set('status', statusFilter)
      return api.get<{ data: Recommendation[] }>(`/api/v1/recommendations?${params}`)
    },
  })

  const { data: stats } = useQuery<RecommendationStats>({
    queryKey: ['ai-recommendations-stats'],
    queryFn: () => api.get<RecommendationStats>('/api/v1/recommendations/stats'),
  })

  const generateMutation = useMutation({
    mutationFn: () => api.post('/api/v1/recommendations/generate', {}),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ai-recommendations'] })
      queryClient.invalidateQueries({ queryKey: ['ai-recommendations-stats'] })
    },
  })

  const acceptMutation = useMutation({
    mutationFn: (id: string) => api.post(`/api/v1/recommendations/${id}/accept`, {}),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ai-recommendations'] })
      queryClient.invalidateQueries({ queryKey: ['ai-recommendations-stats'] })
    },
  })

  const dismissMutation = useMutation({
    mutationFn: (id: string) => api.post(`/api/v1/recommendations/${id}/dismiss`, { reason: 'Not applicable' }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ai-recommendations'] })
      queryClient.invalidateQueries({ queryKey: ['ai-recommendations-stats'] })
    },
  })

  const applyMutation = useMutation({
    mutationFn: (id: string) => api.post(`/api/v1/recommendations/${id}/apply`, {}),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ai-recommendations'] })
      queryClient.invalidateQueries({ queryKey: ['ai-recommendations-stats'] })
    },
  })

  if (isLoading) {
    return <div className="flex justify-center py-12"><LoadingSpinner size="lg" /></div>
  }

  if (isError) {
    return <QueryError error={error} resource="AI recommendations" />
  }

  const recs = recsData?.data || []

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">AI Recommendations</h1>
          <p className="text-muted-foreground">Intelligent suggestions to improve your security posture</p>
        </div>
        <Button onClick={() => generateMutation.mutate()} disabled={generateMutation.isPending}>
          <Sparkles className={`h-4 w-4 mr-2 ${generateMutation.isPending ? 'animate-pulse' : ''}`} />
          {generateMutation.isPending ? 'Analyzing...' : 'Generate Recommendations'}
        </Button>
      </div>

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <Card><CardContent className="pt-4 text-center">
            <Lightbulb className="h-5 w-5 mx-auto mb-1 text-yellow-600" />
            <p className="text-2xl font-bold">{stats.by_status?.pending || 0}</p>
            <p className="text-xs text-muted-foreground">Pending</p>
          </CardContent></Card>
          <Card><CardContent className="pt-4 text-center">
            <Check className="h-5 w-5 mx-auto mb-1 text-green-600" />
            <p className="text-2xl font-bold">{stats.total_accepted}</p>
            <p className="text-xs text-muted-foreground">Accepted</p>
          </CardContent></Card>
          <Card><CardContent className="pt-4 text-center">
            <Zap className="h-5 w-5 mx-auto mb-1 text-primary" />
            <p className="text-2xl font-bold">{stats.by_status?.applied || 0}</p>
            <p className="text-xs text-muted-foreground">Applied</p>
          </CardContent></Card>
          <Card><CardContent className="pt-4 text-center">
            <X className="h-5 w-5 mx-auto mb-1 text-muted-foreground" />
            <p className="text-2xl font-bold">{stats.by_status?.dismissed || 0}</p>
            <p className="text-xs text-muted-foreground">Dismissed</p>
          </CardContent></Card>
          <Card><CardContent className="pt-4 text-center">
            <BarChart3 className="h-5 w-5 mx-auto mb-1 text-purple-600" />
            <p className="text-2xl font-bold">{typeof stats.acceptance_rate === 'number' ? stats.acceptance_rate.toFixed(0) : 0}%</p>
            <p className="text-xs text-muted-foreground">Acceptance Rate</p>
          </CardContent></Card>
        </div>
      )}

      {/* Category distribution */}
      {stats?.pending_by_category && Object.keys(stats.pending_by_category).length > 0 && (
        <Card>
          <CardHeader><CardTitle className="text-base">Pending by Category</CardTitle></CardHeader>
          <CardContent>
            <div className="flex gap-4">
              {Object.entries(stats.pending_by_category).map(([cat, count]) => (
                <div key={cat} className="flex items-center gap-2 bg-muted rounded-lg px-4 py-2">
                  {categoryIcons[cat] || <Bot className="h-4 w-4" />}
                  <span className="capitalize font-medium">{cat}</span>
                  <Badge variant="secondary">{count}</Badge>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Filters */}
      <div className="flex gap-3">
        <select className="border rounded px-3 py-2 text-sm" value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}>
          <option value="pending">Pending</option>
          <option value="accepted">Accepted</option>
          <option value="applied">Applied</option>
          <option value="dismissed">Dismissed</option>
          <option value="">All</option>
        </select>
        <select className="border rounded px-3 py-2 text-sm" value={categoryFilter}
          onChange={(e) => setCategoryFilter(e.target.value)}>
          <option value="">All Categories</option>
          <option value="security">Security</option>
          <option value="compliance">Compliance</option>
          <option value="governance">Governance</option>
          <option value="optimization">Optimization</option>
        </select>
      </div>

      {/* Recommendations List */}
      <div className="space-y-4">
        {recs.map((rec) => (
          <Card key={rec.id} className="hover:shadow-md transition-shadow">
            <CardContent className="pt-5">
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-2">
                    {categoryIcons[rec.category] || <Lightbulb className="h-4 w-4" />}
                    <span className="capitalize text-sm font-medium text-muted-foreground">{rec.category}</span>
                    <Badge className={impactColors[rec.impact] || ''}>Impact: {rec.impact}</Badge>
                    <Badge className={effortColors[rec.effort] || ''}>Effort: {rec.effort}</Badge>
                    <Badge variant="outline">{rec.recommendation_type.replace(/_/g, ' ')}</Badge>
                  </div>
                  <h3 className="font-medium">{rec.title}</h3>
                  <p className="text-sm text-muted-foreground mt-1">{rec.description}</p>

                  {rec.affected_entities?.length > 0 && (
                    <div className="mt-2 flex flex-wrap gap-1">
                      {rec.affected_entities.slice(0, 5).map((e, i) => (
                        <Badge key={i} variant="outline" className="text-xs">
                          {e.name || `${e.count || 0} ${e.type}s`}
                        </Badge>
                      ))}
                      {rec.affected_entities.length > 5 && (
                        <Badge variant="outline" className="text-xs">+{rec.affected_entities.length - 5} more</Badge>
                      )}
                    </div>
                  )}

                  {rec.applied_at && (
                    <p className="text-xs text-green-600 mt-2">Applied on {new Date(rec.applied_at).toLocaleDateString()}</p>
                  )}
                  {rec.dismissed_reason && (
                    <p className="text-xs text-muted-foreground mt-2">Dismissed: {rec.dismissed_reason}</p>
                  )}
                </div>

                {rec.status === 'pending' && (
                  <div className="flex gap-2 ml-4">
                    <Button size="sm" onClick={() => applyMutation.mutate(rec.id)} title="Apply this recommendation">
                      <Zap className="h-3 w-3 mr-1" />Apply
                    </Button>
                    <Button size="sm" variant="outline" onClick={() => acceptMutation.mutate(rec.id)} title="Accept">
                      <Check className="h-3 w-3" />
                    </Button>
                    <Button size="sm" variant="ghost" onClick={() => dismissMutation.mutate(rec.id)} title="Dismiss">
                      <X className="h-3 w-3" />
                    </Button>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        ))}
        {recs.length === 0 && (
          <Card>
            <CardContent className="py-12 text-center text-muted-foreground">
              <Sparkles className="h-12 w-12 mx-auto mb-3 text-muted-foreground" />
              <p className="font-medium">No {statusFilter || ''} recommendations</p>
              <p className="text-sm mt-1">Click "Generate Recommendations" to analyze your environment</p>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  )
}
