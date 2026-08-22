import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'
import { AlertTriangle, Eye, Wrench, TrendingUp, RefreshCw, X, CheckCircle } from 'lucide-react'

interface PostureScore {
  overall_score: number
  category_scores: Record<string, number>
  total_findings: number
  critical_findings: number
  high_findings: number
  medium_findings: number
  low_findings: number
  snapshot_date: string
  details: Record<string, number>
}

interface PostureFinding {
  id: string
  check_type: string
  severity: string
  category: string
  title: string
  description: string
  affected_entity_type: string
  affected_entity_id: string
  affected_entity_name: string
  status: string
  remediation_action: string
  created_at: string
}

interface PostureRule {
  id: string
  name: string
  description: string
  category: string
  check_type: string
  enabled: boolean
  severity: string
  thresholds: Record<string, number>
}

const severityColors: Record<string, string> = {
  critical: 'bg-red-100 text-red-800 border-red-200',
  high: 'bg-orange-100 text-orange-800 border-orange-200',
  medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
  low: 'bg-blue-100 text-blue-800 border-blue-200',
}

const categoryColors: Record<string, string> = {
  authentication: 'text-blue-600',
  authorization: 'text-purple-600',
  accounts: 'text-green-600',
  compliance: 'text-orange-600',
}

function ScoreGauge({ score }: { score: number }) {
  const color = score >= 80 ? 'text-green-600' : score >= 60 ? 'text-yellow-600' : 'text-red-600'
  const bgColor = score >= 80 ? 'bg-green-100' : score >= 60 ? 'bg-yellow-100' : 'bg-red-100'
  return (
    <div className={`inline-flex items-center justify-center w-24 h-24 rounded-full ${bgColor}`}>
      <span className={`text-3xl font-bold ${color}`}>{score}</span>
    </div>
  )
}

function CategoryScore({ name, score }: { name: string; score: number }) {
  const color = score >= 80 ? 'bg-green-500' : score >= 60 ? 'bg-yellow-500' : 'bg-red-500'
  return (
    <div className="space-y-1">
      <div className="flex justify-between text-sm">
        <span className="capitalize">{name}</span>
        <span className="font-medium">{score}%</span>
      </div>
      <div className="h-2 bg-gray-200 rounded-full">
        <div className={`h-2 rounded-full ${color}`} style={{ width: `${score}%` }} />
      </div>
    </div>
  )
}

export function ISPMDashboardPage() {
  const queryClient = useQueryClient()

  const { data: score, isLoading, isError, error } = useQuery<PostureScore>({
    queryKey: ['ispm-score'],
    queryFn: () => api.get<PostureScore>('/api/v1/ispm/score'),
  })

  const { data: findingsData } = useQuery({
    queryKey: ['ispm-findings'],
    queryFn: () => api.get<{ data: PostureFinding[] }>('/api/v1/ispm/findings'),
  })

  const { data: rulesData } = useQuery({
    queryKey: ['ispm-rules'],
    queryFn: () => api.get<{ data: PostureRule[] }>('/api/v1/ispm/rules'),
  })

  const { data: trendsData } = useQuery({
    queryKey: ['ispm-trends'],
    queryFn: () => api.get<{ data: Array<{ date: string; overall_score: number; total_findings: number }> }>('/api/v1/ispm/trends'),
  })

  const scanMutation = useMutation({
    mutationFn: () => api.post('/api/v1/ispm/scan', {}),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ispm-score'] })
      queryClient.invalidateQueries({ queryKey: ['ispm-findings'] })
    },
  })

  const dismissMutation = useMutation({
    mutationFn: (id: string) => api.post(`/api/v1/ispm/findings/${id}/dismiss`, { reason: 'False positive' }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ispm-findings'] })
      queryClient.invalidateQueries({ queryKey: ['ispm-score'] })
    },
  })

  const remediateMutation = useMutation({
    mutationFn: (id: string) => api.post(`/api/v1/ispm/findings/${id}/remediate`, {}),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ispm-findings'] })
      queryClient.invalidateQueries({ queryKey: ['ispm-score'] })
    },
  })

  if (isLoading) {
    return <div className="flex justify-center py-12"><LoadingSpinner size="lg" /></div>
  }

  if (isError) {
    return <QueryError error={error} resource="the security posture dashboard" />
  }

  const findings = findingsData?.data || []
  const rules = rulesData?.data || []
  const trends = trendsData?.data || []

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Identity Security Posture</h1>
          <p className="text-muted-foreground">Monitor and improve your organization's identity security hygiene</p>
        </div>
        <Button onClick={() => scanMutation.mutate()} disabled={scanMutation.isPending}>
          <RefreshCw className={`h-4 w-4 mr-2 ${scanMutation.isPending ? 'animate-spin' : ''}`} />
          {scanMutation.isPending ? 'Scanning...' : 'Run Scan'}
        </Button>
      </div>

      {/* Score Overview */}
      {score && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <Card className="md:col-span-1">
            <CardContent className="pt-6 text-center">
              <ScoreGauge score={score.overall_score} />
              <p className="mt-3 font-medium">Overall Posture Score</p>
              <p className="text-sm text-muted-foreground">{score.snapshot_date}</p>
            </CardContent>
          </Card>
          <Card className="md:col-span-1">
            <CardHeader><CardTitle className="text-base">Category Breakdown</CardTitle></CardHeader>
            <CardContent className="space-y-3">
              {Object.entries(score.category_scores).map(([cat, val]) => (
                <CategoryScore key={cat} name={cat} score={val} />
              ))}
            </CardContent>
          </Card>
          <Card className="md:col-span-1">
            <CardHeader><CardTitle className="text-base">Open Findings</CardTitle></CardHeader>
            <CardContent>
              <div className="space-y-2">
                <div className="flex justify-between items-center">
                  <Badge className={severityColors.critical}>Critical</Badge>
                  <span className="font-bold text-lg">{score.critical_findings}</span>
                </div>
                <div className="flex justify-between items-center">
                  <Badge className={severityColors.high}>High</Badge>
                  <span className="font-bold text-lg">{score.high_findings}</span>
                </div>
                <div className="flex justify-between items-center">
                  <Badge className={severityColors.medium}>Medium</Badge>
                  <span className="font-bold text-lg">{score.medium_findings}</span>
                </div>
                <div className="flex justify-between items-center">
                  <Badge className={severityColors.low}>Low</Badge>
                  <span className="font-bold text-lg">{score.low_findings}</span>
                </div>
                <div className="border-t pt-2 flex justify-between items-center">
                  <span className="font-medium">Total</span>
                  <span className="font-bold text-xl">{score.total_findings}</span>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Trend Chart */}
      {trends.length > 1 && (
        <Card>
          <CardHeader><CardTitle className="flex items-center gap-2"><TrendingUp className="h-5 w-5" />Score Trend</CardTitle></CardHeader>
          <CardContent>
            <div className="flex items-end gap-1 h-32">
              {trends.slice(-30).reverse().map((t, i) => {
                const color = t.overall_score >= 80 ? 'bg-green-500' : t.overall_score >= 60 ? 'bg-yellow-500' : 'bg-red-500'
                return (
                  <div key={i} className="flex-1 flex flex-col items-center" title={`${t.date}: ${t.overall_score}`}>
                    <div className={`w-full rounded-t ${color}`} style={{ height: `${t.overall_score}%` }} />
                  </div>
                )
              })}
            </div>
            <div className="flex justify-between text-xs text-muted-foreground mt-1">
              <span>{trends.length > 0 ? trends[trends.length - 1]?.date : ''}</span>
              <span>{trends.length > 0 ? trends[0]?.date : ''}</span>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Findings Table */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><AlertTriangle className="h-5 w-5" />Active Findings ({findings.length})</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="divide-y">
            {findings.map((f) => (
              <div key={f.id} className="py-3 flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-1">
                    <Badge className={severityColors[f.severity] || ''}>{f.severity}</Badge>
                    <Badge variant="outline" className={categoryColors[f.category] || ''}>{f.category}</Badge>
                    <span className="text-xs text-muted-foreground">{new Date(f.created_at).toLocaleDateString()}</span>
                  </div>
                  <p className="font-medium text-sm">{f.title}</p>
                  <p className="text-xs text-muted-foreground mt-0.5">{f.description}</p>
                  {f.affected_entity_name && (
                    <p className="text-xs mt-1">Affected: <span className="font-medium">{f.affected_entity_name}</span> ({f.affected_entity_type})</p>
                  )}
                </div>
                <div className="flex gap-1 ml-4">
                  <Button size="sm" variant="outline" onClick={() => remediateMutation.mutate(f.id)} title="Auto-remediate">
                    <Wrench className="h-3 w-3" />
                  </Button>
                  <Button size="sm" variant="ghost" onClick={() => dismissMutation.mutate(f.id)} title="Dismiss">
                    <X className="h-3 w-3" />
                  </Button>
                </div>
              </div>
            ))}
            {findings.length === 0 && (
              <div className="py-8 text-center text-muted-foreground">
                <CheckCircle className="h-8 w-8 mx-auto mb-2 text-green-500" />
                <p>No open findings - your posture looks great!</p>
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Rules Configuration */}
      <Card>
        <CardHeader><CardTitle className="flex items-center gap-2"><Eye className="h-5 w-5" />Posture Check Rules ({rules.length})</CardTitle></CardHeader>
        <CardContent>
          <div className="divide-y">
            {rules.map((r) => (
              <div key={r.id} className="py-3 flex items-center justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <p className="font-medium text-sm">{r.name}</p>
                    <Badge className={severityColors[r.severity] || ''} variant="outline">{r.severity}</Badge>
                    <Badge variant="outline" className={categoryColors[r.category] || ''}>{r.category}</Badge>
                  </div>
                  <p className="text-xs text-muted-foreground">{r.description}</p>
                </div>
                <Badge variant={r.enabled ? 'default' : 'secondary'}>{r.enabled ? 'Enabled' : 'Disabled'}</Badge>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
