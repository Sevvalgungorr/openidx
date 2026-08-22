import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import {
  Brain,
  Cpu,
  Loader2,
  MessageCircleQuestion,
  Newspaper,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react'
import { Button } from '../components/ui/button'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Input } from '../components/ui/input'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { UserLink } from '../components/user-link'
import { QueryError } from '../components/query-error'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

interface AIStatus {
  enabled: boolean
  reachable: boolean
  base_url?: string
  model?: string
  detail?: string
}

interface TopRisk {
  user_id: string
  username: string
  email: string
  score: number
  level: string
  reasons: string[]
  mfa_enrolled: boolean
  open_alerts: number
  ziti_anomalies: number
  friction: string
}

interface Overview {
  total_users: number
  risk_levels: Record<string, number>
  identities_at_risk: number
  mfa_enrolled: number
  mfa_coverage_pct: number
  open_alerts: number
  logins_24h: number
  failed_logins_24h: number
  ziti_open_anomalies: number
  top_risks: TopRisk[]
  ai?: AIStatus | null
}

interface Briefing {
  briefing: string
  generated_by: string
  generated_at: string
}

const levelBadge = (level: string) => {
  switch (level) {
    case 'critical':
      return 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'
    case 'high':
      return 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200'
    case 'medium':
      return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200'
    default:
      return 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200'
  }
}

export function AIIdentityIntelligencePage() {
  const { toast } = useToast()
  const [question, setQuestion] = useState('')
  const [answer, setAnswer] = useState('')

  const { data: overview, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['ai-identity-intelligence'],
    queryFn: async () => api.get<Overview>('/api/v1/ai/intelligence/overview'),
  })

  const briefing = useMutation({
    mutationFn: async () => api.get<Briefing>('/api/v1/ai/intelligence/briefing'),
    onError: (error: Error) => {
      toast({ title: 'Briefing Failed', description: error.message, variant: 'destructive' })
    },
  })

  const ask = useMutation({
    mutationFn: async (q: string) =>
      api.post<{ answer: string }>('/api/v1/ai/intelligence/ask', { question: q }),
    onSuccess: (data) => setAnswer(data.answer),
    onError: (error: Error) => {
      toast({ title: 'Ask Failed', description: error.message, variant: 'destructive' })
    },
  })

  const ai = overview?.ai

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-24">
        <LoadingSpinner />
      </div>
    )
  }

  if (isError) {
    return <QueryError error={error} resource="identity intelligence" />
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-2">
            <Brain className="h-8 w-8 text-purple-500" />
            Identity Intelligence
          </h1>
          <p className="text-muted-foreground mt-1">
            Cross-pillar identity risk fusion — logins, alerts, MFA, devices, breaches and the zero-trust overlay in one score
          </p>
        </div>
        <Button variant="outline" onClick={() => refetch()}>
          <RefreshCw className="h-4 w-4 mr-2" />
          Refresh
        </Button>
      </div>

      {/* Summary cards */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Identities at Risk</CardDescription>
            <CardTitle className="text-2xl text-orange-600">
              {overview?.identities_at_risk ?? 0}
              <span className="text-sm font-normal text-muted-foreground"> / {overview?.total_users ?? 0}</span>
            </CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Open Security Alerts</CardDescription>
            <CardTitle className="text-2xl text-red-600">{overview?.open_alerts ?? 0}</CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>MFA Coverage</CardDescription>
            <CardTitle className="text-2xl text-blue-600">
              {(overview?.mfa_coverage_pct ?? 0).toFixed(0)}%
            </CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription className="flex items-center gap-1">
              <Cpu className="h-3 w-3" /> Local AI
            </CardDescription>
            <CardTitle className="text-2xl">
              {ai?.enabled ? (ai.reachable ? 'Online' : 'Unreachable') : 'Off'}
            </CardTitle>
            <div className="flex flex-wrap gap-1 pt-1">
              {ai?.enabled && ai.model && <Badge variant="secondary">{ai.model}</Badge>}
              {ai?.enabled && <Badge variant="secondary">on-premises</Badge>}
              {!ai?.enabled && (
                <span className="text-xs text-muted-foreground">Set AI_ENABLED=true (Ollama etc.)</span>
              )}
            </div>
          </CardHeader>
        </Card>
      </div>

      {/* Daily briefing */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0">
          <div>
            <CardTitle className="flex items-center gap-2">
              <Newspaper className="h-5 w-5 text-blue-500" />
              Security Briefing
            </CardTitle>
            <CardDescription>
              Generated from live facts{ai?.enabled ? ` and narrated by ${ai.model} running locally` : ' (template mode — enable local AI for narrated briefings)'}
            </CardDescription>
          </div>
          <Button onClick={() => briefing.mutate()} disabled={briefing.isPending}>
            {briefing.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
            Generate Briefing
          </Button>
        </CardHeader>
        {briefing.data && (
          <CardContent>
            <p className="whitespace-pre-wrap text-sm">{briefing.data.briefing}</p>
            <p className="text-xs text-muted-foreground mt-3">
              Generated by {briefing.data.generated_by} at {new Date(briefing.data.generated_at).toLocaleString()}
            </p>
          </CardContent>
        )}
      </Card>

      {/* Copilot ask */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <MessageCircleQuestion className="h-5 w-5 text-purple-500" />
            Ask the Security Copilot
          </CardTitle>
          <CardDescription>
            {ai?.enabled
              ? 'Answers are grounded strictly on the current fused facts and computed by your local model — nothing leaves this deployment.'
              : 'Requires the local AI provider (AI_ENABLED=true with an on-prem OpenAI-compatible endpoint such as Ollama).'}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex gap-2">
            <Input
              placeholder="e.g. Which identities need attention first, and why?"
              value={question}
              onChange={(e) => setQuestion(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && question.trim() && ai?.enabled) ask.mutate(question.trim())
              }}
              disabled={!ai?.enabled}
            />
            <Button
              onClick={() => ask.mutate(question.trim())}
              disabled={!ai?.enabled || !question.trim() || ask.isPending}
            >
              {ask.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              Ask
            </Button>
          </div>
          {answer && <p className="whitespace-pre-wrap text-sm p-3 bg-muted rounded-lg">{answer}</p>}
        </CardContent>
      </Card>

      {/* Top risks */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ShieldAlert className="h-5 w-5 text-orange-500" />
            Highest-Risk Identities
          </CardTitle>
          <CardDescription>
            Fused from login risk, open alerts, MFA enrollment, device trust, breach involvement and overlay anomalies
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-muted">
                <tr>
                  <th className="text-left p-4 font-medium">User</th>
                  <th className="text-left p-4 font-medium">Score</th>
                  <th className="text-left p-4 font-medium">Level</th>
                  <th className="text-left p-4 font-medium">MFA</th>
                  <th className="text-left p-4 font-medium">Friction</th>
                  <th className="text-left p-4 font-medium">Why</th>
                </tr>
              </thead>
              <tbody className="divide-y">
                {(overview?.top_risks || []).map((u) => (
                  <tr key={u.user_id} className="hover:bg-muted/50">
                    <td className="p-4">
                      <UserLink userId={u.user_id} name={u.username} subtitle={u.email} />
                    </td>
                    <td className="p-4 font-mono">{u.score}</td>
                    <td className="p-4">
                      <Badge className={levelBadge(u.level)}>{u.level}</Badge>
                    </td>
                    <td className="p-4">
                      {u.mfa_enrolled ? (
                        <ShieldCheck className="h-4 w-4 text-green-600" />
                      ) : (
                        <Badge variant="secondary">none</Badge>
                      )}
                    </td>
                    <td className="p-4">
                      <Badge variant="secondary">{u.friction}</Badge>
                    </td>
                    <td className="p-4 text-sm text-muted-foreground max-w-md">
                      {u.reasons?.length ? u.reasons.join('; ') : '—'}
                    </td>
                  </tr>
                ))}
                {(overview?.top_risks || []).length === 0 && (
                  <tr>
                    <td colSpan={6} className="p-8 text-center text-muted-foreground">
                      No identities found
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
