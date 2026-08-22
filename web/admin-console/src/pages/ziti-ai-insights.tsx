import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Brain,
  RefreshCw,
  Loader2,
  AlertTriangle,
  ShieldAlert,
  ShieldCheck,
  Lightbulb,
  Server,
} from 'lucide-react'
import { Button } from '../components/ui/button'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '../components/ui/table'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'
import { ConfirmAction } from '../components/confirm-action'

interface ControllerFeatures {
  version: string
  semver_major: number
  ha_controllers: boolean
  oidc_auth: boolean
  jwt_session_auth: boolean
  granular_permissions: boolean
  advisories?: string[]
}

interface IdentityRisk {
  identity_id: string
  identity_name: string
  // Who this identity belongs to. The overlay names synced identities after
  // the user's UUID, so identity_name alone tells an admin nothing — and the
  // action on this row cuts that person off the network.
  subject?: string
  subject_kind?: string
  email?: string
  source?: string
  score: number
  level: string
  signals: string[]
  open_anomalies: number
  posture_failures: number
  quarantined: boolean
}

interface Insights {
  identities_total: number
  identities_at_risk: number
  risk_levels: Record<string, number>
  top_risks: IdentityRisk[]
  open_anomalies: number
  recommendation_count: number
  controller_features?: ControllerFeatures | null
}

interface Anomaly {
  id: string
  identity_id: string
  identity_name: string
  anomaly_type: string
  severity: string
  score: number
  details: Record<string, unknown>
  status: string
  detected_at: string
}

interface Recommendation {
  type: string
  severity: string
  title: string
  description: string
  target_name?: string
  action: string
}

interface AnalysisResult {
  observations: number
  new_anomalies: number
  baseline_identities: number
}

const severityBadge = (severity: string) => {
  switch (severity) {
    case 'critical':
      return 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'
    case 'high':
      return 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200'
    case 'medium':
      return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200'
    default:
      return 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200'
  }
}

const anomalyTypeLabel: Record<string, string> = {
  new_service_access: 'New Service Access',
  off_hours_access: 'Off-Hours Activity',
  dormant_identity_active: 'Dormant Identity Reactivated',
  session_spike: 'Session Spike',
}

export function ZitiAIInsightsPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()

  const { data: insights, isLoading, isError, error } = useQuery({
    queryKey: ['ziti-ai-insights'],
    queryFn: async () => api.get<Insights>('/api/v1/access/ziti/ai/insights'),
  })

  const { data: anomalies } = useQuery({
    queryKey: ['ziti-ai-anomalies'],
    queryFn: async () => api.get<Anomaly[]>('/api/v1/access/ziti/ai/anomalies?status=open'),
  })

  const { data: recommendations } = useQuery({
    queryKey: ['ziti-ai-recommendations'],
    queryFn: async () => api.get<Recommendation[]>('/api/v1/access/ziti/ai/recommendations'),
  })

  const invalidateAll = () => {
    queryClient.invalidateQueries({ queryKey: ['ziti-ai-insights'] })
    queryClient.invalidateQueries({ queryKey: ['ziti-ai-anomalies'] })
    queryClient.invalidateQueries({ queryKey: ['ziti-ai-recommendations'] })
  }

  const runAnalysis = useMutation({
    mutationFn: async () => api.post<AnalysisResult>('/api/v1/access/ziti/ai/analyze', {}),
    onSuccess: (result) => {
      invalidateAll()
      toast({
        title: 'Analysis Complete',
        description: `${result.observations} observations analyzed, ${result.new_anomalies} new anomalies detected.`,
      })
    },
    onError: (error: Error) => {
      toast({ title: 'Analysis Failed', description: error.message, variant: 'destructive' })
    },
  })

  const updateAnomaly = useMutation({
    mutationFn: async ({ id, status }: { id: string; status: string }) =>
      api.post(`/api/v1/access/ziti/ai/anomalies/${id}/status`, { status }),
    onSuccess: () => invalidateAll(),
    onError: (error: Error) => {
      toast({ title: 'Update Failed', description: error.message, variant: 'destructive' })
    },
  })

  const quarantine = useMutation({
    mutationFn: async ({ identityId, reason }: { identityId: string; reason: string }) =>
      api.post(`/api/v1/access/ziti/ai/identities/${identityId}/quarantine`, {
        reason,
      }),
    onSuccess: () => {
      invalidateAll()
      toast({ title: 'Identity Quarantined', description: 'Role attributes severed and sessions terminated.' })
    },
    onError: (error: Error) => {
      toast({ title: 'Quarantine Failed', description: error.message, variant: 'destructive' })
    },
  })

  const unquarantine = useMutation({
    mutationFn: async (identityId: string) =>
      api.post(`/api/v1/access/ziti/ai/identities/${identityId}/unquarantine`, {}),
    onSuccess: () => {
      invalidateAll()
      toast({ title: 'Identity Restored', description: 'Saved role attributes have been restored.' })
    },
    onError: (error: Error) => {
      toast({ title: 'Restore Failed', description: error.message, variant: 'destructive' })
    },
  })

  const features = insights?.controller_features

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-24">
        <LoadingSpinner />
      </div>
    )
  }

  if (isError) {
    return <QueryError error={error} resource="Ziti AI insights" />
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-2">
            <Brain className="h-8 w-8 text-purple-500" />
            Ziti AI Insights
          </h1>
          <p className="text-muted-foreground mt-1">
            Behavioral anomaly detection, identity risk scoring and policy hygiene for the zero-trust overlay
          </p>
        </div>
        <Button onClick={() => runAnalysis.mutate()} disabled={runAnalysis.isPending}>
          {runAnalysis.isPending ? (
            <Loader2 className="h-4 w-4 mr-2 animate-spin" />
          ) : (
            <RefreshCw className="h-4 w-4 mr-2" />
          )}
          Run Analysis
        </Button>
      </div>

      {/* Summary Cards */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Identities at Risk</CardDescription>
            <CardTitle className="text-2xl text-orange-600">
              {insights?.identities_at_risk ?? 0}
              <span className="text-sm font-normal text-muted-foreground"> / {insights?.identities_total ?? 0}</span>
            </CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Open Anomalies</CardDescription>
            <CardTitle className="text-2xl text-red-600">{insights?.open_anomalies ?? 0}</CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Recommendations</CardDescription>
            <CardTitle className="text-2xl text-primary">{insights?.recommendation_count ?? 0}</CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription className="flex items-center gap-1">
              <Server className="h-3 w-3" /> Controller
            </CardDescription>
            <CardTitle className="text-2xl">{features?.version || 'unknown'}</CardTitle>
            {features && (
              <div className="flex flex-wrap gap-1 pt-1">
                {features.ha_controllers && <Badge variant="secondary">HA</Badge>}
                {features.oidc_auth && <Badge variant="secondary">OIDC</Badge>}
                {features.jwt_session_auth && <Badge variant="secondary">JWT Auth</Badge>}
                {features.granular_permissions && <Badge variant="secondary">Granular Perms</Badge>}
              </div>
            )}
          </CardHeader>
        </Card>
      </div>

      {/* v2.0 upgrade advisories */}
      {features?.advisories && features.advisories.length > 0 && (
        <Card className="border-yellow-300 dark:border-yellow-700">
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-yellow-600" />
              OpenZiti Upgrade Advisories
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {features.advisories.map((advisory, i) => (
              <p key={i} className="text-sm text-muted-foreground">
                {advisory}
              </p>
            ))}
          </CardContent>
        </Card>
      )}

      {/* Open Anomalies */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ShieldAlert className="h-5 w-5 text-red-500" />
            Open Anomalies
          </CardTitle>
          <CardDescription>Deviations from each identity's learned behavioral baseline</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
              <TableHeader className="bg-muted">
                <TableRow>
                  <TableHead className="text-left p-4 font-medium">Identity</TableHead>
                  <TableHead className="text-left p-4 font-medium">Anomaly</TableHead>
                  <TableHead className="text-left p-4 font-medium">Severity</TableHead>
                  <TableHead className="text-left p-4 font-medium">Detected</TableHead>
                  <TableHead className="text-left p-4 font-medium">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody className="divide-y">
                {(anomalies || []).map((anomaly) => (
                  <TableRow key={anomaly.id} className="hover:bg-muted/50">
                    <TableCell className="p-4">
                      <div className="font-medium">{anomaly.identity_name || anomaly.identity_id}</div>
                      <div className="text-xs text-muted-foreground font-mono">{anomaly.identity_id}</div>
                    </TableCell>
                    <TableCell className="p-4">{anomalyTypeLabel[anomaly.anomaly_type] || anomaly.anomaly_type}</TableCell>
                    <TableCell className="p-4">
                      <Badge className={severityBadge(anomaly.severity)}>{anomaly.severity}</Badge>
                    </TableCell>
                    <TableCell className="p-4 text-sm text-muted-foreground">
                      {new Date(anomaly.detected_at).toLocaleString()}
                    </TableCell>
                    <TableCell className="p-4 space-x-2">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => updateAnomaly.mutate({ id: anomaly.id, status: 'acknowledged' })}
                      >
                        Acknowledge
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => updateAnomaly.mutate({ id: anomaly.id, status: 'resolved' })}
                      >
                        Resolve
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
                {(anomalies || []).length === 0 && (
                  <TableRow>
                    <TableCell colSpan={5} className="p-8 text-center text-muted-foreground">
                      No open anomalies — run an analysis to check the fabric against learned baselines
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
        </CardContent>
      </Card>

      {/* Identity Risk */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5 text-orange-500" />
            Identity Risk
          </CardTitle>
          <CardDescription>
            Fused score from open anomalies, posture failures, enrollment and dormancy signals
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
              <TableHeader className="bg-muted">
                <TableRow>
                  <TableHead className="text-left p-4 font-medium">Identity</TableHead>
                  <TableHead className="text-left p-4 font-medium">Score</TableHead>
                  <TableHead className="text-left p-4 font-medium">Level</TableHead>
                  <TableHead className="text-left p-4 font-medium">Signals</TableHead>
                  <TableHead className="text-left p-4 font-medium">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody className="divide-y">
                {(insights?.top_risks || []).map((risk) => (
                  <TableRow key={risk.identity_id} className="hover:bg-muted/50">
                    <TableCell className="p-4">
                      {/* Lead with the person, not the UUID: the action in this
                          row disconnects them, so who it affects has to be the
                          first thing read. The fabric name stays visible
                          underneath for anyone debugging the overlay. */}
                      <div className="font-medium">{risk.subject || risk.identity_name || risk.identity_id}</div>
                      <div className="text-xs text-muted-foreground">
                        {risk.email ? `${risk.email} · ` : ''}
                        {risk.subject_kind === 'user'
                          ? risk.source
                            ? `person (${risk.source})`
                            : 'person'
                          : risk.subject_kind === 'agent'
                            ? 'device agent'
                            : risk.subject_kind === 'unresolved'
                              ? 'account not visible here'
                              : risk.subject_kind || 'service'}
                      </div>
                      <div className="text-xs text-muted-foreground font-mono">
                          {/* Only show the fabric name when the row is led by
                              something else. Otherwise it is the same string
                              rendered twice, which reads like two identities. */}
                          {risk.subject ? risk.identity_name : null}
                        </div>
                    </TableCell>
                    <TableCell className="p-4 font-mono">{risk.score}</TableCell>
                    <TableCell className="p-4">
                      <Badge className={severityBadge(risk.level)}>{risk.level}</Badge>
                    </TableCell>
                    <TableCell className="p-4 text-sm text-muted-foreground">
                      {risk.signals?.length ? risk.signals.join(', ') : '—'}
                    </TableCell>
                    <TableCell className="p-4">
                      {risk.quarantined ? (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => unquarantine.mutate(risk.identity_id)}
                          disabled={unquarantine.isPending}
                        >
                          Restore Access
                        </Button>
                      ) : (
                        <ConfirmAction
                          title="Quarantine this identity?"
                          description={`Quarantining "${risk.subject || risk.identity_name}" severs its Ziti role attributes and immediately terminates all active sessions, cutting this identity off the network. Access can be restored afterward, but any in-flight sessions are lost.`}
                          destructive
                          requireReason
                          confirmLabel="Quarantine"
                          onConfirm={(reason) =>
                            quarantine.mutateAsync({ identityId: risk.identity_id, reason: reason! })
                          }
                        >
                          {(open) => (
                            <Button
                              size="sm"
                              variant="destructive"
                              onClick={open}
                              disabled={quarantine.isPending}
                            >
                              Quarantine
                            </Button>
                          )}
                        </ConfirmAction>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
                {(insights?.top_risks || []).length === 0 && (
                  <TableRow>
                    <TableCell colSpan={5} className="p-8 text-center text-muted-foreground">
                      No identities found
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
        </CardContent>
      </Card>

      {/* Recommendations */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Lightbulb className="h-5 w-5 text-blue-500" />
            Policy Hygiene Recommendations
          </CardTitle>
          <CardDescription>Over-permissive policies, unused services and stale enrollments</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {(recommendations || []).map((rec, i) => (
            <div key={i} className="flex items-start gap-3 p-3 border rounded-lg">
              <Badge className={severityBadge(rec.severity)}>{rec.severity}</Badge>
              <div className="flex-1">
                <div className="font-medium">
                  {rec.title}
                  {rec.target_name && (
                    <span className="ml-2 text-sm font-mono text-muted-foreground">{rec.target_name}</span>
                  )}
                </div>
                <p className="text-sm text-muted-foreground mt-1">{rec.description}</p>
                <p className="text-sm mt-1">
                  <span className="font-medium">Suggested action:</span> {rec.action}
                </p>
              </div>
            </div>
          ))}
          {(recommendations || []).length === 0 && (
            <p className="py-6 text-center text-muted-foreground">No recommendations — the fabric looks healthy</p>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
