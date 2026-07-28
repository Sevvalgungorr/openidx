import { useQuery } from '@tanstack/react-query'
import {
  CheckCircle2,
  Laptop,
  Lightbulb,
  LogIn,
  RefreshCw,
  Shield,
  ShieldCheck,
  ShieldQuestion,
} from 'lucide-react'
import { Button } from '../components/ui/button'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { api } from '../lib/api'

interface InsightDevice {
  name: string
  trusted: boolean
  last_seen?: string
}

interface InsightLogin {
  at: string
  ip_address: string
  location?: string
  success: boolean
  risk_score: number
}

interface SecurityInsights {
  score: number
  level: string
  friction: string
  summary: string
  generated_by: string
  mfa_enrolled: boolean
  tips: string[]
  devices: InsightDevice[] | null
  recent_logins: InsightLogin[] | null
  open_alerts: number
  failed_logins_7d: number
}

const levelStyles: Record<string, { badge: string; ring: string }> = {
  low: { badge: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200', ring: 'text-green-600' },
  medium: { badge: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200', ring: 'text-yellow-600' },
  high: { badge: 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200', ring: 'text-orange-600' },
  critical: { badge: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200', ring: 'text-red-600' },
}

const frictionLabel: Record<string, string> = {
  low: 'Fewer verification prompts on trusted devices',
  normal: 'Standard verification prompts',
  strict: 'Extra verification on sensitive actions',
}

export function MySecurityPage() {
  const { data, isLoading, refetch } = useQuery({
    queryKey: ['my-security-insights'],
    queryFn: async () => api.get<SecurityInsights>('/api/v1/identity/portal/security-insights'),
  })

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-24">
        <LoadingSpinner />
      </div>
    )
  }

  const style = levelStyles[data?.level || 'low'] || levelStyles.low

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-2">
            <Shield className="h-8 w-8 text-blue-500" />
            My Security
          </h1>
          <p className="text-muted-foreground mt-1">How safe is my account, and what should I do next?</p>
        </div>
        <Button variant="outline" onClick={() => refetch()}>
          <RefreshCw className="h-4 w-4 mr-2" />
          Refresh
        </Button>
      </div>

      {/* Score + summary */}
      <Card>
        <CardContent className="pt-6">
          <div className="flex flex-wrap items-center gap-6">
            <div className="text-center">
              <div className={`text-5xl font-bold ${style.ring}`}>{data?.score ?? 0}</div>
              <div className="text-xs text-muted-foreground mt-1">risk score / 100</div>
              <Badge className={`mt-2 ${style.badge}`}>{data?.level || 'low'}</Badge>
            </div>
            <div className="flex-1 min-w-[260px] space-y-2">
              <p className="text-sm">{data?.summary}</p>
              <div className="flex flex-wrap gap-2">
                <Badge variant="secondary">{frictionLabel[data?.friction || 'normal']}</Badge>
                {data?.mfa_enrolled ? (
                  <Badge className="bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">
                    <ShieldCheck className="h-3 w-3 mr-1" />
                    MFA enrolled
                  </Badge>
                ) : (
                  <Badge className="bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200">
                    <ShieldQuestion className="h-3 w-3 mr-1" />
                    No MFA yet
                  </Badge>
                )}
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Tips */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Lightbulb className="h-4 w-4 text-yellow-500" />
            Recommendations
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          {(data?.tips || []).map((tip, i) => (
            <div key={i} className="flex items-start gap-2 text-sm">
              <CheckCircle2 className="h-4 w-4 mt-0.5 text-blue-500 shrink-0" />
              <span>{tip}</span>
            </div>
          ))}
        </CardContent>
      </Card>

      <div className="grid gap-6 md:grid-cols-2">
        {/* Devices */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Laptop className="h-4 w-4" />
              My Devices
            </CardTitle>
            <CardDescription>Trusted devices see fewer verification prompts</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            {(data?.devices || []).map((d, i) => (
              <div key={i} className="flex items-center justify-between text-sm border rounded-lg p-3">
                <div>
                  <div className="font-medium">{d.name}</div>
                  {d.last_seen && (
                    <div className="text-xs text-muted-foreground">
                      Last seen {new Date(d.last_seen).toLocaleDateString()}
                    </div>
                  )}
                </div>
                {d.trusted ? (
                  <Badge className="bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">trusted</Badge>
                ) : (
                  <Badge variant="secondary">not trusted</Badge>
                )}
              </div>
            ))}
            {(data?.devices || []).length === 0 && (
              <p className="text-sm text-muted-foreground py-4 text-center">No devices registered yet</p>
            )}
          </CardContent>
        </Card>

        {/* Recent logins */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <LogIn className="h-4 w-4" />
              Recent Sign-ins
            </CardTitle>
            <CardDescription>Report anything you don't recognize</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            {(data?.recent_logins || []).map((l, i) => (
              <div key={i} className="flex items-center justify-between text-sm border rounded-lg p-3">
                <div>
                  <div className="font-medium">{new Date(l.at).toLocaleString()}</div>
                  <div className="text-xs text-muted-foreground font-mono">
                    {l.ip_address}
                    {l.location ? ` · ${l.location}` : ''}
                  </div>
                </div>
                {l.success ? (
                  <Badge className="bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">ok</Badge>
                ) : (
                  <Badge className="bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200">failed</Badge>
                )}
              </div>
            ))}
            {(data?.recent_logins || []).length === 0 && (
              <p className="text-sm text-muted-foreground py-4 text-center">No recent sign-ins</p>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
